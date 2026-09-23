import { HttpError } from "./errors";

export const GITHUB_ISSUER = "https://token.actions.githubusercontent.com";
export const GITHUB_JWKS_URL = `${GITHUB_ISSUER}/.well-known/jwks`;

const CLOCK_SKEW_SECONDS = 60;
const JWKS_TTL_MS = 60 * 60 * 1000;
const JWKS_MIN_REFETCH_MS = 60 * 1000;

export interface GitHubClaims {
  iss: string;
  aud: string | string[];
  exp: number;
  nbf?: number;
  repository: string;
  repository_owner: string;
  repository_owner_id: string;
  [claim: string]: unknown;
}

interface KeyCache {
  keys: Map<string, CryptoKey>;
  fetchedAt: number;
}

let cache: KeyCache | undefined;

export function resetJwksCache(): void {
  cache = undefined;
}

const unauthorized = (message: string) =>
  new HttpError(401, message, { "www-authenticate": 'Bearer error="invalid_token"' });

async function loadJwks(now: number): Promise<KeyCache> {
  let body: { keys?: (JsonWebKey & { kid?: string })[] };
  try {
    const res = await fetch(GITHUB_JWKS_URL, { headers: { accept: "application/json" } });
    if (!res.ok) throw new Error(`status ${res.status}`);
    body = await res.json();
  } catch {
    throw new HttpError(503, "could not fetch GitHub OIDC signing keys");
  }

  const keys = new Map<string, CryptoKey>();
  for (const jwk of body.keys ?? []) {
    if (jwk.kty !== "RSA" || !jwk.kid || !jwk.n || !jwk.e) continue;
    if (jwk.alg && jwk.alg !== "RS256") continue;
    if (jwk.use && jwk.use !== "sig") continue;
    const key = await crypto.subtle.importKey(
      "jwk",
      { kty: "RSA", n: jwk.n, e: jwk.e, alg: "RS256", ext: true },
      { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
      false,
      ["verify"],
    );
    keys.set(jwk.kid, key);
  }
  return { keys, fetchedAt: now };
}

async function signingKey(kid: string, now: number): Promise<CryptoKey | undefined> {
  if (!cache || now - cache.fetchedAt > JWKS_TTL_MS) cache = await loadJwks(now);
  let key = cache.keys.get(kid);
  if (!key && now - cache.fetchedAt > JWKS_MIN_REFETCH_MS) {
    cache = await loadJwks(now);
    key = cache.keys.get(kid);
  }
  return key;
}

function base64UrlDecode(input: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]*$/.test(input)) throw unauthorized("malformed token");
  const base64 = input.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (input.length % 4)) % 4);
  return Uint8Array.from(atob(base64), (c) => c.charCodeAt(0));
}

function decodeJson(segment: string): Record<string, unknown> {
  let value: unknown;
  try {
    value = JSON.parse(new TextDecoder().decode(base64UrlDecode(segment)));
  } catch {
    throw unauthorized("malformed token");
  }
  if (!value || typeof value !== "object" || Array.isArray(value)) throw unauthorized("malformed token");
  return value as Record<string, unknown>;
}

export function parseAllowedOwnerIds(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((id) => id.trim())
    .filter((id) => /^\d+$/.test(id));
}

export interface VerifyOptions {
  audience: string;
  allowedOwnerIds: string[];
  now?: number;
}

export async function verifyGitHubToken(token: string, options: VerifyOptions): Promise<GitHubClaims> {
  const now = options.now ?? Date.now();
  const parts = token.split(".");
  if (parts.length !== 3) throw unauthorized("malformed token");
  const [headerPart, payloadPart, signaturePart] = parts as [string, string, string];

  const header = decodeJson(headerPart);
  if (header.alg !== "RS256") throw unauthorized("unsupported token algorithm");
  if (typeof header.kid !== "string") throw unauthorized("token has no key id");

  const key = await signingKey(header.kid, now);
  if (!key) throw unauthorized("unknown token signing key");

  const valid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    key,
    base64UrlDecode(signaturePart),
    new TextEncoder().encode(`${headerPart}.${payloadPart}`),
  );
  if (!valid) throw unauthorized("invalid token signature");

  const claims = decodeJson(payloadPart);
  if (claims.iss !== GITHUB_ISSUER) throw unauthorized("wrong token issuer");

  const audiences = Array.isArray(claims.aud) ? claims.aud : [claims.aud];
  if (!audiences.includes(options.audience)) throw unauthorized("wrong token audience");

  const nowSeconds = Math.floor(now / 1000);
  if (typeof claims.exp !== "number") throw unauthorized("token has no expiry");
  if (nowSeconds - CLOCK_SKEW_SECONDS >= claims.exp) throw unauthorized("token expired");
  if (typeof claims.nbf === "number" && claims.nbf - CLOCK_SKEW_SECONDS > nowSeconds) {
    throw unauthorized("token not yet valid");
  }

  const owner = claims.repository_owner;
  const ownerId = claims.repository_owner_id;
  const repository = claims.repository;
  if (
    typeof owner !== "string" ||
    typeof ownerId !== "string" ||
    !/^\d+$/.test(ownerId) ||
    typeof repository !== "string" ||
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository) ||
    !repository.toLowerCase().startsWith(`${owner.toLowerCase()}/`)
  ) {
    throw unauthorized("token has no valid repository claims");
  }

  if (!options.allowedOwnerIds.includes(ownerId)) {
    throw new HttpError(403, `repository owner "${owner}" (id ${ownerId}) is not allowed`);
  }

  return claims as GitHubClaims;
}
