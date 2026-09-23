import { vi } from "vitest";
import { GITHUB_ISSUER, GITHUB_JWKS_URL } from "../src/oidc";

export interface SigningKey {
  kid: string;
  privateKey: CryptoKey;
  jwk: JsonWebKey & { kid: string };
}

export async function makeSigningKey(kid: string): Promise<SigningKey> {
  const pair = (await crypto.subtle.generateKey(
    { name: "RSASSA-PKCS1-v1_5", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  const exported = (await crypto.subtle.exportKey("jwk", pair.publicKey)) as JsonWebKey;
  return {
    kid,
    privateKey: pair.privateKey,
    jwk: { kty: "RSA", n: exported.n, e: exported.e, alg: "RS256", use: "sig", kid },
  };
}

export function mockJwks(keys: () => SigningKey[]) {
  return vi.spyOn(globalThis, "fetch").mockImplementation(async (input) => {
    const url = input instanceof Request ? input.url : String(input);
    if (url !== GITHUB_JWKS_URL) throw new Error(`unexpected fetch: ${url}`);
    return Response.json({ keys: keys().map((k) => k.jwk) });
  });
}

const encoder = new TextEncoder();

function base64Url(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const jsonPart = (value: unknown) => base64Url(encoder.encode(JSON.stringify(value)));

const OWNER_IDS: Record<string, string> = { peopledrivemecrazy: "1001", "some-org": "1002" };

export function claimsFor(repository: string, overrides: Record<string, unknown> = {}) {
  const now = Math.floor(Date.now() / 1000);
  const owner = repository.split("/")[0]!;
  return {
    iss: GITHUB_ISSUER,
    aud: "r2facts",
    iat: now,
    nbf: now - 5,
    exp: now + 300,
    repository,
    repository_owner: owner,
    repository_owner_id: OWNER_IDS[owner] ?? "9999",
    ref: "refs/heads/master",
    ...overrides,
  };
}

export async function signToken(key: SigningKey, claims: Record<string, unknown>, header: Record<string, unknown> = {}) {
  const signingInput = `${jsonPart({ alg: "RS256", typ: "JWT", kid: key.kid, ...header })}.${jsonPart(claims)}`;
  const signature = await crypto.subtle.sign("RSASSA-PKCS1-v1_5", key.privateKey, encoder.encode(signingInput));
  return `${signingInput}.${base64Url(new Uint8Array(signature))}`;
}
