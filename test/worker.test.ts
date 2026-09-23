import { reset } from "cloudflare:test";
import { env } from "cloudflare:workers";
import { afterEach, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import worker, { type Env } from "../src/index";
import { resetJwksCache } from "../src/oidc";
import { claimsFor, makeSigningKey, mockJwks, signToken, type SigningKey } from "./helpers";

const REPO = "peopledrivemecrazy/simple-secret-service";
const BASE = "https://r2facts.test";
const testEnv = env as unknown as Env;

let key: SigningKey;
let otherKey: SigningKey;
let published: SigningKey[];

beforeAll(async () => {
  key = await makeSigningKey("key-1");
  otherKey = await makeSigningKey("key-2");
});

beforeEach(() => {
  published = [key];
  resetJwksCache();
  mockJwks(() => published);
});

afterEach(async () => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  await reset();
});

async function call(method: string, path: string, token?: string, init: RequestInit = {}, envOverrides: Partial<Env> = {}) {
  const headers = new Headers(init.headers);
  if (token) headers.set("authorization", `Bearer ${token}`);
  const request = new Request(`${BASE}${path}`, { ...init, method, headers });
  return worker.fetch(request as Request<unknown, IncomingRequestCfProperties>, { ...testEnv, ...envOverrides });
}

const tokenFor = (repository = REPO, overrides: Record<string, unknown> = {}) =>
  signToken(key, claimsFor(repository, overrides));

async function upload(path: string, body: string, token?: string) {
  return call("PUT", path, token ?? (await tokenFor()), {
    body,
    headers: { "content-length": String(new TextEncoder().encode(body).length), "content-type": "text/plain" },
  });
}

async function errorOf(res: Response) {
  return ((await res.json()) as { error: string }).error;
}

describe("authentication", () => {
  it("accepts a valid token and round-trips a file", async () => {
    const put = await upload("/candidates/abc/bundle.txt", "hello r2");
    expect(put.status).toBe(201);
    expect(await put.json()).toMatchObject({
      key: `github/${REPO}/candidates/abc/bundle.txt`,
      size: 8,
    });

    const stored = await testEnv.BUCKET.get(`github/${REPO}/candidates/abc/bundle.txt`);
    expect(await stored?.text()).toBe("hello r2");

    const get = await call("GET", "/candidates/abc/bundle.txt", await tokenFor());
    expect(get.status).toBe(200);
    expect(get.headers.get("content-type")).toBe("text/plain");
    expect(await get.text()).toBe("hello r2");
  });

  it("rejects a request without a token", async () => {
    const res = await call("GET", "/a.txt");
    expect(res.status).toBe(401);
    expect(res.headers.get("www-authenticate")).toBe("Bearer");
  });

  it("rejects a malformed token", async () => {
    const res = await call("GET", "/a.txt", "not-a-jwt");
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("malformed token");
  });

  it("rejects the wrong audience", async () => {
    const res = await call("GET", "/a.txt", await tokenFor(REPO, { aud: "sts.amazonaws.com" }));
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("wrong token audience");
  });

  it("rejects the wrong issuer", async () => {
    const res = await call("GET", "/a.txt", await tokenFor(REPO, { iss: "https://evil.example" }));
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("wrong token issuer");
  });

  it("rejects an expired token", async () => {
    const past = Math.floor(Date.now() / 1000) - 3600;
    const res = await call("GET", "/a.txt", await tokenFor(REPO, { iat: past - 300, nbf: past - 300, exp: past }));
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("token expired");
  });

  it("allows small clock skew on exp", async () => {
    const res = await call("HEAD", "/a.txt", await tokenFor(REPO, { exp: Math.floor(Date.now() / 1000) - 30 }));
    expect(res.status).toBe(404);
  });

  it("rejects a token that is not yet valid", async () => {
    const future = Math.floor(Date.now() / 1000) + 3600;
    const res = await call("GET", "/a.txt", await tokenFor(REPO, { nbf: future, exp: future + 300 }));
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("token not yet valid");
  });

  it("rejects a token signed by an unpublished key", async () => {
    const res = await call("GET", "/a.txt", await signToken(otherKey, claimsFor(REPO)));
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("unknown token signing key");
  });

  it("rejects a forged signature", async () => {
    const forged = await signToken(otherKey, claimsFor(REPO), { kid: key.kid });
    const res = await call("GET", "/a.txt", forged);
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("invalid token signature");
  });

  it("rejects tampered claims", async () => {
    const [header, , signature] = (await tokenFor()).split(".");
    const [, payload] = (await tokenFor("peopledrivemecrazy/other")).split(".");
    const res = await call("GET", "/a.txt", `${header}.${payload}.${signature}`);
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("invalid token signature");
  });

  it("rejects algorithms other than RS256", async () => {
    const res = await call("GET", "/a.txt", await signToken(key, claimsFor(REPO), { alg: "none" }));
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("unsupported token algorithm");
  });

  it("rejects an owner that is not allowed", async () => {
    const res = await call("GET", "/a.txt", await tokenFor("someone-else/repo"));
    expect(res.status).toBe(403);
    expect(await errorOf(res)).toBe('repository owner "someone-else" (id 9999) is not allowed');
  });

  it("accepts every listed owner id", async () => {
    const res = await call("HEAD", "/a.txt", await tokenFor("some-org/tools"));
    expect(res.status).toBe(404);
  });

  it("rejects a new account that took over an allowed owner's old name", async () => {
    const res = await call("GET", "/a.txt", await tokenFor(REPO, { repository_owner_id: "5555" }));
    expect(res.status).toBe(403);
    expect(await errorOf(res)).toBe('repository owner "peopledrivemecrazy" (id 5555) is not allowed');
  });

  it("rejects a token without a numeric owner id", async () => {
    const res = await call("GET", "/a.txt", await tokenFor(REPO, { repository_owner_id: undefined }));
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("token has no valid repository claims");
  });

  it("rejects a repository claim outside its owner", async () => {
    const res = await call("GET", "/a.txt", await tokenFor("someone-else/repo", { repository_owner: "peopledrivemecrazy" }));
    expect(res.status).toBe(401);
    expect(await errorOf(res)).toBe("token has no valid repository claims");
  });

  it("fails closed when ALLOWED_OWNER_IDS is not configured", async () => {
    const res = await call("GET", "/a.txt", await tokenFor(), {}, { ALLOWED_OWNER_IDS: " , peopledrivemecrazy" });
    expect(res.status).toBe(500);
    expect(await errorOf(res)).toBe("ALLOWED_OWNER_IDS is not configured");
  });

  it("refetches the JWKS when GitHub rotates keys", async () => {
    vi.useFakeTimers({ toFake: ["Date"] });
    expect((await call("HEAD", "/a.txt", await tokenFor())).status).toBe(404);

    published = [key, otherKey];
    const rotated = await signToken(otherKey, claimsFor(REPO));
    expect((await call("HEAD", "/a.txt", rotated)).status).toBe(401);

    vi.setSystemTime(Date.now() + 61_000);
    const fresh = await signToken(otherKey, claimsFor(REPO));
    expect((await call("HEAD", "/a.txt", fresh)).status).toBe(404);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it("returns 503 when the JWKS cannot be fetched", async () => {
    vi.mocked(fetch).mockResolvedValue(new Response("down", { status: 502 }));
    const res = await call("GET", "/a.txt", await tokenFor());
    expect(res.status).toBe(503);
  });
});

describe("path scoping", () => {
  it.each([
    ["/", "path is required"],
    ["/a//b", "path has an empty segment"],
    ["/a/", "path has an empty segment"],
    ["/..%2fother%2fx", "path has an encoded separator"],
    ["/a%2F..%2F..%2Fother", "path has an encoded separator"],
    ["/a%5c..%5cother", "path has an encoded separator"],
    ["/a%00b", "path has control characters"],
    ["/bad%zzescape", "path has malformed percent-encoding"],
  ])("rejects %s", async (path, message) => {
    const res = await call("GET", path, await tokenFor());
    expect(res.status).toBe(400);
    expect(await errorOf(res)).toBe(message);
  });

  it.each(["/a/../../other/x", "/./x", "/%2e%2e/other/x", "/a/%2E%2E/%2E%2E/other/x"])(
    "rejects unnormalised traversal %s",
    async (path) => {
      const { rawPathname, objectKey } = await import("../src/path");
      expect(rawPathname(`https://r2facts.test${path}?q=1`)).toBe(path);
      expect(() => objectKey(REPO, path)).toThrow("path traversal is not allowed");
    },
  );

  it("rejects paths longer than an R2 key allows", async () => {
    const res = await call("GET", `/${"a".repeat(1100)}`, await tokenFor());
    expect(res.status).toBe(400);
    expect(await errorOf(res)).toBe("path is too long");
  });

  it("keeps each repository inside its own prefix", async () => {
    const ownerA = "peopledrivemecrazy/repo-a";
    const ownerB = "peopledrivemecrazy/repo-b";
    expect((await upload("/shared/file.txt", "from a", await tokenFor(ownerA))).status).toBe(201);

    expect((await call("GET", "/shared/file.txt", await tokenFor(ownerB))).status).toBe(404);
    expect((await call("GET", "/github/peopledrivemecrazy/repo-a/shared/file.txt", await tokenFor(ownerB))).status).toBe(404);
    expect((await call("GET", "/../repo-a/shared/file.txt", await tokenFor(ownerB))).status).toBe(404);
    expect((await call("GET", "/%2e%2e/repo-a/shared/file.txt", await tokenFor(ownerB))).status).toBe(404);

    expect((await upload("/shared/file.txt", "from b", await tokenFor(ownerB))).status).toBe(201);
    expect((await call("DELETE", "/shared/file.txt", await tokenFor(ownerB))).status).toBe(204);
    expect(await (await testEnv.BUCKET.get(`github/${ownerA}/shared/file.txt`))?.text()).toBe("from a");
  });
});

describe("object API", () => {
  it("reports existence and size with HEAD", async () => {
    await upload("/report.txt", "12345");
    const res = await call("HEAD", "/report.txt", await tokenFor());
    expect(res.status).toBe(200);
    expect(res.headers.get("content-length")).toBe("5");
    expect(res.headers.get("etag")).toBeTruthy();
    expect(res.body).toBeNull();
  });

  it("returns 404 for a missing object", async () => {
    const res = await call("GET", "/missing.txt", await tokenFor());
    expect(res.status).toBe(404);
    expect(await errorOf(res)).toBe("not found");
  });

  it("deletes an object", async () => {
    await upload("/gone.txt", "bye");
    expect((await call("DELETE", "/gone.txt", await tokenFor())).status).toBe(204);
    expect((await call("HEAD", "/gone.txt", await tokenFor())).status).toBe(404);
  });

  it("stores an empty file", async () => {
    const res = await upload("/empty.txt", "");
    expect(res.status).toBe(201);
    expect(await (await call("GET", "/empty.txt", await tokenFor())).text()).toBe("");
  });

  it("rejects uploads over the size limit with 413", async () => {
    const res = await upload("/big.bin", "x".repeat(1025));
    expect(res.status).toBe(413);
    expect(await errorOf(res)).toBe("upload is 1025 bytes; the limit is 1024 bytes");
  });

  it("requires Content-Length on uploads", async () => {
    const body = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode("streamed"));
        controller.close();
      },
    });
    const res = await call("PUT", "/stream.txt", await tokenFor(), { body, duplex: "half" } as RequestInit);
    expect(res.status).toBe(411);
  });

  it("rejects unsupported methods", async () => {
    const res = await call("POST", "/a.txt", await tokenFor(), { body: "x" });
    expect(res.status).toBe(405);
    expect(res.headers.get("allow")).toBe("GET, HEAD, PUT, DELETE");
  });
});
