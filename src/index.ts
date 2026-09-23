import { errorResponse, HttpError } from "./errors";
import { parseAllowedOwnerIds, verifyGitHubToken } from "./oidc";
import { objectKey, rawPathname } from "./path";
import { assertMayWrite, parseRefPatterns } from "./refs";

export interface Env {
  BUCKET: R2Bucket;
  ALLOWED_OWNER_IDS?: string;
  ALLOWED_WRITE_REFS?: string;
  AUDIENCE?: string;
  MAX_UPLOAD_BYTES?: string;
}

const DEFAULT_AUDIENCE = "r2facts";
const DEFAULT_MAX_UPLOAD_BYTES = 100 * 1024 * 1024;
const ALLOWED_METHODS = "GET, HEAD, PUT, DELETE";

export default {
  async fetch(request, env): Promise<Response> {
    try {
      return await handle(request, env);
    } catch (err) {
      if (err instanceof HttpError) return errorResponse(err.status, err.message, err.headers);
      console.error("unhandled error:", err instanceof Error ? err.name : typeof err);
      return errorResponse(500, "internal error");
    }
  },
} satisfies ExportedHandler<Env>;

async function handle(request: Request, env: Env): Promise<Response> {
  if (!["GET", "HEAD", "PUT", "DELETE"].includes(request.method)) {
    throw new HttpError(405, "method not allowed", { allow: ALLOWED_METHODS });
  }

  const allowedOwnerIds = parseAllowedOwnerIds(env.ALLOWED_OWNER_IDS);
  if (allowedOwnerIds.length === 0) throw new HttpError(500, "ALLOWED_OWNER_IDS is not configured");

  const token = /^Bearer\s+(\S+)$/i.exec(request.headers.get("authorization") ?? "")?.[1];
  if (!token) throw new HttpError(401, "missing bearer token", { "www-authenticate": "Bearer" });

  const claims = await verifyGitHubToken(token, {
    audience: env.AUDIENCE || DEFAULT_AUDIENCE,
    allowedOwnerIds,
  });
  assertMayWrite(request.method, claims.ref, parseRefPatterns(env.ALLOWED_WRITE_REFS));
  const key = objectKey(claims.repository, rawPathname(request.url));

  switch (request.method) {
    case "PUT":
      return put(request, env, key);
    case "GET": {
      const object = await env.BUCKET.get(key);
      if (!object) throw new HttpError(404, "not found");
      return new Response(object.body, { headers: objectHeaders(object) });
    }
    case "HEAD": {
      const object = await env.BUCKET.head(key);
      if (!object) return new Response(null, { status: 404 });
      return new Response(null, { headers: objectHeaders(object) });
    }
    default: {
      await env.BUCKET.delete(key);
      return new Response(null, { status: 204 });
    }
  }
}

async function put(request: Request, env: Env, key: string): Promise<Response> {
  const maxBytes = Number(env.MAX_UPLOAD_BYTES) || DEFAULT_MAX_UPLOAD_BYTES;
  const lengthHeader = request.headers.get("content-length");
  if (lengthHeader === null) throw new HttpError(411, "Content-Length is required");
  if (!/^\d+$/.test(lengthHeader)) throw new HttpError(400, "invalid Content-Length");
  const length = Number(lengthHeader);
  if (length > maxBytes) throw new HttpError(413, `upload is ${length} bytes; the limit is ${maxBytes} bytes`);

  const object = await env.BUCKET.put(key, request.body ?? new Uint8Array(), {
    httpMetadata: { contentType: request.headers.get("content-type") || "application/octet-stream" },
  });
  return Response.json({ key, size: object.size, etag: object.etag }, { status: 201 });
}

function objectHeaders(object: R2Object): Headers {
  const headers = new Headers();
  object.writeHttpMetadata(headers);
  headers.set("etag", object.httpEtag);
  headers.set("content-length", String(object.size));
  headers.set("last-modified", object.uploaded.toUTCString());
  headers.set("cache-control", "private, no-store");
  return headers;
}
