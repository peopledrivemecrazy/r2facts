import { HttpError } from "./errors";

const MAX_KEY_BYTES = 1024;

const badPath = (message: string) => new HttpError(400, message);

export function rawPathname(url: string): string {
  const afterScheme = url.indexOf("//");
  const start = url.indexOf("/", afterScheme === -1 ? 0 : afterScheme + 2);
  if (start === -1) return "/";
  return url.slice(start).split(/[?#]/, 1)[0]!;
}

export function objectKey(repository: string, pathname: string): string {
  if (!pathname.startsWith("/")) throw badPath("path must be absolute");
  const raw = pathname.slice(1);
  if (raw === "") throw badPath("path is required");

  const segments = raw.split("/").map((segment) => {
    if (segment === "") throw badPath("path has an empty segment");
    let decoded: string;
    try {
      decoded = decodeURIComponent(segment);
    } catch {
      throw badPath("path has malformed percent-encoding");
    }
    if (decoded === "." || decoded === "..") throw badPath("path traversal is not allowed");
    if (/[/\\]/.test(decoded)) throw badPath("path has an encoded separator");
    if (/[\u0000-\u001f\u007f]/.test(decoded)) throw badPath("path has control characters");
    return decoded;
  });

  const key = `github/${repository}/${segments.join("/")}`;
  if (new TextEncoder().encode(key).length > MAX_KEY_BYTES) throw badPath("path is too long");
  return key;
}
