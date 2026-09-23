import { HttpError } from "./errors";

const WRITE_METHODS = new Set(["PUT", "DELETE"]);

export function parseRefPatterns(value: string | undefined): string[] {
  return (value ?? "")
    .split(",")
    .map((pattern) => pattern.trim())
    .filter(Boolean);
}

function refMatches(pattern: string, ref: string): boolean {
  return pattern.endsWith("*") ? ref.startsWith(pattern.slice(0, -1)) : ref === pattern;
}

export function assertMayWrite(method: string, ref: unknown, allowedWriteRefs: string[]): void {
  if (!WRITE_METHODS.has(method) || allowedWriteRefs.length === 0) return;
  const tokenRef = typeof ref === "string" ? ref : "";
  if (!allowedWriteRefs.some((pattern) => refMatches(pattern, tokenRef))) {
    throw new HttpError(403, `ref "${tokenRef}" may not write`);
  }
}
