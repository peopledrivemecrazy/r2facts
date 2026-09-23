export class HttpError extends Error {
  constructor(
    readonly status: number,
    message: string,
    readonly headers: Record<string, string> = {},
  ) {
    super(message);
    this.name = "HttpError";
  }
}

export function errorResponse(status: number, message: string, headers: Record<string, string> = {}): Response {
  return Response.json(
    { error: message },
    { status, headers: { "cache-control": "no-store", ...headers } },
  );
}
