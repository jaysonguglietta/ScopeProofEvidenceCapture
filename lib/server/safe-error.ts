export type SafeErrorClass =
  | "abort_error"
  | "error"
  | "http_4xx"
  | "http_5xx"
  | "http_other"
  | "non_error"
  | "range_error"
  | "syntax_error"
  | "type_error";

/**
 * Return a bounded allowlisted category for operational logs.
 *
 * Error messages are intentionally excluded: provider responses, runtime
 * bindings, key identifiers, request data, and tokens can all flow into an
 * exception message. Callers that need a user-facing error must construct a
 * separate, explicitly reviewed message.
 */
export function classifyErrorForLogging(error: unknown): SafeErrorClass {
  if (error instanceof Response) {
    if (error.status >= 400 && error.status < 500) return "http_4xx";
    if (error.status >= 500 && error.status < 600) return "http_5xx";
    return "http_other";
  }
  if (error instanceof SyntaxError) return "syntax_error";
  if (error instanceof TypeError) return "type_error";
  if (error instanceof RangeError) return "range_error";
  if (typeof DOMException !== "undefined" && error instanceof DOMException && error.name === "AbortError") return "abort_error";
  if (error instanceof Error) return "error";
  return "non_error";
}
