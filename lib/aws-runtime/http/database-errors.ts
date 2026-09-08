import { TenantSecurityError } from "../contracts.ts";

/** Only stable SQLSTATE categories cross HTTP; never expose SQL or values. */
export function databaseProblem(error: unknown): unknown {
  if (error instanceof TenantSecurityError) return error;
  const value = error as { code?: unknown; message?: unknown };
  const code = typeof value?.code === "string" ? value.code : String(value?.message || "").match(/SQLState:\s*([A-Z0-9]{5})/)?.[1];
  if (code === "42501") return new TenantSecurityError("ROLE_FORBIDDEN", "Current membership does not permit this operation.", 403);
  if (code === "P0002") return new TenantSecurityError("RESOURCE_NOT_FOUND", "Resource is unavailable.", 404);
  if (code === "40001" || code === "23505") return new TenantSecurityError("CONCURRENT_MODIFICATION", "The resource changed or the request conflicts. Reload its current state.", 409);
  if (code && ["22023", "22007", "22008", "22P02", "22003", "23514", "23502", "23503"].includes(code)) return new TenantSecurityError("INVALID_IDENTIFIER", "The request contains invalid fields or scope.", 400);
  return error;
}
