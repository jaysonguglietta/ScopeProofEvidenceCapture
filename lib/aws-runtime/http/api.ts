import { TenantSecurityError } from "../contracts.ts";
import { type HostAuthority, type TenantActor, type TenantAuthorityResolver, type TenantPermission } from "../tenancy.ts";
import { exactBearerToken, type CognitoAccessTokenVerifier, type VerifiedCognitoAccessToken } from "./jwt.ts";
import { authorizeVerifiedTenantIdentity, type TenantMembershipRepository } from "./membership.ts";

export interface ApiGatewayV2Event {
  readonly headers?: Readonly<Record<string, string | undefined>>;
  readonly requestContext: Readonly<{
    readonly requestId: string;
    readonly domainName: string;
    readonly http: Readonly<{ readonly method: string }>;
  }>;
  readonly rawPath: string;
}

export interface TrustedEdgeAuthorityVerifier {
  /** Must cryptographically authenticate the edge assertion and consume its replay nonce atomically. */
  verify(event: ApiGatewayV2Event): Promise<Readonly<{ viewerHost: string }>>;
}

export type RequestAuthorityPolicy =
  | Readonly<{ mode: "api_gateway_domain" }>
  | Readonly<{ mode: "trusted_edge"; verifier: TrustedEdgeAuthorityVerifier }>;

export interface AuthorizedApiRequest {
  readonly requestId: string;
  readonly method: string;
  readonly path: string;
  readonly actor: TenantActor;
  readonly identity: VerifiedCognitoAccessToken;
}

export interface ApiAuthenticationDependencies {
  readonly tenants: TenantAuthorityResolver;
  readonly jwt: CognitoAccessTokenVerifier;
  readonly memberships: TenantMembershipRepository;
  readonly authority: RequestAuthorityPolicy;
}

export interface ApiProblem {
  readonly type: "about:blank";
  readonly title: string;
  readonly status: number;
  readonly code: string;
  readonly requestId: string;
}

const requestIdPattern = /^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$/;
const methodPattern = /^(?:GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS)$/;
const pathPattern = /^\/(?:[A-Za-z0-9._~!$&'()*+,;=:@/-]{0,2047})$/;

function validRequestPath(path: string): boolean {
  if (!pathPattern.test(path)) return false;
  let decoded: string;
  try {
    decoded = decodeURIComponent(path);
  } catch {
    return false;
  }
  return !/[\\\p{Cc}]/u.test(decoded) && !decoded.includes("//") && !decoded.split("/").some((segment) => segment === "." || segment === "..");
}

function normalizedHeaders(source: Readonly<Record<string, string | undefined>> | undefined): ReadonlyMap<string, string> {
  const result = new Map<string, string>();
  for (const [rawName, rawValue] of Object.entries(source || {})) {
    const name = rawName.toLowerCase();
    if (!/^[a-z0-9!#$%&'*+.^_`|~-]{1,128}$/.test(name) || typeof rawValue !== "string" || rawValue.length > 32_768 || /\p{Cc}/u.test(rawValue) || result.has(name)) {
      throw new TenantSecurityError("INVALID_PRINCIPAL", "Request headers are invalid.", 400);
    }
    result.set(name, rawValue);
  }
  return result;
}

export async function authorizeApiGatewayRequest(
  event: ApiGatewayV2Event,
  permission: TenantPermission,
  dependencies: ApiAuthenticationDependencies,
): Promise<AuthorizedApiRequest> {
  const requestId = String(event.requestContext?.requestId || "");
  const method = String(event.requestContext?.http?.method || "");
  const path = String(event.rawPath || "");
  if (!requestIdPattern.test(requestId)) throw new TenantSecurityError("INVALID_IDENTIFIER", "Request context is invalid.", 400);
  if (!methodPattern.test(method) || !validRequestPath(path)) throw new TenantSecurityError("INVALID_IDENTIFIER", "Request target is invalid.", 400);
  const headers = normalizedHeaders(event.headers);
  const authority: HostAuthority = dependencies.authority.mode === "api_gateway_domain"
    ? { source: "direct", host: event.requestContext.domainName }
    : { source: "trusted_edge", viewerHost: (await dependencies.authority.verifier.verify(event)).viewerHost, edgeProofVerified: true };
  const resolved = await dependencies.tenants.resolve(authority);
  const token = exactBearerToken(headers.get("authorization"));
  const identity = await dependencies.jwt.verify(token);
  const { actor } = await authorizeVerifiedTenantIdentity({ resolved, identity, memberships: dependencies.memberships, permission });
  return Object.freeze({ requestId, method, path, actor, identity });
}

function problemFor(error: unknown, requestId: string): ApiProblem {
  const status = error instanceof TenantSecurityError && [400, 401, 403, 404, 409, 410, 413, 415, 421, 429].includes(error.safeStatus) ? error.safeStatus : 500;
  const title = status === 401 ? "Authentication required"
    : status === 403 ? "Access denied"
      : status === 404 ? "Resource not found"
        : status === 409 ? "Request conflict"
          : status === 410 ? "Resource expired"
          : status === 413 ? "Request too large"
            : status === 415 ? "Unsupported media type"
              : status === 421 ? "Unknown tenant host"
                : status === 429 ? "Too many requests"
                  : status === 400 ? "Invalid request" : "Internal server error";
  const code = status === 500 ? "INTERNAL_ERROR" : error instanceof TenantSecurityError ? error.code : "INTERNAL_ERROR";
  return Object.freeze({ type: "about:blank", title, status, code, requestId });
}

export function safeProblemResponse(error: unknown, requestId: string): Response {
  const safeRequestId = requestIdPattern.test(requestId) ? requestId : crypto.randomUUID();
  const problem = problemFor(error, safeRequestId);
  const headers = new Headers({
    "cache-control": "no-store",
    "content-type": "application/problem+json",
    "x-content-type-options": "nosniff",
    "x-request-id": safeRequestId,
  });
  if (problem.status === 401) headers.set("www-authenticate", "Bearer");
  if (problem.status === 429) headers.set("retry-after", "60");
  return new Response(JSON.stringify(problem), { status: problem.status, headers });
}

export async function handleAuthorizedApiRequest(
  event: ApiGatewayV2Event,
  permission: TenantPermission,
  dependencies: ApiAuthenticationDependencies,
  handler: (request: AuthorizedApiRequest) => Promise<Response>,
  onInternalError?: (event: Readonly<{ requestId: string; errorName: string }>) => void,
): Promise<Response> {
  const requestId = requestIdPattern.test(String(event.requestContext?.requestId || "")) ? event.requestContext.requestId : crypto.randomUUID();
  try {
    const request = await authorizeApiGatewayRequest(event, permission, dependencies);
    const response = await handler(request);
    const headers = new Headers(response.headers);
    headers.set("x-request-id", request.requestId);
    headers.set("cache-control", headers.get("cache-control") || "no-store");
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
  } catch (error) {
    if (!(error instanceof TenantSecurityError) || error.safeStatus >= 500) onInternalError?.({ requestId, errorName: error instanceof Error ? error.name : "UnknownError" });
    return safeProblemResponse(error, requestId);
  }
}
