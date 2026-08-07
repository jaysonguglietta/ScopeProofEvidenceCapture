export type RedactionKind = "pan" | "aws_access_key" | "github_token" | "api_token" | "jwt" | "private_key" | "authorization";
export interface RedactionFinding { kind: RedactionKind; count: number; }
export interface RedactionResult { value: string; findings: RedactionFinding[]; total: number; }

const REDACTED = "[REDACTED]";

function luhn(value: string): boolean {
  const digits = value.replace(/\D/g, "");
  if (digits.length < 13 || digits.length > 19 || /^(\d)\1+$/.test(digits)) return false;
  let sum = 0;
  let alternate = false;
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    let digit = Number(digits[index]);
    if (alternate) { digit *= 2; if (digit > 9) digit -= 9; }
    sum += digit; alternate = !alternate;
  }
  return sum % 10 === 0;
}

const patterns: Array<{ kind: Exclude<RedactionKind, "pan">; expression: RegExp }> = [
  { kind: "private_key", expression: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { kind: "aws_access_key", expression: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g },
  { kind: "github_token", expression: /\b(?:gh[pousr]_[A-Za-z0-9_]{30,255}|github_pat_[A-Za-z0-9_]{40,255})\b/g },
  { kind: "jwt", expression: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g },
  { kind: "authorization", expression: /\b(?:authorization|proxy-authorization)\s*[:=]\s*(?:bearer|basic)\s+[A-Za-z0-9._~+/-]+=*/gi },
  { kind: "api_token", expression: /\b(?:api[_-]?key|api[_-]?token|access[_-]?token|client[_-]?secret|secret[_-]?key)\s*[:=]\s*["']?[A-Za-z0-9_./+~-]{16,}["']?/gi },
];

export function redactText(input: string): RedactionResult {
  let value = input;
  const counts = new Map<RedactionKind, number>();
  for (const pattern of patterns) {
    value = value.replace(pattern.expression, () => {
      counts.set(pattern.kind, (counts.get(pattern.kind) || 0) + 1);
      return REDACTED;
    });
  }
  value = value.replace(/\b(?:\d[ -]*?){13,19}\b/g, (candidate) => {
    if (!luhn(candidate)) return candidate;
    counts.set("pan", (counts.get("pan") || 0) + 1);
    const digits = candidate.replace(/\D/g, "");
    return `${REDACTED}-PAN-${digits.slice(-4)}`;
  });
  const findings = [...counts].map(([kind, count]) => ({ kind, count }));
  return { value, findings, total: findings.reduce((sum, finding) => sum + finding.count, 0) };
}

export function redactJson(input: unknown): { value: unknown; findings: RedactionFinding[]; total: number } {
  const aggregate = new Map<RedactionKind, number>();
  const visit = (value: unknown): unknown => {
    if (typeof value === "string") {
      const result = redactText(value);
      for (const finding of result.findings) aggregate.set(finding.kind, (aggregate.get(finding.kind) || 0) + finding.count);
      return result.value;
    }
    if (Array.isArray(value)) return value.map(visit);
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, item]) => [key, visit(item)]));
    return value;
  };
  const value = visit(input);
  const findings = [...aggregate].map(([kind, count]) => ({ kind, count }));
  return { value, findings, total: findings.reduce((sum, finding) => sum + finding.count, 0) };
}
