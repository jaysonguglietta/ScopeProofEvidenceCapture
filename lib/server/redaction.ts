export type RedactionKind = "pan" | "aws_access_key" | "github_token" | "api_token" | "jwt" | "private_key" | "authorization";
export interface RedactionFinding { kind: RedactionKind; count: number; }
export interface RedactionResult { value: string; findings: RedactionFinding[]; total: number; }

const REDACTED = "[REDACTED]";
const sensitiveKey = /^(?:api[-_]?key|api[-_]?token|access[-_]?token|refresh[-_]?token|session[-_]?token|client[-_]?secret|secret[-_]?(?:access[-_]?)?key|private[-_]?key|password|passwd|authorization|proxy[-_]?authorization|cookie|set[-_]?cookie)$/i;

function kindForSensitiveKey(key: string): Exclude<RedactionKind, "pan"> {
  const normalized = key.toLowerCase().replace(/[^a-z]/g, "");
  if (normalized.includes("authorization") || normalized.includes("cookie")) return "authorization";
  if (normalized.includes("privatekey")) return "private_key";
  return "api_token";
}

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
  const record = (kind: RedactionKind) => counts.set(kind, (counts.get(kind) || 0) + 1);
  // Quoted JSON/YAML keys and XML-style attributes are not covered by the
  // ordinary `key=value` detector. Preserve the key and replace the complete
  // scalar with a quoted marker so JSON remains valid.
  value = value.replace(/(["']?(api[-_]?key|api[-_]?token|access[-_]?token|refresh[-_]?token|session[-_]?token|client[-_]?secret|secret[-_]?(?:access[-_]?)?key|private[-_]?key|password|passwd|authorization|proxy[-_]?authorization|cookie|set[-_]?cookie)["']?\s*[:=]\s*)(?:"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|[^\s,}\]\r\n<>]+)/gi, (_match, prefix: string, key: string) => {
    record(kindForSensitiveKey(key));
    return `${prefix}"${REDACTED}"`;
  });
  value = value.replace(/<(api[-_]?key|api[-_]?token|access[-_]?token|refresh[-_]?token|session[-_]?token|client[-_]?secret|secret[-_]?(?:access[-_]?)?key|private[-_]?key|password|passwd|authorization|cookie)\b([^>]*)>[\s\S]*?<\/\1\s*>/gi, (_match, key: string, attributes: string) => {
    record(kindForSensitiveKey(key));
    return `<${key}${attributes}>${REDACTED}</${key}>`;
  });
  for (const pattern of patterns) {
    value = value.replace(pattern.expression, () => {
      record(pattern.kind);
      return REDACTED;
    });
  }
  value = value.replace(/\b(?:\d[ -]*?){13,19}\b/g, (candidate) => {
    if (!luhn(candidate)) return candidate;
    record("pan");
    const digits = candidate.replace(/\D/g, "");
    return `${REDACTED}-PAN-${digits.slice(-4)}`;
  });
  const findings = [...counts].map(([kind, count]) => ({ kind, count }));
  return { value, findings, total: findings.reduce((sum, finding) => sum + finding.count, 0) };
}

export function redactJson(input: unknown): { value: unknown; findings: RedactionFinding[]; total: number } {
  const aggregate = new Map<RedactionKind, number>();
  let visited = 0;
  const record = (kind: RedactionKind, count = 1) => aggregate.set(kind, (aggregate.get(kind) || 0) + count);
  const visit = (value: unknown, depth: number): unknown => {
    visited += 1;
    if (depth > 64 || visited > 100_000) throw new Error("Structured evidence exceeds the redaction complexity limit.");
    if (typeof value === "string") {
      const result = redactText(value);
      for (const finding of result.findings) record(finding.kind, finding.count);
      return result.value;
    }
    if (Array.isArray(value)) return value.map((item) => visit(item, depth + 1));
    if (value && typeof value === "object") return Object.fromEntries(Object.entries(value as Record<string, unknown>).map(([key, item]) => {
      if (sensitiveKey.test(key)) {
        record(kindForSensitiveKey(key));
        return [key, REDACTED];
      }
      return [key, visit(item, depth + 1)];
    }));
    return value;
  };
  const value = visit(input, 0);
  const findings = [...aggregate].map(([kind, count]) => ({ kind, count }));
  return { value, findings, total: findings.reduce((sum, finding) => sum + finding.count, 0) };
}
