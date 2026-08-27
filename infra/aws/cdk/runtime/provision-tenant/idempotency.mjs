import { createHash } from "node:crypto";

/**
 * Creates a bounded DynamoDB transaction token from the complete, scalar write
 * contract. A retry with identical parameters reuses the token; any changed
 * timestamp or terminal fact gets a new token and is evaluated conditionally.
 */
export function transactionToken(facts) {
  if (!facts || typeof facts !== "object" || Array.isArray(facts)) {
    throw new Error("Provisioning transaction facts must be an object.");
  }
  const entries = Object.entries(facts).sort(([left], [right]) => left.localeCompare(right));
  if (
    entries.length < 1 ||
    entries.length > 16 ||
    entries.some(([name, value]) =>
      !/^[a-z][A-Za-z0-9]{0,63}$/.test(name) ||
      !(["string", "number", "boolean"].includes(typeof value) || value === null) ||
      (typeof value === "number" && !Number.isSafeInteger(value)) ||
      (typeof value === "string" && (value.length > 1024 || /\p{Cc}/u.test(value)))
    )
  ) {
    throw new Error("Provisioning transaction facts are invalid.");
  }
  const canonical = JSON.stringify(Object.fromEntries(entries));
  const digest = createHash("sha256")
    .update("scopeproof-provision-transaction-v1\0")
    .update(canonical)
    .digest("hex");
  return `sp-${digest.slice(0, 32)}`;
}
