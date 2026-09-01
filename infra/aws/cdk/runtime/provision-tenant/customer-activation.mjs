/** Validate one exact, execution-bound out-of-band activation approval. */
export function validateCustomerActivationApproval(item, input) {
  if (!/^ten_[a-f0-9]{32}$/.test(String(input?.tenantId ?? "")) ||
      !/^arn:(aws|aws-us-gov|aws-cn):states:[a-z0-9-]+:\d{12}:execution:[A-Za-z0-9_-]{1,80}:[A-Za-z0-9_-]{1,80}$/.test(String(input?.executionId ?? "")) ||
      !Number.isFinite(input?.nowMilliseconds)) return false;
  const expectedKeys = [
    "PK", "SK", "approvedAt", "decision", "executionId", "expiresAt", "kind",
    "schemaVersion", "tenantId", "ttlEpochSeconds",
  ];
  const actualKeys = Object.keys(item ?? {}).sort();
  const approvedAt = Date.parse(item?.approvedAt?.S ?? "");
  const expiresAt = Date.parse(item?.expiresAt?.S ?? "");
  const ttlEpochSeconds = Number(item?.ttlEpochSeconds?.N ?? NaN);
  const now = input.nowMilliseconds;
  return JSON.stringify(actualKeys) === JSON.stringify(expectedKeys) &&
    item?.PK?.S === `TENANT#${input.tenantId}` && item?.SK?.S === "CUSTOMER_ENABLED" &&
    item?.kind?.S === "CustomerActivationApproval" && item?.schemaVersion?.N === "1" &&
    item?.tenantId?.S === input.tenantId && item?.decision?.S === "CUSTOMER_ENABLED" &&
    item?.executionId?.S === input.executionId && Number.isFinite(approvedAt) && Number.isFinite(expiresAt) &&
    new Date(approvedAt).toISOString() === item?.approvedAt?.S && new Date(expiresAt).toISOString() === item?.expiresAt?.S &&
    approvedAt <= now + 60_000 && approvedAt >= now - 86_400_000 && expiresAt > now &&
    expiresAt <= approvedAt + 86_400_000 && Number.isSafeInteger(ttlEpochSeconds) &&
    ttlEpochSeconds === Math.floor(expiresAt / 1000);
}
