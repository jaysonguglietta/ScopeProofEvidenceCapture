import { readFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";
import { mappingDigest, validateMapping, validateApproval } from "../infra/aws/cdk/runtime/bootstrap-database/contract.mjs";

// Local, read-only planner. It never calls AWS or emits credentials.
export function planBootstrap(mappingInput, executionName, approverRoleArn, now = Date.now()) {
  const mapping = validateMapping(mappingInput);
  if (!/^[A-Za-z0-9_-]{1,80}$/.test(executionName)) throw new Error("Use an explicit unique execution name.");
  const executionId = `arn:aws:states:${mapping.region}:${mapping.account}:execution:scopeproof-database-bootstrap:${executionName}`;
  const approvalItem = { PK: { S: `BOOTSTRAP#${mapping.tenantId}` }, SK: { S: executionId }, kind: { S: "DatabaseBootstrapApproval" }, decision: { S: "APPROVED" },
    mappingDigest: { S: mappingDigest(mapping) }, executionId: { S: executionId }, approvedAt: { S: new Date(now).toISOString() },
    expiresAt: { S: new Date(now + 600_000).toISOString() }, approvedBy: { S: approverRoleArn } };
  validateApproval(approvalItem, { mapping, executionId, now });
  return { mode: "PLAN_ONLY", mappingDigest: mappingDigest(mapping), executionId, approvalItem,
    startExecution: { stateMachineArn: `arn:aws:states:${mapping.region}:${mapping.account}:stateMachine:scopeproof-database-bootstrap`, name: executionName,
      input: JSON.stringify({ tenantId: mapping.tenantId, revision: mapping.revision }) } };
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [mappingPath, executionName, approverRoleArn, ...extra] = process.argv.slice(2);
  if (!mappingPath || !executionName || !approverRoleArn || extra.length) throw new Error("Usage: node scripts/plan_aws_database_bootstrap.mjs mapping.json execution-name bootstrap-approver-role-arn");
  process.stdout.write(JSON.stringify(planBootstrap(JSON.parse(await readFile(mappingPath, "utf8")), executionName, approverRoleArn), null, 2) + "\n");
}
