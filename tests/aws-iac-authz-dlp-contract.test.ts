import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  validateTenant,
  validateTenantDeploymentSecurity,
} from "../infra/aws/cdk/lib/config.ts";

const tenantStackPath = new URL("../infra/aws/cdk/lib/tenant-stack.ts", import.meta.url);
const TENANT = `ten_${"a".repeat(32)}`;

test("production tenants cannot synthesize an immutable promoter without exact-version DLP", () => {
  const tenant = validateTenant({
    id: TENANT,
    slug: "acme",
    displayName: "Acme Corporation",
    retentionMode: "COMPLIANCE",
  });
  assert.throws(() => validateTenantDeploymentSecurity(tenant, "prod"), /server DLP/i);

  const configured = validateTenant({
    ...tenant,
    dlpScannerEndpoint: "https://scanner.security.example/v1/exact-version",
    dlpScannerSecretArn: "arn:aws:secretsmanager:us-east-1:111111111111:secret:scopeproof-dlp-AbCdEf",
    dlpScannerSecretKmsKeyArn: "arn:aws:kms:us-east-1:111111111111:key/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
    dlpPolicyVersion: "pci-evidence-v4",
  });
  assert.equal(validateTenantDeploymentSecurity(configured, "prod"), configured);
  assert.throws(
    () => validateTenant({ ...configured, dlpScannerEndpoint: undefined }),
    /all server DLP fields together/i,
  );
});

test("API Gateway independently enforces Cognito scopes while Lambdas retain authorization", async () => {
  const source = await readFile(tenantStackPath, "utf8");
  assert.match(source, /new apigateway\.CognitoUserPoolsAuthorizer/);
  assert.match(source, /resultsCacheTtl: Duration\.seconds\(0\)/);
  assert.match(source, /authorizationType: apigateway\.AuthorizationType\.COGNITO/);
  assert.match(source, /authorizationScopes: \["scopeproof\/evidence\.read"\]/);
  assert.match(source, /authorizationScopes: \["scopeproof\/evidence\.collect"\]/);
  assert.match(source, /authorizationScopes: \["scopeproof\/retention\.manage"\]/);
  assert.match(source, /me\.addMethod\("GET", integration, readAuthorization\)/);
  assert.match(source, /uploadIntents\.addMethod\("POST", integration, \{\s*\.\.\.collectAuthorization/);
  assert.match(source, /legalHoldApprovals\.addMethod\("POST", legalHoldIntegration, \{\s*\.\.\.retentionAuthorization/);
  // Application handlers remain the backstop for token-use, client, tenant,
  // membership, and role checks; the outer authorizer is deliberately additive.
  assert.match(source, /entry: path\.join\(__dirname, "\.\.", "runtime", "tenant-api", "index\.ts"\)/);
  assert.match(source, /entry: path\.join\(__dirname, "\.\.", "runtime", "tenant-evidence-read-api", "index\.ts"\)/);
  assert.match(source, /entry: path\.join\(__dirname, "\.\.", "runtime", "tenant-legal-hold-api", "index\.ts"\)/);
});
