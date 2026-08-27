#!/usr/bin/env node
import { App, Environment, Tags } from "aws-cdk-lib";
import {
  parseTenants,
  validateAlertEmail,
  validateBranchName,
  validateMonthlyBudgetUsd,
  validateRootDomain,
} from "../lib/config";
import { ObservabilityStack } from "../lib/observability-stack";
import { SharedPlatformStack } from "../lib/shared-platform-stack";
import { TenantStack } from "../lib/tenant-stack";

const app = new App();
const rootDomain = validateRootDomain(app.node.tryGetContext("rootDomain") ?? "jsontechology.com");
const branchName = validateBranchName(app.node.tryGetContext("branchName") ?? "main");
const hostedZoneId = app.node.tryGetContext("hostedZoneId") as string | undefined;
const alertEmail = validateAlertEmail(app.node.tryGetContext("alertEmail"));
const monthlyBudgetUsd = validateMonthlyBudgetUsd(app.node.tryGetContext("monthlyBudgetUsd"));
const tenants = parseTenants(app.node.tryGetContext("tenants"));
const region = process.env.CDK_DEFAULT_REGION || "us-east-1";
const env: Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region,
};

if (region !== "us-east-1") {
  throw new Error("This foundation currently requires us-east-1 because Cognito custom domains use an ACM certificate in us-east-1.");
}
const shared = new SharedPlatformStack(app, "ScopeproofSharedPlatform", {
  env,
  rootDomain,
  branchName,
  hostedZoneId,
  tenantSlugs: tenants.map((tenant) => tenant.slug),
  alertEmail,
  monthlyBudgetUsd,
  description: "Shared low-idle-cost AWS platform for Scopeproof",
});

const tenantStacks: TenantStack[] = [];
for (const tenant of tenants) {
  const stack = new TenantStack(app, `ScopeproofTenant-${tenant.slug}`, {
    env,
    rootDomain,
    tenant,
    shared,
    description: `Isolated Scopeproof data plane for ${tenant.displayName}`,
  });
  stack.addStackDependency(shared);
  tenantStacks.push(stack);
}

if (tenantStacks.length > 0) {
  const observability = new ObservabilityStack(app, "ScopeproofObservability", {
    env,
    shared,
    tenants: tenantStacks,
    description: "Central, immutable audit trail for Scopeproof tenant data planes",
  });
  observability.addStackDependency(shared);
  for (const tenant of tenantStacks) {
    observability.addStackDependency(tenant);
  }
}

Tags.of(app).add("Application", "Scopeproof");
Tags.of(app).add("ManagedBy", "AWS-CDK");
