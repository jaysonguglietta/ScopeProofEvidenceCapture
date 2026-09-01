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
import {
  parseRecoveryConfiguration,
  validateDeploymentEnvironment,
} from "../lib/recovery-config";
import { RecoveryStack } from "../lib/recovery-stack";
import { SharedPlatformStack } from "../lib/shared-platform-stack";
import { TenantStack } from "../lib/tenant-stack";

const app = new App();
const rootDomain = validateRootDomain(app.node.tryGetContext("rootDomain"));
const branchName = validateBranchName(app.node.tryGetContext("branchName") ?? "main");
const hostedZoneId = app.node.tryGetContext("hostedZoneId") as string | undefined;
const createHostedZone = String(app.node.tryGetContext("createHostedZone") ?? "false").trim().toLowerCase() === "true";
if (Boolean(hostedZoneId) === createHostedZone) {
  throw new Error("Specify exactly one of hostedZoneId or -c createHostedZone=true after reviewing Route 53 ownership and cost.");
}
const alertEmail = validateAlertEmail(app.node.tryGetContext("alertEmail"));
const monthlyBudgetUsd = validateMonthlyBudgetUsd(app.node.tryGetContext("monthlyBudgetUsd"));
const tenants = parseTenants(app.node.tryGetContext("tenants"));
const deploymentEnvironment = validateDeploymentEnvironment(
  app.node.tryGetContext("deploymentEnvironment"),
);
const region = process.env.CDK_DEFAULT_REGION || "us-east-1";
const env: Environment = {
  account: process.env.CDK_DEFAULT_ACCOUNT,
  region,
};

if (region !== "us-east-1") {
  throw new Error("This foundation currently requires us-east-1 because Cognito custom domains use an ACM certificate in us-east-1.");
}
const recovery = parseRecoveryConfiguration(app.node.tryGetContext("recovery"), {
  account: env.account,
  deploymentEnvironment,
  primaryRegion: region,
  tenants,
});

if (recovery.mode === "bootstrap") {
  new RecoveryStack(app, "ScopeproofRecovery", {
    alertEmail,
    configuration: recovery,
    description: "Cross-region immutable recovery resources for Scopeproof",
    env: { account: env.account, region: recovery.region },
    primaryRegion: region,
    tenants,
  });
} else {
  let recoveryStack: RecoveryStack | undefined;
  if (recovery.mode === "enabled") {
    recoveryStack = new RecoveryStack(app, "ScopeproofRecovery", {
      alertEmail,
      configuration: recovery,
      description: "Cross-region immutable recovery resources for Scopeproof",
      env: { account: env.account, region: recovery.region },
      primaryRegion: region,
      tenants,
    });
  }
  const shared = new SharedPlatformStack(app, "ScopeproofSharedPlatform", {
    env,
    rootDomain,
    branchName,
    hostedZoneId,
    createHostedZone,
    tenantSlugs: tenants.map((tenant) => tenant.slug),
    alertEmail,
    monthlyBudgetUsd,
    recovery,
    description: "Shared low-idle-cost AWS platform for Scopeproof",
  });
  if (recoveryStack) shared.addStackDependency(recoveryStack);

  const tenantStacks: TenantStack[] = [];
  for (const tenant of tenants) {
    const stack = new TenantStack(app, `ScopeproofTenant-${tenant.slug}`, {
      env,
      rootDomain,
      tenant,
      shared,
      recovery,
      description: `Isolated Scopeproof data plane for ${tenant.displayName}`,
    });
    stack.addStackDependency(shared);
    if (recoveryStack) stack.addStackDependency(recoveryStack);
    tenantStacks.push(stack);
  }

  const observability = new ObservabilityStack(app, "ScopeproofObservability", {
    env,
    shared,
    tenants: tenantStacks,
    description: "Central, immutable audit trail for Scopeproof platform and tenant data planes",
  });
  observability.addStackDependency(shared);
  for (const tenant of tenantStacks) {
    observability.addStackDependency(tenant);
  }
}

Tags.of(app).add("Application", "Scopeproof");
Tags.of(app).add("ManagedBy", "AWS-CDK");
Tags.of(app).add("Environment", deploymentEnvironment);
