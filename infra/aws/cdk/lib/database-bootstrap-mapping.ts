import type * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";

export interface TenantDatabaseBootstrapMapping {
  readonly schemaVersion: 1;
  readonly tenantId: string;
  readonly revision: number;
  readonly account: string;
  readonly region: string;
  readonly clusterArn: string;
  readonly databaseName: string;
  readonly ownerUsername: string;
  readonly roles: readonly { kind: string; username: string; secretArn: string }[];
}
export interface TenantDatabaseBootstrapSource {
  readonly mapping: TenantDatabaseBootstrapMapping;
  readonly secrets: readonly secretsmanager.ISecret[];
}
