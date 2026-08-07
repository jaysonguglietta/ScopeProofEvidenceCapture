import { sql } from "drizzle-orm";
import { index, integer, sqliteTable, text, uniqueIndex } from "drizzle-orm/sqlite-core";

export const users = sqliteTable("users", {
  id: text("id").primaryKey(),
  email: text("email").notNull(),
  displayName: text("display_name").notNull(),
  role: text("role", { enum: ["admin", "compliance_lead", "reviewer", "auditor"] }).notNull().default("auditor"),
  createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  lastSeenAt: text("last_seen_at").notNull().default(sql`CURRENT_TIMESTAMP`),
}, (table) => [uniqueIndex("idx_users_email").on(table.email)]);

export const collectors = sqliteTable("collectors", {
  id: text("id").primaryKey(),
  provider: text("provider", { enum: ["aws", "github", "okta", "cloudflare", "browser"] }).notNull(),
  displayName: text("display_name").notNull(),
  enabled: integer("enabled", { mode: "boolean" }).notNull().default(true),
  configJson: text("config_json").notNull().default("{}"),
  scheduleCron: text("schedule_cron"),
  status: text("status", { enum: ["not_configured", "healthy", "action_needed", "running"] }).notNull().default("not_configured"),
  lastRunAt: text("last_run_at"),
  lastError: text("last_error"),
  createdBy: text("created_by").notNull(),
  createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  updatedAt: text("updated_at").notNull().default(sql`CURRENT_TIMESTAMP`),
}, (table) => [index("idx_collectors_provider").on(table.provider), index("idx_collectors_enabled").on(table.enabled)]);

export const collectionJobs = sqliteTable("collection_jobs", {
  id: text("id").primaryKey(),
  collectorId: text("collector_id").notNull(),
  requestedBy: text("requested_by").notNull(),
  triggerType: text("trigger_type", { enum: ["manual", "scheduled", "retry"] }).notNull(),
  status: text("status", { enum: ["queued", "running", "completed", "partial", "retrying", "failed"] }).notNull().default("queued"),
  attempt: integer("attempt").notNull().default(0),
  maxAttempts: integer("max_attempts").notNull().default(3),
  artifactCount: integer("artifact_count").notNull().default(0),
  nextAttemptAt: text("next_attempt_at"),
  errorCode: text("error_code"),
  errorMessage: text("error_message"),
  createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  startedAt: text("started_at"),
  completedAt: text("completed_at"),
}, (table) => [index("idx_jobs_status_next_attempt").on(table.status, table.nextAttemptAt), index("idx_jobs_collector_created").on(table.collectorId, table.createdAt)]);

export const evidenceArtifacts = sqliteTable("evidence_artifacts", {
  id: text("id").primaryKey(),
  controlId: text("control_id").notNull(),
  title: text("title").notNull(),
  description: text("description").notNull().default(""),
  type: text("type", { enum: ["screenshot", "code", "configuration", "report"] }).notNull(),
  source: text("source").notNull(),
  system: text("system").notNull(),
  collectorId: text("collector_id"),
  jobId: text("job_id"),
  r2Key: text("r2_key").notNull(),
  contentType: text("content_type").notNull(),
  byteSize: integer("byte_size").notNull(),
  sha256: text("sha256").notNull(),
  encryptionIv: text("encryption_iv").notNull(),
  encryptionVersion: integer("encryption_version").notNull().default(1),
  capturedAt: text("captured_at").notNull(),
  expiresAt: text("expires_at").notNull(),
  status: text("status", { enum: ["needs_review", "approved", "expiring", "rejected"] }).notNull().default("needs_review"),
  redactionCount: integer("redaction_count").notNull().default(0),
  redactionSummaryJson: text("redaction_summary_json").notNull().default("[]"),
  createdBy: text("created_by").notNull(),
  createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  approvedBy: text("approved_by"),
  approvedAt: text("approved_at"),
}, (table) => [
  uniqueIndex("idx_evidence_sha_source_control").on(table.sha256, table.source, table.controlId),
  index("idx_evidence_status_created").on(table.status, table.createdAt),
  index("idx_evidence_control_captured").on(table.controlId, table.capturedAt),
  index("idx_evidence_job").on(table.jobId),
]);

export const auditEvents = sqliteTable("audit_events", {
  sequence: integer("sequence").primaryKey({ autoIncrement: true }),
  id: text("id").notNull(),
  occurredAt: text("occurred_at").notNull(),
  actorId: text("actor_id").notNull(),
  actorEmail: text("actor_email").notNull(),
  action: text("action").notNull(),
  resourceType: text("resource_type").notNull(),
  resourceId: text("resource_id").notNull(),
  detailsJson: text("details_json").notNull().default("{}"),
  previousHash: text("previous_hash").notNull(),
  eventHash: text("event_hash").notNull(),
  signature: text("signature").notNull(),
}, (table) => [uniqueIndex("idx_audit_id").on(table.id), uniqueIndex("idx_audit_event_hash").on(table.eventHash), index("idx_audit_resource").on(table.resourceType, table.resourceId), index("idx_audit_occurred").on(table.occurredAt)]);

export const exportPackages = sqliteTable("export_packages", {
  id: text("id").primaryKey(),
  requestedBy: text("requested_by").notNull(),
  status: text("status", { enum: ["building", "ready", "failed"] }).notNull().default("building"),
  r2Key: text("r2_key"),
  sha256: text("sha256"),
  signature: text("signature"),
  evidenceCount: integer("evidence_count").notNull().default(0),
  byteSize: integer("byte_size").notNull().default(0),
  errorMessage: text("error_message"),
  createdAt: text("created_at").notNull().default(sql`CURRENT_TIMESTAMP`),
  completedAt: text("completed_at"),
  expiresAt: text("expires_at"),
}, (table) => [index("idx_exports_requested_created").on(table.requestedBy, table.createdAt)]);
