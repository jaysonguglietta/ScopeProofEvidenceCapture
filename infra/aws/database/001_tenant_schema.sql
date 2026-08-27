-- Scopeproof tenant database schema (PostgreSQL 16+)
--
-- This migration is applied once to each tenant database by the provisioning
-- workflow while connected as the database owner. The runtime role MUST NOT own
-- these objects, be a superuser, or have BYPASSRLS.

BEGIN;

CREATE SCHEMA scopeproof;

REVOKE ALL ON SCHEMA scopeproof FROM PUBLIC;

CREATE DOMAIN scopeproof.tenant_identifier AS text
  CHECK (VALUE ~ '^ten_[a-f0-9]{32}$');

CREATE DOMAIN scopeproof.resource_identifier AS text
  CHECK (VALUE ~ '^[a-z][a-z0-9]{1,15}_[a-f0-9]{32}$');

CREATE TABLE scopeproof.schema_migrations (
  version integer PRIMARY KEY CHECK (version > 0),
  name text NOT NULL UNIQUE CHECK (name ~ '^[a-z0-9_]{3,80}$'),
  applied_at timestamptz NOT NULL DEFAULT clock_timestamp()
);

CREATE FUNCTION scopeproof.current_tenant_id()
RETURNS scopeproof.tenant_identifier
LANGUAGE sql
STABLE
PARALLEL SAFE
AS $$
  SELECT NULLIF(current_setting('scopeproof.tenant_id', true), '')::scopeproof.tenant_identifier
$$;

REVOKE ALL ON FUNCTION scopeproof.current_tenant_id() FROM PUBLIC;

CREATE TABLE scopeproof.tenant_identity (
  tenant_id scopeproof.tenant_identifier PRIMARY KEY,
  slug text NOT NULL CHECK (slug ~ '^[a-z0-9](?:[a-z0-9-]{0,46}[a-z0-9])?$'),
  display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 2 AND 120),
  status text NOT NULL CHECK (status IN ('PROVISIONING', 'ACTIVE', 'SUSPENDED', 'OFFBOARDING', 'RETAINED', 'DELETED')),
  canonical_hostname text NOT NULL CHECK (
    canonical_hostname = lower(canonical_hostname) AND
    canonical_hostname ~ '^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$' AND
    canonical_hostname LIKE slug || '.%'
  ),
  retention_days integer NOT NULL CHECK (retention_days BETWEEN 1 AND 3650),
  retention_mode text NOT NULL CHECK (retention_mode IN ('GOVERNANCE', 'COMPLIANCE')),
  aws_account_id char(12) NOT NULL CHECK (aws_account_id ~ '^[0-9]{12}$'),
  aws_region text NOT NULL CHECK (aws_region ~ '^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]$'),
  quarantine_bucket text NOT NULL CHECK (quarantine_bucket ~ '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$'),
  evidence_bucket text NOT NULL CHECK (evidence_bucket ~ '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$'),
  evidence_kms_key_arn text NOT NULL CHECK (evidence_kms_key_arn ~ '^arn:(aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]{36}$'),
  singleton boolean NOT NULL DEFAULT true UNIQUE CHECK (singleton),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (quarantine_bucket <> evidence_bucket),
  CHECK (split_part(evidence_kms_key_arn, ':', 4) = aws_region),
  CHECK (split_part(evidence_kms_key_arn, ':', 5) = aws_account_id)
);

COMMENT ON TABLE scopeproof.tenant_identity IS
  'Exactly one immutable tenant identity row exists in each tenant database.';

CREATE TABLE scopeproof.principals (
  tenant_id scopeproof.tenant_identifier NOT NULL,
  id scopeproof.resource_identifier NOT NULL CHECK (id LIKE 'usr\_%' ESCAPE '\'),
  cognito_sub text NOT NULL CHECK (char_length(cognito_sub) BETWEEN 8 AND 200),
  email text NOT NULL CHECK (char_length(email) BETWEEN 3 AND 254),
  display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 160),
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('INVITED', 'ACTIVE', 'DISABLED')),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_seen_at timestamptz,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, cognito_sub),
  UNIQUE (tenant_id, email)
);

CREATE TABLE scopeproof.memberships (
  tenant_id scopeproof.tenant_identifier NOT NULL,
  id scopeproof.resource_identifier NOT NULL CHECK (id LIKE 'mem\_%' ESCAPE '\'),
  principal_id scopeproof.resource_identifier NOT NULL,
  role text NOT NULL CHECK (role IN ('admin', 'compliance_lead', 'reviewer', 'auditor', 'collector')),
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('INVITED', 'ACTIVE', 'SUSPENDED', 'REVOKED')),
  invited_by scopeproof.resource_identifier,
  invited_at timestamptz,
  activated_at timestamptz,
  revoked_at timestamptz,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, principal_id),
  FOREIGN KEY (tenant_id, principal_id) REFERENCES scopeproof.principals (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, invited_by) REFERENCES scopeproof.principals (tenant_id, id) ON DELETE RESTRICT,
  CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL))
);

CREATE TABLE scopeproof.tenant_domains (
  tenant_id scopeproof.tenant_identifier NOT NULL,
  hostname text NOT NULL CHECK (
    hostname = lower(hostname) AND
    hostname ~ '^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$'
  ),
  status text NOT NULL CHECK (status IN ('PENDING', 'VERIFIED', 'DISABLED')),
  is_canonical boolean NOT NULL DEFAULT false,
  verified_at timestamptz,
  PRIMARY KEY (tenant_id, hostname)
);
CREATE UNIQUE INDEX tenant_domains_one_canonical
  ON scopeproof.tenant_domains (tenant_id) WHERE is_canonical;

CREATE TABLE scopeproof.device_enrollments (
  tenant_id scopeproof.tenant_identifier NOT NULL,
  id scopeproof.resource_identifier NOT NULL CHECK (id LIKE 'dev\_%' ESCAPE '\'),
  principal_id scopeproof.resource_identifier NOT NULL,
  device_public_key_sha256 char(64) NOT NULL CHECK (device_public_key_sha256 ~ '^[0-9a-f]{64}$'),
  display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 120),
  platform text NOT NULL DEFAULT 'macOS' CHECK (platform = 'macOS'),
  status text NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('PENDING', 'ACTIVE', 'REVOKED')),
  enrolled_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  last_seen_at timestamptz,
  revoked_at timestamptz,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, device_public_key_sha256),
  FOREIGN KEY (tenant_id, principal_id) REFERENCES scopeproof.principals (tenant_id, id) ON DELETE RESTRICT,
  CHECK ((status = 'REVOKED') = (revoked_at IS NOT NULL))
);

CREATE TABLE scopeproof.assessments (
  tenant_id scopeproof.tenant_identifier NOT NULL,
  id scopeproof.resource_identifier NOT NULL CHECK (id LIKE 'asm\_%' ESCAPE '\'),
  name text NOT NULL CHECK (char_length(name) BETWEEN 2 AND 160),
  framework text NOT NULL CHECK (char_length(framework) BETWEEN 2 AND 80),
  period_start date NOT NULL,
  period_end date NOT NULL,
  owner_id scopeproof.resource_identifier NOT NULL,
  status text NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT', 'ACTIVE', 'CLOSED')),
  systems jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(systems) = 'array'),
  controls jsonb NOT NULL DEFAULT '[]'::jsonb CHECK (jsonb_typeof(controls) = 'array'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, owner_id) REFERENCES scopeproof.principals (tenant_id, id) ON DELETE RESTRICT,
  CHECK (period_end >= period_start)
);
CREATE INDEX assessments_status_period ON scopeproof.assessments (tenant_id, status, period_end);

CREATE TABLE scopeproof.integrations (
  tenant_id scopeproof.tenant_identifier NOT NULL,
  id scopeproof.resource_identifier NOT NULL CHECK (id LIKE 'int\_%' ESCAPE '\'),
  provider text NOT NULL CHECK (provider IN ('AWS', 'GITHUB', 'JIRA', 'OKTA', 'BROWSER')),
  display_name text NOT NULL CHECK (char_length(display_name) BETWEEN 1 AND 120),
  status text NOT NULL DEFAULT 'NOT_CONFIGURED' CHECK (status IN ('NOT_CONFIGURED', 'HEALTHY', 'ACTION_NEEDED', 'DISABLED')),
  secret_arn text CHECK (secret_arn IS NULL OR secret_arn ~ '^arn:[a-z0-9-]+:secretsmanager:'),
  configuration jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(configuration) = 'object'),
  last_tested_at timestamptz,
  last_error_code text,
  created_by scopeproof.resource_identifier NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, provider),
  FOREIGN KEY (tenant_id, created_by) REFERENCES scopeproof.principals (tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE scopeproof.jobs (
  tenant_id scopeproof.tenant_identifier NOT NULL,
  id scopeproof.resource_identifier NOT NULL CHECK (id LIKE 'job\_%' ESCAPE '\'),
  kind text NOT NULL CHECK (kind IN ('collection.run', 'sbom.generate', 'export.build', 'evidence.validate', 'retention.evaluate', 'audit.checkpoint')),
  status text NOT NULL DEFAULT 'queued' CHECK (status IN ('queued', 'leased', 'retry_scheduled', 'succeeded', 'dead_lettered', 'cancelled')),
  requested_by scopeproof.resource_identifier,
  integration_id scopeproof.resource_identifier,
  assessment_id scopeproof.resource_identifier,
  idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 16 AND 200),
  attempt smallint NOT NULL DEFAULT 0 CHECK (attempt BETWEEN 0 AND 10),
  max_attempts smallint NOT NULL DEFAULT 3 CHECK (max_attempts BETWEEN 1 AND 10),
  revision integer NOT NULL DEFAULT 0 CHECK (revision >= 0),
  lease_id text CHECK (lease_id IS NULL OR char_length(lease_id) BETWEEN 2 AND 100),
  leased_by text CHECK (leased_by IS NULL OR char_length(leased_by) BETWEEN 2 AND 100),
  leased_at timestamptz,
  lease_expires_at timestamptz,
  available_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  request jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(request) = 'object'),
  result jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(result) = 'object'),
  error_code text,
  error_summary text CHECK (error_summary IS NULL OR char_length(error_summary) <= 1000),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  started_at timestamptz,
  completed_at timestamptz,
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, idempotency_key),
  FOREIGN KEY (tenant_id, requested_by) REFERENCES scopeproof.principals (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, integration_id) REFERENCES scopeproof.integrations (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, assessment_id) REFERENCES scopeproof.assessments (tenant_id, id) ON DELETE RESTRICT,
  CHECK ((status = 'leased') = (lease_id IS NOT NULL AND leased_by IS NOT NULL AND leased_at IS NOT NULL AND lease_expires_at IS NOT NULL)),
  CHECK (lease_expires_at IS NULL OR lease_expires_at > leased_at),
  CHECK ((status IN ('succeeded', 'dead_lettered', 'cancelled')) = (completed_at IS NOT NULL))
);
CREATE INDEX jobs_due ON scopeproof.jobs (tenant_id, status, available_at);

CREATE TABLE scopeproof.upload_intents (
  tenant_id scopeproof.tenant_identifier NOT NULL,
  id scopeproof.resource_identifier NOT NULL CHECK (id LIKE 'upl\_%' ESCAPE '\'),
  nonce_digest char(64) NOT NULL CHECK (nonce_digest ~ '^[0-9a-f]{64}$'),
  requested_by scopeproof.resource_identifier NOT NULL,
  device_id scopeproof.resource_identifier,
  assessment_id scopeproof.resource_identifier,
  evidence_id scopeproof.resource_identifier NOT NULL CHECK (evidence_id LIKE 'evd\_%' ESCAPE '\'),
  quarantine_bucket text NOT NULL CHECK (char_length(quarantine_bucket) BETWEEN 3 AND 63),
  object_key text NOT NULL CHECK (object_key ~ '^tenants/ten_[a-f0-9]{32}/quarantine/upl_[a-f0-9]{32}\.upload$'),
  final_object_key text NOT NULL CHECK (final_object_key ~ '^tenants/ten_[a-f0-9]{32}/evidence/evd_[a-f0-9]{32}\.(png|json|spdx\.json|cdx\.json|txt|csv)$'),
  content_type text NOT NULL CHECK (content_type IN ('image/png', 'application/json', 'application/spdx+json', 'application/vnd.cyclonedx+json', 'text/plain', 'text/csv')),
  content_length bigint NOT NULL CHECK (content_length BETWEEN 1 AND 26214400),
  checksum_sha256 char(64) NOT NULL CHECK (checksum_sha256 ~ '^[0-9a-f]{64}$'),
  status text NOT NULL DEFAULT 'issued' CHECK (status IN ('issued', 'quarantined', 'validated', 'promoted', 'rejected', 'expired')),
  revision integer NOT NULL DEFAULT 0 CHECK (revision >= 0),
  expires_at timestamptz NOT NULL,
  required_retention_until timestamptz NOT NULL,
  consumed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, nonce_digest),
  UNIQUE (tenant_id, object_key),
  FOREIGN KEY (tenant_id, requested_by) REFERENCES scopeproof.principals (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, device_id) REFERENCES scopeproof.device_enrollments (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, assessment_id) REFERENCES scopeproof.assessments (tenant_id, id) ON DELETE RESTRICT,
  CHECK (expires_at <= created_at + interval '10 minutes'),
  CHECK (required_retention_until > expires_at),
  CHECK (object_key LIKE 'tenants/' || tenant_id || '/quarantine/%'),
  CHECK (final_object_key LIKE 'tenants/' || tenant_id || '/evidence/' || evidence_id || '.%'),
  CHECK (consumed_at IS NULL OR consumed_at >= created_at)
);
CREATE INDEX upload_intents_expiry ON scopeproof.upload_intents (tenant_id, expires_at) WHERE consumed_at IS NULL;

CREATE TABLE scopeproof.evidence_artifacts (
  tenant_id scopeproof.tenant_identifier NOT NULL,
  id scopeproof.resource_identifier NOT NULL CHECK (id LIKE 'evd\_%' ESCAPE '\'),
  assessment_id scopeproof.resource_identifier,
  control_id text NOT NULL CHECK (control_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
  title text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 240),
  description text NOT NULL DEFAULT '' CHECK (char_length(description) <= 8000),
  evidence_type text NOT NULL CHECK (evidence_type IN ('SCREENSHOT', 'CODE', 'CONFIGURATION', 'REPORT', 'SBOM', 'EXPORT')),
  source text NOT NULL CHECK (char_length(source) BETWEEN 1 AND 120),
  system_name text NOT NULL CHECK (char_length(system_name) BETWEEN 1 AND 160),
  status text NOT NULL DEFAULT 'QUARANTINED' CHECK (status IN ('QUARANTINED', 'VALIDATING', 'NEEDS_REVIEW', 'APPROVED', 'REJECTED', 'EXPIRED', 'PURGED')),
  content_type text NOT NULL CHECK (char_length(content_type) BETWEEN 3 AND 120),
  byte_size bigint NOT NULL CHECK (byte_size BETWEEN 1 AND 26214400),
  checksum_sha256 char(64) NOT NULL CHECK (checksum_sha256 ~ '^[0-9a-f]{64}$'),
  evidence_bucket text,
  object_key text CHECK (object_key IS NULL OR object_key ~ '^tenants/ten_[a-f0-9]{32}/evidence/evd_[a-f0-9]{32}\.(png|json|spdx\.json|cdx\.json|txt|csv)$'),
  object_version_id text,
  kms_key_arn text CHECK (kms_key_arn IS NULL OR kms_key_arn ~ '^arn:[a-z0-9-]+:kms:'),
  object_lock_mode text CHECK (object_lock_mode IS NULL OR object_lock_mode IN ('GOVERNANCE', 'COMPLIANCE')),
  retain_until timestamptz,
  captured_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  created_by scopeproof.resource_identifier NOT NULL,
  approved_by scopeproof.resource_identifier,
  approved_at timestamptz,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(metadata) = 'object'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, assessment_id, checksum_sha256, source, control_id),
  FOREIGN KEY (tenant_id, assessment_id) REFERENCES scopeproof.assessments (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, created_by) REFERENCES scopeproof.principals (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, approved_by) REFERENCES scopeproof.principals (tenant_id, id) ON DELETE RESTRICT,
  CHECK (expires_at >= captured_at),
  CHECK (object_key IS NULL OR object_key LIKE 'tenants/' || tenant_id || '/evidence/%'),
  CHECK ((status IN ('NEEDS_REVIEW', 'APPROVED', 'EXPIRED', 'PURGED')) = (evidence_bucket IS NOT NULL AND object_key IS NOT NULL AND object_version_id IS NOT NULL AND kms_key_arn IS NOT NULL AND object_lock_mode IS NOT NULL AND retain_until IS NOT NULL)),
  CHECK (retain_until IS NULL OR retain_until >= expires_at),
  CHECK ((approved_at IS NULL) = (approved_by IS NULL)),
  CHECK (approved_by IS NULL OR approved_by <> created_by),
  CHECK (status <> 'APPROVED' OR approved_at IS NOT NULL),
  CHECK (approved_at IS NULL OR status IN ('APPROVED', 'EXPIRED', 'PURGED'))
);
CREATE INDEX evidence_control_captured ON scopeproof.evidence_artifacts (tenant_id, control_id, captured_at DESC);
CREATE INDEX evidence_status_created ON scopeproof.evidence_artifacts (tenant_id, status, created_at DESC);

CREATE TABLE scopeproof.ingest_receipts (
  tenant_id scopeproof.tenant_identifier NOT NULL,
  id scopeproof.resource_identifier NOT NULL CHECK (id LIKE 'rcp\_%' ESCAPE '\'),
  upload_intent_id scopeproof.resource_identifier NOT NULL,
  evidence_id scopeproof.resource_identifier NOT NULL,
  quarantine_version_id text NOT NULL,
  evidence_version_id text NOT NULL,
  checksum_sha256 char(64) NOT NULL CHECK (checksum_sha256 ~ '^[0-9a-f]{64}$'),
  kms_key_arn text NOT NULL CHECK (kms_key_arn ~ '^arn:[a-z0-9-]+:kms:'),
  object_lock_mode text NOT NULL CHECK (object_lock_mode IN ('GOVERNANCE', 'COMPLIANCE')),
  retain_until timestamptz NOT NULL,
  malware_status text NOT NULL CHECK (malware_status = 'CLEAN'),
  receipt_sha256 char(64) NOT NULL CHECK (receipt_sha256 ~ '^[0-9a-f]{64}$'),
  signature text NOT NULL CHECK (char_length(signature) BETWEEN 40 AND 4096),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, upload_intent_id),
  UNIQUE (tenant_id, receipt_sha256),
  FOREIGN KEY (tenant_id, upload_intent_id) REFERENCES scopeproof.upload_intents (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, evidence_id) REFERENCES scopeproof.evidence_artifacts (tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE scopeproof.retention_holds (
  tenant_id scopeproof.tenant_identifier NOT NULL,
  id scopeproof.resource_identifier NOT NULL CHECK (id LIKE 'hld\_%' ESCAPE '\'),
  evidence_id scopeproof.resource_identifier NOT NULL,
  kind text NOT NULL CHECK (kind IN ('LEGAL', 'AUDIT', 'SECURITY_INCIDENT')),
  reason text NOT NULL CHECK (char_length(reason) BETWEEN 10 AND 2000),
  created_by scopeproof.resource_identifier NOT NULL,
  approved_by scopeproof.resource_identifier NOT NULL,
  expires_at timestamptz,
  released_at timestamptz,
  release_reason text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, evidence_id) REFERENCES scopeproof.evidence_artifacts (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, created_by) REFERENCES scopeproof.principals (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, approved_by) REFERENCES scopeproof.principals (tenant_id, id) ON DELETE RESTRICT,
  CHECK (created_by <> approved_by),
  CHECK ((released_at IS NULL) = (release_reason IS NULL))
);
CREATE INDEX active_retention_holds ON scopeproof.retention_holds (tenant_id, evidence_id) WHERE released_at IS NULL;

CREATE TABLE scopeproof.audit_heads (
  tenant_id scopeproof.tenant_identifier NOT NULL,
  sequence bigint NOT NULL DEFAULT 0 CHECK (sequence >= 0),
  event_hash text NOT NULL DEFAULT 'GENESIS' CHECK (event_hash = 'GENESIS' OR event_hash ~ '^[0-9a-f]{64}$'),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id),
  CHECK ((sequence = 0) = (event_hash = 'GENESIS'))
);

CREATE TABLE scopeproof.audit_events (
  tenant_id scopeproof.tenant_identifier NOT NULL,
  sequence bigint NOT NULL CHECK (sequence > 0),
  id scopeproof.resource_identifier NOT NULL CHECK (id LIKE 'evt\_%' ESCAPE '\'),
  occurred_at timestamptz NOT NULL,
  actor_type text NOT NULL CHECK (actor_type IN ('user', 'device', 'worker', 'support', 'system')),
  actor_id text NOT NULL CHECK (char_length(actor_id) BETWEEN 1 AND 200),
  action text NOT NULL CHECK (action ~ '^[a-z0-9_.-]{3,120}$'),
  resource_type text NOT NULL CHECK (resource_type ~ '^[a-z0-9_.-]{2,80}$'),
  resource_id text NOT NULL CHECK (char_length(resource_id) BETWEEN 1 AND 200),
  request_id text NOT NULL CHECK (char_length(request_id) BETWEEN 3 AND 200),
  outcome text NOT NULL CHECK (outcome IN ('succeeded', 'denied', 'failed')),
  details jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object'),
  previous_hash text NOT NULL CHECK (previous_hash = 'GENESIS' OR previous_hash ~ '^[0-9a-f]{64}$'),
  event_hash char(64) NOT NULL CHECK (event_hash ~ '^[0-9a-f]{64}$'),
  kms_signature text NOT NULL CHECK (char_length(kms_signature) BETWEEN 40 AND 4096),
  PRIMARY KEY (tenant_id, sequence),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, event_hash),
  CHECK ((sequence = 1) = (previous_hash = 'GENESIS'))
);
CREATE INDEX audit_resource ON scopeproof.audit_events (tenant_id, resource_type, resource_id, sequence DESC);

CREATE FUNCTION scopeproof.advance_audit_head()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  current_sequence bigint;
  current_hash text;
BEGIN
  INSERT INTO scopeproof.audit_heads (tenant_id)
  VALUES (NEW.tenant_id)
  ON CONFLICT (tenant_id) DO NOTHING;

  SELECT sequence, event_hash
    INTO STRICT current_sequence, current_hash
    FROM scopeproof.audit_heads
   WHERE tenant_id = NEW.tenant_id
   FOR UPDATE;

  IF NEW.sequence IS DISTINCT FROM current_sequence + 1 OR
     NEW.previous_hash IS DISTINCT FROM current_hash THEN
    RAISE EXCEPTION 'audit chain continuation violation' USING ERRCODE = '23514';
  END IF;

  UPDATE scopeproof.audit_heads
     SET sequence = NEW.sequence,
         event_hash = NEW.event_hash,
         updated_at = clock_timestamp()
   WHERE tenant_id = NEW.tenant_id;
  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.advance_audit_head() FROM PUBLIC;

CREATE TABLE scopeproof.export_receipts (
  tenant_id scopeproof.tenant_identifier NOT NULL,
  id scopeproof.resource_identifier NOT NULL CHECK (id LIKE 'pkg\_%' ESCAPE '\'),
  assessment_id scopeproof.resource_identifier,
  requested_by scopeproof.resource_identifier NOT NULL,
  status text NOT NULL CHECK (status IN ('BUILDING', 'READY', 'FAILED', 'EXPIRED')),
  object_key text,
  object_version_id text,
  checksum_sha256 char(64) CHECK (checksum_sha256 IS NULL OR checksum_sha256 ~ '^[0-9a-f]{64}$'),
  manifest_signature text,
  evidence_count integer NOT NULL DEFAULT 0 CHECK (evidence_count >= 0),
  expires_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  completed_at timestamptz,
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, assessment_id) REFERENCES scopeproof.assessments (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, requested_by) REFERENCES scopeproof.principals (tenant_id, id) ON DELETE RESTRICT,
  CHECK ((status = 'READY') = (object_key IS NOT NULL AND object_version_id IS NOT NULL AND checksum_sha256 IS NOT NULL AND manifest_signature IS NOT NULL))
);

CREATE TABLE scopeproof.support_access_grants (
  tenant_id scopeproof.tenant_identifier NOT NULL,
  id scopeproof.resource_identifier NOT NULL CHECK (id LIKE 'sag\_%' ESCAPE '\'),
  operator_subject text NOT NULL CHECK (char_length(operator_subject) BETWEEN 8 AND 200),
  ticket_reference text NOT NULL CHECK (char_length(ticket_reference) BETWEEN 3 AND 120),
  reason text NOT NULL CHECK (char_length(reason) BETWEEN 10 AND 1000),
  scopes text[] NOT NULL CHECK (cardinality(scopes) BETWEEN 1 AND 10),
  approved_by scopeproof.resource_identifier NOT NULL,
  starts_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  revoked_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, approved_by) REFERENCES scopeproof.principals (tenant_id, id) ON DELETE RESTRICT,
  CHECK (expires_at > starts_at AND expires_at <= starts_at + interval '4 hours')
);

CREATE FUNCTION scopeproof.assert_database_tenant()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  expected_tenant scopeproof.tenant_identifier;
  expected_quarantine_bucket text;
  expected_evidence_bucket text;
  expected_kms_key_arn text;
  expected_retention_mode text;
BEGIN
  SELECT tenant_id, quarantine_bucket, evidence_bucket, evidence_kms_key_arn, retention_mode
    INTO STRICT expected_tenant, expected_quarantine_bucket, expected_evidence_bucket, expected_kms_key_arn, expected_retention_mode
    FROM scopeproof.tenant_identity
   WHERE singleton;
  IF NEW.tenant_id IS DISTINCT FROM expected_tenant THEN
    RAISE EXCEPTION 'tenant boundary violation' USING ERRCODE = '42501';
  END IF;
  IF TG_TABLE_NAME = 'upload_intents' AND NEW.quarantine_bucket IS DISTINCT FROM expected_quarantine_bucket THEN
    RAISE EXCEPTION 'quarantine destination violation' USING ERRCODE = '42501';
  END IF;
  IF TG_TABLE_NAME = 'evidence_artifacts' AND NEW.evidence_bucket IS NOT NULL AND
     (NEW.evidence_bucket IS DISTINCT FROM expected_evidence_bucket OR
      NEW.kms_key_arn IS DISTINCT FROM expected_kms_key_arn OR
      NEW.object_lock_mode IS DISTINCT FROM expected_retention_mode) THEN
    RAISE EXCEPTION 'evidence destination violation' USING ERRCODE = '42501';
  END IF;
  IF TG_TABLE_NAME = 'ingest_receipts' AND
     (NEW.kms_key_arn IS DISTINCT FROM expected_kms_key_arn OR
      NEW.object_lock_mode IS DISTINCT FROM expected_retention_mode) THEN
    RAISE EXCEPTION 'receipt encryption key violation' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.assert_database_tenant() FROM PUBLIC;

CREATE FUNCTION scopeproof.protect_immutable_security_fields()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
BEGIN
  IF TG_TABLE_NAME = 'upload_intents' AND
     (to_jsonb(NEW) - ARRAY['status', 'revision', 'consumed_at']) IS DISTINCT FROM
     (to_jsonb(OLD) - ARRAY['status', 'revision', 'consumed_at']) THEN
    RAISE EXCEPTION 'upload intent immutable field violation' USING ERRCODE = '42501';
  ELSIF TG_TABLE_NAME = 'evidence_artifacts' AND
     (to_jsonb(NEW) - ARRAY['status', 'approved_by', 'approved_at']) IS DISTINCT FROM
     (to_jsonb(OLD) - ARRAY['status', 'approved_by', 'approved_at']) THEN
    RAISE EXCEPTION 'evidence metadata immutable field violation' USING ERRCODE = '42501';
  ELSIF TG_TABLE_NAME = 'retention_holds' AND
     (to_jsonb(NEW) - ARRAY['released_at', 'release_reason']) IS DISTINCT FROM
     (to_jsonb(OLD) - ARRAY['released_at', 'release_reason']) THEN
    RAISE EXCEPTION 'retention hold immutable field violation' USING ERRCODE = '42501';
  ELSIF TG_TABLE_NAME = 'support_access_grants' AND
     (to_jsonb(NEW) - ARRAY['revoked_at']) IS DISTINCT FROM
     (to_jsonb(OLD) - ARRAY['revoked_at']) THEN
    RAISE EXCEPTION 'support grant immutable field violation' USING ERRCODE = '42501';
  ELSIF TG_TABLE_NAME = 'jobs' AND
     (to_jsonb(NEW) - ARRAY[
       'status', 'attempt', 'max_attempts', 'revision', 'lease_id', 'leased_by',
       'leased_at', 'lease_expires_at', 'available_at', 'result', 'error_code',
       'error_summary', 'started_at', 'completed_at'
     ]) IS DISTINCT FROM
     (to_jsonb(OLD) - ARRAY[
       'status', 'attempt', 'max_attempts', 'revision', 'lease_id', 'leased_by',
       'leased_at', 'lease_expires_at', 'available_at', 'result', 'error_code',
       'error_summary', 'started_at', 'completed_at'
     ]) THEN
    RAISE EXCEPTION 'job immutable field violation' USING ERRCODE = '42501';
  END IF;

  IF TG_TABLE_NAME = 'upload_intents' AND
     (NEW.revision IS DISTINCT FROM OLD.revision + 1 OR NOT (
       (OLD.status = 'issued' AND NEW.status IN ('quarantined', 'rejected', 'expired')) OR
       (OLD.status = 'quarantined' AND NEW.status IN ('validated', 'rejected')) OR
       (OLD.status = 'validated' AND NEW.status = 'promoted')
     )) THEN
    RAISE EXCEPTION 'upload intent state transition violation' USING ERRCODE = '23514';
  END IF;

  IF TG_TABLE_NAME = 'jobs' AND
     (NEW.revision IS DISTINCT FROM OLD.revision + 1 OR NOT (
       (OLD.status IN ('queued', 'retry_scheduled') AND NEW.status IN ('leased', 'dead_lettered', 'cancelled')) OR
       (OLD.status = 'leased' AND NEW.status IN ('leased', 'retry_scheduled', 'succeeded', 'dead_lettered')) OR
       (OLD.status = 'dead_lettered' AND NEW.status = 'queued')
     )) THEN
    RAISE EXCEPTION 'job state transition violation' USING ERRCODE = '23514';
  END IF;

  IF TG_TABLE_NAME = 'evidence_artifacts' AND OLD.status <> NEW.status AND NOT (
    (OLD.status = 'QUARANTINED' AND NEW.status IN ('VALIDATING', 'REJECTED')) OR
    (OLD.status = 'VALIDATING' AND NEW.status IN ('NEEDS_REVIEW', 'REJECTED')) OR
    (OLD.status = 'NEEDS_REVIEW' AND NEW.status IN ('APPROVED', 'REJECTED')) OR
    (OLD.status = 'APPROVED' AND NEW.status = 'EXPIRED') OR
    (OLD.status IN ('REJECTED', 'EXPIRED') AND NEW.status = 'PURGED')
  ) THEN
    RAISE EXCEPTION 'evidence state transition violation' USING ERRCODE = '23514';
  END IF;

  IF TG_TABLE_NAME = 'retention_holds' AND OLD.released_at IS NOT NULL THEN
    RAISE EXCEPTION 'released retention hold is immutable' USING ERRCODE = '42501';
  END IF;

  IF TG_TABLE_NAME = 'support_access_grants' AND OLD.revoked_at IS NOT NULL THEN
    RAISE EXCEPTION 'revoked support grant is immutable' USING ERRCODE = '42501';
  END IF;
  RETURN NEW;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.protect_immutable_security_fields() FROM PUBLIC;

DO $$
DECLARE
  table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'principals', 'memberships', 'tenant_domains', 'device_enrollments',
    'assessments', 'integrations', 'jobs', 'upload_intents',
    'evidence_artifacts', 'ingest_receipts', 'retention_holds',
    'audit_heads', 'audit_events', 'export_receipts', 'support_access_grants'
  ]
  LOOP
    EXECUTE format(
      'ALTER TABLE scopeproof.%I ADD CONSTRAINT %I FOREIGN KEY (tenant_id) REFERENCES scopeproof.tenant_identity (tenant_id) ON DELETE RESTRICT',
      table_name,
      left(table_name || '_tenant_identity_fk', 63)
    );
    EXECUTE format('ALTER TABLE scopeproof.%I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE scopeproof.%I FORCE ROW LEVEL SECURITY', table_name);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON scopeproof.%I USING (tenant_id = scopeproof.current_tenant_id()) WITH CHECK (tenant_id = scopeproof.current_tenant_id())',
      table_name
    );
    EXECUTE format(
      'CREATE TRIGGER enforce_database_tenant BEFORE INSERT OR UPDATE ON scopeproof.%I FOR EACH ROW EXECUTE FUNCTION scopeproof.assert_database_tenant()',
      table_name
    );
  END LOOP;
END;
$$;

CREATE TRIGGER append_audit_chain
BEFORE INSERT ON scopeproof.audit_events
FOR EACH ROW EXECUTE FUNCTION scopeproof.advance_audit_head();

DO $$
DECLARE
  table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'jobs', 'upload_intents', 'evidence_artifacts', 'retention_holds', 'support_access_grants'
  ]
  LOOP
    EXECUTE format(
      'CREATE TRIGGER protect_immutable_fields BEFORE UPDATE ON scopeproof.%I FOR EACH ROW EXECUTE FUNCTION scopeproof.protect_immutable_security_fields()',
      table_name
    );
  END LOOP;
END;
$$;

REVOKE ALL ON ALL TABLES IN SCHEMA scopeproof FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA scopeproof FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA scopeproof REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA scopeproof REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA scopeproof REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

INSERT INTO scopeproof.schema_migrations (version, name)
VALUES (1, 'tenant_security_baseline');

COMMIT;
