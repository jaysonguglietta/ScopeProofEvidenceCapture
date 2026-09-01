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
  audit_signing_key_arn text NOT NULL CHECK (audit_signing_key_arn ~ '^arn:(aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]{36}$'),
  singleton boolean NOT NULL DEFAULT true UNIQUE CHECK (singleton),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  CHECK (quarantine_bucket <> evidence_bucket),
  CHECK (audit_signing_key_arn <> evidence_kms_key_arn),
  CHECK (split_part(evidence_kms_key_arn, ':', 4) = aws_region),
  CHECK (split_part(evidence_kms_key_arn, ':', 5) = aws_account_id),
  CHECK (split_part(audit_signing_key_arn, ':', 4) = aws_region),
  CHECK (split_part(audit_signing_key_arn, ':', 5) = aws_account_id)
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
  last_upload_sequence bigint NOT NULL DEFAULT 0 CHECK (last_upload_sequence >= 0),
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
  control_id text NOT NULL CHECK (control_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
  quarantine_bucket text NOT NULL CHECK (char_length(quarantine_bucket) BETWEEN 3 AND 63),
  object_key text NOT NULL CHECK (object_key ~ '^tenants/ten_[a-f0-9]{32}/controls/[A-Za-z0-9][A-Za-z0-9._-]{0,63}/quarantine/upl_[a-f0-9]{32}\.upload$'),
  final_object_key text NOT NULL CHECK (final_object_key ~ '^tenants/ten_[a-f0-9]{32}/controls/[A-Za-z0-9][A-Za-z0-9._-]{0,63}/evidence/evd_[a-f0-9]{32}\.(png|json|spdx\.json|cdx\.json|txt|csv)$'),
  content_type text NOT NULL CHECK (content_type IN ('image/png', 'application/json', 'application/spdx+json', 'application/vnd.cyclonedx+json', 'text/plain', 'text/csv')),
  content_length bigint NOT NULL CHECK (content_length BETWEEN 1 AND 26214400),
  checksum_sha256 char(64) NOT NULL CHECK (checksum_sha256 ~ '^[0-9a-f]{64}$'),
  status text NOT NULL DEFAULT 'issued' CHECK (status IN ('issued', 'quarantined', 'validated', 'promoted', 'rejected', 'expired')),
  revision integer NOT NULL DEFAULT 0 CHECK (revision >= 0),
  promotion_fence bigint NOT NULL DEFAULT 0 CHECK (promotion_fence >= 0),
  promotion_attempt_id text CHECK (promotion_attempt_id IS NULL OR promotion_attempt_id ~ '^pat_[0-9a-f]{32}$'),
  promotion_lease_expires_at timestamptz,
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
  CHECK (object_key LIKE 'tenants/' || tenant_id || '/controls/' || control_id || '/quarantine/%'),
  CHECK (final_object_key LIKE 'tenants/' || tenant_id || '/controls/' || control_id || '/evidence/' || evidence_id || '.%'),
  CHECK (consumed_at IS NULL OR consumed_at >= created_at),
  CHECK ((promotion_fence = 0) = (promotion_attempt_id IS NULL AND promotion_lease_expires_at IS NULL))
);
CREATE INDEX upload_intents_expiry ON scopeproof.upload_intents (tenant_id, expires_at) WHERE consumed_at IS NULL;
CREATE UNIQUE INDEX upload_intents_one_active_per_evidence
  ON scopeproof.upload_intents (tenant_id, evidence_id)
  WHERE status IN ('issued', 'quarantined', 'validated');

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
  revision integer NOT NULL DEFAULT 0 CHECK (revision >= 0),
  content_type text NOT NULL CHECK (char_length(content_type) BETWEEN 3 AND 120),
  byte_size bigint NOT NULL CHECK (byte_size BETWEEN 1 AND 26214400),
  checksum_sha256 char(64) NOT NULL CHECK (checksum_sha256 ~ '^[0-9a-f]{64}$'),
  evidence_bucket text,
  object_key text CHECK (object_key IS NULL OR object_key ~ '^tenants/ten_[a-f0-9]{32}/controls/[A-Za-z0-9][A-Za-z0-9._-]{0,63}/evidence/evd_[a-f0-9]{32}\.(png|json|spdx\.json|cdx\.json|txt|csv)$'),
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
  CHECK (object_key IS NULL OR object_key LIKE 'tenants/' || tenant_id || '/controls/' || control_id || '/evidence/' || id || '.%'),
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
  upload_revision integer NOT NULL CHECK (upload_revision > 0),
  evidence_revision integer NOT NULL CHECK (evidence_revision > 0),
  promotion_fence bigint NOT NULL CHECK (promotion_fence > 0),
  promotion_attempt_id text NOT NULL CHECK (promotion_attempt_id ~ '^pat_[0-9a-f]{32}$'),
  idempotency_digest char(64) NOT NULL CHECK (idempotency_digest ~ '^[0-9a-f]{64}$'),
  promotion_facts jsonb NOT NULL CHECK (jsonb_typeof(promotion_facts) = 'object'),
  receipt_sha256 char(64) NOT NULL CHECK (receipt_sha256 ~ '^[0-9a-f]{64}$'),
  canonical_receipt text NOT NULL CHECK (octet_length(canonical_receipt) BETWEEN 64 AND 16384),
  signing_key_arn text NOT NULL CHECK (signing_key_arn ~ '^arn:(aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]{36}$'),
  signing_algorithm text NOT NULL CHECK (signing_algorithm = 'RSASSA_PSS_SHA_256'),
  signature text NOT NULL CHECK (char_length(signature) = 512 AND signature ~ '^[A-Za-z0-9+/]+={0,2}$'),
  signed_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, upload_intent_id),
  UNIQUE (tenant_id, idempotency_digest),
  UNIQUE (tenant_id, receipt_sha256),
  FOREIGN KEY (tenant_id, upload_intent_id) REFERENCES scopeproof.upload_intents (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, evidence_id) REFERENCES scopeproof.evidence_artifacts (tenant_id, id) ON DELETE RESTRICT
);

CREATE TABLE scopeproof.retention_holds (
  tenant_id scopeproof.tenant_identifier NOT NULL,
  id scopeproof.resource_identifier NOT NULL CHECK (id LIKE 'hld\_%' ESCAPE '\'),
  evidence_id scopeproof.resource_identifier NOT NULL,
  control_id text NOT NULL CHECK (control_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
  kind text NOT NULL CHECK (kind IN ('LEGAL', 'AUDIT', 'SECURITY_INCIDENT')),
  reason text NOT NULL CHECK (char_length(reason) BETWEEN 10 AND 2000),
  created_by scopeproof.resource_identifier NOT NULL,
  approved_by scopeproof.resource_identifier NOT NULL,
  evidence_bucket text NOT NULL CHECK (evidence_bucket ~ '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$'),
  object_key text NOT NULL CHECK (object_key ~ '^tenants/ten_[a-f0-9]{32}/controls/[A-Za-z0-9][A-Za-z0-9._-]{0,63}/evidence/evd_[a-f0-9]{32}\.(png|json|spdx\.json|cdx\.json|txt|csv)$'),
  object_version_id text NOT NULL CHECK (object_version_id ~ '^[A-Za-z0-9][A-Za-z0-9._:+/=-]{0,511}$'),
  provider_request_id text NOT NULL CHECK (provider_request_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{2,199}$'),
  provider_verify_request_id text NOT NULL CHECK (provider_verify_request_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{2,199}$'),
  s3_legal_hold_status text NOT NULL DEFAULT 'ON' CHECK (s3_legal_hold_status IN ('ON', 'OFF')),
  revision integer NOT NULL DEFAULT 0 CHECK (revision >= 0),
  expires_at timestamptz,
  released_at timestamptz,
  release_reason text,
  release_requested_by scopeproof.resource_identifier,
  release_approved_by scopeproof.resource_identifier,
  release_provider_request_id text,
  release_verify_request_id text,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  FOREIGN KEY (tenant_id, evidence_id) REFERENCES scopeproof.evidence_artifacts (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, created_by) REFERENCES scopeproof.principals (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, approved_by) REFERENCES scopeproof.principals (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, release_requested_by) REFERENCES scopeproof.principals (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, release_approved_by) REFERENCES scopeproof.principals (tenant_id, id) ON DELETE RESTRICT,
  CHECK (created_by <> approved_by),
  CHECK (evidence_bucket <> ''),
  CHECK (object_key LIKE 'tenants/' || tenant_id || '/controls/' || control_id || '/evidence/' || evidence_id || '.%'),
  CHECK ((released_at IS NULL) = (release_reason IS NULL)),
  CHECK ((released_at IS NULL) = (release_requested_by IS NULL)),
  CHECK ((released_at IS NULL) = (release_approved_by IS NULL)),
  CHECK ((released_at IS NULL) = (release_provider_request_id IS NULL)),
  CHECK ((released_at IS NULL) = (release_verify_request_id IS NULL)),
  CHECK ((released_at IS NULL) = (s3_legal_hold_status = 'ON')),
  CHECK (release_requested_by IS NULL OR release_requested_by <> release_approved_by),
  CHECK (release_provider_request_id IS NULL OR release_provider_request_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{2,199}$'),
  CHECK (release_verify_request_id IS NULL OR release_verify_request_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{2,199}$')
);
CREATE UNIQUE INDEX active_retention_holds
  ON scopeproof.retention_holds (tenant_id, evidence_id, evidence_bucket, object_key, object_version_id)
  WHERE released_at IS NULL;

CREATE TABLE scopeproof.legal_hold_operations (
  tenant_id scopeproof.tenant_identifier NOT NULL,
  id scopeproof.resource_identifier NOT NULL CHECK (id LIKE 'lho\_%' ESCAPE '\'),
  hold_id scopeproof.resource_identifier NOT NULL CHECK (hold_id LIKE 'hld\_%' ESCAPE '\'),
  evidence_id scopeproof.resource_identifier NOT NULL CHECK (evidence_id LIKE 'evd\_%' ESCAPE '\'),
  control_id text NOT NULL CHECK (control_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'),
  evidence_bucket text NOT NULL CHECK (evidence_bucket ~ '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$'),
  object_key text NOT NULL CHECK (object_key ~ '^tenants/ten_[a-f0-9]{32}/controls/[A-Za-z0-9][A-Za-z0-9._-]{0,63}/evidence/evd_[a-f0-9]{32}\.(png|json|spdx\.json|cdx\.json|txt|csv)$'),
  object_version_id text NOT NULL CHECK (object_version_id ~ '^[A-Za-z0-9][A-Za-z0-9._:+/=-]{0,511}$'),
  desired_status text NOT NULL CHECK (desired_status IN ('ON', 'OFF')),
  hold_kind text NOT NULL CHECK (hold_kind IN ('LEGAL', 'AUDIT', 'SECURITY_INCIDENT')),
  reason text NOT NULL CHECK (char_length(reason) BETWEEN 10 AND 2000),
  requested_by scopeproof.resource_identifier NOT NULL,
  approved_by scopeproof.resource_identifier,
  expected_hold_revision integer NOT NULL CHECK (expected_hold_revision >= 0),
  operation_state text NOT NULL DEFAULT 'REQUESTED' CHECK (operation_state IN ('REQUESTED', 'APPROVED', 'APPLYING', 'APPLIED', 'EXPIRED')),
  revision integer NOT NULL DEFAULT 0 CHECK (revision >= 0),
  changed_at timestamptz NOT NULL,
  canonical_request text NOT NULL CHECK (octet_length(canonical_request) BETWEEN 128 AND 16384),
  request_digest char(64) NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
  approved_at timestamptz,
  canonical_approval text CHECK (canonical_approval IS NULL OR octet_length(canonical_approval) BETWEEN 128 AND 16384),
  approval_digest char(64) CHECK (approval_digest IS NULL OR approval_digest ~ '^[0-9a-f]{64}$'),
  application_attempt_id char(64) CHECK (application_attempt_id IS NULL OR application_attempt_id ~ '^[0-9a-f]{64}$'),
  application_prior_status text CHECK (application_prior_status IS NULL OR application_prior_status IN ('ON', 'OFF')),
  application_observed_request_id text CHECK (application_observed_request_id IS NULL OR application_observed_request_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{2,199}$'),
  application_started_at timestamptz,
  receipt jsonb CHECK (receipt IS NULL OR jsonb_typeof(receipt) = 'object'),
  canonical_receipt text CHECK (canonical_receipt IS NULL OR octet_length(canonical_receipt) BETWEEN 128 AND 16384),
  receipt_sha256 char(64) CHECK (receipt_sha256 IS NULL OR receipt_sha256 ~ '^[0-9a-f]{64}$'),
  provider_request_id text CHECK (provider_request_id IS NULL OR provider_request_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{2,199}$'),
  provider_verify_request_id text CHECK (provider_verify_request_id IS NULL OR provider_verify_request_id ~ '^[A-Za-z0-9][A-Za-z0-9_-]{2,199}$'),
  applied_at timestamptz,
  recovery_published_at timestamptz,
  expired_at timestamptz,
  reconciliation_attempt_count integer NOT NULL DEFAULT 0 CHECK (reconciliation_attempt_count BETWEEN 0 AND 1000000),
  reconciliation_next_attempt_at timestamptz,
  reconciliation_last_error_code text CHECK (reconciliation_last_error_code IS NULL OR reconciliation_last_error_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
  reconciliation_last_failed_at timestamptz,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, request_digest),
  FOREIGN KEY (tenant_id, evidence_id) REFERENCES scopeproof.evidence_artifacts (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, requested_by) REFERENCES scopeproof.principals (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, approved_by) REFERENCES scopeproof.principals (tenant_id, id) ON DELETE RESTRICT,
  CHECK (approved_by IS NULL OR requested_by <> approved_by),
  CHECK (object_key LIKE 'tenants/' || tenant_id || '/controls/' || control_id || '/evidence/' || evidence_id || '.%'),
  CHECK (desired_status <> 'ON' OR expected_hold_revision = 0),
  CHECK (
    (operation_state = 'REQUESTED' AND revision = 0 AND approved_by IS NULL AND approved_at IS NULL AND
      canonical_approval IS NULL AND approval_digest IS NULL) OR
    (operation_state = 'APPROVED' AND revision = 1 AND approved_by IS NOT NULL AND approved_at IS NOT NULL AND
      canonical_approval IS NOT NULL AND approval_digest IS NOT NULL) OR
    (operation_state = 'APPLYING' AND revision = 2 AND approved_by IS NOT NULL AND approved_at IS NOT NULL AND
      canonical_approval IS NOT NULL AND approval_digest IS NOT NULL) OR
    (operation_state = 'APPLIED' AND revision = 3 AND approved_by IS NOT NULL AND approved_at IS NOT NULL AND
      canonical_approval IS NOT NULL AND approval_digest IS NOT NULL) OR
    (operation_state = 'EXPIRED' AND revision = 1 AND approved_by IS NULL AND approved_at IS NULL AND
      canonical_approval IS NULL AND approval_digest IS NULL)
  ),
  CHECK (approved_at IS NULL OR (approved_at >= changed_at AND approved_at <= changed_at + interval '24 hours')),
  CHECK ((operation_state = 'EXPIRED') = (expired_at IS NOT NULL)),
  CHECK ((operation_state IN ('APPLYING', 'APPLIED')) = (application_attempt_id IS NOT NULL)),
  CHECK ((operation_state IN ('APPLYING', 'APPLIED')) = (application_prior_status IS NOT NULL)),
  CHECK ((operation_state IN ('APPLYING', 'APPLIED')) = (application_observed_request_id IS NOT NULL)),
  CHECK ((operation_state IN ('APPLYING', 'APPLIED')) = (application_started_at IS NOT NULL)),
  CHECK (application_prior_status IS NULL OR application_prior_status <> desired_status),
  CHECK (expired_at IS NULL OR expired_at >= changed_at + interval '24 hours'),
  CHECK ((operation_state = 'APPLIED') = (receipt IS NOT NULL)),
  CHECK ((operation_state = 'APPLIED') = (canonical_receipt IS NOT NULL)),
  CHECK ((operation_state = 'APPLIED') = (receipt_sha256 IS NOT NULL)),
  CHECK ((operation_state = 'APPLIED') = (provider_request_id IS NOT NULL)),
  CHECK ((operation_state = 'APPLIED') = (provider_verify_request_id IS NOT NULL)),
  CHECK ((operation_state = 'APPLIED') = (applied_at IS NOT NULL)),
  CHECK (recovery_published_at IS NULL OR
    (operation_state = 'APPLIED' AND recovery_published_at >= applied_at)),
  CHECK (
    (reconciliation_attempt_count = 0 AND reconciliation_next_attempt_at IS NULL AND
      reconciliation_last_error_code IS NULL AND reconciliation_last_failed_at IS NULL) OR
    (reconciliation_attempt_count > 0 AND reconciliation_next_attempt_at IS NOT NULL AND
      reconciliation_last_error_code IS NOT NULL AND reconciliation_last_failed_at IS NOT NULL AND
      reconciliation_next_attempt_at > reconciliation_last_failed_at)
  )
);
CREATE UNIQUE INDEX one_pending_legal_hold_operation_per_version
  ON scopeproof.legal_hold_operations (tenant_id, evidence_bucket, object_key, object_version_id)
  WHERE operation_state IN ('REQUESTED', 'APPROVED', 'APPLYING');

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
  action text NOT NULL CHECK (action ~ '^[a-z0-9_.:-]{3,120}$'),
  resource_type text NOT NULL CHECK (resource_type ~ '^[a-z0-9_.:-]{2,80}$'),
  resource_id text NOT NULL CHECK (char_length(resource_id) BETWEEN 1 AND 200),
  request_id text NOT NULL CHECK (char_length(request_id) BETWEEN 3 AND 200),
  outcome text NOT NULL CHECK (outcome IN ('succeeded', 'denied', 'failed')),
  details jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(details) = 'object'),
  previous_hash text NOT NULL CHECK (previous_hash = 'GENESIS' OR previous_hash ~ '^[0-9a-f]{64}$'),
  event_hash char(64) NOT NULL CHECK (event_hash ~ '^[0-9a-f]{64}$'),
  canonical_event text NOT NULL CHECK (octet_length(canonical_event) BETWEEN 64 AND 32000),
  receipt_payload jsonb NOT NULL CHECK (jsonb_typeof(receipt_payload) = 'object'),
  canonical_receipt text NOT NULL CHECK (octet_length(canonical_receipt) BETWEEN 64 AND 16384),
  receipt_payload_sha256 char(64) NOT NULL CHECK (receipt_payload_sha256 ~ '^[0-9a-f]{64}$'),
  signing_key_arn text NOT NULL CHECK (signing_key_arn ~ '^arn:(aws|aws-us-gov|aws-cn):kms:[a-z0-9-]+:[0-9]{12}:key/[0-9a-f-]{36}$'),
  signing_algorithm text NOT NULL CHECK (signing_algorithm = 'RSASSA_PSS_SHA_256'),
  kms_signature text NOT NULL CHECK (char_length(kms_signature) = 512 AND kms_signature ~ '^[A-Za-z0-9+/]+={0,2}$'),
  signed_at timestamptz NOT NULL,
  PRIMARY KEY (tenant_id, sequence),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, event_hash),
  CHECK ((sequence = 1) = (previous_hash = 'GENESIS'))
);
CREATE INDEX audit_resource ON scopeproof.audit_events (tenant_id, resource_type, resource_id, sequence DESC);

-- Public APIs cannot hold the tenant KMS signing capability. They durably
-- enqueue a minimal, server-normalized action record here; the isolated audit
-- signer can later transform it into the immutable signed audit chain. API
-- roles receive EXECUTE on the writer function only, never table privileges.
CREATE TABLE scopeproof.api_audit_outbox (
  tenant_id scopeproof.tenant_identifier NOT NULL,
  id scopeproof.resource_identifier NOT NULL CHECK (id LIKE 'aob\_%' ESCAPE '\'),
  occurred_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  actor_user_id scopeproof.resource_identifier NOT NULL CHECK (actor_user_id LIKE 'usr\_%' ESCAPE '\'),
  membership_id scopeproof.resource_identifier NOT NULL CHECK (membership_id LIKE 'mem\_%' ESCAPE '\'),
  request_id text NOT NULL CHECK (
    char_length(request_id) BETWEEN 8 AND 128 AND
    request_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$'
  ),
  action text NOT NULL CHECK (action IN (
    'evidence.upload_intent_issued',
    'evidence.search_performed',
    'evidence.download_intent_issued',
    'evidence.legal_hold_requested',
    'evidence.legal_hold_approved'
  )),
  resource_type text NOT NULL CHECK (resource_type IN ('evidence', 'evidence_collection', 'legal_hold_operation')),
  resource_id text NOT NULL CHECK (char_length(resource_id) BETWEEN 8 AND 200),
  outcome text NOT NULL DEFAULT 'succeeded' CHECK (outcome = 'succeeded'),
  idempotency_key text NOT NULL CHECK (char_length(idempotency_key) BETWEEN 16 AND 200),
  details jsonb NOT NULL CHECK (jsonb_typeof(details) = 'object' AND octet_length(details::text) <= 16384),
  event_digest char(64) NOT NULL CHECK (event_digest ~ '^[0-9a-f]{64}$'),
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, idempotency_key),
  UNIQUE (tenant_id, event_digest),
  FOREIGN KEY (tenant_id, actor_user_id) REFERENCES scopeproof.principals (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, membership_id) REFERENCES scopeproof.memberships (tenant_id, id) ON DELETE RESTRICT
);
CREATE INDEX api_audit_outbox_pending ON scopeproof.api_audit_outbox (tenant_id, occurred_at, id);

-- Mutable delivery state is deliberately separated from the immutable API
-- action record. Only SECURITY DEFINER worker procedures may lease, retry, or
-- complete these rows; API identities receive no access to this table.
CREATE TABLE scopeproof.api_audit_outbox_work (
  tenant_id scopeproof.tenant_identifier NOT NULL,
  outbox_id scopeproof.resource_identifier NOT NULL CHECK (outbox_id LIKE 'aob\_%' ESCAPE '\'),
  attempt_count integer NOT NULL DEFAULT 0 CHECK (attempt_count BETWEEN 0 AND 8),
  next_attempt_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  lease_token text CHECK (
    lease_token IS NULL OR
    (char_length(lease_token) BETWEEN 16 AND 128 AND lease_token ~ '^[A-Za-z0-9_-]{16,128}$')
  ),
  lease_expires_at timestamptz,
  last_error_code text CHECK (last_error_code IS NULL OR last_error_code ~ '^[A-Z][A-Z0-9_]{2,63}$'),
  last_failed_at timestamptz,
  dead_lettered_at timestamptz,
  completed_at timestamptz,
  audit_event_id scopeproof.resource_identifier CHECK (audit_event_id IS NULL OR audit_event_id LIKE 'evt\_%' ESCAPE '\'),
  audit_event_hash char(64) CHECK (audit_event_hash IS NULL OR audit_event_hash ~ '^[0-9a-f]{64}$'),
  PRIMARY KEY (tenant_id, outbox_id),
  FOREIGN KEY (tenant_id, outbox_id) REFERENCES scopeproof.api_audit_outbox (tenant_id, id) ON DELETE RESTRICT,
  CHECK ((lease_token IS NULL) = (lease_expires_at IS NULL)),
  CHECK ((last_error_code IS NULL) = (last_failed_at IS NULL)),
  CHECK ((dead_lettered_at IS NULL) OR (attempt_count = 8 AND completed_at IS NULL)),
  CHECK ((completed_at IS NULL) = (audit_event_id IS NULL)),
  CHECK ((completed_at IS NULL) = (audit_event_hash IS NULL)),
  CHECK (completed_at IS NULL OR (lease_token IS NULL AND dead_lettered_at IS NULL))
);
CREATE INDEX api_audit_outbox_work_due
  ON scopeproof.api_audit_outbox_work (tenant_id, next_attempt_at, outbox_id)
  WHERE completed_at IS NULL AND dead_lettered_at IS NULL;

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
  expected_signing_key_arn text;
  expected_retention_mode text;
BEGIN
  SELECT tenant_id, quarantine_bucket, evidence_bucket, evidence_kms_key_arn, audit_signing_key_arn, retention_mode
    INTO STRICT expected_tenant, expected_quarantine_bucket, expected_evidence_bucket, expected_kms_key_arn, expected_signing_key_arn, expected_retention_mode
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
      NEW.signing_key_arn IS DISTINCT FROM expected_signing_key_arn OR
      NEW.object_lock_mode IS DISTINCT FROM expected_retention_mode) THEN
    RAISE EXCEPTION 'receipt encryption key violation' USING ERRCODE = '42501';
  END IF;
  IF TG_TABLE_NAME = 'audit_events' AND NEW.signing_key_arn IS DISTINCT FROM expected_signing_key_arn THEN
    RAISE EXCEPTION 'audit signing key violation' USING ERRCODE = '42501';
  END IF;
  IF TG_TABLE_NAME IN ('retention_holds', 'legal_hold_operations') AND
     NEW.evidence_bucket IS DISTINCT FROM expected_evidence_bucket THEN
    RAISE EXCEPTION 'legal hold evidence destination violation' USING ERRCODE = '42501';
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
  IF TG_TABLE_NAME = 'api_audit_outbox' THEN
    RAISE EXCEPTION 'API audit outbox records are immutable' USING ERRCODE = '42501';
  ELSIF TG_TABLE_NAME = 'upload_intents' AND
     (to_jsonb(NEW) - ARRAY[
       'status', 'revision', 'consumed_at', 'promotion_fence',
       'promotion_attempt_id', 'promotion_lease_expires_at'
     ]) IS DISTINCT FROM
     (to_jsonb(OLD) - ARRAY[
       'status', 'revision', 'consumed_at', 'promotion_fence',
       'promotion_attempt_id', 'promotion_lease_expires_at'
     ]) THEN
    RAISE EXCEPTION 'upload intent immutable field violation' USING ERRCODE = '42501';
  ELSIF TG_TABLE_NAME = 'evidence_artifacts' THEN
    IF (
      NEW.evidence_bucket IS DISTINCT FROM OLD.evidence_bucket OR
      NEW.object_key IS DISTINCT FROM OLD.object_key OR
      NEW.object_version_id IS DISTINCT FROM OLD.object_version_id OR
      NEW.kms_key_arn IS DISTINCT FROM OLD.kms_key_arn OR
      NEW.object_lock_mode IS DISTINCT FROM OLD.object_lock_mode OR
      NEW.retain_until IS DISTINCT FROM OLD.retain_until
    ) AND NOT (
      OLD.status IN ('QUARANTINED', 'VALIDATING') AND NEW.status = 'NEEDS_REVIEW' AND
      OLD.evidence_bucket IS NULL AND OLD.object_key IS NULL AND
      OLD.object_version_id IS NULL AND OLD.kms_key_arn IS NULL AND
      OLD.object_lock_mode IS NULL AND OLD.retain_until IS NULL AND
      NEW.evidence_bucket IS NOT NULL AND NEW.object_key IS NOT NULL AND
      NEW.object_version_id IS NOT NULL AND NEW.kms_key_arn IS NOT NULL AND
      NEW.object_lock_mode IS NOT NULL AND NEW.retain_until IS NOT NULL
    ) THEN
      RAISE EXCEPTION 'evidence object binding violation' USING ERRCODE = '42501';
    END IF;
    IF (to_jsonb(NEW) - ARRAY[
      'status', 'revision', 'approved_by', 'approved_at', 'evidence_bucket', 'object_key',
      'object_version_id', 'kms_key_arn', 'object_lock_mode', 'retain_until'
    ]) IS DISTINCT FROM (to_jsonb(OLD) - ARRAY[
      'status', 'revision', 'approved_by', 'approved_at', 'evidence_bucket', 'object_key',
      'object_version_id', 'kms_key_arn', 'object_lock_mode', 'retain_until'
    ]) THEN
      RAISE EXCEPTION 'evidence metadata immutable field violation' USING ERRCODE = '42501';
    END IF;
  ELSIF TG_TABLE_NAME = 'ingest_receipts' THEN
    RAISE EXCEPTION 'promotion receipt immutable field violation' USING ERRCODE = '42501';
  ELSIF TG_TABLE_NAME = 'retention_holds' AND
     (to_jsonb(NEW) - ARRAY[
       'released_at', 'release_reason', 'release_requested_by', 'release_approved_by',
       'release_provider_request_id', 'release_verify_request_id', 's3_legal_hold_status', 'revision'
     ]) IS DISTINCT FROM (to_jsonb(OLD) - ARRAY[
       'released_at', 'release_reason', 'release_requested_by', 'release_approved_by',
       'release_provider_request_id', 'release_verify_request_id', 's3_legal_hold_status', 'revision'
     ]) THEN
    RAISE EXCEPTION 'retention hold immutable field violation' USING ERRCODE = '42501';
  ELSIF TG_TABLE_NAME = 'legal_hold_operations' AND
     (to_jsonb(NEW) - ARRAY[
       'operation_state', 'revision', 'approved_by', 'approved_at', 'canonical_approval', 'approval_digest',
       'receipt', 'canonical_receipt', 'receipt_sha256',
       'provider_request_id', 'provider_verify_request_id', 'applied_at', 'recovery_published_at', 'expired_at',
       'reconciliation_attempt_count', 'reconciliation_next_attempt_at',
       'reconciliation_last_error_code', 'reconciliation_last_failed_at'
     ]) IS DISTINCT FROM (to_jsonb(OLD) - ARRAY[
       'operation_state', 'revision', 'approved_by', 'approved_at', 'canonical_approval', 'approval_digest',
       'receipt', 'canonical_receipt', 'receipt_sha256',
       'provider_request_id', 'provider_verify_request_id', 'applied_at', 'recovery_published_at', 'expired_at',
       'reconciliation_attempt_count', 'reconciliation_next_attempt_at',
       'reconciliation_last_error_code', 'reconciliation_last_failed_at'
     ]) THEN
    RAISE EXCEPTION 'legal hold operation immutable field violation' USING ERRCODE = '42501';
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

  IF TG_TABLE_NAME = 'upload_intents' THEN
    IF NEW.status = OLD.status AND NEW.revision = OLD.revision THEN
      IF NEW.status NOT IN ('issued', 'quarantined', 'validated') OR
         NEW.promotion_attempt_id IS NULL OR
         NEW.promotion_lease_expires_at IS NULL OR
         NEW.promotion_lease_expires_at <= clock_timestamp() OR NOT (
           (NEW.promotion_fence > OLD.promotion_fence AND
            NEW.promotion_attempt_id IS DISTINCT FROM OLD.promotion_attempt_id) OR
           (NEW.promotion_fence = OLD.promotion_fence AND
            NEW.promotion_attempt_id IS NOT DISTINCT FROM OLD.promotion_attempt_id AND
            NEW.promotion_lease_expires_at > OLD.promotion_lease_expires_at)
         ) THEN
        RAISE EXCEPTION 'upload intent promotion fence violation' USING ERRCODE = '40001';
      END IF;
    ELSIF NEW.revision IS DISTINCT FROM OLD.revision + 1 OR NOT (
      (OLD.status = 'issued' AND NEW.status IN ('quarantined', 'promoted', 'rejected', 'expired')) OR
      (OLD.status = 'quarantined' AND NEW.status IN ('validated', 'promoted', 'rejected')) OR
      (OLD.status = 'validated' AND NEW.status = 'promoted')
    ) OR NEW.promotion_fence IS DISTINCT FROM OLD.promotion_fence OR
       NEW.promotion_attempt_id IS DISTINCT FROM OLD.promotion_attempt_id OR
       NEW.promotion_lease_expires_at IS DISTINCT FROM OLD.promotion_lease_expires_at THEN
      RAISE EXCEPTION 'upload intent state transition violation' USING ERRCODE = '23514';
    END IF;
  END IF;

  IF TG_TABLE_NAME = 'jobs' AND
     (NEW.revision IS DISTINCT FROM OLD.revision + 1 OR NOT (
       (OLD.status IN ('queued', 'retry_scheduled') AND NEW.status IN ('leased', 'dead_lettered', 'cancelled')) OR
       (OLD.status = 'leased' AND NEW.status IN ('leased', 'retry_scheduled', 'succeeded', 'dead_lettered')) OR
       (OLD.status = 'dead_lettered' AND NEW.status = 'queued')
     )) THEN
    RAISE EXCEPTION 'job state transition violation' USING ERRCODE = '23514';
  END IF;

  IF TG_TABLE_NAME = 'evidence_artifacts' AND OLD.status <> NEW.status AND (
    NEW.revision IS DISTINCT FROM OLD.revision + 1 OR NOT (
    (OLD.status = 'QUARANTINED' AND NEW.status IN ('VALIDATING', 'NEEDS_REVIEW', 'REJECTED')) OR
    (OLD.status = 'VALIDATING' AND NEW.status IN ('NEEDS_REVIEW', 'REJECTED')) OR
    (OLD.status = 'NEEDS_REVIEW' AND NEW.status IN ('APPROVED', 'REJECTED')) OR
    (OLD.status = 'APPROVED' AND NEW.status = 'EXPIRED') OR
    (OLD.status IN ('REJECTED', 'EXPIRED') AND NEW.status = 'PURGED')
  )) THEN
    RAISE EXCEPTION 'evidence state transition violation' USING ERRCODE = '23514';
  END IF;

  IF TG_TABLE_NAME = 'retention_holds' THEN
    IF OLD.released_at IS NOT NULL THEN
      RAISE EXCEPTION 'released retention hold is immutable' USING ERRCODE = '42501';
    END IF;
    IF NEW.revision IS DISTINCT FROM OLD.revision + 1 OR
       NEW.released_at IS NULL OR NEW.release_reason IS NULL OR
       NEW.release_requested_by IS NULL OR NEW.release_approved_by IS NULL OR
       NEW.release_requested_by = NEW.release_approved_by OR
       NEW.release_provider_request_id IS NULL OR NEW.release_verify_request_id IS NULL OR
       NEW.s3_legal_hold_status <> 'OFF' THEN
      RAISE EXCEPTION 'retention hold release transition violation' USING ERRCODE = '23514';
    END IF;
  END IF;

  IF TG_TABLE_NAME = 'legal_hold_operations' THEN
    IF NOT (OLD.operation_state IN ('APPROVED', 'APPLYING') AND NEW.operation_state = OLD.operation_state) AND (
         NEW.reconciliation_attempt_count IS DISTINCT FROM OLD.reconciliation_attempt_count OR
         NEW.reconciliation_next_attempt_at IS DISTINCT FROM OLD.reconciliation_next_attempt_at OR
         NEW.reconciliation_last_error_code IS DISTINCT FROM OLD.reconciliation_last_error_code OR
         NEW.reconciliation_last_failed_at IS DISTINCT FROM OLD.reconciliation_last_failed_at
       ) THEN
      RAISE EXCEPTION 'legal hold reconciliation metadata transition violation' USING ERRCODE = '23514';
    END IF;
    IF OLD.operation_state = 'REQUESTED' AND NEW.operation_state = 'APPROVED' THEN
      IF NEW.revision IS DISTINCT FROM 1 OR OLD.revision IS DISTINCT FROM 0 OR
         NEW.approved_by IS NULL OR NEW.approved_at IS NULL OR
         NEW.canonical_approval IS NULL OR NEW.approval_digest IS NULL OR
         NEW.receipt IS NOT NULL OR NEW.canonical_receipt IS NOT NULL OR
         NEW.receipt_sha256 IS NOT NULL OR NEW.provider_request_id IS NOT NULL OR
         NEW.provider_verify_request_id IS NOT NULL OR NEW.applied_at IS NOT NULL THEN
        RAISE EXCEPTION 'legal hold approval transition violation' USING ERRCODE = '23514';
      END IF;
    ELSIF OLD.operation_state = 'REQUESTED' AND NEW.operation_state = 'EXPIRED' THEN
      IF NEW.revision IS DISTINCT FROM 1 OR OLD.revision IS DISTINCT FROM 0 OR
         NEW.expired_at IS NULL OR NEW.expired_at < OLD.changed_at + interval '24 hours' OR
         NEW.approved_by IS NOT NULL OR NEW.approved_at IS NOT NULL OR
         NEW.canonical_approval IS NOT NULL OR NEW.approval_digest IS NOT NULL OR
         NEW.receipt IS NOT NULL OR NEW.canonical_receipt IS NOT NULL OR
         NEW.receipt_sha256 IS NOT NULL OR NEW.provider_request_id IS NOT NULL OR
         NEW.provider_verify_request_id IS NOT NULL OR NEW.applied_at IS NOT NULL THEN
        RAISE EXCEPTION 'legal hold expiry transition violation' USING ERRCODE = '23514';
      END IF;
    ELSIF OLD.operation_state = 'APPROVED' AND NEW.operation_state = 'APPLYING' THEN
      IF NEW.revision IS DISTINCT FROM 2 OR OLD.revision IS DISTINCT FROM 1 OR
         NEW.application_attempt_id IS NULL OR NEW.application_prior_status IS NULL OR
         NEW.application_observed_request_id IS NULL OR NEW.application_started_at IS NULL OR
         NEW.receipt IS NOT NULL OR NEW.applied_at IS NOT NULL THEN
        RAISE EXCEPTION 'legal hold precondition transition violation' USING ERRCODE = '23514';
      END IF;
    ELSIF OLD.operation_state = 'APPLYING' AND NEW.operation_state = 'APPLIED' THEN
      IF NEW.revision IS DISTINCT FROM 3 OR OLD.revision IS DISTINCT FROM 2 OR
         NEW.approved_by IS DISTINCT FROM OLD.approved_by OR
         NEW.approved_at IS DISTINCT FROM OLD.approved_at OR
         NEW.canonical_approval IS DISTINCT FROM OLD.canonical_approval OR
         NEW.approval_digest IS DISTINCT FROM OLD.approval_digest OR
         NEW.receipt IS NULL OR NEW.canonical_receipt IS NULL OR NEW.receipt_sha256 IS NULL OR
         NEW.provider_request_id IS NULL OR NEW.provider_verify_request_id IS NULL OR
         NEW.applied_at IS NULL THEN
        RAISE EXCEPTION 'legal hold application transition violation' USING ERRCODE = '23514';
      END IF;
    ELSIF OLD.operation_state = 'APPLIED' AND NEW.operation_state = 'APPLIED' THEN
      IF OLD.recovery_published_at IS NOT NULL OR NEW.recovery_published_at IS NULL OR
         NEW.recovery_published_at < OLD.applied_at OR
         (to_jsonb(NEW) - 'recovery_published_at') IS DISTINCT FROM
           (to_jsonb(OLD) - 'recovery_published_at') THEN
        RAISE EXCEPTION 'legal hold recovery publication acknowledgement violation' USING ERRCODE = '23514';
      END IF;
    ELSIF OLD.operation_state IN ('APPROVED', 'APPLYING') AND NEW.operation_state = OLD.operation_state THEN
      IF (to_jsonb(NEW) - ARRAY[
            'reconciliation_attempt_count', 'reconciliation_next_attempt_at',
            'reconciliation_last_error_code', 'reconciliation_last_failed_at'
          ]) IS DISTINCT FROM (to_jsonb(OLD) - ARRAY[
            'reconciliation_attempt_count', 'reconciliation_next_attempt_at',
            'reconciliation_last_error_code', 'reconciliation_last_failed_at'
          ]) OR
         NEW.reconciliation_attempt_count IS DISTINCT FROM OLD.reconciliation_attempt_count + 1 OR
         NEW.reconciliation_next_attempt_at IS NULL OR
         NEW.reconciliation_last_error_code !~ '^[A-Z][A-Z0-9_]{2,63}$' OR
         NEW.reconciliation_last_failed_at IS NULL OR
         NEW.reconciliation_next_attempt_at <= NEW.reconciliation_last_failed_at THEN
        RAISE EXCEPTION 'legal hold reconciliation retry transition violation' USING ERRCODE = '23514';
      END IF;
    ELSE
      RAISE EXCEPTION 'legal hold operation transition violation' USING ERRCODE = '23514';
    END IF;
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
    'evidence_artifacts', 'ingest_receipts', 'retention_holds', 'legal_hold_operations',
    'audit_heads', 'audit_events', 'api_audit_outbox', 'api_audit_outbox_work',
    'export_receipts', 'support_access_grants'
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

CREATE TRIGGER protect_api_audit_outbox
BEFORE UPDATE OR DELETE ON scopeproof.api_audit_outbox
FOR EACH ROW EXECUTE FUNCTION scopeproof.protect_immutable_security_fields();

CREATE TRIGGER append_audit_chain
BEFORE INSERT ON scopeproof.audit_events
FOR EACH ROW EXECUTE FUNCTION scopeproof.advance_audit_head();

DO $$
DECLARE
  table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'jobs', 'upload_intents', 'evidence_artifacts', 'retention_holds',
    'legal_hold_operations', 'support_access_grants'
  ]
  LOOP
    EXECUTE format(
      'CREATE TRIGGER protect_immutable_fields BEFORE UPDATE ON scopeproof.%I FOR EACH ROW EXECUTE FUNCTION scopeproof.protect_immutable_security_fields()',
      table_name
    );
  END LOOP;
END;
$$;

CREATE FUNCTION scopeproof.assert_actor_permission(
  p_actor_user_id scopeproof.resource_identifier,
  p_permission text
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  actor_role text;
BEGIN
  IF p_permission NOT IN ('evidence:collect', 'retention:manage') THEN
    RAISE EXCEPTION 'unsupported database permission' USING ERRCODE = '22023';
  END IF;

  SELECT membership.role
    INTO actor_role
    FROM scopeproof.memberships AS membership
    JOIN scopeproof.principals AS principal
      ON principal.tenant_id = membership.tenant_id
     AND principal.id = membership.principal_id
   WHERE membership.tenant_id = scopeproof.current_tenant_id()
     AND membership.principal_id = p_actor_user_id
     AND membership.status = 'ACTIVE'
     AND principal.status = 'ACTIVE';

  IF actor_role IS NULL OR
     (p_permission = 'evidence:collect' AND actor_role NOT IN ('admin', 'compliance_lead', 'collector')) OR
     (p_permission = 'retention:manage' AND actor_role <> 'admin') THEN
    RAISE EXCEPTION 'active membership does not permit this operation' USING ERRCODE = '42501';
  END IF;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.assert_actor_permission(scopeproof.resource_identifier, text) FROM PUBLIC;

CREATE FUNCTION scopeproof.resolve_active_membership(
  p_identity_subject text
)
RETURNS TABLE (
  tenant_id scopeproof.tenant_identifier,
  identity_subject text,
  membership_id scopeproof.resource_identifier,
  principal_id scopeproof.resource_identifier,
  role text
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();
BEGIN
  IF active_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant context is required' USING ERRCODE = '42501';
  END IF;
  IF p_identity_subject IS NULL OR
     char_length(p_identity_subject) NOT BETWEEN 8 AND 200 OR
     p_identity_subject ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'identity subject is invalid' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT principal.tenant_id, principal.cognito_sub, membership.id,
         principal.id, membership.role
    FROM scopeproof.principals AS principal
    JOIN scopeproof.memberships AS membership
      ON membership.tenant_id = principal.tenant_id
     AND membership.principal_id = principal.id
   WHERE principal.tenant_id = active_tenant
     AND principal.cognito_sub = p_identity_subject
     AND principal.status = 'ACTIVE'
     AND membership.status = 'ACTIVE';
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.resolve_active_membership(text) FROM PUBLIC;

CREATE FUNCTION scopeproof.record_api_audit_event(
  p_actor_user_id scopeproof.resource_identifier,
  p_membership_id scopeproof.resource_identifier,
  p_request_id text,
  p_action text,
  p_resource_type text,
  p_resource_id text,
  p_idempotency_key text,
  p_details jsonb
)
RETURNS TABLE (
  outbox_id scopeproof.resource_identifier,
  was_created boolean,
  committed_event_digest text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();
  actor_role text;
  expected_digest text;
  expected_id scopeproof.resource_identifier;
  existing scopeproof.api_audit_outbox%ROWTYPE;
BEGIN
  IF active_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant context is required' USING ERRCODE = '42501';
  END IF;
  IF num_nonnulls(
       p_actor_user_id, p_membership_id, p_request_id, p_action,
       p_resource_type, p_resource_id, p_idempotency_key, p_details
     ) <> 8 OR
     p_actor_user_id NOT LIKE 'usr\_%' ESCAPE '\' OR
     p_membership_id NOT LIKE 'mem\_%' ESCAPE '\' OR
     p_request_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$' OR
     char_length(p_idempotency_key) NOT BETWEEN 16 AND 200 OR
     p_idempotency_key ~ '[[:cntrl:]]' OR
     jsonb_typeof(p_details) <> 'object' OR
     p_details ?| ARRAY['scopeproofOutboxId', 'scopeproofOutboxDigest', 'scopeproofMembershipId'] OR
     octet_length(p_details::text) > 16384 THEN
    RAISE EXCEPTION 'API audit record is invalid' USING ERRCODE = '22023';
  END IF;

  SELECT membership.role
    INTO actor_role
    FROM scopeproof.memberships AS membership
    JOIN scopeproof.principals AS principal
      ON principal.tenant_id = membership.tenant_id
     AND principal.id = membership.principal_id
   WHERE membership.tenant_id = active_tenant
     AND membership.id = p_membership_id
     AND membership.principal_id = p_actor_user_id
     AND membership.status = 'ACTIVE'
     AND principal.status = 'ACTIVE';

  IF actor_role IS NULL OR
     (p_action = 'evidence.upload_intent_issued' AND actor_role NOT IN ('admin', 'compliance_lead', 'collector')) OR
     (p_action IN ('evidence.search_performed', 'evidence.download_intent_issued') AND
       actor_role NOT IN ('admin', 'compliance_lead', 'reviewer', 'auditor')) OR
     (p_action IN ('evidence.legal_hold_requested', 'evidence.legal_hold_approved') AND actor_role <> 'admin') OR
     p_action NOT IN (
       'evidence.upload_intent_issued',
       'evidence.search_performed',
       'evidence.download_intent_issued',
       'evidence.legal_hold_requested',
       'evidence.legal_hold_approved'
     ) THEN
    RAISE EXCEPTION 'active membership does not permit this audited operation' USING ERRCODE = '42501';
  END IF;

  IF (p_action IN ('evidence.upload_intent_issued', 'evidence.download_intent_issued') AND
       (p_resource_type <> 'evidence' OR p_resource_id !~ '^evd_[a-f0-9]{32}$')) OR
     (p_action = 'evidence.search_performed' AND
       (p_resource_type <> 'evidence_collection' OR p_resource_id IS DISTINCT FROM active_tenant::text)) OR
     (p_action IN ('evidence.legal_hold_requested', 'evidence.legal_hold_approved') AND
       (p_resource_type <> 'legal_hold_operation' OR p_resource_id !~ '^lho_[a-f0-9]{32}$')) THEN
    RAISE EXCEPTION 'API audit resource binding is invalid' USING ERRCODE = '22023';
  END IF;

  expected_digest := encode(sha256(convert_to(
    'scopeproof-api-audit-outbox-v1' || chr(10) ||
    active_tenant::text || chr(10) || p_actor_user_id::text || chr(10) ||
    p_membership_id::text || chr(10) || p_action || chr(10) ||
    p_resource_type || chr(10) || p_resource_id || chr(10) ||
    p_idempotency_key || chr(10) || p_details::text,
    'UTF8'
  )), 'hex');
  expected_id := ('aob_' || substr(expected_digest, 1, 32))::scopeproof.resource_identifier;

  SELECT * INTO existing
    FROM scopeproof.api_audit_outbox
   WHERE tenant_id = active_tenant AND idempotency_key = p_idempotency_key
   FOR UPDATE;
  IF FOUND THEN
    IF existing.id IS DISTINCT FROM expected_id OR
       existing.actor_user_id IS DISTINCT FROM p_actor_user_id OR
       existing.membership_id IS DISTINCT FROM p_membership_id OR
       existing.action IS DISTINCT FROM p_action OR
       existing.resource_type IS DISTINCT FROM p_resource_type OR
       existing.resource_id IS DISTINCT FROM p_resource_id OR
       existing.details IS DISTINCT FROM p_details OR
       existing.event_digest::text IS DISTINCT FROM expected_digest THEN
      RAISE EXCEPTION 'API audit idempotency key conflicts with different facts' USING ERRCODE = '23505';
    END IF;
    INSERT INTO scopeproof.api_audit_outbox_work (tenant_id, outbox_id)
    VALUES (active_tenant, existing.id)
    ON CONFLICT (tenant_id, outbox_id) DO NOTHING;
    RETURN QUERY SELECT existing.id, false, existing.event_digest::text;
    RETURN;
  END IF;

  INSERT INTO scopeproof.api_audit_outbox (
    tenant_id, id, actor_user_id, membership_id, request_id, action,
    resource_type, resource_id, idempotency_key, details, event_digest
  ) VALUES (
    active_tenant, expected_id, p_actor_user_id, p_membership_id, p_request_id, p_action,
    p_resource_type, p_resource_id, p_idempotency_key, p_details, expected_digest
  );
  INSERT INTO scopeproof.api_audit_outbox_work (tenant_id, outbox_id)
  VALUES (active_tenant, expected_id);
  RETURN QUERY SELECT expected_id, true, expected_digest;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.record_api_audit_event(
  scopeproof.resource_identifier, scopeproof.resource_identifier, text, text, text, text, text, jsonb
) FROM PUBLIC;

CREATE FUNCTION scopeproof.claim_next_api_audit_event(
  p_lease_token text,
  p_claimed_at timestamptz,
  p_lease_seconds integer
)
RETURNS TABLE (
  outbox_id scopeproof.resource_identifier,
  event_id scopeproof.resource_identifier,
  occurred_at timestamptz,
  actor_user_id scopeproof.resource_identifier,
  membership_id scopeproof.resource_identifier,
  request_id text,
  action text,
  resource_type text,
  resource_id text,
  outcome text,
  details jsonb,
  event_digest text,
  attempt_count integer,
  lease_expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();
BEGIN
  IF active_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant context is required' USING ERRCODE = '42501';
  END IF;
  IF p_lease_token IS NULL OR
     p_lease_token !~ '^[A-Za-z0-9_-]{16,128}$' OR
     p_claimed_at IS NULL OR
     p_claimed_at < clock_timestamp() - interval '5 minutes' OR
     p_claimed_at > clock_timestamp() + interval '5 minutes' OR
     p_lease_seconds NOT BETWEEN 30 AND 300 THEN
    RAISE EXCEPTION 'API audit outbox lease is invalid' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  WITH candidate AS MATERIALIZED (
    SELECT work.outbox_id
      FROM scopeproof.api_audit_outbox_work AS work
      JOIN scopeproof.api_audit_outbox AS queued
        ON queued.tenant_id = work.tenant_id
       AND queued.id = work.outbox_id
     WHERE work.tenant_id = active_tenant
       AND work.completed_at IS NULL
       AND work.dead_lettered_at IS NULL
       AND work.attempt_count < 8
       AND work.next_attempt_at <= p_claimed_at
       AND (work.lease_token IS NULL OR work.lease_expires_at <= p_claimed_at)
     ORDER BY queued.occurred_at, queued.id
     FOR UPDATE OF work SKIP LOCKED
     LIMIT 1
  ), claimed AS (
    UPDATE scopeproof.api_audit_outbox_work AS work
       SET lease_token = p_lease_token,
           lease_expires_at = p_claimed_at + make_interval(secs => p_lease_seconds)
      FROM candidate
     WHERE work.tenant_id = active_tenant
       AND work.outbox_id = candidate.outbox_id
    RETURNING work.outbox_id, work.attempt_count, work.lease_expires_at
  )
  SELECT queued.id,
         ('evt_' || substr(queued.event_digest::text, 1, 32))::scopeproof.resource_identifier,
         queued.occurred_at, queued.actor_user_id, queued.membership_id,
         queued.request_id, queued.action, queued.resource_type,
         queued.resource_id, queued.outcome, queued.details,
         queued.event_digest::text, claimed.attempt_count, claimed.lease_expires_at
    FROM claimed
    JOIN scopeproof.api_audit_outbox AS queued
      ON queued.tenant_id = active_tenant
     AND queued.id = claimed.outbox_id;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.claim_next_api_audit_event(text, timestamptz, integer) FROM PUBLIC;

CREATE FUNCTION scopeproof.record_api_audit_outbox_failure(
  p_outbox_id scopeproof.resource_identifier,
  p_lease_token text,
  p_error_code text,
  p_failed_at timestamptz
)
RETURNS TABLE (
  failure_state text,
  committed_attempt_count integer,
  committed_next_attempt_at timestamptz,
  committed_dead_lettered_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();
  work scopeproof.api_audit_outbox_work%ROWTYPE;
  next_attempt_count integer;
BEGIN
  IF active_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant context is required' USING ERRCODE = '42501';
  END IF;
  IF p_outbox_id IS NULL OR p_outbox_id NOT LIKE 'aob\_%' ESCAPE '\' OR
     p_lease_token IS NULL OR p_lease_token !~ '^[A-Za-z0-9_-]{16,128}$' OR
     p_error_code IS NULL OR p_error_code !~ '^[A-Z][A-Z0-9_]{2,63}$' OR
     p_failed_at IS NULL OR
     p_failed_at < clock_timestamp() - interval '5 minutes' OR
     p_failed_at > clock_timestamp() + interval '5 minutes' THEN
    RAISE EXCEPTION 'API audit outbox failure record is invalid' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO work
    FROM scopeproof.api_audit_outbox_work
   WHERE tenant_id = active_tenant AND outbox_id = p_outbox_id
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'API audit outbox work was not found' USING ERRCODE = '40001';
  END IF;
  IF work.completed_at IS NOT NULL THEN
    RETURN QUERY SELECT 'already_completed'::text, work.attempt_count,
      work.next_attempt_at, work.dead_lettered_at;
    RETURN;
  END IF;
  IF work.dead_lettered_at IS NOT NULL THEN
    RETURN QUERY SELECT 'already_dead_lettered'::text, work.attempt_count,
      work.next_attempt_at, work.dead_lettered_at;
    RETURN;
  END IF;
  IF work.lease_token IS DISTINCT FROM p_lease_token THEN
    RAISE EXCEPTION 'API audit outbox lease changed' USING ERRCODE = '40001';
  END IF;

  next_attempt_count := work.attempt_count + 1;
  UPDATE scopeproof.api_audit_outbox_work AS pending
     SET attempt_count = next_attempt_count,
         next_attempt_at = p_failed_at + make_interval(secs => least(
           21600,
           (30 * power(2, least(work.attempt_count, 10)))::integer
         )),
         lease_token = NULL,
         lease_expires_at = NULL,
         last_error_code = p_error_code,
         last_failed_at = p_failed_at,
         dead_lettered_at = CASE WHEN next_attempt_count >= 8 THEN p_failed_at ELSE NULL END
   WHERE pending.tenant_id = active_tenant
     AND pending.outbox_id = p_outbox_id
     AND pending.lease_token = p_lease_token;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'API audit outbox failure transition changed' USING ERRCODE = '40001';
  END IF;

  SELECT * INTO STRICT work
    FROM scopeproof.api_audit_outbox_work
   WHERE tenant_id = active_tenant AND outbox_id = p_outbox_id;
  RETURN QUERY SELECT
    CASE WHEN work.dead_lettered_at IS NULL THEN 'retry_scheduled' ELSE 'dead_lettered' END,
    work.attempt_count, work.next_attempt_at, work.dead_lettered_at;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.record_api_audit_outbox_failure(
  scopeproof.resource_identifier, text, text, timestamptz
) FROM PUBLIC;

CREATE FUNCTION scopeproof.read_api_audit_outbox_health(
  p_observed_at timestamptz
)
RETURNS TABLE (
  backlog_count bigint,
  dead_lettered_count bigint,
  oldest_unsigned_age_seconds bigint
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();
BEGIN
  IF active_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant context is required' USING ERRCODE = '42501';
  END IF;
  IF p_observed_at IS NULL OR
     p_observed_at < clock_timestamp() - interval '5 minutes' OR
     p_observed_at > clock_timestamp() + interval '5 minutes' THEN
    RAISE EXCEPTION 'API audit outbox observation time is invalid' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT count(*)::bigint,
         count(*) FILTER (WHERE work.dead_lettered_at IS NOT NULL)::bigint,
         coalesce(max(greatest(0, floor(extract(epoch FROM (p_observed_at - queued.occurred_at)))::bigint)), 0)::bigint
    FROM scopeproof.api_audit_outbox AS queued
    JOIN scopeproof.api_audit_outbox_work AS work
      ON work.tenant_id = queued.tenant_id
     AND work.outbox_id = queued.id
   WHERE queued.tenant_id = active_tenant
     AND work.completed_at IS NULL;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.read_api_audit_outbox_health(timestamptz) FROM PUBLIC;

-- Owner-only recovery after the root cause of a poison row has been corrected.
-- The signer role is intentionally not granted this function.
CREATE FUNCTION scopeproof.requeue_dead_lettered_api_audit_event(
  p_outbox_id scopeproof.resource_identifier,
  p_requeued_at timestamptz
)
RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();
BEGIN
  IF active_tenant IS NULL OR
     p_outbox_id IS NULL OR p_outbox_id NOT LIKE 'aob\_%' ESCAPE '\' OR
     p_requeued_at IS NULL OR
     p_requeued_at < clock_timestamp() - interval '5 minutes' OR
     p_requeued_at > clock_timestamp() + interval '5 minutes' THEN
    RAISE EXCEPTION 'API audit dead-letter requeue is invalid' USING ERRCODE = '22023';
  END IF;
  UPDATE scopeproof.api_audit_outbox_work
     SET attempt_count = 0,
         next_attempt_at = p_requeued_at,
         lease_token = NULL,
         lease_expires_at = NULL,
         last_error_code = NULL,
         last_failed_at = NULL,
         dead_lettered_at = NULL
   WHERE tenant_id = active_tenant
     AND outbox_id = p_outbox_id
     AND completed_at IS NULL
     AND dead_lettered_at IS NOT NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'API audit dead-letter row is not requeueable' USING ERRCODE = '40001';
  END IF;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.requeue_dead_lettered_api_audit_event(
  scopeproof.resource_identifier, timestamptz
) FROM PUBLIC;

CREATE FUNCTION scopeproof.reserve_exact_version_legal_hold(
  p_operation_id scopeproof.resource_identifier,
  p_hold_id scopeproof.resource_identifier,
  p_evidence_id scopeproof.resource_identifier,
  p_control_id text,
  p_evidence_bucket text,
  p_object_key text,
  p_object_version_id text,
  p_desired_status text,
  p_hold_kind text,
  p_reason text,
  p_requested_by scopeproof.resource_identifier,
  p_expected_hold_revision integer,
  p_changed_at timestamptz,
  p_canonical_request text,
  p_request_digest text
)
RETURNS TABLE (
  operation_state text,
  operation_revision integer,
  committed_canonical_approval text,
  committed_approval_digest text,
  committed_canonical_receipt text,
  committed_receipt_sha256 text,
  committed_application_attempt_id text,
  committed_application_prior_status text,
  committed_application_observed_request_id text,
  committed_application_started_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();
  configured_bucket text;
  evidence_row scopeproof.evidence_artifacts%ROWTYPE;
  existing_operation scopeproof.legal_hold_operations%ROWTYPE;
  active_hold scopeproof.retention_holds%ROWTYPE;
  active_hold_count integer;
  expected_request jsonb;
BEGIN
  IF active_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant context is required' USING ERRCODE = '42501';
  END IF;
  IF num_nonnulls(
       p_operation_id, p_hold_id, p_evidence_id, p_control_id,
       p_evidence_bucket, p_object_key, p_object_version_id, p_desired_status,
       p_hold_kind, p_reason, p_requested_by, p_expected_hold_revision,
       p_changed_at, p_canonical_request, p_request_digest
     ) <> 15 OR
     p_operation_id NOT LIKE 'lho\_%' ESCAPE '\' OR
     p_hold_id NOT LIKE 'hld\_%' ESCAPE '\' OR
     p_evidence_id NOT LIKE 'evd\_%' ESCAPE '\' OR
     p_requested_by NOT LIKE 'usr\_%' ESCAPE '\' OR
     p_control_id !~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$' OR
     p_evidence_bucket !~ '^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$' OR
     p_object_key !~ '^tenants/ten_[a-f0-9]{32}/controls/[A-Za-z0-9][A-Za-z0-9._-]{0,63}/evidence/evd_[a-f0-9]{32}\.(png|json|spdx\.json|cdx\.json|txt|csv)$' OR
     p_object_version_id !~ '^[A-Za-z0-9][A-Za-z0-9._:+/=-]{0,511}$' OR
     p_desired_status NOT IN ('ON', 'OFF') OR
     p_hold_kind NOT IN ('LEGAL', 'AUDIT', 'SECURITY_INCIDENT') OR
     char_length(p_reason) NOT BETWEEN 10 AND 2000 OR
     p_expected_hold_revision < 0 OR
     (p_desired_status = 'ON' AND p_expected_hold_revision <> 0) OR
     p_changed_at IS NULL OR
     octet_length(p_canonical_request) NOT BETWEEN 128 AND 16384 OR
     p_request_digest !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'legal hold operation input is invalid' USING ERRCODE = '22023';
  END IF;

  SELECT evidence_bucket
    INTO STRICT configured_bucket
    FROM scopeproof.tenant_identity
   WHERE tenant_id = active_tenant AND singleton;
  IF p_evidence_bucket IS DISTINCT FROM configured_bucket THEN
    RAISE EXCEPTION 'legal hold destination mismatch' USING ERRCODE = '42501';
  END IF;

  SELECT *
    INTO STRICT evidence_row
    FROM scopeproof.evidence_artifacts
   WHERE tenant_id = active_tenant AND id = p_evidence_id
   FOR UPDATE;
  IF evidence_row.control_id IS DISTINCT FROM p_control_id OR
     evidence_row.evidence_bucket IS DISTINCT FROM p_evidence_bucket OR
     evidence_row.object_key IS DISTINCT FROM p_object_key OR
     evidence_row.object_version_id IS DISTINCT FROM p_object_version_id OR
     evidence_row.status NOT IN ('NEEDS_REVIEW', 'APPROVED', 'EXPIRED') OR
     p_object_key NOT LIKE 'tenants/' || active_tenant || '/controls/' || p_control_id || '/evidence/' || p_evidence_id || '.%' THEN
    RAISE EXCEPTION 'exact evidence version was not found' USING ERRCODE = 'P0002';
  END IF;

  expected_request := jsonb_build_object(
    'schemaVersion', 2,
    'operationId', p_operation_id,
    'holdId', p_hold_id,
    'tenantId', active_tenant,
    'controlId', p_control_id,
    'evidenceId', p_evidence_id,
    'bucket', p_evidence_bucket,
    'key', p_object_key,
    'versionId', p_object_version_id,
    'status', p_desired_status,
    'kind', p_hold_kind,
    'reason', p_reason,
    'requestedBy', p_requested_by,
    'expectedHoldRevision', p_expected_hold_revision,
    'changedAt', to_char(p_changed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  );
  IF p_canonical_request::jsonb IS DISTINCT FROM expected_request OR
     encode(sha256(convert_to('scopeproof-legal-hold-request-v2' || E'\n' || p_canonical_request, 'UTF8')), 'hex')
       IS DISTINCT FROM p_request_digest THEN
    RAISE EXCEPTION 'canonical legal hold request mismatch' USING ERRCODE = '22023';
  END IF;

  SELECT *
    INTO existing_operation
    FROM scopeproof.legal_hold_operations
   WHERE tenant_id = active_tenant AND id = p_operation_id
   FOR UPDATE;
  IF FOUND THEN
    IF existing_operation.canonical_request IS DISTINCT FROM p_canonical_request OR
       existing_operation.request_digest IS DISTINCT FROM p_request_digest THEN
      RAISE EXCEPTION 'legal hold request idempotency conflict' USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT existing_operation.operation_state, existing_operation.revision,
      existing_operation.canonical_approval, existing_operation.approval_digest::text,
      existing_operation.canonical_receipt, existing_operation.receipt_sha256::text,
      existing_operation.application_attempt_id::text, existing_operation.application_prior_status,
      existing_operation.application_observed_request_id, existing_operation.application_started_at;
    RETURN;
  END IF;
  IF EXISTS (
    SELECT 1 FROM scopeproof.legal_hold_operations AS operation
     WHERE operation.tenant_id = active_tenant
       AND operation.request_digest = p_request_digest
  ) THEN
    RAISE EXCEPTION 'legal hold request digest collision' USING ERRCODE = '23505';
  END IF;

  -- Client-stable timestamps are part of the signed/idempotent canonical
  -- request. Enforce server-clock proximity only when creating the transition;
  -- an exact replay of a durable row above must remain valid indefinitely.
  IF p_changed_at < clock_timestamp() - interval '5 minutes' OR
     p_changed_at > clock_timestamp() + interval '5 minutes' THEN
    RAISE EXCEPTION 'legal hold request timestamp is outside the allowed clock skew' USING ERRCODE = '22023';
  END IF;

  -- Phase one authenticates only the requester. No approver identity is
  -- accepted by this function, so a requester cannot nominate a second user.
  PERFORM scopeproof.assert_actor_permission(p_requested_by, 'retention:manage');

  -- A REQUESTED row cannot be approved after 24 hours. Expire an abandoned
  -- request for this exact version in the same transaction before reserving a
  -- replacement; never expire APPROVED/APPLIED work or mutate S3/hold state.
  UPDATE scopeproof.legal_hold_operations AS operation
     SET operation_state = 'EXPIRED',
         revision = 1,
         expired_at = clock_timestamp()
   WHERE operation.tenant_id = active_tenant
     AND operation.evidence_bucket = p_evidence_bucket
     AND operation.object_key = p_object_key
     AND operation.object_version_id = p_object_version_id
     AND operation.operation_state = 'REQUESTED'
     AND operation.revision = 0
     AND operation.changed_at + interval '24 hours' <= clock_timestamp();

  IF EXISTS (
    SELECT 1 FROM scopeproof.legal_hold_operations AS operation
     WHERE operation.tenant_id = active_tenant
       AND operation.evidence_bucket = p_evidence_bucket
       AND operation.object_key = p_object_key
       AND operation.object_version_id = p_object_version_id
       AND operation.operation_state IN ('REQUESTED', 'APPROVED', 'APPLYING')
  ) THEN
    RAISE EXCEPTION 'another legal hold request is pending for this exact version' USING ERRCODE = '40001';
  END IF;

  IF p_desired_status = 'ON' THEN
    IF EXISTS (
      SELECT 1 FROM scopeproof.retention_holds
       WHERE tenant_id = active_tenant AND id = p_hold_id
    ) THEN
      RAISE EXCEPTION 'retention hold identifier already exists' USING ERRCODE = '23505';
    END IF;
    IF EXISTS (
      SELECT 1 FROM scopeproof.retention_holds
       WHERE tenant_id = active_tenant
         AND evidence_id = p_evidence_id
         AND evidence_bucket = p_evidence_bucket
         AND object_key = p_object_key
         AND object_version_id = p_object_version_id
         AND released_at IS NULL
    ) THEN
      RAISE EXCEPTION 'an active retention hold already protects this exact version' USING ERRCODE = '23514';
    END IF;
  ELSE
    SELECT count(*)
      INTO active_hold_count
      FROM (
        SELECT id
          FROM scopeproof.retention_holds
         WHERE tenant_id = active_tenant
           AND evidence_id = p_evidence_id
           AND evidence_bucket = p_evidence_bucket
           AND object_key = p_object_key
           AND object_version_id = p_object_version_id
           AND released_at IS NULL
         FOR UPDATE
      ) AS locked_active_holds;
    IF active_hold_count <> 1 THEN
      RAISE EXCEPTION 'S3 legal hold may be disabled only for the last active exact-version hold' USING ERRCODE = '23514';
    END IF;
    SELECT *
      INTO STRICT active_hold
      FROM scopeproof.retention_holds
     WHERE tenant_id = active_tenant
       AND id = p_hold_id
       AND evidence_id = p_evidence_id
       AND evidence_bucket = p_evidence_bucket
       AND object_key = p_object_key
       AND object_version_id = p_object_version_id
       AND released_at IS NULL
     FOR UPDATE;
    IF active_hold.revision IS DISTINCT FROM p_expected_hold_revision OR
       active_hold.kind IS DISTINCT FROM p_hold_kind THEN
      RAISE EXCEPTION 'retention hold revision changed' USING ERRCODE = '40001';
    END IF;
  END IF;

  INSERT INTO scopeproof.legal_hold_operations (
    tenant_id, id, hold_id, evidence_id, control_id, evidence_bucket, object_key,
    object_version_id, desired_status, hold_kind, reason, requested_by,
    expected_hold_revision, operation_state, revision, changed_at,
    canonical_request, request_digest
  ) VALUES (
    active_tenant, p_operation_id, p_hold_id, p_evidence_id, p_control_id,
    p_evidence_bucket, p_object_key, p_object_version_id, p_desired_status,
    p_hold_kind, p_reason, p_requested_by, p_expected_hold_revision,
    'REQUESTED', 0, p_changed_at, p_canonical_request, p_request_digest
  );

  RETURN QUERY SELECT 'REQUESTED'::text, 0, NULL::text, NULL::text, NULL::text, NULL::text,
    NULL::text, NULL::text, NULL::text, NULL::timestamptz;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.reserve_exact_version_legal_hold(
  scopeproof.resource_identifier, scopeproof.resource_identifier,
  scopeproof.resource_identifier, text, text, text, text, text, text, text,
  scopeproof.resource_identifier, integer, timestamptz, text, text
) FROM PUBLIC;

CREATE FUNCTION scopeproof.approve_exact_version_legal_hold(
  p_operation_id scopeproof.resource_identifier,
  p_request_digest text,
  p_approved_by scopeproof.resource_identifier,
  p_approved_at timestamptz,
  p_canonical_approval text,
  p_approval_digest text
)
RETURNS TABLE (
  operation_state text,
  operation_revision integer,
  committed_canonical_approval text,
  committed_approval_digest text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();
  requested_operation scopeproof.legal_hold_operations%ROWTYPE;
  expected_approval jsonb;
BEGIN
  IF active_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant context is required' USING ERRCODE = '42501';
  END IF;
  IF num_nonnulls(
       p_operation_id, p_request_digest, p_approved_by, p_approved_at,
       p_canonical_approval, p_approval_digest
     ) <> 6 OR
     p_operation_id NOT LIKE 'lho\_%' ESCAPE '\' OR
     p_request_digest !~ '^[0-9a-f]{64}$' OR
     p_approved_by NOT LIKE 'usr\_%' ESCAPE '\' OR
     octet_length(p_canonical_approval) NOT BETWEEN 128 AND 16384 OR
     p_approval_digest !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'legal hold approval input is invalid' USING ERRCODE = '22023';
  END IF;

  SELECT *
    INTO STRICT requested_operation
    FROM scopeproof.legal_hold_operations
   WHERE tenant_id = active_tenant AND id = p_operation_id
   FOR UPDATE;
  IF requested_operation.request_digest IS DISTINCT FROM p_request_digest THEN
    RAISE EXCEPTION 'legal hold request digest conflict' USING ERRCODE = '23505';
  END IF;
  IF p_approved_by = requested_operation.requested_by THEN
    RAISE EXCEPTION 'requester cannot approve the same legal hold request' USING ERRCODE = '42501';
  END IF;
  IF p_approved_at < requested_operation.changed_at OR
     p_approved_at > requested_operation.changed_at + interval '24 hours' THEN
    RAISE EXCEPTION 'legal hold approval is outside the allowed request window' USING ERRCODE = '22023';
  END IF;

  expected_approval := jsonb_build_object(
    'schemaVersion', 1,
    'tenantId', active_tenant,
    'operationId', p_operation_id,
    'requestDigest', p_request_digest,
    'approvedBy', p_approved_by,
    'approvedAt', to_char(p_approved_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  );
  IF p_canonical_approval::jsonb IS DISTINCT FROM expected_approval OR
     encode(sha256(convert_to('scopeproof-legal-hold-approval-v1' || E'\n' || p_canonical_approval, 'UTF8')), 'hex')
       IS DISTINCT FROM p_approval_digest THEN
    RAISE EXCEPTION 'canonical legal hold approval mismatch' USING ERRCODE = '22023';
  END IF;

  IF requested_operation.operation_state IN ('APPROVED', 'APPLYING', 'APPLIED') THEN
    IF requested_operation.canonical_approval IS DISTINCT FROM p_canonical_approval OR
       requested_operation.approval_digest IS DISTINCT FROM p_approval_digest OR
       requested_operation.approved_by IS DISTINCT FROM p_approved_by OR
       requested_operation.approved_at IS DISTINCT FROM p_approved_at THEN
      RAISE EXCEPTION 'legal hold approval idempotency conflict' USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT requested_operation.operation_state, requested_operation.revision,
      requested_operation.canonical_approval, requested_operation.approval_digest::text;
    RETURN;
  END IF;
  IF requested_operation.operation_state <> 'REQUESTED' OR requested_operation.revision <> 0 THEN
    RAISE EXCEPTION 'legal hold request cannot be approved from its current state' USING ERRCODE = '40001';
  END IF;

  -- As with requests, apply clock-skew validation only to a new transition.
  -- The exact committed approval replay above remains a durable idempotency
  -- result even after the five-minute admission window has elapsed.
  IF p_approved_at < clock_timestamp() - interval '5 minutes' OR
     p_approved_at > clock_timestamp() + interval '5 minutes' THEN
    RAISE EXCEPTION 'legal hold approval timestamp is outside the allowed clock skew' USING ERRCODE = '22023';
  END IF;

  -- Phase two authenticates the independently supplied approver at approval
  -- time. Requester authorization was captured by the immutable request row.
  PERFORM scopeproof.assert_actor_permission(p_approved_by, 'retention:manage');

  UPDATE scopeproof.legal_hold_operations
     SET approved_by = p_approved_by,
         approved_at = p_approved_at,
         canonical_approval = p_canonical_approval,
         approval_digest = p_approval_digest,
         operation_state = 'APPROVED',
         revision = 1
   WHERE tenant_id = active_tenant
     AND id = p_operation_id
     AND operation_state = 'REQUESTED'
     AND revision = 0;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'legal hold request could not be atomically approved' USING ERRCODE = '40001';
  END IF;

  RETURN QUERY SELECT 'APPROVED'::text, 1, p_canonical_approval, p_approval_digest;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.approve_exact_version_legal_hold(
  scopeproof.resource_identifier, text, scopeproof.resource_identifier,
  timestamptz, text, text
) FROM PUBLIC;

-- Public legal-hold API wrappers. The workflow transition and its audit outbox
-- row are one PostgreSQL transaction: an audit failure rolls back the state
-- change, so a privileged request can never succeed without a durable record.
CREATE FUNCTION scopeproof.reserve_exact_version_legal_hold_with_audit(
  p_operation_id scopeproof.resource_identifier,
  p_hold_id scopeproof.resource_identifier,
  p_evidence_id scopeproof.resource_identifier,
  p_control_id text,
  p_evidence_bucket text,
  p_object_key text,
  p_object_version_id text,
  p_desired_status text,
  p_hold_kind text,
  p_reason text,
  p_requested_by scopeproof.resource_identifier,
  p_expected_hold_revision integer,
  p_changed_at timestamptz,
  p_canonical_request text,
  p_request_digest text,
  p_membership_id scopeproof.resource_identifier,
  p_request_id text
)
RETURNS TABLE (
  operation_state text,
  operation_revision integer,
  committed_canonical_approval text,
  committed_approval_digest text,
  committed_canonical_receipt text,
  committed_receipt_sha256 text,
  committed_application_attempt_id text,
  committed_application_prior_status text,
  committed_application_observed_request_id text,
  committed_application_started_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  reserved record;
BEGIN
  SELECT *
    INTO STRICT reserved
    FROM scopeproof.reserve_exact_version_legal_hold(
      p_operation_id, p_hold_id, p_evidence_id, p_control_id,
      p_evidence_bucket, p_object_key, p_object_version_id, p_desired_status,
      p_hold_kind, p_reason, p_requested_by, p_expected_hold_revision,
      p_changed_at, p_canonical_request, p_request_digest
    );

  PERFORM scopeproof.record_api_audit_event(
    p_requested_by,
    p_membership_id,
    p_request_id,
    'evidence.legal_hold_requested',
    'legal_hold_operation',
    p_operation_id::text,
    'legal-hold-request:' || p_operation_id::text,
    jsonb_build_object(
      'evidenceId', p_evidence_id,
      'holdId', p_hold_id,
      'requestDigest', p_request_digest,
      'desiredStatus', p_desired_status,
      'operationRevision', reserved.operation_revision
    )
  );

  RETURN QUERY SELECT
    reserved.operation_state::text,
    reserved.operation_revision::integer,
    reserved.committed_canonical_approval::text,
    reserved.committed_approval_digest::text,
    reserved.committed_canonical_receipt::text,
    reserved.committed_receipt_sha256::text,
    reserved.committed_application_attempt_id::text,
    reserved.committed_application_prior_status::text,
    reserved.committed_application_observed_request_id::text,
    reserved.committed_application_started_at::timestamptz;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.reserve_exact_version_legal_hold_with_audit(
  scopeproof.resource_identifier, scopeproof.resource_identifier,
  scopeproof.resource_identifier, text, text, text, text, text, text, text,
  scopeproof.resource_identifier, integer, timestamptz, text, text,
  scopeproof.resource_identifier, text
) FROM PUBLIC;

CREATE FUNCTION scopeproof.approve_exact_version_legal_hold_with_audit(
  p_operation_id scopeproof.resource_identifier,
  p_request_digest text,
  p_approved_by scopeproof.resource_identifier,
  p_approved_at timestamptz,
  p_canonical_approval text,
  p_approval_digest text,
  p_membership_id scopeproof.resource_identifier,
  p_request_id text
)
RETURNS TABLE (
  operation_state text,
  operation_revision integer,
  committed_canonical_approval text,
  committed_approval_digest text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  approved record;
BEGIN
  SELECT *
    INTO STRICT approved
    FROM scopeproof.approve_exact_version_legal_hold(
      p_operation_id, p_request_digest, p_approved_by, p_approved_at,
      p_canonical_approval, p_approval_digest
    );

  PERFORM scopeproof.record_api_audit_event(
    p_approved_by,
    p_membership_id,
    p_request_id,
    'evidence.legal_hold_approved',
    'legal_hold_operation',
    p_operation_id::text,
    'legal-hold-approval:' || p_operation_id::text || ':' || p_approved_by::text,
    jsonb_build_object(
      'requestDigest', p_request_digest,
      'approvalDigest', p_approval_digest,
      'operationRevision', approved.operation_revision
    )
  );

  RETURN QUERY SELECT
    approved.operation_state::text,
    approved.operation_revision::integer,
    approved.committed_canonical_approval::text,
    approved.committed_approval_digest::text;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.approve_exact_version_legal_hold_with_audit(
  scopeproof.resource_identifier, text, scopeproof.resource_identifier,
  timestamptz, text, text, scopeproof.resource_identifier, text
) FROM PUBLIC;

CREATE FUNCTION scopeproof.read_exact_version_legal_hold_operation(
  p_operation_id scopeproof.resource_identifier,
  p_request_digest text
)
RETURNS TABLE (
  operation_state text,
  operation_revision integer,
  committed_canonical_approval text,
  committed_approval_digest text,
  committed_canonical_receipt text,
  committed_receipt_sha256 text,
  committed_application_attempt_id text,
  committed_application_prior_status text,
  committed_application_observed_request_id text,
  committed_application_started_at timestamptz
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();
BEGIN
  IF active_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant context is required' USING ERRCODE = '42501';
  END IF;
  IF p_operation_id IS NULL OR p_operation_id NOT LIKE 'lho\_%' ESCAPE '\' OR
     p_request_digest IS NULL OR p_request_digest !~ '^[0-9a-f]{64}$' THEN
    RAISE EXCEPTION 'legal hold read input is invalid' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT operation.operation_state, operation.revision,
    operation.canonical_approval, operation.approval_digest::text,
    operation.canonical_receipt, operation.receipt_sha256::text,
    operation.application_attempt_id::text, operation.application_prior_status,
    operation.application_observed_request_id, operation.application_started_at
    FROM scopeproof.legal_hold_operations AS operation
   WHERE operation.tenant_id = active_tenant
     AND operation.id = p_operation_id
     AND operation.request_digest = p_request_digest;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'exact legal hold request was not found' USING ERRCODE = 'P0002';
  END IF;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.read_exact_version_legal_hold_operation(
  scopeproof.resource_identifier, text
) FROM PUBLIC;

CREATE FUNCTION scopeproof.begin_exact_version_legal_hold_application(
  p_operation_id scopeproof.resource_identifier,
  p_expected_operation_revision integer,
  p_request_digest text,
  p_approval_digest text,
  p_attempt_id text,
  p_prior_status text,
  p_observed_request_id text,
  p_started_at timestamptz
)
RETURNS TABLE (
  operation_state text,
  operation_revision integer,
  application_attempt_id text,
  application_prior_status text,
  application_observed_request_id text,
  application_started_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();
  pending scopeproof.legal_hold_operations%ROWTYPE;
  expected_attempt text;
BEGIN
  SELECT * INTO STRICT pending FROM scopeproof.legal_hold_operations
   WHERE tenant_id = active_tenant AND id = p_operation_id FOR UPDATE;
  IF pending.request_digest IS DISTINCT FROM p_request_digest OR pending.approval_digest IS DISTINCT FROM p_approval_digest THEN
    RAISE EXCEPTION 'legal hold application digest conflict' USING ERRCODE = '23505';
  END IF;
  expected_attempt := encode(sha256(convert_to(
    'scopeproof-legal-hold-apply-attempt-v1' || chr(31) || pending.id || chr(31) || pending.request_digest || chr(31) ||
    pending.approval_digest || chr(31) || p_prior_status || chr(31) || pending.desired_status, 'UTF8')), 'hex');
  IF p_attempt_id IS DISTINCT FROM expected_attempt OR p_prior_status NOT IN ('ON', 'OFF') OR
     p_prior_status = pending.desired_status OR p_observed_request_id !~ '^[A-Za-z0-9][A-Za-z0-9_-]{2,199}$' THEN
    RAISE EXCEPTION 'legal hold application precondition is invalid' USING ERRCODE = '23514';
  END IF;
  IF pending.operation_state IN ('APPLYING', 'APPLIED') THEN
    IF pending.application_attempt_id IS DISTINCT FROM p_attempt_id OR pending.application_prior_status IS DISTINCT FROM p_prior_status OR
       pending.application_observed_request_id IS DISTINCT FROM p_observed_request_id OR pending.application_started_at IS DISTINCT FROM p_started_at THEN
      RAISE EXCEPTION 'legal hold application idempotency conflict' USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT pending.operation_state, pending.revision, pending.application_attempt_id::text,
      pending.application_prior_status, pending.application_observed_request_id, pending.application_started_at;
    RETURN;
  END IF;
  IF pending.operation_state <> 'APPROVED' OR pending.revision <> p_expected_operation_revision OR p_expected_operation_revision <> 1 OR
     p_started_at < clock_timestamp() - interval '5 minutes' OR p_started_at > clock_timestamp() + interval '5 minutes' THEN
    RAISE EXCEPTION 'legal hold application cannot begin from current state' USING ERRCODE = '40001';
  END IF;
  UPDATE scopeproof.legal_hold_operations SET operation_state = 'APPLYING', revision = 2,
    application_attempt_id = p_attempt_id, application_prior_status = p_prior_status,
    application_observed_request_id = p_observed_request_id, application_started_at = p_started_at
   WHERE tenant_id = active_tenant AND id = p_operation_id AND operation_state = 'APPROVED' AND revision = 1;
  RETURN QUERY SELECT 'APPLYING'::text, 2, p_attempt_id, p_prior_status, p_observed_request_id, p_started_at;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.begin_exact_version_legal_hold_application(
  scopeproof.resource_identifier, integer, text, text, text, text, text, timestamptz
) FROM PUBLIC;

CREATE FUNCTION scopeproof.confirm_exact_version_legal_hold(
  p_operation_id scopeproof.resource_identifier,
  p_expected_operation_revision integer,
  p_request_digest text,
  p_approval_digest text,
  p_receipt jsonb,
  p_canonical_receipt text,
  p_receipt_sha256 text,
  p_put_request_id text,
  p_verify_request_id text
)
RETURNS TABLE (
  was_created boolean,
  operation_revision integer,
  hold_revision integer,
  committed_canonical_receipt text,
  committed_receipt_sha256 text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();
  pending_operation scopeproof.legal_hold_operations%ROWTYPE;
  active_hold scopeproof.retention_holds%ROWTYPE;
  active_hold_count integer;
  committed_hold_revision integer;
  expected_receipt jsonb;
BEGIN
  IF active_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant context is required' USING ERRCODE = '42501';
  END IF;
  IF num_nonnulls(
       p_operation_id, p_expected_operation_revision, p_request_digest, p_approval_digest,
       p_receipt, p_canonical_receipt, p_receipt_sha256,
       p_put_request_id, p_verify_request_id
     ) <> 9 OR
     p_expected_operation_revision <> 2 OR
     p_request_digest !~ '^[0-9a-f]{64}$' OR
     p_approval_digest !~ '^[0-9a-f]{64}$' OR
     jsonb_typeof(p_receipt) <> 'object' OR
     octet_length(p_canonical_receipt) NOT BETWEEN 128 AND 16384 OR
     p_receipt_sha256 !~ '^[0-9a-f]{64}$' OR
     p_put_request_id !~ '^[A-Za-z0-9][A-Za-z0-9_-]{2,199}$' OR
     p_verify_request_id !~ '^[A-Za-z0-9][A-Za-z0-9_-]{2,199}$' THEN
    RAISE EXCEPTION 'legal hold confirmation input is invalid' USING ERRCODE = '22023';
  END IF;

  SELECT *
    INTO STRICT pending_operation
    FROM scopeproof.legal_hold_operations
   WHERE tenant_id = active_tenant AND id = p_operation_id
   FOR UPDATE;
  IF pending_operation.request_digest IS DISTINCT FROM p_request_digest OR
     pending_operation.approval_digest IS DISTINCT FROM p_approval_digest THEN
    RAISE EXCEPTION 'legal hold request or approval digest conflict' USING ERRCODE = '23505';
  END IF;

  IF pending_operation.operation_state = 'APPLIED' THEN
    SELECT revision
      INTO STRICT committed_hold_revision
      FROM scopeproof.retention_holds
     WHERE tenant_id = active_tenant AND id = pending_operation.hold_id;
    RETURN QUERY SELECT false, pending_operation.revision, committed_hold_revision,
      pending_operation.canonical_receipt, pending_operation.receipt_sha256::text;
    RETURN;
  END IF;
  IF pending_operation.operation_state <> 'APPLYING' OR
     pending_operation.revision IS DISTINCT FROM p_expected_operation_revision THEN
    RAISE EXCEPTION 'legal hold operation revision changed' USING ERRCODE = '40001';
  END IF;

  expected_receipt := jsonb_build_object(
    'schemaVersion', 1,
    'operationId', pending_operation.id,
    'holdId', pending_operation.hold_id,
    'tenantId', active_tenant,
    'controlId', pending_operation.control_id,
    'evidenceId', pending_operation.evidence_id,
    'bucket', pending_operation.evidence_bucket,
    'key', pending_operation.object_key,
    'versionId', pending_operation.object_version_id,
    'status', pending_operation.desired_status,
    'changedAt', to_char(pending_operation.changed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'applicationAttemptId', pending_operation.application_attempt_id,
    'priorStatus', pending_operation.application_prior_status,
    'putRequestId', p_put_request_id,
    'verifyRequestId', p_verify_request_id
  );
  IF p_receipt IS DISTINCT FROM expected_receipt OR
     p_canonical_receipt::jsonb IS DISTINCT FROM expected_receipt OR
     p_receipt ->> 'applicationAttemptId' IS DISTINCT FROM pending_operation.application_attempt_id OR
     p_receipt ->> 'priorStatus' IS DISTINCT FROM pending_operation.application_prior_status OR
     p_receipt ->> 'putRequestId' IS DISTINCT FROM p_put_request_id OR
     p_receipt ->> 'verifyRequestId' IS DISTINCT FROM p_verify_request_id OR
     encode(sha256(convert_to('scopeproof-legal-hold-receipt-v1' || E'\n' || p_canonical_receipt, 'UTF8')), 'hex')
       IS DISTINCT FROM p_receipt_sha256 THEN
    RAISE EXCEPTION 'canonical legal hold receipt mismatch' USING ERRCODE = '22023';
  END IF;

  -- Both independent authorizations were committed before S3 was called.
  -- Re-checking mutable membership here could strand a verified S3 result, so
  -- confirmation trusts only the immutable request and approval records.
  IF pending_operation.approved_by IS NULL OR
     pending_operation.requested_by = pending_operation.approved_by OR
     pending_operation.canonical_approval IS NULL OR
     pending_operation.approval_digest IS NULL THEN
    RAISE EXCEPTION 'two distinct administrators are required' USING ERRCODE = '42501';
  END IF;

  IF pending_operation.desired_status = 'ON' THEN
    INSERT INTO scopeproof.retention_holds (
      tenant_id, id, evidence_id, control_id, kind, reason, created_by,
      approved_by, evidence_bucket, object_key, object_version_id,
      provider_request_id, provider_verify_request_id, s3_legal_hold_status,
      revision
    ) VALUES (
      active_tenant, pending_operation.hold_id, pending_operation.evidence_id,
      pending_operation.control_id, pending_operation.hold_kind,
      pending_operation.reason, pending_operation.requested_by,
      pending_operation.approved_by, pending_operation.evidence_bucket,
      pending_operation.object_key, pending_operation.object_version_id,
      p_put_request_id, p_verify_request_id, 'ON', 0
    );
    committed_hold_revision := 0;
  ELSE
    SELECT count(*)
      INTO active_hold_count
      FROM (
        SELECT id
          FROM scopeproof.retention_holds
         WHERE tenant_id = active_tenant
           AND evidence_id = pending_operation.evidence_id
           AND evidence_bucket = pending_operation.evidence_bucket
           AND object_key = pending_operation.object_key
           AND object_version_id = pending_operation.object_version_id
           AND released_at IS NULL
         FOR UPDATE
      ) AS locked_active_holds;
    IF active_hold_count <> 1 THEN
      RAISE EXCEPTION 'S3 legal hold may be disabled only for the last active exact-version hold' USING ERRCODE = '23514';
    END IF;
    SELECT *
      INTO STRICT active_hold
      FROM scopeproof.retention_holds
     WHERE tenant_id = active_tenant
       AND id = pending_operation.hold_id
       AND evidence_id = pending_operation.evidence_id
       AND evidence_bucket = pending_operation.evidence_bucket
       AND object_key = pending_operation.object_key
       AND object_version_id = pending_operation.object_version_id
       AND released_at IS NULL
     FOR UPDATE;
    IF active_hold.revision IS DISTINCT FROM pending_operation.expected_hold_revision OR
       active_hold.kind IS DISTINCT FROM pending_operation.hold_kind THEN
      RAISE EXCEPTION 'retention hold revision changed' USING ERRCODE = '40001';
    END IF;
    UPDATE scopeproof.retention_holds
       SET released_at = clock_timestamp(),
           release_reason = pending_operation.reason,
           release_requested_by = pending_operation.requested_by,
           release_approved_by = pending_operation.approved_by,
           release_provider_request_id = p_put_request_id,
           release_verify_request_id = p_verify_request_id,
           s3_legal_hold_status = 'OFF',
           revision = revision + 1
     WHERE tenant_id = active_tenant
       AND id = pending_operation.hold_id
       AND revision = pending_operation.expected_hold_revision
       AND released_at IS NULL;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'retention hold could not be atomically released' USING ERRCODE = '40001';
    END IF;
    committed_hold_revision := pending_operation.expected_hold_revision + 1;
  END IF;

  UPDATE scopeproof.legal_hold_operations
     SET operation_state = 'APPLIED',
         revision = revision + 1,
         receipt = p_receipt,
         canonical_receipt = p_canonical_receipt,
         receipt_sha256 = p_receipt_sha256,
         provider_request_id = p_put_request_id,
         provider_verify_request_id = p_verify_request_id,
         applied_at = clock_timestamp()
   WHERE tenant_id = active_tenant
     AND id = p_operation_id
     AND operation_state = 'APPLYING'
     AND revision = p_expected_operation_revision;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'legal hold operation could not be atomically confirmed' USING ERRCODE = '40001';
  END IF;

  RETURN QUERY SELECT true, p_expected_operation_revision + 1,
    committed_hold_revision, p_canonical_receipt, p_receipt_sha256;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.confirm_exact_version_legal_hold(
  scopeproof.resource_identifier, integer, text, text, jsonb, text, text, text, text
) FROM PUBLIC;

CREATE FUNCTION scopeproof.create_upload_intent(
  p_id scopeproof.resource_identifier,
  p_nonce_digest text,
  p_requested_by scopeproof.resource_identifier,
  p_device_id scopeproof.resource_identifier,
  p_assessment_id scopeproof.resource_identifier,
  p_evidence_id scopeproof.resource_identifier,
  p_object_key text,
  p_final_object_key text,
  p_content_type text,
  p_content_length bigint,
  p_checksum_sha256 text,
  p_expires_at timestamptz,
  p_required_retention_until timestamptz,
  p_control_id text,
  p_title text,
  p_description text,
  p_evidence_type text,
  p_source text,
  p_system_name text,
  p_captured_at timestamptz,
  p_artifact_expires_at timestamptz,
  p_metadata jsonb
)
RETURNS TABLE (
  upload_intent_id scopeproof.resource_identifier,
  evidence_id scopeproof.resource_identifier,
  was_created boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier;
  configured_quarantine_bucket text;
  configured_retention_days integer;
  assessment_controls jsonb;
  assessment_status text;
  existing_intent scopeproof.upload_intents%ROWTYPE;
  existing_evidence scopeproof.evidence_artifacts%ROWTYPE;
  device_public_key_sha256 text;
  device_last_upload_sequence bigint;
  device_proof jsonb;
  signed_manifest jsonb;
  expected_manifest jsonb;
  device_sequence bigint;
  intent_exists boolean := false;
BEGIN
  active_tenant := scopeproof.current_tenant_id();
  IF active_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant transaction context is required' USING ERRCODE = '42501';
  END IF;
  PERFORM scopeproof.assert_actor_permission(p_requested_by, 'evidence:collect');

  IF p_device_id IS NULL THEN
    RAISE EXCEPTION 'active actor-bound device enrollment is required' USING ERRCODE = '42501';
  END IF;
  SELECT device.device_public_key_sha256::text, device.last_upload_sequence
    INTO device_public_key_sha256, device_last_upload_sequence
    FROM scopeproof.device_enrollments AS device
   WHERE device.tenant_id = active_tenant
     AND device.id = p_device_id
     AND device.principal_id = p_requested_by
     AND device.status = 'ACTIVE'
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'active actor-bound device enrollment is required' USING ERRCODE = '42501';
  END IF;
  IF p_captured_at > clock_timestamp() + interval '5 minutes' OR
     p_captured_at < clock_timestamp() - interval '30 days' THEN
    RAISE EXCEPTION 'evidence capture time is outside the collection window' USING ERRCODE = '22023';
  END IF;

  device_proof := p_metadata -> 'scopeproofDeviceProof';
  IF jsonb_typeof(device_proof) <> 'object' OR
     (SELECT count(*) FROM jsonb_object_keys(device_proof)) <> 10 OR
     device_proof ->> 'schemaVersion' <> '1' OR
     device_proof ->> 'algorithm' <> 'ECDSA_P256_SHA256' OR
     device_proof ->> 'publicKeySha256' IS DISTINCT FROM device_public_key_sha256 OR
     device_proof ->> 'publicKeySha256' !~ '^[0-9a-f]{64}$' OR
     device_proof ->> 'manifestDigest' !~ '^[0-9a-f]{64}$' OR
     device_proof ->> 'challengeDigest' !~ '^[0-9a-f]{64}$' OR
     device_proof ->> 'nonceDigest' !~ '^[0-9a-f]{64}$' OR
     device_proof ->> 'signature' !~ '^[A-Za-z0-9_-]{86}$' OR
     device_proof ->> 'sequence' !~ '^[1-9][0-9]{0,15}$' OR
     device_proof ->> 'signedAt' !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{3}Z$' OR
     octet_length(device_proof ->> 'canonicalManifest') NOT BETWEEN 128 AND 8192 THEN
    RAISE EXCEPTION 'device upload proof is invalid' USING ERRCODE = '22023';
  END IF;
  BEGIN
    signed_manifest := (device_proof ->> 'canonicalManifest')::jsonb;
    device_sequence := (device_proof ->> 'sequence')::bigint;
  EXCEPTION WHEN OTHERS THEN
    RAISE EXCEPTION 'device upload proof is invalid' USING ERRCODE = '22023';
  END;
  expected_manifest := jsonb_build_object(
    'schemaVersion', 1,
    'tenantId', active_tenant,
    'userId', p_requested_by,
    'deviceId', p_device_id,
    'assessmentId', p_assessment_id,
    'controlId', p_control_id,
    'evidenceId', p_evidence_id,
    'expectedSha256', p_checksum_sha256,
    'expectedSize', p_content_length,
    'contentType', p_content_type,
    'capturedAt', to_char(p_captured_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'challenge', signed_manifest ->> 'challenge',
    'nonce', signed_manifest ->> 'nonce',
    'sequence', device_sequence,
    'signedAt', signed_manifest ->> 'signedAt'
  );
  IF signed_manifest IS DISTINCT FROM expected_manifest OR
     char_length(signed_manifest ->> 'challenge') NOT BETWEEN 8 AND 200 OR
     char_length(signed_manifest ->> 'nonce') NOT BETWEEN 16 AND 200 OR
     device_proof ->> 'signedAt' IS DISTINCT FROM signed_manifest ->> 'signedAt' OR
     (device_proof ->> 'signedAt')::timestamptz < clock_timestamp() - interval '5 minutes' OR
     (device_proof ->> 'signedAt')::timestamptz > clock_timestamp() + interval '5 minutes' OR
     encode(sha256(convert_to(
       'scopeproof-device-upload-manifest-v1' || chr(10) || (device_proof ->> 'canonicalManifest'), 'UTF8'
     )), 'hex') IS DISTINCT FROM device_proof ->> 'manifestDigest' OR
     encode(sha256(convert_to(
       'scopeproof-device-token-challenge-v1' || chr(10) || (signed_manifest ->> 'challenge'), 'UTF8'
     )), 'hex') IS DISTINCT FROM device_proof ->> 'challengeDigest' OR
     encode(sha256(convert_to(
       'scopeproof-device-upload-nonce-v1' || chr(10) || (signed_manifest ->> 'nonce'), 'UTF8'
     )), 'hex') IS DISTINCT FROM device_proof ->> 'nonceDigest' THEN
    RAISE EXCEPTION 'device upload manifest binding is invalid' USING ERRCODE = '22023';
  END IF;

  SELECT quarantine_bucket, retention_days
    INTO STRICT configured_quarantine_bucket, configured_retention_days
    FROM scopeproof.tenant_identity
   WHERE tenant_id = active_tenant AND singleton;

  IF p_required_retention_until IS DISTINCT FROM
       p_captured_at + make_interval(days => configured_retention_days) OR
     p_artifact_expires_at IS DISTINCT FROM p_required_retention_until THEN
    RAISE EXCEPTION 'evidence retention must match the tenant policy' USING ERRCODE = '22023';
  END IF;

  SELECT status, controls
    INTO STRICT assessment_status, assessment_controls
    FROM scopeproof.assessments
   WHERE tenant_id = active_tenant AND id = p_assessment_id
   FOR SHARE;
  IF assessment_status NOT IN ('DRAFT', 'ACTIVE') THEN
    RAISE EXCEPTION 'closed assessments cannot accept evidence' USING ERRCODE = '42501';
  END IF;
  IF jsonb_array_length(assessment_controls) = 0 OR
     NOT (assessment_controls ? p_control_id) THEN
    RAISE EXCEPTION 'control is outside the assessment scope' USING ERRCODE = '42501';
  END IF;

  SELECT *
    INTO existing_intent
    FROM scopeproof.upload_intents
   WHERE tenant_id = active_tenant AND id = p_id
   FOR UPDATE;
  intent_exists := FOUND;

  IF intent_exists THEN
    SELECT *
      INTO STRICT existing_evidence
      FROM scopeproof.evidence_artifacts
     WHERE tenant_id = active_tenant AND id = p_evidence_id;
    IF existing_intent.status <> 'issued' OR existing_intent.revision <> 0 OR
       existing_intent.nonce_digest IS DISTINCT FROM p_nonce_digest OR
       existing_intent.requested_by IS DISTINCT FROM p_requested_by OR
       existing_intent.device_id IS DISTINCT FROM p_device_id OR
       existing_intent.assessment_id IS DISTINCT FROM p_assessment_id OR
       existing_intent.evidence_id IS DISTINCT FROM p_evidence_id OR
       existing_intent.control_id IS DISTINCT FROM p_control_id OR
       existing_intent.object_key IS DISTINCT FROM p_object_key OR
       existing_intent.final_object_key IS DISTINCT FROM p_final_object_key OR
       existing_intent.content_type IS DISTINCT FROM p_content_type OR
       existing_intent.content_length IS DISTINCT FROM p_content_length OR
       existing_intent.checksum_sha256 IS DISTINCT FROM p_checksum_sha256 OR
       existing_intent.expires_at IS DISTINCT FROM p_expires_at OR
       existing_intent.required_retention_until IS DISTINCT FROM p_required_retention_until OR
       existing_evidence.control_id IS DISTINCT FROM p_control_id OR
       existing_evidence.title IS DISTINCT FROM p_title OR
       existing_evidence.description IS DISTINCT FROM p_description OR
       existing_evidence.evidence_type IS DISTINCT FROM p_evidence_type OR
       existing_evidence.source IS DISTINCT FROM p_source OR
       existing_evidence.system_name IS DISTINCT FROM p_system_name OR
       existing_evidence.content_type IS DISTINCT FROM p_content_type OR
       existing_evidence.byte_size IS DISTINCT FROM p_content_length OR
       existing_evidence.checksum_sha256 IS DISTINCT FROM p_checksum_sha256 OR
       existing_evidence.captured_at IS DISTINCT FROM p_captured_at OR
       existing_evidence.expires_at IS DISTINCT FROM p_artifact_expires_at OR
       existing_evidence.metadata IS DISTINCT FROM p_metadata THEN
      RAISE EXCEPTION 'upload intent idempotency conflict' USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT p_id, p_evidence_id, false;
    RETURN;
  END IF;

  IF device_sequence <= device_last_upload_sequence THEN
    RAISE EXCEPTION 'device upload sequence has already been consumed' USING ERRCODE = '23505';
  END IF;
  UPDATE scopeproof.device_enrollments
     SET last_upload_sequence = device_sequence,
         last_seen_at = clock_timestamp()
   WHERE tenant_id = active_tenant
     AND id = p_device_id
     AND last_upload_sequence = device_last_upload_sequence;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'device upload sequence changed concurrently' USING ERRCODE = '40001';
  END IF;

  INSERT INTO scopeproof.evidence_artifacts (
    tenant_id, id, assessment_id, control_id, title, description, evidence_type,
    source, system_name, status, content_type, byte_size, checksum_sha256,
    captured_at, expires_at, created_by, metadata
  ) VALUES (
    active_tenant, p_evidence_id, p_assessment_id, p_control_id, p_title,
    p_description, p_evidence_type, p_source, p_system_name, 'QUARANTINED',
    p_content_type, p_content_length, p_checksum_sha256, p_captured_at,
    p_artifact_expires_at, p_requested_by, p_metadata
  );

  INSERT INTO scopeproof.upload_intents (
    tenant_id, id, nonce_digest, requested_by, device_id, assessment_id,
    evidence_id, control_id, quarantine_bucket, object_key, final_object_key, content_type,
    content_length, checksum_sha256, expires_at, required_retention_until
  ) VALUES (
    active_tenant, p_id, p_nonce_digest, p_requested_by, p_device_id,
    p_assessment_id, p_evidence_id, p_control_id, configured_quarantine_bucket, p_object_key,
    p_final_object_key, p_content_type, p_content_length, p_checksum_sha256,
    p_expires_at, p_required_retention_until
  );

  RETURN QUERY SELECT p_id, p_evidence_id, true;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.create_upload_intent(
  scopeproof.resource_identifier, text, scopeproof.resource_identifier,
  scopeproof.resource_identifier, scopeproof.resource_identifier,
  scopeproof.resource_identifier, text, text, text, bigint, text, timestamptz,
  timestamptz, text, text, text, text, text, text, timestamptz, timestamptz, jsonb
) FROM PUBLIC;

-- Mirrors the authoritative DynamoDB lease fence at the independent database
-- boundary. A later worker can only advance this value; an older worker can
-- never reclaim or reconcile after its lease has expired.
CREATE FUNCTION scopeproof.claim_promotion_fence(
  p_upload_intent_id scopeproof.resource_identifier,
  p_promotion_fence bigint,
  p_promotion_attempt_id text,
  p_lease_expires_at timestamptz
)
RETURNS TABLE (
  committed_fence bigint,
  committed_attempt_id text,
  committed_lease_expires_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();
  intent scopeproof.upload_intents%ROWTYPE;
BEGIN
  IF active_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant transaction context is required' USING ERRCODE = '42501';
  END IF;
  IF p_promotion_fence IS NULL OR p_promotion_fence < 1 OR
     p_promotion_attempt_id IS NULL OR
     p_promotion_attempt_id !~ '^pat_[0-9a-f]{32}$' OR
     p_lease_expires_at IS NULL THEN
    RAISE EXCEPTION 'promotion fence input is invalid' USING ERRCODE = '22023';
  END IF;

  SELECT *
    INTO STRICT intent
    FROM scopeproof.upload_intents
   WHERE tenant_id = active_tenant AND id = p_upload_intent_id
   FOR UPDATE;
  IF intent.status = 'promoted' THEN
    IF intent.promotion_fence IS DISTINCT FROM p_promotion_fence OR
       intent.promotion_attempt_id IS DISTINCT FROM p_promotion_attempt_id THEN
      RAISE EXCEPTION 'promotion fence was superseded' USING ERRCODE = '40001';
    END IF;
    RETURN QUERY SELECT intent.promotion_fence, intent.promotion_attempt_id,
                        intent.promotion_lease_expires_at;
    RETURN;
  END IF;
  IF intent.status NOT IN ('issued', 'quarantined', 'validated') THEN
    RAISE EXCEPTION 'promotion fence cannot be claimed from the current state' USING ERRCODE = '40001';
  END IF;
  IF p_lease_expires_at <= clock_timestamp() OR
     p_lease_expires_at > clock_timestamp() + interval '15 minutes' THEN
    RAISE EXCEPTION 'promotion fence input is invalid' USING ERRCODE = '22023';
  END IF;
  IF intent.promotion_fence > p_promotion_fence OR
     (intent.promotion_fence = p_promotion_fence AND
      intent.promotion_attempt_id IS DISTINCT FROM p_promotion_attempt_id) THEN
    RAISE EXCEPTION 'promotion fence was superseded' USING ERRCODE = '40001';
  END IF;
  IF intent.promotion_fence < p_promotion_fence THEN
    IF intent.promotion_fence > 0 AND
       intent.promotion_lease_expires_at > clock_timestamp() THEN
      RAISE EXCEPTION 'active promotion fence cannot be superseded' USING ERRCODE = '40001';
    END IF;
    UPDATE scopeproof.upload_intents
       SET promotion_fence = p_promotion_fence,
           promotion_attempt_id = p_promotion_attempt_id,
           promotion_lease_expires_at = p_lease_expires_at
     WHERE tenant_id = active_tenant AND id = p_upload_intent_id;
  ELSIF intent.promotion_lease_expires_at < p_lease_expires_at THEN
    -- Extending one exact current attempt is safe and does not change its
    -- fencing identity. The immutable-field trigger permits only advances.
    UPDATE scopeproof.upload_intents
       SET promotion_lease_expires_at = p_lease_expires_at
     WHERE tenant_id = active_tenant AND id = p_upload_intent_id;
  END IF;

  RETURN QUERY
  SELECT current_intent.promotion_fence, current_intent.promotion_attempt_id,
         current_intent.promotion_lease_expires_at
    FROM scopeproof.upload_intents AS current_intent
   WHERE current_intent.tenant_id = active_tenant
     AND current_intent.id = p_upload_intent_id;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.claim_promotion_fence(
  scopeproof.resource_identifier, bigint, text, timestamptz
) FROM PUBLIC;

CREATE FUNCTION scopeproof.reconcile_promoted_evidence(
  p_receipt_id scopeproof.resource_identifier,
  p_upload_intent_id scopeproof.resource_identifier,
  p_evidence_id scopeproof.resource_identifier,
  p_quarantine_version_id text,
  p_evidence_version_id text,
  p_checksum_sha256 text,
  p_kms_key_arn text,
  p_object_lock_mode text,
  p_retain_until timestamptz,
  p_required_retention_until timestamptz,
  p_expected_upload_revision integer,
  p_expected_evidence_revision integer,
  p_promotion_fence bigint,
  p_promotion_attempt_id text,
  p_idempotency_digest text,
  p_promotion_facts jsonb,
  p_canonical_receipt text,
  p_receipt_sha256 text,
  p_signing_key_arn text,
  p_signing_algorithm text,
  p_signature text,
  p_signed_at timestamptz,
  p_reconciled_at timestamptz
)
RETURNS TABLE (
  receipt_id scopeproof.resource_identifier,
  was_created boolean,
  committed_upload_revision integer,
  committed_evidence_revision integer,
  committed_idempotency_digest text,
  committed_promotion_facts jsonb,
  committed_canonical_receipt text,
  committed_receipt_sha256 text,
  committed_signing_key_arn text,
  committed_signing_algorithm text,
  committed_signature text,
  committed_signed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier;
  configured_quarantine_bucket text;
  configured_evidence_bucket text;
  configured_evidence_key_arn text;
  configured_signing_key_arn text;
  configured_retention_mode text;
  configured_retention_days integer;
  intent scopeproof.upload_intents%ROWTYPE;
  artifact scopeproof.evidence_artifacts%ROWTYPE;
  existing_receipt scopeproof.ingest_receipts%ROWTYPE;
BEGIN
  active_tenant := scopeproof.current_tenant_id();
  IF active_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant transaction context is required' USING ERRCODE = '42501';
  END IF;
  IF p_expected_upload_revision < 0 OR p_expected_evidence_revision < 0 THEN
    RAISE EXCEPTION 'promotion revisions must be nonnegative' USING ERRCODE = '22023';
  END IF;
  IF p_promotion_fence IS NULL OR p_promotion_fence < 1 OR
     p_promotion_attempt_id IS NULL OR
     p_promotion_attempt_id !~ '^pat_[0-9a-f]{32}$' THEN
    RAISE EXCEPTION 'promotion fencing identity is invalid' USING ERRCODE = '22023';
  END IF;
  IF jsonb_typeof(p_promotion_facts) IS DISTINCT FROM 'object' OR
     p_canonical_receipt::jsonb IS DISTINCT FROM p_promotion_facts THEN
    RAISE EXCEPTION 'canonical promotion facts mismatch' USING ERRCODE = '22023';
  END IF;
  IF encode(sha256(convert_to('scopeproof-promotion-reconciliation-v1' || chr(10) || p_canonical_receipt, 'UTF8')), 'hex')
     IS DISTINCT FROM p_idempotency_digest THEN
    RAISE EXCEPTION 'promotion idempotency digest mismatch' USING ERRCODE = '22023';
  END IF;
  IF encode(sha256(convert_to('scopeproof-promotion-receipt-v1' || chr(10) || p_canonical_receipt, 'UTF8')), 'hex')
     IS DISTINCT FROM p_receipt_sha256 THEN
    RAISE EXCEPTION 'canonical receipt digest mismatch' USING ERRCODE = '22023';
  END IF;
  IF p_signed_at > clock_timestamp() + interval '5 minutes' OR p_signed_at < p_reconciled_at THEN
    RAISE EXCEPTION 'receipt signing timestamp is invalid' USING ERRCODE = '22023';
  END IF;

  SELECT quarantine_bucket, evidence_bucket, evidence_kms_key_arn,
         audit_signing_key_arn, retention_mode, retention_days
    INTO STRICT configured_quarantine_bucket, configured_evidence_bucket,
         configured_evidence_key_arn, configured_signing_key_arn,
         configured_retention_mode, configured_retention_days
    FROM scopeproof.tenant_identity
   WHERE tenant_id = active_tenant AND singleton;

  IF p_kms_key_arn IS DISTINCT FROM configured_evidence_key_arn OR
     p_signing_key_arn IS DISTINCT FROM configured_signing_key_arn OR
     p_object_lock_mode IS DISTINCT FROM configured_retention_mode OR
     p_required_retention_until > p_retain_until THEN
    RAISE EXCEPTION 'promotion policy does not match tenant identity' USING ERRCODE = '42501';
  END IF;

  SELECT *
    INTO existing_receipt
    FROM scopeproof.ingest_receipts
   WHERE tenant_id = active_tenant AND upload_intent_id = p_upload_intent_id;
  IF FOUND THEN
    IF existing_receipt.id IS DISTINCT FROM p_receipt_id OR
       existing_receipt.evidence_id IS DISTINCT FROM p_evidence_id OR
       existing_receipt.quarantine_version_id IS DISTINCT FROM p_quarantine_version_id OR
       existing_receipt.evidence_version_id IS DISTINCT FROM p_evidence_version_id OR
       existing_receipt.checksum_sha256 IS DISTINCT FROM p_checksum_sha256 OR
       existing_receipt.kms_key_arn IS DISTINCT FROM p_kms_key_arn OR
       existing_receipt.object_lock_mode IS DISTINCT FROM p_object_lock_mode OR
       existing_receipt.retain_until IS DISTINCT FROM p_retain_until OR
       existing_receipt.upload_revision IS DISTINCT FROM p_expected_upload_revision + 1 OR
       existing_receipt.evidence_revision IS DISTINCT FROM p_expected_evidence_revision + 1 OR
       existing_receipt.promotion_fence IS DISTINCT FROM p_promotion_fence OR
       existing_receipt.promotion_attempt_id IS DISTINCT FROM p_promotion_attempt_id OR
       existing_receipt.idempotency_digest IS DISTINCT FROM p_idempotency_digest OR
       existing_receipt.promotion_facts IS DISTINCT FROM p_promotion_facts OR
       existing_receipt.receipt_sha256 IS DISTINCT FROM p_receipt_sha256 OR
       existing_receipt.canonical_receipt IS DISTINCT FROM p_canonical_receipt OR
       existing_receipt.signing_key_arn IS DISTINCT FROM p_signing_key_arn OR
       existing_receipt.signing_algorithm IS DISTINCT FROM p_signing_algorithm THEN
      RAISE EXCEPTION 'promotion reconciliation idempotency conflict' USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT existing_receipt.id, false,
      existing_receipt.upload_revision, existing_receipt.evidence_revision,
      existing_receipt.idempotency_digest::text, existing_receipt.promotion_facts,
      existing_receipt.canonical_receipt, existing_receipt.receipt_sha256::text,
      existing_receipt.signing_key_arn, existing_receipt.signing_algorithm,
      existing_receipt.signature, existing_receipt.signed_at;
    RETURN;
  END IF;

  SELECT *
    INTO STRICT intent
    FROM scopeproof.upload_intents
   WHERE tenant_id = active_tenant AND id = p_upload_intent_id
   FOR UPDATE;
  SELECT *
    INTO STRICT artifact
    FROM scopeproof.evidence_artifacts
   WHERE tenant_id = active_tenant AND id = p_evidence_id
   FOR UPDATE;

  IF intent.evidence_id IS DISTINCT FROM p_evidence_id OR
     intent.revision IS DISTINCT FROM p_expected_upload_revision OR
     artifact.revision IS DISTINCT FROM p_expected_evidence_revision OR
     intent.promotion_fence IS DISTINCT FROM p_promotion_fence OR
     intent.promotion_attempt_id IS DISTINCT FROM p_promotion_attempt_id OR
     intent.promotion_lease_expires_at <= clock_timestamp() OR
     intent.final_object_key NOT LIKE 'tenants/' || active_tenant || '/controls/' || intent.control_id || '/evidence/' || p_evidence_id || '.%' OR
     artifact.control_id IS DISTINCT FROM intent.control_id OR
     intent.checksum_sha256 IS DISTINCT FROM p_checksum_sha256 OR
     artifact.checksum_sha256 IS DISTINCT FROM p_checksum_sha256 OR
     artifact.content_type IS DISTINCT FROM intent.content_type OR
     artifact.byte_size IS DISTINCT FROM intent.content_length OR
     intent.required_retention_until IS DISTINCT FROM p_required_retention_until OR
     (p_promotion_facts ->> 'uploadedAt') IS NULL OR
     (p_promotion_facts ->> 'uploadedAt') IS DISTINCT FROM to_char(
       (p_promotion_facts ->> 'uploadedAt')::timestamptz AT TIME ZONE 'UTC',
       'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
     ) OR
     (p_promotion_facts ->> 'uploadedAt')::timestamptz < intent.created_at - interval '60 seconds' OR
     (p_promotion_facts ->> 'uploadedAt')::timestamptz > intent.expires_at + interval '1 second' OR
     (p_promotion_facts ->> 'uploadedAt')::timestamptz > p_reconciled_at OR
     p_retain_until IS DISTINCT FROM greatest(
       intent.required_retention_until,
       (p_promotion_facts ->> 'uploadedAt')::timestamptz +
         make_interval(days => configured_retention_days)
     ) OR
     intent.status NOT IN ('issued', 'quarantined', 'validated') OR
     artifact.status NOT IN ('QUARANTINED', 'VALIDATING') OR
     (p_promotion_facts ->> 'schemaVersion') IS DISTINCT FROM '1' OR
     (p_promotion_facts ->> 'tenantId') IS DISTINCT FROM active_tenant OR
     (p_promotion_facts ->> 'uploadIntentId') IS DISTINCT FROM p_upload_intent_id OR
     (p_promotion_facts ->> 'evidenceId') IS DISTINCT FROM p_evidence_id OR
     (p_promotion_facts ->> 'controlId') IS DISTINCT FROM intent.control_id OR
     (p_promotion_facts ->> 'quarantineBucket') IS DISTINCT FROM configured_quarantine_bucket OR
     (p_promotion_facts ->> 'quarantineKey') IS DISTINCT FROM intent.object_key OR
     (p_promotion_facts ->> 'quarantineVersionId') IS DISTINCT FROM p_quarantine_version_id OR
     (p_promotion_facts ->> 'evidenceBucket') IS DISTINCT FROM configured_evidence_bucket OR
     (p_promotion_facts ->> 'evidenceKey') IS DISTINCT FROM intent.final_object_key OR
     (p_promotion_facts ->> 'evidenceVersionId') IS DISTINCT FROM p_evidence_version_id OR
     (p_promotion_facts ->> 'sha256') IS DISTINCT FROM p_checksum_sha256 OR
     (p_promotion_facts ->> 'byteSize')::bigint IS DISTINCT FROM intent.content_length OR
     (p_promotion_facts ->> 'contentType') IS DISTINCT FROM intent.content_type OR
     (p_promotion_facts ->> 'copyAttemptId') IS NULL OR
     (p_promotion_facts ->> 'copyAttemptId') !~ '^pat_[0-9a-f]{32}$' OR
     (p_promotion_facts ->> 'copyFence') IS NULL OR
     (p_promotion_facts ->> 'copyFence')::bigint < 1 OR
     (p_promotion_facts ->> 'copyFence')::bigint > p_promotion_fence OR
     (p_promotion_facts ->> 'promotionAttemptId') IS NULL OR
     (p_promotion_facts ->> 'promotionAttemptId') IS DISTINCT FROM p_promotion_attempt_id OR
     (p_promotion_facts ->> 'promotionFence') IS NULL OR
     (p_promotion_facts ->> 'promotionFence')::bigint IS DISTINCT FROM p_promotion_fence OR
     (p_promotion_facts ->> 'kmsKeyArn') IS DISTINCT FROM p_kms_key_arn OR
     (p_promotion_facts ->> 'objectLockMode') IS DISTINCT FROM p_object_lock_mode OR
     (p_promotion_facts ->> 'retainUntil')::timestamptz IS DISTINCT FROM p_retain_until OR
     (p_promotion_facts ->> 'promotedAt')::timestamptz IS DISTINCT FROM p_reconciled_at OR
     (p_promotion_facts ->> 'providerRequestId') IS NULL THEN
    RAISE EXCEPTION 'promotion facts do not match the authoritative upload intent' USING ERRCODE = '23514';
  END IF;

  UPDATE scopeproof.upload_intents
     SET status = 'promoted', revision = revision + 1,
         consumed_at = COALESCE(consumed_at, p_reconciled_at)
   WHERE tenant_id = active_tenant
     AND id = p_upload_intent_id
     AND revision = p_expected_upload_revision
     AND status IN ('issued', 'quarantined', 'validated');
  IF NOT FOUND THEN
    RAISE EXCEPTION 'upload intent could not be atomically promoted' USING ERRCODE = '40001';
  END IF;

  UPDATE scopeproof.evidence_artifacts
     SET status = 'NEEDS_REVIEW',
         revision = revision + 1,
         evidence_bucket = configured_evidence_bucket,
         object_key = intent.final_object_key,
         object_version_id = p_evidence_version_id,
         kms_key_arn = p_kms_key_arn,
         object_lock_mode = p_object_lock_mode,
         retain_until = p_retain_until
   WHERE tenant_id = active_tenant
     AND id = p_evidence_id
     AND revision = p_expected_evidence_revision
     AND status IN ('QUARANTINED', 'VALIDATING');
  IF NOT FOUND THEN
    RAISE EXCEPTION 'evidence artifact could not be atomically reconciled' USING ERRCODE = '40001';
  END IF;

  INSERT INTO scopeproof.ingest_receipts (
    tenant_id, id, upload_intent_id, evidence_id, quarantine_version_id,
    evidence_version_id, checksum_sha256, kms_key_arn, object_lock_mode,
    retain_until, malware_status, upload_revision, evidence_revision,
    promotion_fence, promotion_attempt_id,
    idempotency_digest, promotion_facts, receipt_sha256, canonical_receipt,
    signing_key_arn, signing_algorithm, signature, signed_at
  ) VALUES (
    active_tenant, p_receipt_id, p_upload_intent_id, p_evidence_id,
    p_quarantine_version_id, p_evidence_version_id, p_checksum_sha256,
    p_kms_key_arn, p_object_lock_mode, p_retain_until, 'CLEAN',
    p_expected_upload_revision + 1, p_expected_evidence_revision + 1,
    p_promotion_fence, p_promotion_attempt_id,
    p_idempotency_digest, p_promotion_facts, p_receipt_sha256,
    p_canonical_receipt, p_signing_key_arn,
    p_signing_algorithm, p_signature, p_signed_at
  );

  RETURN QUERY SELECT p_receipt_id, true,
    p_expected_upload_revision + 1, p_expected_evidence_revision + 1,
    p_idempotency_digest, p_promotion_facts, p_canonical_receipt,
    p_receipt_sha256, p_signing_key_arn, p_signing_algorithm,
    p_signature, p_signed_at;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.reconcile_promoted_evidence(
  scopeproof.resource_identifier, scopeproof.resource_identifier,
  scopeproof.resource_identifier, text, text, text, text, text, timestamptz,
  timestamptz, integer, integer, bigint, text, text, jsonb, text, text, text, text, text,
  timestamptz, timestamptz
) FROM PUBLIC;

-- Returns the one authoritative, immutable promotion receipt for retry
-- recovery. The ingest role receives EXECUTE on this tenant-scoped function,
-- never SELECT on the underlying receipt table.
CREATE FUNCTION scopeproof.read_promoted_evidence_receipt(
  p_upload_intent_id scopeproof.resource_identifier
)
RETURNS TABLE (
  receipt_id scopeproof.resource_identifier,
  committed_upload_revision integer,
  committed_evidence_revision integer,
  committed_idempotency_digest text,
  committed_promotion_facts jsonb,
  committed_canonical_receipt text,
  committed_receipt_sha256 text,
  committed_signing_key_arn text,
  committed_signing_algorithm text,
  committed_signature text,
  committed_signed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier;
BEGIN
  active_tenant := scopeproof.current_tenant_id();
  IF active_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant transaction context is required' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  SELECT receipt.id, receipt.upload_revision, receipt.evidence_revision,
         receipt.idempotency_digest::text, receipt.promotion_facts,
         receipt.canonical_receipt, receipt.receipt_sha256::text,
         receipt.signing_key_arn, receipt.signing_algorithm,
         receipt.signature, receipt.signed_at
    FROM scopeproof.ingest_receipts AS receipt
   WHERE receipt.tenant_id = active_tenant
     AND receipt.upload_intent_id = p_upload_intent_id;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.read_promoted_evidence_receipt(
  scopeproof.resource_identifier
) FROM PUBLIC;

CREATE FUNCTION scopeproof.append_signed_audit_event(
  p_sequence bigint,
  p_event_id scopeproof.resource_identifier,
  p_occurred_at timestamptz,
  p_actor jsonb,
  p_action text,
  p_resource_type text,
  p_resource_id scopeproof.resource_identifier,
  p_request_id text,
  p_outcome text,
  p_details jsonb,
  p_previous_hash text,
  p_event_hash text,
  p_canonical_event text,
  p_receipt_payload jsonb,
  p_canonical_receipt text,
  p_receipt_payload_sha256 text,
  p_signing_key_arn text,
  p_signing_algorithm text,
  p_signature text,
  p_signed_at timestamptz
)
RETURNS TABLE (
  committed_sequence bigint,
  committed_event_hash text,
  was_created boolean,
  committed_canonical_receipt text,
  committed_receipt_payload_sha256 text,
  committed_signature text,
  committed_signed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier;
  configured_signing_key_arn text;
  event_document jsonb;
  receipt_document jsonb;
  v_actor_type text;
  v_actor_id text;
  existing_event scopeproof.audit_events%ROWTYPE;
BEGIN
  active_tenant := scopeproof.current_tenant_id();
  IF active_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant transaction context is required' USING ERRCODE = '42501';
  END IF;
  SELECT audit_signing_key_arn
    INTO STRICT configured_signing_key_arn
    FROM scopeproof.tenant_identity
   WHERE tenant_id = active_tenant AND singleton;
  IF p_signing_key_arn IS DISTINCT FROM configured_signing_key_arn OR
     p_signing_algorithm IS DISTINCT FROM 'RSASSA_PSS_SHA_256' OR
     char_length(p_signature) IS DISTINCT FROM 512 OR
     p_signature !~ '^[A-Za-z0-9+/]+={0,2}$' THEN
    RAISE EXCEPTION 'audit signing policy violation' USING ERRCODE = '42501';
  END IF;
  IF jsonb_typeof(p_actor) IS DISTINCT FROM 'object' OR
     jsonb_typeof(p_details) IS DISTINCT FROM 'object' OR
     jsonb_typeof(p_receipt_payload) IS DISTINCT FROM 'object' THEN
    RAISE EXCEPTION 'audit JSON document is invalid' USING ERRCODE = '22023';
  END IF;
  v_actor_type := p_actor ->> 'type';
  IF v_actor_type = 'user' AND
     p_actor = jsonb_build_object(
       'type', 'user',
       'userId', p_actor ->> 'userId',
       'membershipId', p_actor ->> 'membershipId'
     ) AND
     (p_actor ->> 'userId') ~ '^usr_[a-f0-9]{32}$' AND
     (p_actor ->> 'membershipId') ~ '^mem_[a-f0-9]{32}$' THEN
    v_actor_id := p_actor ->> 'userId';
  ELSIF v_actor_type = 'device' AND
     p_actor = jsonb_build_object(
       'type', 'device',
       'deviceId', p_actor ->> 'deviceId',
       'userId', p_actor ->> 'userId'
     ) AND
     (p_actor ->> 'deviceId') ~ '^dev_[a-f0-9]{32}$' AND
     (p_actor ->> 'userId') ~ '^usr_[a-f0-9]{32}$' THEN
    v_actor_id := p_actor ->> 'deviceId';
  ELSIF v_actor_type = 'system' AND
     p_actor = jsonb_build_object('type', 'system', 'service', p_actor ->> 'service') AND
     char_length(p_actor ->> 'service') BETWEEN 2 AND 100 THEN
    v_actor_id := p_actor ->> 'service';
  ELSE
    RAISE EXCEPTION 'audit actor is invalid' USING ERRCODE = '22023';
  END IF;

  event_document := p_canonical_event::jsonb;
  receipt_document := p_canonical_receipt::jsonb;
  IF event_document IS DISTINCT FROM jsonb_build_object(
       'schemaVersion', 1,
       'tenantId', active_tenant,
       'sequence', p_sequence,
       'id', p_event_id,
       'occurredAt', to_char(p_occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
       'actor', p_actor,
       'action', p_action,
       'resourceType', p_resource_type,
       'resourceId', p_resource_id,
       'requestId', p_request_id,
       'outcome', p_outcome,
       'details', p_details,
       'previousHash', p_previous_hash
     ) OR
     encode(sha256(convert_to(p_canonical_event, 'UTF8')), 'hex') IS DISTINCT FROM p_event_hash THEN
    RAISE EXCEPTION 'canonical audit event mismatch' USING ERRCODE = '22023';
  END IF;
  IF receipt_document IS DISTINCT FROM p_receipt_payload OR
     receipt_document IS DISTINCT FROM jsonb_build_object(
       'schemaVersion', 1,
       'domain', 'scopeproof-audit-receipt-v1',
       'tenantId', active_tenant,
       'sequence', p_sequence,
       'eventId', p_event_id,
       'eventHash', p_event_hash,
       'previousHash', p_previous_hash,
       'occurredAt', to_char(p_occurred_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
       'signedAt', to_char(p_signed_at AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
       'action', p_action,
       'resourceType', p_resource_type,
       'resourceId', p_resource_id,
       'requestId', p_request_id,
       'outcome', p_outcome
     ) OR
     encode(sha256(
       convert_to('scopeproof-audit-receipt-v1', 'UTF8') ||
       decode('00', 'hex') ||
       convert_to(p_canonical_receipt, 'UTF8')
     ), 'hex') IS DISTINCT FROM p_receipt_payload_sha256 OR
     p_signed_at < p_occurred_at OR
     p_signed_at > clock_timestamp() + interval '5 minutes' THEN
    RAISE EXCEPTION 'canonical audit receipt mismatch' USING ERRCODE = '22023';
  END IF;

  SELECT *
    INTO existing_event
    FROM scopeproof.audit_events
   WHERE tenant_id = active_tenant AND id = p_event_id;
  IF FOUND THEN
    IF existing_event.sequence IS DISTINCT FROM p_sequence OR
       existing_event.event_hash IS DISTINCT FROM p_event_hash OR
       existing_event.canonical_event IS DISTINCT FROM p_canonical_event OR
       existing_event.signing_key_arn IS DISTINCT FROM p_signing_key_arn OR
       existing_event.signing_algorithm IS DISTINCT FROM p_signing_algorithm THEN
      RAISE EXCEPTION 'audit event idempotency conflict' USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT existing_event.sequence, existing_event.event_hash::text,
      false, existing_event.canonical_receipt,
      existing_event.receipt_payload_sha256::text, existing_event.kms_signature,
      existing_event.signed_at;
    RETURN;
  END IF;

  INSERT INTO scopeproof.audit_events (
    tenant_id, sequence, id, occurred_at, actor_type, actor_id, action,
    resource_type, resource_id, request_id, outcome, details, previous_hash,
    event_hash, canonical_event, receipt_payload, canonical_receipt,
    receipt_payload_sha256, signing_key_arn, signing_algorithm, kms_signature,
    signed_at
  ) VALUES (
    active_tenant, p_sequence, p_event_id, p_occurred_at, v_actor_type,
    v_actor_id, p_action, p_resource_type, p_resource_id, p_request_id,
    p_outcome, p_details, p_previous_hash, p_event_hash, p_canonical_event,
    p_receipt_payload, p_canonical_receipt, p_receipt_payload_sha256,
    p_signing_key_arn, p_signing_algorithm, p_signature, p_signed_at
  );

  RETURN QUERY SELECT p_sequence, p_event_hash, true, p_canonical_receipt,
    p_receipt_payload_sha256, p_signature, p_signed_at;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.append_signed_audit_event(
  bigint, scopeproof.resource_identifier, timestamptz, jsonb, text, text,
  scopeproof.resource_identifier, text, text, jsonb, text, text, text, jsonb,
  text, text, text, text, text, timestamptz
) FROM PUBLIC;

-- The public-API signer can append only the exact immutable row it leased. It
-- is never granted the generic append function, so a compromised worker cannot
-- invent an actor, action, resource, request, or event payload.
CREATE FUNCTION scopeproof.append_signed_api_audit_event(
  p_outbox_id scopeproof.resource_identifier,
  p_lease_token text,
  p_sequence bigint,
  p_event_id scopeproof.resource_identifier,
  p_occurred_at timestamptz,
  p_actor jsonb,
  p_action text,
  p_resource_type text,
  p_resource_id scopeproof.resource_identifier,
  p_request_id text,
  p_outcome text,
  p_details jsonb,
  p_previous_hash text,
  p_event_hash text,
  p_canonical_event text,
  p_receipt_payload jsonb,
  p_canonical_receipt text,
  p_receipt_payload_sha256 text,
  p_signing_key_arn text,
  p_signing_algorithm text,
  p_signature text,
  p_signed_at timestamptz
)
RETURNS TABLE (
  committed_sequence bigint,
  committed_event_hash text,
  was_created boolean,
  committed_canonical_receipt text,
  committed_receipt_payload_sha256 text,
  committed_signature text,
  committed_signed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();
  queued scopeproof.api_audit_outbox%ROWTYPE;
  work scopeproof.api_audit_outbox_work%ROWTYPE;
  expected_actor jsonb;
  expected_details jsonb;
  expected_event_id scopeproof.resource_identifier;
  expected_outbox_id scopeproof.resource_identifier;
  expected_outbox_digest text;
  appended_sequence bigint;
  appended_event_hash text;
  appended_was_created boolean;
  appended_canonical_receipt text;
  appended_receipt_payload_sha256 text;
  appended_signature text;
  appended_signed_at timestamptz;
BEGIN
  IF active_tenant IS NULL OR
     p_outbox_id IS NULL OR p_outbox_id NOT LIKE 'aob\_%' ESCAPE '\' OR
     p_lease_token IS NULL OR p_lease_token !~ '^[A-Za-z0-9_-]{16,128}$' THEN
    RAISE EXCEPTION 'API audit append lease is invalid' USING ERRCODE = '22023';
  END IF;

  SELECT queued_row, work_row
    INTO STRICT queued, work
    FROM scopeproof.api_audit_outbox AS queued_row
    JOIN scopeproof.api_audit_outbox_work AS work_row
      ON work_row.tenant_id = queued_row.tenant_id
     AND work_row.outbox_id = queued_row.id
   WHERE queued_row.tenant_id = active_tenant
     AND queued_row.id = p_outbox_id
   FOR UPDATE OF work_row;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'API audit outbox work was not found' USING ERRCODE = '40001';
  END IF;

  expected_outbox_digest := encode(sha256(convert_to(
    'scopeproof-api-audit-outbox-v1' || chr(10) ||
    active_tenant::text || chr(10) || queued.actor_user_id::text || chr(10) ||
    queued.membership_id::text || chr(10) || queued.action || chr(10) ||
    queued.resource_type || chr(10) || queued.resource_id || chr(10) ||
    queued.idempotency_key || chr(10) || queued.details::text,
    'UTF8'
  )), 'hex');
  expected_outbox_id := ('aob_' || substr(expected_outbox_digest, 1, 32))::scopeproof.resource_identifier;
  expected_event_id := ('evt_' || substr(expected_outbox_digest, 1, 32))::scopeproof.resource_identifier;
  expected_actor := jsonb_build_object(
    'type', 'user',
    'userId', queued.actor_user_id,
    'membershipId', queued.membership_id
  );
  expected_details := queued.details || jsonb_build_object(
    'scopeproofOutboxId', queued.id,
    'scopeproofOutboxDigest', queued.event_digest::text,
    'scopeproofMembershipId', queued.membership_id
  );
  IF queued.id IS DISTINCT FROM expected_outbox_id OR
     queued.event_digest::text IS DISTINCT FROM expected_outbox_digest OR
     p_event_id IS DISTINCT FROM expected_event_id OR
     p_occurred_at IS DISTINCT FROM queued.occurred_at OR
     p_actor IS DISTINCT FROM expected_actor OR
     p_action IS DISTINCT FROM queued.action OR
     p_resource_type IS DISTINCT FROM queued.resource_type OR
     p_resource_id::text IS DISTINCT FROM queued.resource_id OR
     p_request_id IS DISTINCT FROM queued.request_id OR
     p_outcome IS DISTINCT FROM queued.outcome OR
     p_details IS DISTINCT FROM expected_details THEN
    RAISE EXCEPTION 'signed API audit event does not match its immutable outbox row' USING ERRCODE = '42501';
  END IF;

  IF work.completed_at IS NOT NULL THEN
    IF work.audit_event_id IS DISTINCT FROM p_event_id OR
       work.audit_event_hash::text IS DISTINCT FROM p_event_hash THEN
      RAISE EXCEPTION 'completed API audit event conflicts with replay' USING ERRCODE = '23505';
    END IF;
    RETURN QUERY
    SELECT event.sequence, event.event_hash::text, false,
           event.canonical_receipt, event.receipt_payload_sha256::text,
           event.kms_signature, event.signed_at
      FROM scopeproof.audit_events AS event
     WHERE event.tenant_id = active_tenant AND event.id = p_event_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'completed API audit event is missing' USING ERRCODE = '40001';
    END IF;
    RETURN;
  END IF;
  IF work.dead_lettered_at IS NOT NULL OR work.lease_token IS DISTINCT FROM p_lease_token THEN
    RAISE EXCEPTION 'API audit outbox lease changed' USING ERRCODE = '40001';
  END IF;

  SELECT * INTO STRICT
    appended_sequence, appended_event_hash, appended_was_created,
    appended_canonical_receipt, appended_receipt_payload_sha256,
    appended_signature, appended_signed_at
    FROM scopeproof.append_signed_audit_event(
      p_sequence, p_event_id, p_occurred_at, p_actor, p_action,
      p_resource_type, p_resource_id, p_request_id, p_outcome, p_details,
      p_previous_hash, p_event_hash, p_canonical_event, p_receipt_payload,
      p_canonical_receipt, p_receipt_payload_sha256, p_signing_key_arn,
      p_signing_algorithm, p_signature, p_signed_at
    );

  UPDATE scopeproof.api_audit_outbox_work
     SET lease_token = NULL,
         lease_expires_at = NULL,
         completed_at = clock_timestamp(),
         audit_event_id = p_event_id,
         audit_event_hash = appended_event_hash
   WHERE tenant_id = active_tenant
     AND outbox_id = p_outbox_id
     AND lease_token = p_lease_token
     AND completed_at IS NULL
     AND dead_lettered_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'API audit outbox completion transition changed' USING ERRCODE = '40001';
  END IF;

  RETURN QUERY SELECT appended_sequence, appended_event_hash,
    appended_was_created, appended_canonical_receipt,
    appended_receipt_payload_sha256, appended_signature, appended_signed_at;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.append_signed_api_audit_event(
  scopeproof.resource_identifier, text, bigint, scopeproof.resource_identifier,
  timestamptz, jsonb, text, text, scopeproof.resource_identifier, text, text,
  jsonb, text, text, text, jsonb, text, text, text, text, text, timestamptz
) FROM PUBLIC;

-- Bounded worker queue. REQUESTED rows are intentionally returned for age
-- monitoring only; the application worker is required to call read(), which
-- refuses to mutate S3 until an independent APPROVED transition is committed.
CREATE FUNCTION scopeproof.list_pending_exact_version_legal_holds(
  p_state_changed_before timestamptz,
  p_limit integer
)
RETURNS TABLE (
  canonical_request text,
  request_digest text,
  operation_state text,
  state_changed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();
BEGIN
  IF active_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant context is required' USING ERRCODE = '42501';
  END IF;
  IF p_state_changed_before IS NULL OR
     p_state_changed_before > clock_timestamp() OR
     p_limit NOT BETWEEN 1 AND 100 THEN
    RAISE EXCEPTION 'legal hold sweep bounds are invalid' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT operation.canonical_request,
         operation.request_digest::text,
         operation.operation_state,
         CASE
           WHEN operation.operation_state = 'APPROVED' THEN operation.approved_at
           WHEN operation.operation_state = 'APPLYING' THEN operation.application_started_at
           ELSE operation.created_at
         END AS state_changed_at
    FROM scopeproof.legal_hold_operations AS operation
   WHERE operation.tenant_id = active_tenant
     AND operation.operation_state IN ('REQUESTED', 'APPROVED', 'APPLYING')
     AND (
       operation.operation_state = 'REQUESTED' OR
       operation.reconciliation_next_attempt_at IS NULL OR
       operation.reconciliation_next_attempt_at <= clock_timestamp()
     )
     AND CASE
           WHEN operation.operation_state = 'APPROVED' THEN operation.approved_at
           WHEN operation.operation_state = 'APPLYING' THEN operation.application_started_at
           ELSE operation.created_at
         END <= p_state_changed_before
   ORDER BY CASE WHEN operation.operation_state IN ('APPROVED', 'APPLYING') THEN 0 ELSE 1 END,
            state_changed_at,
            operation.id
   LIMIT p_limit;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.list_pending_exact_version_legal_holds(
  timestamptz, integer
) FROM PUBLIC;

-- A failing provider/DB operation remains APPROVED, but exponential backoff
-- prevents one poison row from permanently occupying the bounded queue head.
-- Only a safe error code is retained; provider messages are never persisted.
CREATE FUNCTION scopeproof.record_exact_version_legal_hold_reconciliation_failure(
  p_operation_id scopeproof.resource_identifier,
  p_request_digest text,
  p_error_code text,
  p_failed_at timestamptz
)
RETURNS TABLE (
  attempt_count integer,
  next_attempt_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();
BEGIN
  IF active_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant context is required' USING ERRCODE = '42501';
  END IF;
  IF p_operation_id IS NULL OR p_operation_id NOT LIKE 'lho\_%' ESCAPE '\' OR
     p_request_digest IS NULL OR p_request_digest !~ '^[0-9a-f]{64}$' OR
     p_error_code IS NULL OR p_error_code !~ '^[A-Z][A-Z0-9_]{2,63}$' OR
     p_failed_at IS NULL OR
     p_failed_at < clock_timestamp() - interval '5 minutes' OR
     p_failed_at > clock_timestamp() + interval '5 minutes' THEN
    RAISE EXCEPTION 'legal hold reconciliation failure input is invalid' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  UPDATE scopeproof.legal_hold_operations AS operation
     SET reconciliation_attempt_count = operation.reconciliation_attempt_count + 1,
         reconciliation_last_error_code = p_error_code,
         reconciliation_last_failed_at = p_failed_at,
         reconciliation_next_attempt_at = p_failed_at + make_interval(secs => least(
           21600,
           (30 * power(2, least(operation.reconciliation_attempt_count, 10)))::integer
         ))
   WHERE operation.tenant_id = active_tenant
     AND operation.id = p_operation_id
     AND operation.request_digest = p_request_digest
     AND operation.operation_state IN ('APPROVED', 'APPLYING')
     AND operation.revision = CASE WHEN operation.operation_state = 'APPROVED' THEN 1 ELSE 2 END
     AND operation.reconciliation_attempt_count < 1000000
  RETURNING operation.reconciliation_attempt_count,
            operation.reconciliation_next_attempt_at;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'legal hold reconciliation retry state changed' USING ERRCODE = '40001';
  END IF;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.record_exact_version_legal_hold_reconciliation_failure(
  scopeproof.resource_identifier, text, text, timestamptz
) FROM PUBLIC;

-- Worker-only bounded expiry. REQUESTED work becomes terminal only after its
-- approval window has elapsed; this never changes S3 or an active hold.
CREATE FUNCTION scopeproof.expire_stale_exact_version_legal_hold_requests(
  p_now timestamptz,
  p_limit integer
)
RETURNS TABLE (
  operation_id scopeproof.resource_identifier,
  canonical_request text,
  request_digest text,
  expired_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();
BEGIN
  IF active_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant context is required' USING ERRCODE = '42501';
  END IF;
  IF p_now IS NULL OR
     p_now < clock_timestamp() - interval '5 minutes' OR
     p_now > clock_timestamp() + interval '5 minutes' OR
     p_limit NOT BETWEEN 1 AND 100 THEN
    RAISE EXCEPTION 'legal hold expiry bounds are invalid' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  WITH candidates AS (
    SELECT operation.tenant_id, operation.id
      FROM scopeproof.legal_hold_operations AS operation
     WHERE operation.tenant_id = active_tenant
       AND operation.operation_state = 'REQUESTED'
       AND operation.revision = 0
       AND operation.changed_at + interval '24 hours' <= p_now
     ORDER BY operation.changed_at, operation.id
     FOR UPDATE SKIP LOCKED
     LIMIT p_limit
  )
  UPDATE scopeproof.legal_hold_operations AS operation
     SET operation_state = 'EXPIRED',
         revision = 1,
         expired_at = p_now
    FROM candidates
   WHERE operation.tenant_id = candidates.tenant_id
     AND operation.id = candidates.id
     AND operation.operation_state = 'REQUESTED'
     AND operation.revision = 0
  RETURNING operation.id, operation.canonical_request,
            operation.request_digest::text, operation.expired_at;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.expire_stale_exact_version_legal_hold_requests(
  timestamptz, integer
) FROM PUBLIC;

-- S3, the signed Aurora audit, and the DynamoDB recovery ledger cannot share a
-- transaction. Keep APPLIED work eligible until the ledger write has been
-- independently acknowledged in Aurora; an audit commit alone must not clear
-- this outbox.
CREATE FUNCTION scopeproof.list_unaudited_applied_legal_holds(
  p_limit integer
)
RETURNS TABLE (
  canonical_request text,
  request_digest text,
  applied_at timestamptz,
  audit_canonical_event text,
  audit_canonical_receipt text,
  audit_receipt_payload_sha256 text,
  audit_signing_key_arn text,
  audit_signing_algorithm text,
  audit_signature text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();
BEGIN
  IF active_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant context is required' USING ERRCODE = '42501';
  END IF;
  IF p_limit NOT BETWEEN 1 AND 100 THEN
    RAISE EXCEPTION 'legal hold audit sweep bound is invalid' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT operation.canonical_request,
         operation.request_digest::text,
         operation.applied_at,
         event.canonical_event,
         event.canonical_receipt,
         event.receipt_payload_sha256::text,
         event.signing_key_arn,
         event.signing_algorithm,
         event.kms_signature
    FROM scopeproof.legal_hold_operations AS operation
    LEFT JOIN scopeproof.audit_events AS event
      ON event.tenant_id = operation.tenant_id
     AND event.id = ('evt_' || substr(encode(sha256(
       convert_to('scopeproof-legal-hold-audit-v1', 'UTF8') || decode('00', 'hex') ||
       convert_to(operation.id::text, 'UTF8')
     )), 'hex'), 1, 32))::scopeproof.resource_identifier
     AND event.resource_type = 'legal_hold_operation'
     AND event.resource_id = operation.id
     AND event.action = 'evidence.legal_hold_applied'
     AND event.outcome = 'succeeded'
   WHERE operation.tenant_id = active_tenant
     AND operation.operation_state = 'APPLIED'
     AND operation.recovery_published_at IS NULL
   ORDER BY operation.applied_at, operation.id
   LIMIT p_limit;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.list_unaudited_applied_legal_holds(
  integer
) FROM PUBLIC;

CREATE FUNCTION scopeproof.acknowledge_legal_hold_recovery_publication(
  p_operation_id scopeproof.resource_identifier,
  p_request_digest text,
  p_published_at timestamptz
)
RETURNS timestamptz
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();
  acknowledged_at timestamptz;
BEGIN
  IF active_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant context is required' USING ERRCODE = '42501';
  END IF;
  IF p_operation_id IS NULL OR p_operation_id NOT LIKE 'lho\_%' ESCAPE '\' OR
     p_request_digest IS NULL OR p_request_digest !~ '^[0-9a-f]{64}$' OR
     p_published_at IS NULL OR p_published_at > clock_timestamp() + interval '5 minutes' THEN
    RAISE EXCEPTION 'legal hold recovery acknowledgement is invalid' USING ERRCODE = '22023';
  END IF;

  UPDATE scopeproof.legal_hold_operations AS operation
     SET recovery_published_at = p_published_at
   WHERE operation.tenant_id = active_tenant
     AND operation.id = p_operation_id
     AND operation.request_digest = p_request_digest
     AND operation.operation_state = 'APPLIED'
     AND operation.recovery_published_at IS NULL
     AND p_published_at >= operation.applied_at
     AND EXISTS (
       SELECT 1
         FROM scopeproof.audit_events AS event
        WHERE event.tenant_id = operation.tenant_id
          AND event.resource_type = 'legal_hold_operation'
          AND event.resource_id = operation.id
          AND event.action = 'evidence.legal_hold_applied'
          AND event.outcome = 'succeeded'
     )
  RETURNING operation.recovery_published_at INTO acknowledged_at;
  IF FOUND THEN RETURN acknowledged_at; END IF;

  SELECT operation.recovery_published_at
    INTO acknowledged_at
    FROM scopeproof.legal_hold_operations AS operation
   WHERE operation.tenant_id = active_tenant
     AND operation.id = p_operation_id
     AND operation.request_digest = p_request_digest
     AND operation.operation_state = 'APPLIED'
     AND operation.recovery_published_at = p_published_at;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'legal hold recovery acknowledgement state changed' USING ERRCODE = '40001';
  END IF;
  RETURN acknowledged_at;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.acknowledge_legal_hold_recovery_publication(
  scopeproof.resource_identifier, text, timestamptz
) FROM PUBLIC;

-- Expiry and its KMS signature cannot share one transaction. Keep every
-- terminal expiry eligible until its independently signed audit event exists.
CREATE FUNCTION scopeproof.list_unaudited_expired_legal_holds(
  p_limit integer
)
RETURNS TABLE (
  canonical_request text,
  request_digest text,
  expired_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();
BEGIN
  IF active_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant context is required' USING ERRCODE = '42501';
  END IF;
  IF p_limit NOT BETWEEN 1 AND 100 THEN
    RAISE EXCEPTION 'legal hold expiry audit sweep bound is invalid' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT operation.canonical_request,
         operation.request_digest::text,
         operation.expired_at
    FROM scopeproof.legal_hold_operations AS operation
   WHERE operation.tenant_id = active_tenant
     AND operation.operation_state = 'EXPIRED'
     AND NOT EXISTS (
       SELECT 1
         FROM scopeproof.audit_events AS event
        WHERE event.tenant_id = operation.tenant_id
          AND event.resource_type = 'legal_hold_operation'
          AND event.resource_id = operation.id
          AND event.action = 'evidence.legal_hold_request_expired'
          AND event.outcome = 'succeeded'
     )
   ORDER BY operation.expired_at, operation.id
   LIMIT p_limit;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.list_unaudited_expired_legal_holds(
  integer
) FROM PUBLIC;

CREATE FUNCTION scopeproof.read_tenant_audit_head()
RETURNS TABLE (
  current_sequence bigint,
  current_event_hash text
)
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();
BEGIN
  IF active_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant context is required' USING ERRCODE = '42501';
  END IF;

  RETURN QUERY
  SELECT COALESCE(head.sequence, 0), COALESCE(head.event_hash::text, 'GENESIS')
    FROM (SELECT 1) AS singleton
    LEFT JOIN scopeproof.audit_heads AS head
      ON head.tenant_id = active_tenant;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.read_tenant_audit_head() FROM PUBLIC;

REVOKE ALL ON ALL TABLES IN SCHEMA scopeproof FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA scopeproof FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA scopeproof REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA scopeproof REVOKE ALL ON SEQUENCES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA scopeproof REVOKE EXECUTE ON FUNCTIONS FROM PUBLIC;

INSERT INTO scopeproof.schema_migrations (version, name)
VALUES (1, 'tenant_security_baseline');

COMMIT;
