-- Forward-only hardening for already provisioned tenant databases.
-- Never fold these definitions into 001/006 without a separate compatibility
-- review: the provisioner applies this exact migration as schema version 3.

BEGIN;

-- The baseline permitted rejection from issued/quarantined but not from the
-- short validated window. Amend exactly one reviewed clause so a GuardDuty
-- rejection can win the final race before immutable promotion. Refuse to
-- continue if the installed trigger definition is not the expected lineage.
DO $$
DECLARE
  definition text;
  expected CONSTANT text := '(OLD.status = ''validated'' AND NEW.status = ''promoted'')';
  replacement CONSTANT text := '(OLD.status = ''validated'' AND NEW.status IN (''promoted'', ''rejected''))';
BEGIN
  SELECT pg_get_functiondef('scopeproof.protect_immutable_security_fields()'::regprocedure)
    INTO STRICT definition;
  IF (length(definition) - length(replace(definition, expected, ''))) / length(expected) <> 1 THEN
    RAISE EXCEPTION 'unexpected immutable-state trigger lineage; reviewed migration required'
      USING ERRCODE = '55000';
  END IF;
  EXECUTE replace(definition, expected, replacement);
END;
$$;

-- Existing version-2 databases predate the exact-version server-DLP facts.
-- Patch the one catalog-generated definition only when the reviewed clause is
-- absent; refuse unexpected lineages rather than silently weakening checks.
DO $$
DECLARE
  definition text;
  needle CONSTANT text := '     (p_promotion_facts ->> ''kmsKeyArn'') IS DISTINCT FROM p_kms_key_arn OR';
  dlp_clause CONSTANT text := $clause$     (p_promotion_facts ->> 'dlpPolicyVersion') IS NULL OR
     (p_promotion_facts ->> 'dlpPolicyVersion') !~ '^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$' OR
     (p_promotion_facts ->> 'dlpReceiptSha256') IS NULL OR
     (p_promotion_facts ->> 'dlpReceiptSha256') !~ '^[0-9a-f]{64}$' OR
     (p_promotion_facts ->> 'dlpScannedAt') IS NULL OR
     (p_promotion_facts ->> 'dlpScannedAt') IS DISTINCT FROM to_char(
       (p_promotion_facts ->> 'dlpScannedAt')::timestamptz AT TIME ZONE 'UTC',
       'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'
     ) OR
     (p_promotion_facts ->> 'dlpScannedAt')::timestamptz > p_reconciled_at OR
     (p_promotion_facts ->> 'dlpScannedAt')::timestamptz <
       (p_promotion_facts ->> 'uploadedAt')::timestamptz OR
     (p_promotion_facts ->> 'dlpScannerRequestId') IS NULL OR
     (p_promotion_facts ->> 'dlpScannerRequestId') !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$' OR
$clause$;
BEGIN
  SELECT pg_get_functiondef('scopeproof.reconcile_promoted_evidence(scopeproof.resource_identifier,scopeproof.resource_identifier,scopeproof.resource_identifier,text,text,text,text,text,timestamp with time zone,timestamp with time zone,integer,integer,bigint,text,text,jsonb,text,text,text,text,text,timestamp with time zone,timestamp with time zone)'::regprocedure)
    INTO STRICT definition;
  IF position('dlpReceiptSha256' IN definition) = 0 THEN
    IF (length(definition) - length(replace(definition, needle, ''))) / length(needle) <> 1 THEN
      RAISE EXCEPTION 'unexpected promotion function lineage; reviewed migration required' USING ERRCODE = '55000';
    END IF;
    EXECUTE replace(definition, needle, dlp_clause || needle);
  ELSIF (length(definition) - length(replace(definition, 'dlpReceiptSha256', ''))) / length('dlpReceiptSha256') <> 2 THEN
    RAISE EXCEPTION 'unexpected DLP promotion definition; reviewed migration required' USING ERRCODE = '55000';
  END IF;
END;
$$;

CREATE OR REPLACE FUNCTION scopeproof.evidence_reader_role(
  p_actor_user_id scopeproof.resource_identifier
)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
STABLE
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE actor_role text;
BEGIN
  SELECT membership.role INTO actor_role
    FROM scopeproof.memberships AS membership
    JOIN scopeproof.principals AS principal
      ON principal.tenant_id = membership.tenant_id AND principal.id = membership.principal_id
   WHERE membership.tenant_id = scopeproof.current_tenant_id()
     AND membership.principal_id = p_actor_user_id
     AND membership.status = 'ACTIVE' AND principal.status = 'ACTIVE';
  IF actor_role NOT IN ('admin', 'compliance_lead', 'reviewer', 'auditor') THEN
    RAISE EXCEPTION 'active membership does not permit evidence reads' USING ERRCODE = '42501';
  END IF;
  RETURN actor_role;
END;
$$;
REVOKE ALL ON FUNCTION scopeproof.evidence_reader_role(scopeproof.resource_identifier) FROM PUBLIC;

-- Upgrade the two v2 evidence-read functions without duplicating their long,
-- typed result contracts. pg_get_functiondef supplies server-quoted DDL; the
-- exact replacements below are applied only to the reviewed v2 lineage.
DO $$
DECLARE
  identity regprocedure;
  definition text;
  declaration CONSTANT text := '  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();';
  old_authorize CONSTANT text := '  PERFORM scopeproof.assert_actor_permission(p_requested_by, ''evidence:read'');';
  new_authorize CONSTANT text := '  actor_role := scopeproof.evidence_reader_role(p_requested_by);';
  visibility CONSTANT text := $filter$     AND (actor_role <> 'auditor' OR
          (artifact.status = 'APPROVED' AND artifact.retain_until > clock_timestamp()))
$filter$;
BEGIN
  FOREACH identity IN ARRAY ARRAY[
    'scopeproof.list_accessible_evidence(scopeproof.resource_identifier,timestamp with time zone,scopeproof.resource_identifier,integer)'::regprocedure,
    'scopeproof.read_accessible_evidence(scopeproof.resource_identifier,scopeproof.resource_identifier)'::regprocedure
  ] LOOP
    SELECT pg_get_functiondef(identity) INTO STRICT definition;
    IF position('actor_role := scopeproof.evidence_reader_role' IN definition) = 0 THEN
      IF position(declaration IN definition) = 0 OR position(old_authorize IN definition) = 0 OR
         (length(definition) - length(replace(definition, '     AND artifact.retain_until IS NOT NULL', ''))) /
           length('     AND artifact.retain_until IS NOT NULL') <> 1 THEN
        RAISE EXCEPTION 'unexpected evidence-read function lineage; reviewed migration required' USING ERRCODE = '55000';
      END IF;
      definition := replace(definition, declaration, declaration || chr(10) || '  actor_role text;');
      definition := replace(definition, old_authorize, new_authorize);
      definition := replace(definition, '     AND artifact.retain_until IS NOT NULL' || chr(10),
        '     AND artifact.retain_until IS NOT NULL' || chr(10) || visibility);
      EXECUTE definition;
    ELSIF position('actor_role text;' IN definition) = 0 OR position('actor_role <> ''auditor''' IN definition) = 0 THEN
      RAISE EXCEPTION 'unexpected auditor evidence-read definition; reviewed migration required' USING ERRCODE = '55000';
    END IF;
  END LOOP;
END;
$$;

CREATE TABLE scopeproof.rejected_ingest_receipts (
  tenant_id scopeproof.tenant_identifier NOT NULL,
  id scopeproof.resource_identifier NOT NULL CHECK (id LIKE 'rej\_%' ESCAPE '\'),
  upload_intent_id scopeproof.resource_identifier NOT NULL,
  evidence_id scopeproof.resource_identifier NOT NULL,
  quarantine_version_id text NOT NULL CHECK (quarantine_version_id ~ '^[A-Za-z0-9][A-Za-z0-9._:+/=-]{0,511}$'),
  scan_result text NOT NULL CHECK (scan_result IN ('THREATS_FOUND', 'UNSUPPORTED', 'ACCESS_DENIED', 'FAILED')),
  provider_event_id text NOT NULL CHECK (provider_event_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$'),
  upload_revision integer NOT NULL CHECK (upload_revision > 0),
  evidence_revision integer NOT NULL CHECK (evidence_revision > 0),
  rejection_facts jsonb NOT NULL CHECK (jsonb_typeof(rejection_facts) = 'object'),
  receipt_sha256 char(64) NOT NULL CHECK (receipt_sha256 ~ '^[0-9a-f]{64}$'),
  canonical_receipt text NOT NULL CHECK (octet_length(canonical_receipt) BETWEEN 64 AND 16384),
  rejected_at timestamptz NOT NULL,
  created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
  PRIMARY KEY (tenant_id, id),
  UNIQUE (tenant_id, upload_intent_id),
  UNIQUE (tenant_id, provider_event_id),
  UNIQUE (tenant_id, receipt_sha256),
  FOREIGN KEY (tenant_id, upload_intent_id) REFERENCES scopeproof.upload_intents (tenant_id, id) ON DELETE RESTRICT,
  FOREIGN KEY (tenant_id, evidence_id) REFERENCES scopeproof.evidence_artifacts (tenant_id, id) ON DELETE RESTRICT
);

ALTER TABLE scopeproof.rejected_ingest_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE scopeproof.rejected_ingest_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON scopeproof.rejected_ingest_receipts
  USING (tenant_id = scopeproof.current_tenant_id())
  WITH CHECK (tenant_id = scopeproof.current_tenant_id());
ALTER TABLE scopeproof.rejected_ingest_receipts
  ADD CONSTRAINT rejected_ingest_receipts_tenant_identity_fk
  FOREIGN KEY (tenant_id) REFERENCES scopeproof.tenant_identity (tenant_id) ON DELETE RESTRICT;
CREATE TRIGGER enforce_database_tenant
  BEFORE INSERT OR UPDATE ON scopeproof.rejected_ingest_receipts
  FOR EACH ROW EXECUTE FUNCTION scopeproof.assert_database_tenant();

CREATE FUNCTION scopeproof.reject_rejected_ingest_receipt_mutation()
RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
BEGIN
  RAISE EXCEPTION 'rejected ingest receipts are append-only' USING ERRCODE = '42501';
END;
$$;
REVOKE ALL ON FUNCTION scopeproof.reject_rejected_ingest_receipt_mutation() FROM PUBLIC;
CREATE TRIGGER protect_rejected_ingest_receipt
  BEFORE UPDATE OR DELETE ON scopeproof.rejected_ingest_receipts
  FOR EACH ROW EXECUTE FUNCTION scopeproof.reject_rejected_ingest_receipt_mutation();

CREATE FUNCTION scopeproof.reconcile_rejected_evidence(
  p_receipt_id scopeproof.resource_identifier,
  p_upload_intent_id scopeproof.resource_identifier,
  p_evidence_id scopeproof.resource_identifier,
  p_quarantine_version_id text,
  p_scan_result text,
  p_provider_event_id text,
  p_expected_upload_revision integer,
  p_expected_evidence_revision integer,
  p_rejection_facts jsonb,
  p_canonical_receipt text,
  p_receipt_sha256 text,
  p_rejected_at timestamptz
)
RETURNS TABLE (
  receipt_id scopeproof.resource_identifier,
  was_created boolean,
  committed_upload_revision integer,
  committed_evidence_revision integer,
  committed_receipt_sha256 text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();
  intent scopeproof.upload_intents%ROWTYPE;
  artifact scopeproof.evidence_artifacts%ROWTYPE;
  existing scopeproof.rejected_ingest_receipts%ROWTYPE;
BEGIN
  IF num_nonnulls(p_receipt_id, p_upload_intent_id, p_evidence_id, p_quarantine_version_id,
       p_scan_result, p_provider_event_id, p_expected_upload_revision, p_expected_evidence_revision,
       p_rejection_facts, p_canonical_receipt, p_receipt_sha256, p_rejected_at) <> 12 OR
     active_tenant IS NULL OR p_expected_upload_revision < 0 OR p_expected_evidence_revision < 0 OR
     p_receipt_id NOT LIKE 'rej\_%' ESCAPE '\' OR
     p_quarantine_version_id !~ '^[A-Za-z0-9][A-Za-z0-9._:+/=-]{0,511}$' OR
     p_scan_result NOT IN ('THREATS_FOUND', 'UNSUPPORTED', 'ACCESS_DENIED', 'FAILED') OR
     p_provider_event_id !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$' OR
     jsonb_typeof(p_rejection_facts) IS DISTINCT FROM 'object' OR
     p_canonical_receipt::jsonb IS DISTINCT FROM p_rejection_facts OR
     encode(sha256(convert_to('scopeproof-ingest-rejection-v1' || chr(10) || p_canonical_receipt, 'UTF8')), 'hex') IS DISTINCT FROM p_receipt_sha256 OR
     (p_rejection_facts ->> 'rejectedAt')::timestamptz IS DISTINCT FROM p_rejected_at THEN
    RAISE EXCEPTION 'rejection reconciliation input is invalid' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO existing FROM scopeproof.rejected_ingest_receipts
   WHERE tenant_id = active_tenant AND upload_intent_id = p_upload_intent_id;
  IF FOUND THEN
    IF existing.id IS DISTINCT FROM p_receipt_id OR existing.evidence_id IS DISTINCT FROM p_evidence_id OR
       existing.quarantine_version_id IS DISTINCT FROM p_quarantine_version_id OR
       existing.scan_result IS DISTINCT FROM p_scan_result OR existing.provider_event_id IS DISTINCT FROM p_provider_event_id OR
       existing.rejection_facts IS DISTINCT FROM p_rejection_facts OR existing.canonical_receipt IS DISTINCT FROM p_canonical_receipt OR
       existing.receipt_sha256 IS DISTINCT FROM p_receipt_sha256 OR existing.rejected_at IS DISTINCT FROM p_rejected_at THEN
      RAISE EXCEPTION 'rejection reconciliation idempotency conflict' USING ERRCODE = '23505';
    END IF;
    RETURN QUERY SELECT existing.id, false, existing.upload_revision, existing.evidence_revision, existing.receipt_sha256::text;
    RETURN;
  END IF;

  -- The persisted DynamoDB rejection receipt is the recovery authority after a
  -- partial commit. Its authenticated facts may legitimately arrive here after
  -- the source queue's four-day retention or a later DLQ redrive, so permit the
  -- complete fourteen-day durable retry horizon for a new relational commit.
  IF p_rejected_at < clock_timestamp() - interval '14 days' OR
     p_rejected_at > clock_timestamp() + interval '5 minutes' THEN
    RAISE EXCEPTION 'rejection reconciliation timestamp is outside the durable recovery window' USING ERRCODE = '22023';
  END IF;

  SELECT * INTO STRICT intent FROM scopeproof.upload_intents
   WHERE tenant_id = active_tenant AND id = p_upload_intent_id FOR UPDATE;
  SELECT * INTO STRICT artifact FROM scopeproof.evidence_artifacts
   WHERE tenant_id = active_tenant AND id = p_evidence_id FOR UPDATE;
  IF intent.evidence_id IS DISTINCT FROM p_evidence_id OR intent.revision IS DISTINCT FROM p_expected_upload_revision OR
     artifact.revision IS DISTINCT FROM p_expected_evidence_revision OR artifact.control_id IS DISTINCT FROM intent.control_id OR
     intent.status NOT IN ('issued', 'quarantined', 'validated') OR artifact.status NOT IN ('QUARANTINED', 'VALIDATING') OR
     (p_rejection_facts ->> 'schemaVersion') IS DISTINCT FROM '1' OR
     (p_rejection_facts ->> 'tenantId') IS DISTINCT FROM active_tenant OR
     (p_rejection_facts ->> 'uploadIntentId') IS DISTINCT FROM p_upload_intent_id OR
     (p_rejection_facts ->> 'evidenceId') IS DISTINCT FROM p_evidence_id OR
     (p_rejection_facts ->> 'quarantineBucket') IS DISTINCT FROM intent.quarantine_bucket OR
     (p_rejection_facts ->> 'quarantineKey') IS DISTINCT FROM intent.object_key OR
     (p_rejection_facts ->> 'quarantineVersionId') IS DISTINCT FROM p_quarantine_version_id OR
     (p_rejection_facts ->> 'scanResult') IS DISTINCT FROM p_scan_result OR
     (p_rejection_facts ->> 'providerEventId') IS DISTINCT FROM p_provider_event_id OR
     (p_rejection_facts ->> 'rejectedAt')::timestamptz IS DISTINCT FROM p_rejected_at THEN
    RAISE EXCEPTION 'rejection facts do not match the authoritative upload intent' USING ERRCODE = '23514';
  END IF;

  UPDATE scopeproof.upload_intents SET status = 'rejected', revision = revision + 1, consumed_at = p_rejected_at
   WHERE tenant_id = active_tenant AND id = p_upload_intent_id AND revision = p_expected_upload_revision
     AND status IN ('issued', 'quarantined', 'validated');
  IF NOT FOUND THEN RAISE EXCEPTION 'upload rejection transition changed' USING ERRCODE = '40001'; END IF;
  UPDATE scopeproof.evidence_artifacts SET status = 'REJECTED', revision = revision + 1
   WHERE tenant_id = active_tenant AND id = p_evidence_id AND revision = p_expected_evidence_revision
     AND status IN ('QUARANTINED', 'VALIDATING');
  IF NOT FOUND THEN RAISE EXCEPTION 'evidence rejection transition changed' USING ERRCODE = '40001'; END IF;

  INSERT INTO scopeproof.rejected_ingest_receipts (
    tenant_id, id, upload_intent_id, evidence_id, quarantine_version_id, scan_result,
    provider_event_id, upload_revision, evidence_revision, rejection_facts,
    receipt_sha256, canonical_receipt, rejected_at
  ) VALUES (
    active_tenant, p_receipt_id, p_upload_intent_id, p_evidence_id, p_quarantine_version_id, p_scan_result,
    p_provider_event_id, p_expected_upload_revision + 1, p_expected_evidence_revision + 1,
    p_rejection_facts, p_receipt_sha256, p_canonical_receipt, p_rejected_at
  );
  RETURN QUERY SELECT p_receipt_id, true, p_expected_upload_revision + 1,
    p_expected_evidence_revision + 1, p_receipt_sha256;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.reconcile_rejected_evidence(
  scopeproof.resource_identifier, scopeproof.resource_identifier, scopeproof.resource_identifier,
  text, text, text, integer, integer, jsonb, text, text, timestamptz
) FROM PUBLIC;
REVOKE ALL ON TABLE scopeproof.rejected_ingest_receipts FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA scopeproof FROM PUBLIC;

INSERT INTO scopeproof.schema_migrations (version, name)
VALUES (3, 'runtime_hardening');

COMMIT;
