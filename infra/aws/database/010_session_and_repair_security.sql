-- Forward-only schema version 4. Apply after the exact attested v3 bundle.
-- This does not bypass enrollment, membership, assessment scope, retention,
-- equality checks, or device sequence checks. No public repair grant is made.
BEGIN;

CREATE OR REPLACE FUNCTION scopeproof.evidence_reader_role(
  p_actor_user_id scopeproof.resource_identifier
)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE actor_role text;
BEGIN
  PERFORM scopeproof.assert_actor_permission(p_actor_user_id, 'evidence:read');
  SELECT membership.role INTO actor_role
    FROM scopeproof.memberships AS membership
    JOIN scopeproof.principals AS principal
      ON principal.tenant_id = membership.tenant_id AND principal.id = membership.principal_id
   WHERE membership.tenant_id = scopeproof.current_tenant_id()
     AND membership.principal_id = p_actor_user_id
     AND membership.status = 'ACTIVE' AND principal.status = 'ACTIVE';
  IF actor_role IS NULL OR actor_role NOT IN ('admin', 'compliance_lead', 'reviewer', 'auditor') THEN
    RAISE EXCEPTION 'active membership does not permit evidence reads' USING ERRCODE = '42501';
  END IF;
  RETURN actor_role;
END;
$$;
REVOKE ALL ON FUNCTION scopeproof.evidence_reader_role(scopeproof.resource_identifier) FROM PUBLIC;

-- Authentication time, not refresh/issue time, prevents a refresh token from
-- re-entering after an epoch change. Epoch advancement is owner-only.
ALTER TABLE scopeproof.principals
  ADD COLUMN session_epoch bigint NOT NULL DEFAULT 0 CHECK (session_epoch >= 0),
  ADD COLUMN sessions_revoked_through timestamptz NOT NULL DEFAULT '-infinity',
  ADD COLUMN session_revocation_reason text,
  ADD COLUMN session_revoked_by name;

CREATE FUNCTION scopeproof.resolve_active_session_membership(
  p_identity_subject text, p_authenticated_at timestamptz
)
RETURNS TABLE (
  tenant_id scopeproof.tenant_identifier, identity_subject text,
  membership_id scopeproof.resource_identifier, principal_id scopeproof.resource_identifier,
  role text
)
LANGUAGE plpgsql SECURITY DEFINER STABLE
SET search_path = pg_catalog, scopeproof
AS $$
BEGIN
  IF p_authenticated_at IS NULL OR NOT isfinite(p_authenticated_at) THEN
    RAISE EXCEPTION 'authentication time is required' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  SELECT member.tenant_id, member.identity_subject, member.membership_id, member.principal_id, member.role
    FROM scopeproof.resolve_active_membership(p_identity_subject) AS member
    JOIN scopeproof.principals AS principal
      ON principal.tenant_id = member.tenant_id AND principal.id = member.principal_id
   WHERE principal.tenant_id = scopeproof.current_tenant_id()
     AND p_authenticated_at > principal.sessions_revoked_through;
END;
$$;
REVOKE ALL ON FUNCTION scopeproof.resolve_active_session_membership(text, timestamptz) FROM PUBLIC;

CREATE FUNCTION scopeproof.advance_session_epoch(
  p_principal_id scopeproof.resource_identifier, p_expected_epoch bigint, p_reason text
)
RETURNS TABLE (session_epoch bigint, sessions_revoked_through timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE cutoff timestamptz := date_trunc('second', clock_timestamp());
BEGIN
  IF scopeproof.current_tenant_id() IS NULL OR p_expected_epoch IS NULL OR p_expected_epoch < 0 OR
     p_reason IS NULL OR char_length(btrim(p_reason)) NOT BETWEEN 8 AND 1000 OR p_reason ~ '[[:cntrl:]]' THEN
    RAISE EXCEPTION 'invalid session revocation request' USING ERRCODE = '22023';
  END IF;
  RETURN QUERY
  UPDATE scopeproof.principals AS principal
     SET session_epoch = principal.session_epoch + 1,
         sessions_revoked_through = greatest(principal.sessions_revoked_through, cutoff),
         session_revocation_reason = p_reason, session_revoked_by = session_user
   WHERE principal.tenant_id = scopeproof.current_tenant_id()
     AND principal.id = p_principal_id AND principal.session_epoch = p_expected_epoch
  RETURNING principal.session_epoch, principal.sessions_revoked_through;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'session revocation revision conflict' USING ERRCODE = '40001';
  END IF;
END;
$$;
REVOKE ALL ON FUNCTION scopeproof.advance_session_epoch(scopeproof.resource_identifier, bigint, text) FROM PUBLIC;
-- Deliberately no grant to any public API/login. Run as the separately approved
-- tenant owner; record the returned epoch/cutoff and operator change reference.

CREATE OR REPLACE FUNCTION scopeproof.create_upload_intent(
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

  -- Exact already-committed retries above must remain idempotent after the
  -- device proof freshness window. All actor/device/scope/equality checks remain.
  IF (device_proof ->> 'signedAt')::timestamptz < clock_timestamp() - interval '5 minutes' OR
     (device_proof ->> 'signedAt')::timestamptz > clock_timestamp() + interval '5 minutes' THEN
    RAISE EXCEPTION 'device proof is outside the fresh issuance window' USING ERRCODE = '22023';
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

CREATE FUNCTION scopeproof.repair_upload_intent(
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
  p_metadata jsonb,
  p_reserved_at timestamptz
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
  -- Only the separately privileged repair worker may supply this time, after
  -- strongly reading the exact immutable Dynamo reservation and projection digest.
  -- Fresh public issuance cannot execute this function.
  IF p_reserved_at IS NULL OR NOT isfinite(p_reserved_at) OR
     p_reserved_at > clock_timestamp() OR
     p_reserved_at < clock_timestamp() - interval '14 days' OR
     p_expires_at <= p_reserved_at OR
     p_expires_at > p_reserved_at + interval '10 minutes' THEN
    RAISE EXCEPTION 'upload reservation is outside the repair horizon' USING ERRCODE = '22023';
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
  IF p_captured_at > p_reserved_at + interval '5 minutes' OR
     p_captured_at < p_reserved_at - interval '30 days' THEN
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

  -- Exact already-committed retries above must remain idempotent after the
  -- device proof freshness window. All actor/device/scope/equality checks remain.
  IF (device_proof ->> 'signedAt')::timestamptz < p_reserved_at - interval '5 minutes' OR
     (device_proof ->> 'signedAt')::timestamptz > p_reserved_at + interval '5 minutes' THEN
    RAISE EXCEPTION 'device proof is outside the fresh issuance window' USING ERRCODE = '22023';
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
    content_length, checksum_sha256, expires_at, required_retention_until, created_at
  ) VALUES (
    active_tenant, p_id, p_nonce_digest, p_requested_by, p_device_id,
    p_assessment_id, p_evidence_id, p_control_id, configured_quarantine_bucket, p_object_key,
    p_final_object_key, p_content_type, p_content_length, p_checksum_sha256,
    p_expires_at, p_required_retention_until, p_reserved_at
  );

  RETURN QUERY SELECT p_id, p_evidence_id, true;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.repair_upload_intent(
  scopeproof.resource_identifier, text, scopeproof.resource_identifier,
  scopeproof.resource_identifier, scopeproof.resource_identifier,
  scopeproof.resource_identifier, text, text, text, bigint, text, timestamptz,
  timestamptz, text, text, text, text, text, text, timestamptz, timestamptz, jsonb, timestamptz
) FROM PUBLIC;

-- Extend the existing durable/KMS-signed audit outbox; revocation and outbox
-- insertion commit together, or neither operation commits.
ALTER TABLE scopeproof.api_audit_outbox DROP CONSTRAINT api_audit_outbox_action_check;
ALTER TABLE scopeproof.api_audit_outbox ADD CONSTRAINT api_audit_outbox_action_check
  CHECK (action IN ('evidence.upload_intent_issued', 'evidence.search_performed',
    'evidence.download_intent_issued', 'evidence.legal_hold_requested',
    'evidence.legal_hold_approved', 'session.all_revoked'));
ALTER TABLE scopeproof.api_audit_outbox DROP CONSTRAINT api_audit_outbox_resource_type_check;
ALTER TABLE scopeproof.api_audit_outbox ADD CONSTRAINT api_audit_outbox_resource_type_check
  CHECK (resource_type IN ('evidence', 'evidence_collection', 'legal_hold_operation', 'principal'));

CREATE OR REPLACE FUNCTION scopeproof.record_api_audit_event(
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
       'evidence.legal_hold_approved',
       'session.all_revoked'
     ) THEN
    RAISE EXCEPTION 'active membership does not permit this audited operation' USING ERRCODE = '42501';
  END IF;

  IF (p_action = 'session.all_revoked' AND (p_resource_type <> 'principal' OR p_resource_id IS DISTINCT FROM p_actor_user_id::text)) OR
     (p_action IN ('evidence.upload_intent_issued', 'evidence.download_intent_issued') AND
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


CREATE FUNCTION scopeproof.revoke_own_sessions(
  p_identity_subject text, p_authenticated_at timestamptz, p_request_id text
)
RETURNS TABLE (session_epoch bigint, sessions_revoked_through timestamptz)
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  member record;
  principal_state scopeproof.principals%ROWTYPE;
  result record;
BEGIN
  SELECT * INTO member FROM scopeproof.resolve_active_session_membership(p_identity_subject, p_authenticated_at);
  IF NOT FOUND THEN
    RAISE EXCEPTION 'active session membership required' USING ERRCODE = '42501';
  END IF;
  SELECT * INTO STRICT principal_state FROM scopeproof.principals AS principal
   WHERE principal.tenant_id = member.tenant_id AND principal.id = member.principal_id FOR UPDATE;
  IF p_authenticated_at <= principal_state.sessions_revoked_through THEN
    RAISE EXCEPTION 'session already revoked' USING ERRCODE = '42501';
  END IF;
  SELECT * INTO result FROM scopeproof.advance_session_epoch(
    member.principal_id, principal_state.session_epoch, 'User requested all-session sign-out'
  );
  PERFORM scopeproof.record_api_audit_event(
    member.principal_id, member.membership_id, p_request_id, 'session.all_revoked',
    'principal', member.principal_id::text, 'session-revoke:' || p_request_id,
    jsonb_build_object('sessionEpoch', result.session_epoch,
      'revokedThrough', to_char(result.sessions_revoked_through AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'))
  );
  RETURN QUERY SELECT result.session_epoch::bigint, result.sessions_revoked_through::timestamptz;
END;
$$;
REVOKE ALL ON FUNCTION scopeproof.revoke_own_sessions(text, timestamptz, text) FROM PUBLIC;
INSERT INTO scopeproof.schema_migrations(version, name) VALUES (4, 'session_and_repair_security');
COMMIT;
