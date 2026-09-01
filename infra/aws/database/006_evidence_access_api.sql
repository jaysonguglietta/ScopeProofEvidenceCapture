-- Run after 001_tenant_schema.sql and before 002_runtime_role.sql.
--
-- These SECURITY DEFINER functions are the only public-API read boundary for
-- immutable evidence metadata. The caller must establish the transaction-local
-- scopeproof.tenant_id context first. Bucket, key, and version identifiers are
-- returned only from authoritative promoted database rows; no client-provided
-- storage location is accepted.

BEGIN;

-- Matches the tenant-bound keyset pagination order used by the public read
-- procedure and avoids an unbounded sort as a tenant's evidence set grows.
CREATE INDEX evidence_access_captured
  ON scopeproof.evidence_artifacts (tenant_id, captured_at DESC, id DESC)
  WHERE status IN ('NEEDS_REVIEW', 'APPROVED', 'EXPIRED')
    AND object_version_id IS NOT NULL;

CREATE OR REPLACE FUNCTION scopeproof.assert_actor_permission(
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
  IF p_permission NOT IN ('evidence:read', 'evidence:collect', 'retention:manage') THEN
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
     (p_permission = 'evidence:read' AND actor_role NOT IN ('admin', 'compliance_lead', 'reviewer', 'auditor')) OR
     (p_permission = 'evidence:collect' AND actor_role NOT IN ('admin', 'compliance_lead', 'collector')) OR
     (p_permission = 'retention:manage' AND actor_role <> 'admin') THEN
    RAISE EXCEPTION 'active membership does not permit this operation' USING ERRCODE = '42501';
  END IF;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.assert_actor_permission(scopeproof.resource_identifier, text) FROM PUBLIC;

CREATE FUNCTION scopeproof.list_accessible_evidence(
  p_requested_by scopeproof.resource_identifier,
  p_cursor_captured_at timestamptz,
  p_cursor_evidence_id scopeproof.resource_identifier,
  p_result_limit integer
)
RETURNS TABLE (
  tenant_id scopeproof.tenant_identifier,
  evidence_id scopeproof.resource_identifier,
  control_id text,
  title text,
  description text,
  evidence_type text,
  source text,
  system_name text,
  status text,
  revision integer,
  content_type text,
  byte_size bigint,
  checksum_sha256 text,
  evidence_bucket text,
  object_key text,
  object_version_id text,
  captured_at timestamptz,
  retain_until timestamptz,
  created_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();
BEGIN
  IF active_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant transaction context is required' USING ERRCODE = '42501';
  END IF;
  IF p_result_limit IS NULL OR p_result_limit NOT BETWEEN 2 AND 101 OR
     ((p_cursor_captured_at IS NULL) <> (p_cursor_evidence_id IS NULL)) OR
     (p_cursor_evidence_id IS NOT NULL AND p_cursor_evidence_id::text !~ '^evd_[a-f0-9]{32}$') THEN
    RAISE EXCEPTION 'evidence page request is invalid' USING ERRCODE = '22023';
  END IF;

  PERFORM scopeproof.assert_actor_permission(p_requested_by, 'evidence:read');

  RETURN QUERY
  SELECT artifact.tenant_id,
         artifact.id,
         artifact.control_id,
         artifact.title,
         artifact.description,
         artifact.evidence_type,
         artifact.source,
         artifact.system_name,
         artifact.status,
         artifact.revision,
         artifact.content_type,
         artifact.byte_size,
         artifact.checksum_sha256::text,
         artifact.evidence_bucket,
         artifact.object_key,
         artifact.object_version_id,
         artifact.captured_at,
         artifact.retain_until,
         artifact.created_at
    FROM scopeproof.evidence_artifacts AS artifact
   WHERE artifact.tenant_id = active_tenant
     AND artifact.status IN ('NEEDS_REVIEW', 'APPROVED', 'EXPIRED')
     AND artifact.evidence_bucket IS NOT NULL
     AND artifact.object_key IS NOT NULL
     AND artifact.object_version_id IS NOT NULL
     AND artifact.retain_until IS NOT NULL
     AND (
       p_cursor_captured_at IS NULL OR
       (artifact.captured_at, artifact.id) < (p_cursor_captured_at, p_cursor_evidence_id)
     )
   ORDER BY artifact.captured_at DESC, artifact.id DESC
   LIMIT p_result_limit;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.list_accessible_evidence(
  scopeproof.resource_identifier, timestamptz, scopeproof.resource_identifier, integer
) FROM PUBLIC;

CREATE FUNCTION scopeproof.read_accessible_evidence(
  p_requested_by scopeproof.resource_identifier,
  p_evidence_id scopeproof.resource_identifier
)
RETURNS TABLE (
  tenant_id scopeproof.tenant_identifier,
  evidence_id scopeproof.resource_identifier,
  control_id text,
  title text,
  description text,
  evidence_type text,
  source text,
  system_name text,
  status text,
  revision integer,
  content_type text,
  byte_size bigint,
  checksum_sha256 text,
  evidence_bucket text,
  object_key text,
  object_version_id text,
  captured_at timestamptz,
  retain_until timestamptz,
  created_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();
BEGIN
  IF active_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant transaction context is required' USING ERRCODE = '42501';
  END IF;
  IF p_evidence_id IS NULL OR p_evidence_id::text !~ '^evd_[a-f0-9]{32}$' THEN
    RAISE EXCEPTION 'evidence identifier is invalid' USING ERRCODE = '22023';
  END IF;

  PERFORM scopeproof.assert_actor_permission(p_requested_by, 'evidence:read');

  RETURN QUERY
  SELECT artifact.tenant_id,
         artifact.id,
         artifact.control_id,
         artifact.title,
         artifact.description,
         artifact.evidence_type,
         artifact.source,
         artifact.system_name,
         artifact.status,
         artifact.revision,
         artifact.content_type,
         artifact.byte_size,
         artifact.checksum_sha256::text,
         artifact.evidence_bucket,
         artifact.object_key,
         artifact.object_version_id,
         artifact.captured_at,
         artifact.retain_until,
         artifact.created_at
    FROM scopeproof.evidence_artifacts AS artifact
   WHERE artifact.tenant_id = active_tenant
     AND artifact.id = p_evidence_id
     AND artifact.status IN ('NEEDS_REVIEW', 'APPROVED', 'EXPIRED')
     AND artifact.evidence_bucket IS NOT NULL
     AND artifact.object_key IS NOT NULL
     AND artifact.object_version_id IS NOT NULL
     AND artifact.retain_until IS NOT NULL
   LIMIT 1;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.read_accessible_evidence(
  scopeproof.resource_identifier, scopeproof.resource_identifier
) FROM PUBLIC;

INSERT INTO scopeproof.schema_migrations (version, name)
VALUES (2, 'evidence_access_api');

COMMIT;
