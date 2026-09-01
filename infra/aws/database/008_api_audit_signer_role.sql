-- Run after 001_tenant_schema.sql while connected as the schema owner.
--
-- This execute-only login may lease immutable public-API audit outbox rows,
-- append only the exact leased facts through the specialized signed procedure,
-- record bounded retry state, and read queue health. It has no generic audit
-- append permission, direct table access, or legal-hold/evidence capability.

BEGIN;

DO $$
DECLARE
  signer_role CONSTANT text := '__SCOPEPROOF_API_AUDIT_SIGNER_ROLE__';
  target record;
BEGIN
  IF signer_role !~ '^tenant_[a-z0-9_]{3,55}_audit_signer$' OR char_length(signer_role) > 63 THEN
    RAISE EXCEPTION 'invalid Scopeproof API audit-signer role name' USING ERRCODE = '22023';
  END IF;

  SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls
    INTO STRICT target
    FROM pg_catalog.pg_roles
   WHERE rolname = signer_role;
  IF target.rolsuper OR target.rolcreaterole OR target.rolcreatedb OR
     target.rolreplication OR target.rolbypassrls THEN
    RAISE EXCEPTION 'Scopeproof API audit-signer role is privileged and cannot receive signer access'
      USING ERRCODE = '42501';
  END IF;

  EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), signer_role);
  EXECUTE format('GRANT USAGE ON SCHEMA scopeproof TO %I', signer_role);
  EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA scopeproof FROM %I', signer_role);
  EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA scopeproof FROM %I', signer_role);
  EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA scopeproof FROM %I', signer_role);
  EXECUTE format('GRANT EXECUTE ON FUNCTION scopeproof.current_tenant_id() TO %I', signer_role);
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.claim_next_api_audit_event(text, timestamptz, integer) TO %I',
    signer_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.read_tenant_audit_head() TO %I',
    signer_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.append_signed_api_audit_event(scopeproof.resource_identifier, text, bigint, scopeproof.resource_identifier, timestamptz, jsonb, text, text, scopeproof.resource_identifier, text, text, jsonb, text, text, text, jsonb, text, text, text, text, text, timestamptz) TO %I',
    signer_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.record_api_audit_outbox_failure(scopeproof.resource_identifier, text, text, timestamptz) TO %I',
    signer_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.read_api_audit_outbox_health(timestamptz) TO %I',
    signer_role
  );

  EXECUTE format('ALTER ROLE %I SET search_path = pg_catalog, scopeproof', signer_role);
  EXECUTE format('ALTER ROLE %I SET row_security = on', signer_role);
  EXECUTE format('ALTER ROLE %I SET statement_timeout = %L', signer_role, '15s');
  EXECUTE format('ALTER ROLE %I SET lock_timeout = %L', signer_role, '3s');
  EXECUTE format('ALTER ROLE %I SET idle_in_transaction_session_timeout = %L', signer_role, '15s');
END;
$$;

COMMIT;
