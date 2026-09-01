-- Run after 001_tenant_schema.sql and 006_evidence_access_api.sql while
-- connected as the schema owner.
--
-- The provisioner replaces __SCOPEPROOF_EVIDENCE_READ_ROLE__ only after
-- validating it against ^tenant_[a-z0-9_]{3,56}_read$. This login is dedicated
-- to evidence metadata listing and exact-version download issuance. It cannot
-- create upload intents or execute retention/legal-hold operations.

BEGIN;

DO $$
DECLARE
  read_role CONSTANT text := '__SCOPEPROOF_EVIDENCE_READ_ROLE__';
  target record;
BEGIN
  IF read_role !~ '^tenant_[a-z0-9_]{3,56}_read$' THEN
    RAISE EXCEPTION 'invalid Scopeproof evidence-read role name' USING ERRCODE = '22023';
  END IF;

  SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls
    INTO STRICT target
    FROM pg_catalog.pg_roles
   WHERE rolname = read_role;

  IF target.rolsuper OR target.rolcreaterole OR target.rolcreatedb OR
     target.rolreplication OR target.rolbypassrls THEN
    RAISE EXCEPTION 'Scopeproof evidence-read role is privileged and cannot receive application access'
      USING ERRCODE = '42501';
  END IF;

  EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), read_role);
  EXECUTE format('GRANT USAGE ON SCHEMA scopeproof TO %I', read_role);
  EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA scopeproof FROM %I', read_role);
  EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA scopeproof FROM %I', read_role);
  EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA scopeproof FROM %I', read_role);
  EXECUTE format('GRANT EXECUTE ON FUNCTION scopeproof.current_tenant_id() TO %I', read_role);
  EXECUTE format('GRANT EXECUTE ON FUNCTION scopeproof.resolve_active_membership(text) TO %I', read_role);
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.list_accessible_evidence(scopeproof.resource_identifier, timestamptz, scopeproof.resource_identifier, integer) TO %I',
    read_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.read_accessible_evidence(scopeproof.resource_identifier, scopeproof.resource_identifier) TO %I',
    read_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.record_api_audit_event(scopeproof.resource_identifier, scopeproof.resource_identifier, text, text, text, text, text, jsonb) TO %I',
    read_role
  );
  EXECUTE format('ALTER ROLE %I SET search_path = pg_catalog, scopeproof', read_role);
  EXECUTE format('ALTER ROLE %I SET row_security = on', read_role);
  EXECUTE format('ALTER ROLE %I SET statement_timeout = %L', read_role, '15s');
  EXECUTE format('ALTER ROLE %I SET lock_timeout = %L', read_role, '3s');
  EXECUTE format('ALTER ROLE %I SET idle_in_transaction_session_timeout = %L', read_role, '15s');
END;
$$;

COMMIT;
