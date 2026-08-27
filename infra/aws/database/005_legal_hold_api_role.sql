-- Run after 001_tenant_schema.sql while connected as the schema owner.
--
-- This public-API login can only resolve the active tenant membership, create
-- a legal-hold request, or record a second administrator's approval. It cannot
-- read/apply queued work, access tables directly, append audit events, or
-- invoke any reconciliation boundary.

BEGIN;

DO $$
DECLARE
  legal_api_role CONSTANT text := '__SCOPEPROOF_LEGAL_API_ROLE__';
  target record;
BEGIN
  IF legal_api_role !~ '^tenant_[a-z0-9_]{3,56}_legal_api$' THEN
    RAISE EXCEPTION 'invalid Scopeproof legal-hold API role name' USING ERRCODE = '22023';
  END IF;

  SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls
    INTO STRICT target
    FROM pg_catalog.pg_roles
   WHERE rolname = legal_api_role;

  IF target.rolsuper OR target.rolcreaterole OR target.rolcreatedb OR
     target.rolreplication OR target.rolbypassrls THEN
    RAISE EXCEPTION 'Scopeproof legal-hold API role is privileged and cannot receive workflow access'
      USING ERRCODE = '42501';
  END IF;

  EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), legal_api_role);
  EXECUTE format('GRANT USAGE ON SCHEMA scopeproof TO %I', legal_api_role);
  -- Re-applying this migration is an allow-list reset, not an additive grant.
  EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA scopeproof FROM %I', legal_api_role);
  EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA scopeproof FROM %I', legal_api_role);
  EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA scopeproof FROM %I', legal_api_role);
  EXECUTE format('GRANT EXECUTE ON FUNCTION scopeproof.current_tenant_id() TO %I', legal_api_role);
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.resolve_active_membership(text) TO %I',
    legal_api_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.reserve_exact_version_legal_hold(scopeproof.resource_identifier, scopeproof.resource_identifier, scopeproof.resource_identifier, text, text, text, text, text, text, text, scopeproof.resource_identifier, integer, timestamptz, text, text) TO %I',
    legal_api_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.approve_exact_version_legal_hold(scopeproof.resource_identifier, text, scopeproof.resource_identifier, timestamptz, text, text) TO %I',
    legal_api_role
  );

  EXECUTE format('ALTER ROLE %I SET search_path = pg_catalog, scopeproof', legal_api_role);
  EXECUTE format('ALTER ROLE %I SET row_security = on', legal_api_role);
  EXECUTE format('ALTER ROLE %I SET statement_timeout = %L', legal_api_role, '15s');
  EXECUTE format('ALTER ROLE %I SET lock_timeout = %L', legal_api_role, '3s');
  EXECUTE format('ALTER ROLE %I SET idle_in_transaction_session_timeout = %L', legal_api_role, '15s');
END;
$$;

COMMIT;
