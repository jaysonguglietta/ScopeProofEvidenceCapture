-- Run after 001_tenant_schema.sql while connected as the schema owner.
--
-- The provisioner substitutes one validated NOINHERIT login role. This role is
-- intentionally separate from the general application and ingest identities:
-- it may expire stale requests, reconcile already-approved exact-version
-- legal-hold operations, and append KMS-signed receipts, but cannot request or
-- approve an operation and has no direct table access.

BEGIN;

DO $$
DECLARE
  control_role CONSTANT text := '__SCOPEPROOF_CONTROL_ROLE__';
  target record;
BEGIN
  IF control_role !~ '^tenant_[a-z0-9_]{3,56}_control$' THEN
    RAISE EXCEPTION 'invalid Scopeproof evidence-control role name' USING ERRCODE = '22023';
  END IF;

  SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls
    INTO STRICT target
    FROM pg_catalog.pg_roles
   WHERE rolname = control_role;

  IF target.rolsuper OR target.rolcreaterole OR target.rolcreatedb OR
     target.rolreplication OR target.rolbypassrls THEN
    RAISE EXCEPTION 'Scopeproof evidence-control role is privileged and cannot be granted control access'
      USING ERRCODE = '42501';
  END IF;

  EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), control_role);
  EXECUTE format('GRANT USAGE ON SCHEMA scopeproof TO %I', control_role);
  -- Re-applying this migration also removes obsolete or accidental grants.
  EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA scopeproof FROM %I', control_role);
  EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA scopeproof FROM %I', control_role);
  EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA scopeproof FROM %I', control_role);
  EXECUTE format('GRANT EXECUTE ON FUNCTION scopeproof.current_tenant_id() TO %I', control_role);
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.append_signed_audit_event(bigint, scopeproof.resource_identifier, timestamptz, jsonb, text, text, scopeproof.resource_identifier, text, text, jsonb, text, text, text, jsonb, text, text, text, text, text, timestamptz) TO %I',
    control_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.read_exact_version_legal_hold_operation(scopeproof.resource_identifier, text) TO %I',
    control_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.begin_exact_version_legal_hold_application(scopeproof.resource_identifier, integer, text, text, text, text, text, timestamptz) TO %I',
    control_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.confirm_exact_version_legal_hold(scopeproof.resource_identifier, integer, text, text, jsonb, text, text, text, text) TO %I',
    control_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.list_pending_exact_version_legal_holds(timestamptz, integer) TO %I',
    control_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.record_exact_version_legal_hold_reconciliation_failure(scopeproof.resource_identifier, text, text, timestamptz) TO %I',
    control_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.expire_stale_exact_version_legal_hold_requests(timestamptz, integer) TO %I',
    control_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.list_unaudited_applied_legal_holds(integer) TO %I',
    control_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.acknowledge_legal_hold_recovery_publication(scopeproof.resource_identifier, text, timestamptz) TO %I',
    control_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.list_unaudited_expired_legal_holds(integer) TO %I',
    control_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.read_tenant_audit_head() TO %I',
    control_role
  );

  EXECUTE format('ALTER ROLE %I SET search_path = pg_catalog, scopeproof', control_role);
  EXECUTE format('ALTER ROLE %I SET row_security = on', control_role);
  EXECUTE format('ALTER ROLE %I SET statement_timeout = %L', control_role, '15s');
  EXECUTE format('ALTER ROLE %I SET lock_timeout = %L', control_role, '3s');
  EXECUTE format('ALTER ROLE %I SET idle_in_transaction_session_timeout = %L', control_role, '15s');
END;
$$;

COMMIT;
