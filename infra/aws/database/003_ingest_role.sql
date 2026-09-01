-- Run after 001_tenant_schema.sql while connected as the schema owner.
--
-- The provisioner substitutes one validated NOINHERIT login role. This worker
-- can only establish tenant context and call the exact promotion reconciliation
-- procedure. It cannot read or mutate application tables directly.

BEGIN;

DO $$
DECLARE
  ingest_role CONSTANT text := '__SCOPEPROOF_INGEST_ROLE__';
  target record;
BEGIN
  IF ingest_role !~ '^tenant_[a-z0-9_]{3,56}_ingest$' THEN
    RAISE EXCEPTION 'invalid Scopeproof ingest role name' USING ERRCODE = '22023';
  END IF;

  SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls
    INTO STRICT target
    FROM pg_catalog.pg_roles
   WHERE rolname = ingest_role;

  IF target.rolsuper OR target.rolcreaterole OR target.rolcreatedb OR
     target.rolreplication OR target.rolbypassrls THEN
    RAISE EXCEPTION 'Scopeproof ingest role is privileged and cannot reconcile evidence'
      USING ERRCODE = '42501';
  END IF;

  -- Re-running this script must converge to the exact intended capability
  -- set. Revoke inherited/default grants before restoring the four approved
  -- SECURITY DEFINER entry points below.
  EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA scopeproof FROM %I', ingest_role);
  EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA scopeproof FROM %I', ingest_role);
  EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA scopeproof FROM %I', ingest_role);

  EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), ingest_role);
  EXECUTE format('GRANT USAGE ON SCHEMA scopeproof TO %I', ingest_role);
  EXECUTE format('GRANT EXECUTE ON FUNCTION scopeproof.current_tenant_id() TO %I', ingest_role);
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.claim_promotion_fence(scopeproof.resource_identifier, bigint, text, timestamptz) TO %I',
    ingest_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.reconcile_promoted_evidence(scopeproof.resource_identifier, scopeproof.resource_identifier, scopeproof.resource_identifier, text, text, text, text, text, timestamptz, timestamptz, integer, integer, bigint, text, text, jsonb, text, text, text, text, text, timestamptz, timestamptz) TO %I',
    ingest_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.read_promoted_evidence_receipt(scopeproof.resource_identifier) TO %I',
    ingest_role
  );

  EXECUTE format('ALTER ROLE %I SET search_path = pg_catalog, scopeproof', ingest_role);
  EXECUTE format('ALTER ROLE %I SET row_security = on', ingest_role);
  EXECUTE format('ALTER ROLE %I SET statement_timeout = %L', ingest_role, '15s');
  EXECUTE format('ALTER ROLE %I SET lock_timeout = %L', ingest_role, '3s');
  EXECUTE format('ALTER ROLE %I SET idle_in_transaction_session_timeout = %L', ingest_role, '15s');
END;
$$;

COMMIT;
