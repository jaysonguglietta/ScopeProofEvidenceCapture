-- Run after 001_tenant_schema.sql while connected as the schema owner.
--
-- The provisioner must replace __SCOPEPROOF_RUNTIME_ROLE__ only after validating
-- it against ^tenant_[a-z0-9_]{3,56}_runtime$. PostgreSQL identifiers cannot be
-- bound as ordinary SQL parameters, so this file intentionally uses one narrow,
-- visibly unique substitution token.

BEGIN;

DO $$
DECLARE
  runtime_role CONSTANT text := '__SCOPEPROOF_RUNTIME_ROLE__';
  target record;
BEGIN
  IF runtime_role !~ '^tenant_[a-z0-9_]{3,56}_runtime$' THEN
    RAISE EXCEPTION 'invalid Scopeproof runtime role name' USING ERRCODE = '22023';
  END IF;

  SELECT rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls
    INTO STRICT target
    FROM pg_catalog.pg_roles
   WHERE rolname = runtime_role;

  IF target.rolsuper OR target.rolcreaterole OR target.rolcreatedb OR
     target.rolreplication OR target.rolbypassrls THEN
    RAISE EXCEPTION 'Scopeproof runtime role is privileged and cannot be granted application access'
      USING ERRCODE = '42501';
  END IF;

  EXECUTE format('GRANT CONNECT ON DATABASE %I TO %I', current_database(), runtime_role);
  EXECUTE format('GRANT USAGE ON SCHEMA scopeproof TO %I', runtime_role);
  EXECUTE format('GRANT EXECUTE ON FUNCTION scopeproof.current_tenant_id() TO %I', runtime_role);

  EXECUTE format(
    'GRANT SELECT ON scopeproof.tenant_identity, scopeproof.tenant_domains TO %I',
    runtime_role
  );
  EXECUTE format(
    'GRANT SELECT, INSERT, UPDATE ON scopeproof.principals, scopeproof.memberships, scopeproof.device_enrollments, scopeproof.assessments, scopeproof.integrations, scopeproof.jobs, scopeproof.upload_intents, scopeproof.evidence_artifacts, scopeproof.retention_holds, scopeproof.export_receipts, scopeproof.support_access_grants TO %I',
    runtime_role
  );
  EXECUTE format('GRANT SELECT, INSERT ON scopeproof.ingest_receipts TO %I', runtime_role);
  EXECUTE format('GRANT SELECT, INSERT ON scopeproof.audit_events TO %I', runtime_role);
  EXECUTE format('GRANT SELECT ON scopeproof.audit_heads TO %I', runtime_role);
  EXECUTE format('GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA scopeproof TO %I', runtime_role);

  EXECUTE format('ALTER ROLE %I SET search_path = pg_catalog, scopeproof', runtime_role);
  EXECUTE format('ALTER ROLE %I SET row_security = on', runtime_role);
  EXECUTE format('ALTER ROLE %I SET statement_timeout = %L', runtime_role, '15s');
  EXECUTE format('ALTER ROLE %I SET lock_timeout = %L', runtime_role, '3s');
  EXECUTE format('ALTER ROLE %I SET idle_in_transaction_session_timeout = %L', runtime_role, '15s');
END;
$$;

COMMIT;
