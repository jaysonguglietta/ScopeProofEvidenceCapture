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
  -- This migration is an allow-list reset. Reapplying it removes legacy table
  -- grants before restoring only the nine reviewed runtime entrypoints.
  EXECUTE format('REVOKE ALL ON ALL TABLES IN SCHEMA scopeproof FROM %I', runtime_role);
  EXECUTE format('REVOKE ALL ON ALL SEQUENCES IN SCHEMA scopeproof FROM %I', runtime_role);
  EXECUTE format('REVOKE ALL ON ALL FUNCTIONS IN SCHEMA scopeproof FROM %I', runtime_role);
  EXECUTE format('GRANT EXECUTE ON FUNCTION scopeproof.current_tenant_id() TO %I', runtime_role);
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.resolve_active_membership(text) TO %I',
    runtime_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.create_upload_intent(scopeproof.resource_identifier, text, scopeproof.resource_identifier, scopeproof.resource_identifier, scopeproof.resource_identifier, scopeproof.resource_identifier, text, text, text, bigint, text, timestamptz, timestamptz, text, text, text, text, text, text, timestamptz, timestamptz, jsonb) TO %I',
    runtime_role
  );
  EXECUTE format(
    'GRANT EXECUTE ON FUNCTION scopeproof.record_api_audit_event(scopeproof.resource_identifier, scopeproof.resource_identifier, text, text, text, text, text, jsonb) TO %I',
    runtime_role
  );
  EXECUTE format('GRANT EXECUTE ON FUNCTION scopeproof.resolve_active_session_membership(text, timestamptz) TO %I', runtime_role);
  EXECUTE format('GRANT EXECUTE ON FUNCTION scopeproof.revoke_own_sessions(text, timestamptz, text) TO %I', runtime_role);
  EXECUTE format('GRANT EXECUTE ON FUNCTION scopeproof.customer_read(text, timestamptz, text, jsonb) TO %I', runtime_role);
  EXECUTE format('GRANT EXECUTE ON FUNCTION scopeproof.customer_mutate(text, timestamptz, text, jsonb, text) TO %I', runtime_role);
  EXECUTE format('GRANT EXECUTE ON FUNCTION scopeproof.customer_accept_invitation(text, timestamptz, text) TO %I', runtime_role);
END;
$$;

COMMIT;
