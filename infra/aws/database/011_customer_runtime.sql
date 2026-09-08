-- Forward-only schema version 5: operator-assisted, existing-subject customer pilot.
-- Apply after exact historical 001, 006, 009, 010 and before role grants.
-- No public login receives table DML, storage-key choice, or owner authority.
BEGIN;

-- Shared triggers must branch by table BEFORE PostgreSQL resolves fields that
-- do not exist on other row types. Boolean short-circuiting cannot do this.
CREATE OR REPLACE FUNCTION scopeproof.assert_database_tenant()
RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,scopeproof AS $$
DECLARE expected scopeproof.tenant_identity%ROWTYPE;
BEGIN
  SELECT * INTO STRICT expected FROM scopeproof.tenant_identity WHERE singleton;
  IF NEW.tenant_id IS DISTINCT FROM expected.tenant_id THEN RAISE EXCEPTION 'tenant boundary violation' USING ERRCODE='42501'; END IF;
  IF TG_TABLE_NAME='upload_intents' THEN
    IF NEW.quarantine_bucket IS DISTINCT FROM expected.quarantine_bucket THEN RAISE EXCEPTION 'quarantine destination violation' USING ERRCODE='42501'; END IF;
  ELSIF TG_TABLE_NAME='evidence_artifacts' THEN
    IF NEW.evidence_bucket IS NOT NULL AND (NEW.evidence_bucket IS DISTINCT FROM expected.evidence_bucket OR NEW.kms_key_arn IS DISTINCT FROM expected.evidence_kms_key_arn OR NEW.object_lock_mode IS DISTINCT FROM expected.retention_mode) THEN RAISE EXCEPTION 'evidence destination violation' USING ERRCODE='42501'; END IF;
  ELSIF TG_TABLE_NAME='ingest_receipts' THEN
    IF NEW.kms_key_arn IS DISTINCT FROM expected.evidence_kms_key_arn OR NEW.signing_key_arn IS DISTINCT FROM expected.audit_signing_key_arn OR NEW.object_lock_mode IS DISTINCT FROM expected.retention_mode THEN RAISE EXCEPTION 'receipt encryption key violation' USING ERRCODE='42501'; END IF;
  ELSIF TG_TABLE_NAME='audit_events' THEN
    IF NEW.signing_key_arn IS DISTINCT FROM expected.audit_signing_key_arn THEN RAISE EXCEPTION 'audit signing key violation' USING ERRCODE='42501'; END IF;
  ELSIF TG_TABLE_NAME IN ('retention_holds','legal_hold_operations') THEN
    IF NEW.evidence_bucket IS DISTINCT FROM expected.evidence_bucket THEN RAISE EXCEPTION 'legal hold evidence destination violation' USING ERRCODE='42501'; END IF;
  END IF;
  RETURN NEW;
END; $$;
REVOKE ALL ON FUNCTION scopeproof.assert_database_tenant() FROM PUBLIC;

-- Preserve the already-applied 009 hardening when replacing only row guards.
DO $$ DECLARE definition text; BEGIN
  SELECT pg_get_functiondef('scopeproof.protect_immutable_security_fields()'::regprocedure) INTO definition;
  IF position('IF TG_TABLE_NAME = ''jobs'' AND' IN definition)=0 OR position('IF TG_TABLE_NAME = ''evidence_artifacts'' AND OLD.status' IN definition)=0 THEN RAISE EXCEPTION 'unexpected immutable transition lineage'; END IF;
  definition := replace(definition,'IF TG_TABLE_NAME = ''jobs'' AND'||chr(10)||'     (NEW.revision','IF TG_TABLE_NAME = ''jobs'' THEN'||chr(10)||'    IF (NEW.revision');
  definition := replace(definition,'RAISE EXCEPTION ''job state transition violation'' USING ERRCODE = ''23514'';'||chr(10)||'  END IF;','RAISE EXCEPTION ''job state transition violation'' USING ERRCODE = ''23514'';'||chr(10)||'    END IF;'||chr(10)||'  END IF;');
  definition := replace(definition,'IF TG_TABLE_NAME = ''evidence_artifacts'' AND OLD.status','IF TG_TABLE_NAME = ''evidence_artifacts'' THEN'||chr(10)||'    IF OLD.status');
  definition := replace(definition,'RAISE EXCEPTION ''evidence state transition violation'' USING ERRCODE = ''23514'';'||chr(10)||'  END IF;','RAISE EXCEPTION ''evidence state transition violation'' USING ERRCODE = ''23514'';'||chr(10)||'    END IF;'||chr(10)||'  END IF;');
  definition := replace(definition,'IF TG_TABLE_NAME = ''support_access_grants'' AND OLD.revoked_at IS NOT NULL THEN','IF TG_TABLE_NAME = ''support_access_grants'' THEN'||chr(10)||'    IF OLD.revoked_at IS NOT NULL THEN');
  definition := replace(definition,'RAISE EXCEPTION ''revoked support grant is immutable'' USING ERRCODE = ''42501'';'||chr(10)||'  END IF;','RAISE EXCEPTION ''revoked support grant is immutable'' USING ERRCODE = ''42501'';'||chr(10)||'    END IF;'||chr(10)||'  END IF;');
  EXECUTE definition;
END; $$;

-- PostgreSQL ARE repetition bounds stop at255. Preserve the original 1..512
-- version alphabet/length contract with legal bounded repetitions. This fixes
-- the historical hold/rejection predicates without relaxing validation.
DO $$
DECLARE target record; definition text;
  needle CONSTANT text := '[A-Za-z0-9._:+/=-]{0,511}';
  replacement CONSTANT text := '[A-Za-z0-9._:+/=-]{0,255}[A-Za-z0-9._:+/=-]{0,255}[A-Za-z0-9._:+/=-]?';
BEGIN
  FOR target IN SELECT p.oid FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='scopeproof' LOOP
    definition := pg_get_functiondef(target.oid);
    IF position(needle IN definition)>0 THEN definition := replace(definition,needle,replacement); END IF;
    -- RETURNS TABLE(operation_state ...) introduces a PL/pgSQL output variable;
    -- qualify the reviewed UPDATE predicate so the column is unambiguous.
    IF position('UPDATE scopeproof.legal_hold_operations' IN definition)>0 AND position('AND operation_state =' IN definition)>0 THEN definition := replace(definition,'AND operation_state =','AND legal_hold_operations.operation_state ='); END IF;
    IF definition IS DISTINCT FROM pg_get_functiondef(target.oid) THEN EXECUTE definition; END IF;
  END LOOP;
  FOR target IN SELECT c.conname,c.conrelid::regclass AS relation,pg_get_constraintdef(c.oid) AS definition FROM pg_constraint c JOIN pg_namespace n ON n.oid=c.connamespace WHERE n.nspname='scopeproof' AND c.contype='c' AND position(needle IN pg_get_constraintdef(c.oid))>0 LOOP
    EXECUTE format('ALTER TABLE %s DROP CONSTRAINT %I',target.relation,target.conname);
    EXECUTE format('ALTER TABLE %s ADD CONSTRAINT %I %s',target.relation,target.conname,replace(target.definition,needle,replacement));
  END LOOP;
END; $$;

ALTER TABLE scopeproof.memberships ADD COLUMN revision integer NOT NULL DEFAULT 0 CHECK (revision >= 0), ADD COLUMN invitation_expires_at timestamptz;
ALTER TABLE scopeproof.device_enrollments ADD COLUMN revision integer NOT NULL DEFAULT 0 CHECK (revision >= 0);
ALTER TABLE scopeproof.assessments ADD COLUMN revision integer NOT NULL DEFAULT 0 CHECK (revision >= 0), ADD COLUMN catalog_id text, ADD COLUMN creation_request_sha256 text;

CREATE TABLE scopeproof.customer_control_catalogs (
  id text PRIMARY KEY, framework text NOT NULL, version text NOT NULL, title text NOT NULL,
  controls jsonb NOT NULL CHECK (jsonb_typeof(controls) = 'array'), digest_sha256 text NOT NULL CHECK (digest_sha256 ~ '^[a-f0-9]{64}$')
);
REVOKE ALL ON TABLE scopeproof.customer_control_catalogs FROM PUBLIC;
ALTER TABLE scopeproof.assessments ADD CONSTRAINT assessments_customer_catalog_fk FOREIGN KEY (catalog_id) REFERENCES scopeproof.customer_control_catalogs(id);

CREATE FUNCTION scopeproof.customer_exact_body(p_body jsonb, p_keys text[])
RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog, scopeproof AS $$
BEGIN
  IF p_body IS NULL OR jsonb_typeof(p_body) <> 'object' OR octet_length(p_body::text) > 16384 OR
    (SELECT coalesce(array_agg(key ORDER BY key), ARRAY[]::text[]) FROM jsonb_object_keys(p_body) AS key) IS DISTINCT FROM
    (SELECT array_agg(key ORDER BY key) FROM unnest(p_keys) AS key) THEN
    RAISE EXCEPTION 'invalid customer body' USING ERRCODE = '22023';
  END IF;
END; $$;
REVOKE ALL ON FUNCTION scopeproof.customer_exact_body(jsonb,text[]) FROM PUBLIC;

CREATE FUNCTION scopeproof.customer_actor(p_subject text, p_authenticated_at timestamptz, p_roles text[])
RETURNS TABLE(principal_id scopeproof.resource_identifier, membership_id scopeproof.resource_identifier, role text)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, scopeproof AS $$
BEGIN
  IF scopeproof.current_tenant_id() IS NULL OR NOT EXISTS (SELECT 1 FROM scopeproof.tenant_identity WHERE tenant_id = scopeproof.current_tenant_id() AND status = 'ACTIVE') THEN RAISE EXCEPTION 'tenant unavailable' USING ERRCODE = '42501'; END IF;
  RETURN QUERY SELECT member.principal_id, member.membership_id, member.role
    FROM scopeproof.resolve_active_session_membership(p_subject,p_authenticated_at) AS member WHERE member.role = ANY(p_roles);
  IF NOT FOUND THEN RAISE EXCEPTION 'active authorized session required' USING ERRCODE = '42501'; END IF;
END; $$;
REVOKE ALL ON FUNCTION scopeproof.customer_actor(text,timestamptz,text[]) FROM PUBLIC;

ALTER TABLE scopeproof.api_audit_outbox DROP CONSTRAINT api_audit_outbox_action_check;
ALTER TABLE scopeproof.api_audit_outbox ADD CONSTRAINT api_audit_outbox_action_check CHECK (action IN (
  'evidence.upload_intent_issued','evidence.search_performed','evidence.download_intent_issued','evidence.legal_hold_requested','evidence.legal_hold_approved','session.all_revoked',
  'customer.members_invited','customer.members_updated','customer.invitation_accepted','customer.devices_enrolled','customer.devices_revoked','customer.assessments_created','customer.assessments_updated','customer.evidence_reviewed'));
ALTER TABLE scopeproof.api_audit_outbox DROP CONSTRAINT api_audit_outbox_resource_type_check;
ALTER TABLE scopeproof.api_audit_outbox ADD CONSTRAINT api_audit_outbox_resource_type_check CHECK (resource_type IN ('evidence','evidence_collection','legal_hold_operation','principal','device','assessment'));

-- Private helper: called only after action-specific authorization and mutation
-- in the same transaction. Do not grant this function to a runtime login.
CREATE FUNCTION scopeproof.record_customer_event(p_user scopeproof.resource_identifier,p_membership scopeproof.resource_identifier,p_request text,p_action text,p_type text,p_id text,p_details jsonb)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, scopeproof AS $$
DECLARE tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id(); digest text; event_id scopeproof.resource_identifier; idem text := 'customer:' || p_request || ':' || p_action;
BEGIN
  IF tenant IS NULL OR p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$' OR p_details IS NULL OR jsonb_typeof(p_details) <> 'object' THEN RAISE EXCEPTION 'invalid customer audit facts' USING ERRCODE = '22023'; END IF;
  digest := encode(sha256(convert_to('scopeproof-api-audit-outbox-v1'||chr(10)||tenant::text||chr(10)||p_user::text||chr(10)||p_membership::text||chr(10)||p_action||chr(10)||p_type||chr(10)||p_id||chr(10)||idem||chr(10)||p_details::text,'UTF8')),'hex');
  event_id := ('aob_'||substr(digest,1,32))::scopeproof.resource_identifier;
  INSERT INTO scopeproof.api_audit_outbox(tenant_id,id,actor_user_id,membership_id,request_id,action,resource_type,resource_id,idempotency_key,details,event_digest)
    VALUES(tenant,event_id,p_user,p_membership,p_request,p_action,p_type,p_id,idem,p_details,digest);
  INSERT INTO scopeproof.api_audit_outbox_work(tenant_id,outbox_id) VALUES(tenant,event_id);
END; $$;
REVOKE ALL ON FUNCTION scopeproof.record_customer_event(scopeproof.resource_identifier,scopeproof.resource_identifier,text,text,text,text,jsonb) FROM PUBLIC;

CREATE FUNCTION scopeproof.customer_validate_scope(p_body jsonb)
RETURNS void LANGUAGE plpgsql SET search_path = pg_catalog, scopeproof AS $$
DECLARE catalog jsonb;
BEGIN
  SELECT controls INTO catalog FROM scopeproof.customer_control_catalogs WHERE id = p_body->>'catalogId';
  IF catalog IS NULL OR jsonb_typeof(p_body->'systems') IS DISTINCT FROM 'array' OR jsonb_typeof(p_body->'controls') IS DISTINCT FROM 'array' OR
    jsonb_array_length(p_body->'systems') > 250 OR jsonb_array_length(p_body->'controls') > 500 OR
    EXISTS (SELECT 1 FROM jsonb_array_elements(p_body->'systems') AS value WHERE jsonb_typeof(value) <> 'string' OR char_length(value#>>'{}') NOT BETWEEN 1 AND 160 OR (value#>>'{}') ~ '[[:cntrl:]]') OR
    EXISTS (SELECT 1 FROM jsonb_array_elements(p_body->'controls') AS selected(value) WHERE jsonb_typeof(selected.value) <> 'string' OR NOT EXISTS (SELECT 1 FROM jsonb_array_elements(catalog) AS catalog_control(value) WHERE catalog_control.value->>'id' = selected.value#>>'{}')) OR
    (p_body->>'status' <> 'DRAFT' AND (jsonb_array_length(p_body->'systems') = 0 OR jsonb_array_length(p_body->'controls') = 0)) THEN
    RAISE EXCEPTION 'explicit versioned scope required' USING ERRCODE = '22023';
  END IF;
  IF (SELECT count(*) FROM jsonb_array_elements(p_body->'systems')) <> (SELECT count(DISTINCT value) FROM jsonb_array_elements(p_body->'systems') AS value) OR
     (SELECT count(*) FROM jsonb_array_elements(p_body->'controls')) <> (SELECT count(DISTINCT value) FROM jsonb_array_elements(p_body->'controls') AS value) THEN RAISE EXCEPTION 'scope values must be unique' USING ERRCODE = '22023'; END IF;
END; $$;
REVOKE ALL ON FUNCTION scopeproof.customer_validate_scope(jsonb) FROM PUBLIC;

-- Existing legacy assessments remain explicitly legacy; this forward change
-- does not invent a catalog for historical evidence or block old repair facts.
-- Every assessment created by the customer API has a non-null reviewed catalog.
CREATE FUNCTION scopeproof.enforce_customer_evidence_scope()
RETURNS trigger LANGUAGE plpgsql SET search_path = pg_catalog, scopeproof AS $$
DECLARE assessment scopeproof.assessments%ROWTYPE;
BEGIN
  SELECT * INTO assessment FROM scopeproof.assessments WHERE tenant_id = NEW.tenant_id AND id = NEW.assessment_id FOR SHARE;
  IF assessment.catalog_id IS NOT NULL AND (assessment.status <> 'ACTIVE' OR NOT assessment.controls ? NEW.control_id OR NOT assessment.systems ? NEW.system_name) THEN RAISE EXCEPTION 'evidence outside current assessment scope' USING ERRCODE = '42501'; END IF;
  RETURN NEW;
END; $$;
REVOKE ALL ON FUNCTION scopeproof.enforce_customer_evidence_scope() FROM PUBLIC;
CREATE TRIGGER enforce_customer_scope BEFORE INSERT ON scopeproof.evidence_artifacts FOR EACH ROW EXECUTE FUNCTION scopeproof.enforce_customer_evidence_scope();

-- A reviewer rejection retains the immutable promoted bytes. Scanner rejection
-- before promotion still has no final-object tuple, as in the historical schema.
DO $$ DECLARE target text; BEGIN
  SELECT conname INTO STRICT target FROM pg_constraint WHERE conrelid = 'scopeproof.evidence_artifacts'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%status%NEEDS_REVIEW%APPROVED%EXPIRED%PURGED%evidence_bucket%';
  EXECUTE format('ALTER TABLE scopeproof.evidence_artifacts DROP CONSTRAINT %I', target);
END; $$;
ALTER TABLE scopeproof.evidence_artifacts ADD CONSTRAINT evidence_promotion_tuple_state CHECK (
  ((status IN ('NEEDS_REVIEW','APPROVED','EXPIRED','PURGED')) = (evidence_bucket IS NOT NULL AND object_key IS NOT NULL AND object_version_id IS NOT NULL AND kms_key_arn IS NOT NULL AND object_lock_mode IS NOT NULL AND retain_until IS NOT NULL)) OR
  (status = 'REJECTED' AND evidence_bucket IS NOT NULL AND object_key IS NOT NULL AND object_version_id IS NOT NULL AND kms_key_arn IS NOT NULL AND object_lock_mode IS NOT NULL AND retain_until IS NOT NULL));

CREATE FUNCTION scopeproof.customer_read(p_subject text,p_authenticated_at timestamptz,p_view text,p_body jsonb)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, scopeproof AS $$
DECLARE tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id(); actor record; rows jsonb; result_limit integer; cursor_id text; target scopeproof.evidence_artifacts%ROWTYPE; catalogs jsonb;
BEGIN
  SELECT * INTO STRICT actor FROM scopeproof.customer_actor(p_subject,p_authenticated_at,ARRAY['admin','compliance_lead','reviewer','auditor','collector']);
  IF p_view = 'evidence.status' THEN
    PERFORM scopeproof.customer_exact_body(p_body,ARRAY['evidenceId']);
    IF p_body->>'evidenceId' IS NULL OR p_body->>'evidenceId' !~ '^evd_[a-f0-9]{32}$' THEN RAISE EXCEPTION 'invalid evidence identifier' USING ERRCODE = '22023'; END IF;
    SELECT * INTO target FROM scopeproof.evidence_artifacts WHERE tenant_id = tenant AND id::text = p_body->>'evidenceId';
    IF NOT FOUND OR (actor.role = 'collector' AND target.created_by <> actor.principal_id) OR (actor.role = 'auditor' AND (target.approved_by IS NULL OR target.status NOT IN ('APPROVED','EXPIRED'))) THEN RAISE EXCEPTION 'evidence unavailable' USING ERRCODE = 'P0002'; END IF;
    RETURN jsonb_build_object('tenantId',tenant,'evidenceId',target.id,'assessmentId',target.assessment_id,'controlId',target.control_id,'systemName',target.system_name,'title',target.title,'status',target.status,'revision',target.revision,'createdBy',target.created_by,'approvedBy',target.approved_by,'expiresAt',target.expires_at,'capturedAt',target.captured_at,'checksumSha256',target.checksum_sha256,'byteSize',target.byte_size);
  END IF;
  PERFORM scopeproof.customer_exact_body(p_body,ARRAY['cursor','limit']);
  IF jsonb_typeof(p_body->'limit') IS DISTINCT FROM 'number' OR (p_body->>'limit') !~ '^[1-9][0-9]{0,2}$' THEN RAISE EXCEPTION 'invalid page limit' USING ERRCODE = '22023'; END IF;
  result_limit := (p_body->>'limit')::integer; cursor_id := p_body->>'cursor';
  IF result_limit NOT BETWEEN 1 AND 100 OR (cursor_id IS NOT NULL AND cursor_id !~ '^(usr|dev|asm)_[a-f0-9]{32}$') THEN RAISE EXCEPTION 'invalid page' USING ERRCODE = '22023'; END IF;
  IF p_view = 'members.search' AND actor.role = 'admin' THEN
    SELECT coalesce(jsonb_agg(value ORDER BY value->>'id'),'[]'::jsonb) INTO rows FROM (SELECT jsonb_build_object('id',p.id,'subject',p.cognito_sub,'email',p.email,'displayName',p.display_name,'role',m.role,'status',m.status,'revision',m.revision,'invitationExpiresAt',m.invitation_expires_at) AS value FROM scopeproof.principals p JOIN scopeproof.memberships m ON m.tenant_id=p.tenant_id AND m.principal_id=p.id WHERE p.tenant_id=tenant AND (cursor_id IS NULL OR p.id::text>cursor_id) ORDER BY p.id LIMIT result_limit+1) page;
  ELSIF p_view = 'devices.search' AND actor.role IN ('admin','compliance_lead') THEN
    SELECT coalesce(jsonb_agg(value ORDER BY value->>'id'),'[]'::jsonb) INTO rows FROM (SELECT jsonb_build_object('id',d.id,'displayName',d.display_name,'principalId',d.principal_id,'status',d.status,'revision',d.revision,'enrolledAt',d.enrolled_at,'lastSeenAt',d.last_seen_at,'publicKeySha256',d.device_public_key_sha256) AS value FROM scopeproof.device_enrollments d WHERE d.tenant_id=tenant AND (cursor_id IS NULL OR d.id::text>cursor_id) ORDER BY d.id LIMIT result_limit+1) page;
  ELSIF p_view = 'assessments.search' THEN
    SELECT coalesce(jsonb_agg(value ORDER BY value->>'id'),'[]'::jsonb) INTO rows FROM (SELECT jsonb_build_object('id',a.id,'name',a.name,'status',a.status,'revision',a.revision,'framework',a.framework,'catalogId',a.catalog_id,'systems',a.systems,'controls',a.controls,'periodStart',a.period_start,'periodEnd',a.period_end,'scopeLocked',a.status<>'DRAFT' OR EXISTS(SELECT 1 FROM scopeproof.evidence_artifacts e WHERE e.tenant_id=tenant AND e.assessment_id=a.id)) AS value FROM scopeproof.assessments a WHERE a.tenant_id=tenant AND (actor.role<>'collector' OR a.status='ACTIVE') AND (cursor_id IS NULL OR a.id::text>cursor_id) ORDER BY a.id LIMIT result_limit+1) page;
    SELECT coalesce(jsonb_agg(jsonb_build_object('id',id,'title',title,'framework',framework,'version',version,'controls',controls,'digestSha256',digest_sha256) ORDER BY id),'[]'::jsonb) INTO catalogs FROM scopeproof.customer_control_catalogs;
  ELSE RAISE EXCEPTION 'customer read not permitted' USING ERRCODE = '42501'; END IF;
  RETURN jsonb_build_object('tenantId',tenant,'items',(SELECT coalesce(jsonb_agg(value ORDER BY ord),'[]'::jsonb) FROM jsonb_array_elements(rows) WITH ORDINALITY AS item(value,ord) WHERE ord<=result_limit),'nextCursor',CASE WHEN jsonb_array_length(rows)>result_limit THEN rows->(result_limit-1)->>'id' ELSE NULL END,'catalogs',coalesce(catalogs,'[]'::jsonb));
END; $$;
REVOKE ALL ON FUNCTION scopeproof.customer_read(text,timestamptz,text,jsonb) FROM PUBLIC;

CREATE FUNCTION scopeproof.customer_accept_invitation(p_subject text,p_authenticated_at timestamptz,p_request text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, scopeproof AS $$
DECLARE tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id(); principal scopeproof.principals%ROWTYPE; member scopeproof.memberships%ROWTYPE;
BEGIN
  IF tenant IS NULL OR p_subject IS NULL OR char_length(p_subject) NOT BETWEEN 8 AND 200 OR p_authenticated_at IS NULL OR NOT isfinite(p_authenticated_at) OR NOT EXISTS(SELECT 1 FROM scopeproof.tenant_identity WHERE tenant_id=tenant AND status='ACTIVE') THEN RAISE EXCEPTION 'invitation unavailable' USING ERRCODE = '42501'; END IF;
  SELECT * INTO principal FROM scopeproof.principals WHERE tenant_id=tenant AND cognito_sub=p_subject FOR UPDATE;
  IF NOT FOUND OR p_authenticated_at<=principal.sessions_revoked_through THEN RAISE EXCEPTION 'invitation unavailable' USING ERRCODE = '42501'; END IF;
  SELECT * INTO member FROM scopeproof.memberships WHERE tenant_id=tenant AND principal_id=principal.id FOR UPDATE;
  IF NOT FOUND OR member.status NOT IN ('INVITED','ACTIVE') OR principal.status NOT IN ('INVITED','ACTIVE') THEN RAISE EXCEPTION 'invitation unavailable' USING ERRCODE = '42501'; END IF;
  IF member.status='ACTIVE' AND principal.status='ACTIVE' THEN RETURN jsonb_build_object('tenantId',tenant,'userId',principal.id,'membershipId',member.id,'role',member.role,'status','ACTIVE'); END IF;
  IF member.status<>'INVITED' OR principal.status<>'INVITED' OR member.invitation_expires_at IS NULL OR member.invitation_expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'invitation expired or unavailable' USING ERRCODE = '42501'; END IF;
  UPDATE scopeproof.principals SET status='ACTIVE' WHERE tenant_id=tenant AND id=principal.id;
  UPDATE scopeproof.memberships SET status='ACTIVE',activated_at=clock_timestamp(),revision=revision+1 WHERE tenant_id=tenant AND id=member.id;
  PERFORM scopeproof.record_customer_event(principal.id,member.id,p_request,'customer.invitation_accepted','principal',principal.id::text,jsonb_build_object('previousStatus','INVITED','status','ACTIVE'));
  RETURN jsonb_build_object('tenantId',tenant,'userId',principal.id,'membershipId',member.id,'role',member.role,'status','ACTIVE');
END; $$;
REVOKE ALL ON FUNCTION scopeproof.customer_accept_invitation(text,timestamptz,text) FROM PUBLIC;

-- Remaining action procedures and the audited-function correction follow.

CREATE FUNCTION scopeproof.customer_text(p_body jsonb,p_key text,p_min integer,p_max integer)
RETURNS text LANGUAGE plpgsql SET search_path = pg_catalog, scopeproof AS $$
DECLARE value text := p_body->>p_key;
BEGIN
  IF jsonb_typeof(p_body->p_key) IS DISTINCT FROM 'string' OR value IS NULL OR value<>btrim(value) OR char_length(value) NOT BETWEEN p_min AND p_max OR value ~ '[[:cntrl:]]' THEN RAISE EXCEPTION 'invalid customer text field' USING ERRCODE='22023'; END IF;
  RETURN value;
END; $$;
REVOKE ALL ON FUNCTION scopeproof.customer_text(jsonb,text,integer,integer) FROM PUBLIC;

CREATE FUNCTION scopeproof.customer_revision(p_body jsonb)
RETURNS integer LANGUAGE plpgsql SET search_path = pg_catalog, scopeproof AS $$
BEGIN
  IF jsonb_typeof(p_body->'expectedRevision') IS DISTINCT FROM 'number' OR (p_body->>'expectedRevision') !~ '^(0|[1-9][0-9]{0,9})$' THEN RAISE EXCEPTION 'expected revision required' USING ERRCODE='22023'; END IF;
  RETURN (p_body->>'expectedRevision')::integer;
END; $$;
REVOKE ALL ON FUNCTION scopeproof.customer_revision(jsonb) FROM PUBLIC;

CREATE FUNCTION scopeproof.customer_mutate(p_subject text,p_authenticated_at timestamptz,p_action text,p_body jsonb,p_request text)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, scopeproof AS $$
DECLARE
  tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id(); actor record;
  principal scopeproof.principals%ROWTYPE; member scopeproof.memberships%ROWTYPE;
  device scopeproof.device_enrollments%ROWTYPE; assessment scopeproof.assessments%ROWTYPE; evidence scopeproof.evidence_artifacts%ROWTYPE;
  target_id scopeproof.resource_identifier; membership_id scopeproof.resource_identifier;
  expected integer; new_role text; new_status text; name text; subject text; email text; key_hash text; decision text; reason text;
  period_start date; period_end date; catalog scopeproof.customer_control_catalogs%ROWTYPE;
  creation_digest text; detail jsonb; output jsonb; audit_action text; resource_type text;
BEGIN
  SELECT * INTO STRICT actor FROM scopeproof.customer_actor(p_subject,p_authenticated_at,ARRAY['admin','compliance_lead','reviewer','collector']);
  IF p_request IS NULL OR p_request !~ '^[A-Za-z0-9][A-Za-z0-9._:-]{7,127}$' THEN RAISE EXCEPTION 'request id required' USING ERRCODE='22023'; END IF;
  IF p_action='members.invite' AND actor.role='admin' THEN
    PERFORM scopeproof.customer_exact_body(p_body,ARRAY['subject','email','displayName','role']);
    subject := scopeproof.customer_text(p_body,'subject',8,200); email := scopeproof.customer_text(p_body,'email',3,254); name := scopeproof.customer_text(p_body,'displayName',1,160); new_role := scopeproof.customer_text(p_body,'role',5,20);
    IF email<>lower(email) OR email !~ '^[^[:space:]@]+@[^[:space:]@]+\.[^[:space:]@]+$' OR new_role NOT IN ('admin','compliance_lead','reviewer','auditor','collector') THEN RAISE EXCEPTION 'invitation fields invalid' USING ERRCODE='22023'; END IF;
    target_id := ('usr_'||substr(encode(sha256(convert_to('customer-subject-v1'||chr(10)||tenant::text||chr(10)||subject,'UTF8')),'hex'),1,32))::scopeproof.resource_identifier;
    membership_id := ('mem_'||substr(encode(sha256(convert_to(tenant::text||chr(10)||subject,'UTF8')),'hex'),1,32))::scopeproof.resource_identifier;
    INSERT INTO scopeproof.principals(tenant_id,id,cognito_sub,email,display_name,status) VALUES(tenant,target_id,subject,email,name,'INVITED');
    INSERT INTO scopeproof.memberships(tenant_id,id,principal_id,role,status,invited_by,invited_at,invitation_expires_at) VALUES(tenant,membership_id,target_id,new_role,'INVITED',actor.principal_id,clock_timestamp(),clock_timestamp()+interval '7 days');
    output := jsonb_build_object('id',target_id,'subject',subject,'email',email,'displayName',name,'role',new_role,'status','INVITED','revision',0,'invitationMode','existing_cognito_subject');
    audit_action := 'customer.members_invited'; resource_type := 'principal'; detail := jsonb_build_object('role',new_role,'status','INVITED','invitationMode','existing_cognito_subject');
  ELSIF p_action='members.update' AND actor.role='admin' THEN
    PERFORM scopeproof.customer_exact_body(p_body,ARRAY['principalId','expectedRevision','status','role']);
    target_id := scopeproof.customer_text(p_body,'principalId',36,36)::scopeproof.resource_identifier; expected := scopeproof.customer_revision(p_body); new_role := scopeproof.customer_text(p_body,'role',5,20); new_status := scopeproof.customer_text(p_body,'status',6,9);
    IF target_id::text !~ '^usr_[a-f0-9]{32}$' OR new_role NOT IN ('admin','compliance_lead','reviewer','auditor','collector') OR new_status NOT IN ('ACTIVE','SUSPENDED','REVOKED') THEN RAISE EXCEPTION 'member transition invalid' USING ERRCODE='22023'; END IF;
    -- Serializes all changes affecting the last active administrator.
    PERFORM 1 FROM scopeproof.tenant_identity WHERE tenant_id=tenant FOR UPDATE;
    SELECT * INTO member FROM scopeproof.memberships WHERE tenant_id=tenant AND principal_id=target_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'member unavailable' USING ERRCODE='P0002'; END IF;
    IF member.revision<>expected OR member.status='REVOKED' OR (member.status='INVITED' AND new_status<>'REVOKED') OR target_id=actor.principal_id THEN RAISE EXCEPTION 'member changed or protected' USING ERRCODE='40001'; END IF;
    IF member.role='admin' AND member.status='ACTIVE' AND (new_role<>'admin' OR new_status<>'ACTIVE') AND (SELECT count(*) FROM scopeproof.memberships m JOIN scopeproof.principals p ON p.tenant_id=m.tenant_id AND p.id=m.principal_id WHERE m.tenant_id=tenant AND m.status='ACTIVE' AND m.role='admin' AND p.status='ACTIVE')<=1 THEN RAISE EXCEPTION 'last administrator protected' USING ERRCODE='42501'; END IF;
    UPDATE scopeproof.memberships SET role=new_role,status=new_status,revision=revision+1,revoked_at=CASE WHEN new_status='REVOKED' THEN clock_timestamp() ELSE NULL END WHERE tenant_id=tenant AND id=member.id;
    UPDATE scopeproof.principals SET status=CASE WHEN new_status='REVOKED' THEN 'DISABLED' ELSE status END,session_epoch=session_epoch+1,sessions_revoked_through=greatest(sessions_revoked_through,date_trunc('second',clock_timestamp())),session_revocation_reason='Customer membership changed',session_revoked_by=session_user WHERE tenant_id=tenant AND id=target_id;
    IF new_status='REVOKED' THEN UPDATE scopeproof.device_enrollments SET status='REVOKED',revoked_at=clock_timestamp(),revision=revision+1 WHERE tenant_id=tenant AND principal_id=target_id AND status<>'REVOKED'; END IF;
    output := jsonb_build_object('id',target_id,'role',new_role,'status',new_status,'revision',expected+1,'reauthenticationRequired',true);
    audit_action := 'customer.members_updated'; resource_type := 'principal'; detail := jsonb_build_object('previousRole',member.role,'role',new_role,'previousStatus',member.status,'status',new_status,'previousRevision',expected,'revision',expected+1);
  ELSIF p_action='devices.enroll' AND actor.role IN ('admin','compliance_lead','collector') THEN
    -- publicKeySha256 is derived from a verified P-256 possession proof by the
    -- concrete adapter, never accepted from the public JSON route.
    PERFORM scopeproof.customer_exact_body(p_body,ARRAY['deviceId','displayName','publicKeySha256']);
    target_id := scopeproof.customer_text(p_body,'deviceId',36,36)::scopeproof.resource_identifier; name := scopeproof.customer_text(p_body,'displayName',1,120); key_hash := scopeproof.customer_text(p_body,'publicKeySha256',64,64);
    IF target_id::text !~ '^dev_[a-f0-9]{32}$' OR key_hash !~ '^[a-f0-9]{64}$' THEN RAISE EXCEPTION 'device enrollment invalid' USING ERRCODE='22023'; END IF;
    SELECT * INTO device FROM scopeproof.device_enrollments WHERE tenant_id=tenant AND id=target_id FOR UPDATE;
    IF FOUND THEN
      IF device.status<>'ACTIVE' OR device.principal_id<>actor.principal_id OR device.device_public_key_sha256::text<>key_hash OR device.display_name<>name THEN RAISE EXCEPTION 'device enrollment conflicts' USING ERRCODE='40001'; END IF;
      RETURN jsonb_build_object('tenantId',tenant,'id',device.id,'principalId',device.principal_id,'status',device.status,'revision',device.revision,'publicKeySha256',device.device_public_key_sha256);
    END IF;
    INSERT INTO scopeproof.device_enrollments(tenant_id,id,principal_id,device_public_key_sha256,display_name) VALUES(tenant,target_id,actor.principal_id,key_hash,name);
    output := jsonb_build_object('id',target_id,'principalId',actor.principal_id,'status','ACTIVE','revision',0,'publicKeySha256',key_hash);
    audit_action := 'customer.devices_enrolled'; resource_type := 'device'; detail := jsonb_build_object('principalId',actor.principal_id,'publicKeySha256',key_hash);
  ELSIF p_action='devices.revoke' AND actor.role IN ('admin','compliance_lead') THEN
    PERFORM scopeproof.customer_exact_body(p_body,ARRAY['deviceId','expectedRevision']);
    target_id := scopeproof.customer_text(p_body,'deviceId',36,36)::scopeproof.resource_identifier; expected := scopeproof.customer_revision(p_body);
    IF target_id::text !~ '^dev_[a-f0-9]{32}$' THEN RAISE EXCEPTION 'device identifier invalid' USING ERRCODE='22023'; END IF;
    UPDATE scopeproof.device_enrollments SET status='REVOKED',revoked_at=clock_timestamp(),revision=revision+1 WHERE tenant_id=tenant AND id=target_id AND status<>'REVOKED' AND revision=expected RETURNING * INTO device;
    IF NOT FOUND THEN RAISE EXCEPTION 'device changed or unavailable' USING ERRCODE='40001'; END IF;
    output := jsonb_build_object('id',device.id,'principalId',device.principal_id,'status',device.status,'revision',device.revision);
    audit_action := 'customer.devices_revoked'; resource_type := 'device'; detail := jsonb_build_object('principalId',device.principal_id,'previousRevision',expected,'revision',device.revision);
  ELSIF p_action IN ('assessments.create','assessments.update') AND actor.role IN ('admin','compliance_lead') THEN
    IF p_action='assessments.create' THEN PERFORM scopeproof.customer_exact_body(p_body,ARRAY['idempotencyKey','name','periodStart','periodEnd','catalogId','systems','controls','status']);
    ELSE PERFORM scopeproof.customer_exact_body(p_body,ARRAY['assessmentId','expectedRevision','name','periodStart','periodEnd','catalogId','systems','controls','status']); END IF;
    name := scopeproof.customer_text(p_body,'name',2,160); new_status := scopeproof.customer_text(p_body,'status',5,6);
    IF scopeproof.customer_text(p_body,'periodStart',10,10) !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' OR scopeproof.customer_text(p_body,'periodEnd',10,10) !~ '^[0-9]{4}-[0-9]{2}-[0-9]{2}$' THEN RAISE EXCEPTION 'calendar dates required' USING ERRCODE='22023'; END IF;
    period_start := (p_body->>'periodStart')::date; period_end := (p_body->>'periodEnd')::date;
    IF period_start>period_end OR new_status NOT IN ('DRAFT','ACTIVE','CLOSED') THEN RAISE EXCEPTION 'assessment definition invalid' USING ERRCODE='22023'; END IF;
    PERFORM scopeproof.customer_validate_scope(p_body);
    SELECT * INTO STRICT catalog FROM scopeproof.customer_control_catalogs WHERE id=p_body->>'catalogId';
    IF p_action='assessments.create' THEN
      IF new_status='CLOSED' THEN RAISE EXCEPTION 'cannot create closed assessment' USING ERRCODE='22023'; END IF;
      subject := scopeproof.customer_text(p_body,'idempotencyKey',16,128);
      target_id := ('asm_'||substr(encode(sha256(convert_to('customer-assessment-v1'||chr(10)||tenant::text||chr(10)||actor.principal_id::text||chr(10)||subject,'UTF8')),'hex'),1,32))::scopeproof.resource_identifier;
      creation_digest := encode(sha256(convert_to(p_body::text,'UTF8')),'hex');
      SELECT * INTO assessment FROM scopeproof.assessments WHERE tenant_id=tenant AND id=target_id FOR UPDATE;
      IF FOUND THEN
        IF assessment.creation_request_sha256 IS DISTINCT FROM creation_digest THEN RAISE EXCEPTION 'assessment idempotency conflict' USING ERRCODE='40001'; END IF;
        RETURN jsonb_build_object('tenantId',tenant,'id',assessment.id,'status',assessment.status,'revision',assessment.revision);
      END IF;
      INSERT INTO scopeproof.assessments(tenant_id,id,name,framework,period_start,period_end,owner_id,status,systems,controls,catalog_id,creation_request_sha256) VALUES(tenant,target_id,name,catalog.framework||' '||catalog.version,period_start,period_end,actor.principal_id,new_status,p_body->'systems',p_body->'controls',catalog.id,creation_digest) RETURNING * INTO assessment;
      audit_action := 'customer.assessments_created';
    ELSE
      target_id := scopeproof.customer_text(p_body,'assessmentId',36,36)::scopeproof.resource_identifier; expected := scopeproof.customer_revision(p_body);
      IF target_id::text !~ '^asm_[a-f0-9]{32}$' THEN RAISE EXCEPTION 'assessment identifier invalid' USING ERRCODE='22023'; END IF;
      SELECT * INTO assessment FROM scopeproof.assessments WHERE tenant_id=tenant AND id=target_id FOR UPDATE;
      IF NOT FOUND THEN RAISE EXCEPTION 'assessment unavailable' USING ERRCODE='P0002'; END IF;
      IF assessment.revision<>expected OR assessment.status='CLOSED' OR (assessment.status='ACTIVE' AND new_status='DRAFT') OR (assessment.status='DRAFT' AND new_status='CLOSED') THEN RAISE EXCEPTION 'assessment transition conflicts' USING ERRCODE='40001'; END IF;
      IF (assessment.status='ACTIVE' OR EXISTS(SELECT 1 FROM scopeproof.evidence_artifacts WHERE tenant_id=tenant AND assessment_id=target_id)) AND
        (assessment.name<>name OR assessment.period_start<>period_start OR assessment.period_end<>period_end OR assessment.catalog_id IS DISTINCT FROM catalog.id OR assessment.systems IS DISTINCT FROM p_body->'systems' OR assessment.controls IS DISTINCT FROM p_body->'controls') THEN RAISE EXCEPTION 'historical scope immutable' USING ERRCODE='40001'; END IF;
      UPDATE scopeproof.assessments SET name=p_body->>'name',period_start=(p_body->>'periodStart')::date,period_end=(p_body->>'periodEnd')::date,framework=catalog.framework||' '||catalog.version,status=new_status,systems=p_body->'systems',controls=p_body->'controls',catalog_id=catalog.id,revision=revision+1,updated_at=clock_timestamp() WHERE tenant_id=tenant AND id=target_id RETURNING * INTO assessment;
      audit_action := 'customer.assessments_updated';
    END IF;
    output := jsonb_build_object('id',assessment.id,'name',assessment.name,'status',assessment.status,'revision',assessment.revision,'catalogId',assessment.catalog_id,'systems',assessment.systems,'controls',assessment.controls,'periodStart',assessment.period_start,'periodEnd',assessment.period_end);
    resource_type := 'assessment'; detail := jsonb_build_object('status',assessment.status,'revision',assessment.revision,'catalogId',catalog.id,'scopeSha256',encode(sha256(convert_to(jsonb_build_object('systems',assessment.systems,'controls',assessment.controls,'catalogId',catalog.id)::text,'UTF8')),'hex'));
  ELSIF p_action='evidence.review' AND actor.role IN ('admin','reviewer') THEN
    PERFORM scopeproof.customer_exact_body(p_body,ARRAY['evidenceId','expectedRevision','decision','reason']);
    target_id := scopeproof.customer_text(p_body,'evidenceId',36,36)::scopeproof.resource_identifier; expected := scopeproof.customer_revision(p_body); decision := scopeproof.customer_text(p_body,'decision',8,8); reason := scopeproof.customer_text(p_body,'reason',20,2000);
    IF target_id::text !~ '^evd_[a-f0-9]{32}$' OR decision NOT IN ('APPROVED','REJECTED') THEN RAISE EXCEPTION 'review decision invalid' USING ERRCODE='22023'; END IF;
    SELECT * INTO evidence FROM scopeproof.evidence_artifacts WHERE tenant_id=tenant AND id=target_id FOR UPDATE;
    IF NOT FOUND THEN RAISE EXCEPTION 'evidence unavailable' USING ERRCODE='P0002'; END IF;
    IF evidence.revision<>expected OR evidence.status<>'NEEDS_REVIEW' OR evidence.created_by=actor.principal_id OR evidence.expires_at<=clock_timestamp() THEN RAISE EXCEPTION 'evidence is not independently reviewable' USING ERRCODE='40001'; END IF;
    IF evidence.object_version_id IS NULL OR NOT EXISTS (SELECT 1 FROM scopeproof.ingest_receipts r WHERE r.tenant_id=tenant AND r.evidence_id=target_id AND r.evidence_version_id=evidence.object_version_id AND r.checksum_sha256=evidence.checksum_sha256 AND r.evidence_revision=evidence.revision AND r.malware_status='CLEAN') THEN RAISE EXCEPTION 'promoted receipt required' USING ERRCODE='42501'; END IF;
    SELECT * INTO assessment FROM scopeproof.assessments WHERE tenant_id=tenant AND id=evidence.assessment_id FOR SHARE;
    IF NOT FOUND OR assessment.status<>'ACTIVE' OR assessment.catalog_id IS NULL OR NOT assessment.controls ? evidence.control_id OR NOT assessment.systems ? evidence.system_name THEN RAISE EXCEPTION 'evidence outside reviewed scope' USING ERRCODE='42501'; END IF;
    UPDATE scopeproof.evidence_artifacts SET status=decision,revision=revision+1,approved_by=CASE WHEN decision='APPROVED' THEN actor.principal_id ELSE NULL END,approved_at=CASE WHEN decision='APPROVED' THEN clock_timestamp() ELSE NULL END WHERE tenant_id=tenant AND id=target_id;
    output := jsonb_build_object('evidenceId',target_id,'status',decision,'revision',expected+1);
    audit_action := 'customer.evidence_reviewed'; resource_type := 'evidence'; detail := jsonb_build_object('decision',decision,'reason',reason,'previousRevision',expected,'revision',expected+1,'createdBy',evidence.created_by);
  ELSE RAISE EXCEPTION 'customer mutation not permitted' USING ERRCODE='42501'; END IF;
  PERFORM scopeproof.record_customer_event(actor.principal_id,actor.membership_id,p_request,audit_action,resource_type,target_id::text,detail);
  RETURN jsonb_build_object('tenantId',tenant)||output;
END; $$;
REVOKE ALL ON FUNCTION scopeproof.customer_mutate(text,timestamptz,text,jsonb,text) FROM PUBLIC;

-- Private location resolution for the separate legal-hold Lambda. No customer
-- route returns these fields or accepts an S3 bucket/key/version as authority.
CREATE FUNCTION scopeproof.customer_legal_hold_target(p_subject text,p_authenticated_at timestamptz,p_evidence_id scopeproof.resource_identifier,p_revision integer)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,scopeproof AS $$
DECLARE tenant scopeproof.tenant_identifier:=scopeproof.current_tenant_id(); evidence scopeproof.evidence_artifacts%ROWTYPE;
BEGIN
  PERFORM 1 FROM scopeproof.customer_actor(p_subject,p_authenticated_at,ARRAY['admin']);
  SELECT * INTO evidence FROM scopeproof.evidence_artifacts WHERE tenant_id=tenant AND id=p_evidence_id;
  IF NOT FOUND OR evidence.object_version_id IS NULL OR evidence.status NOT IN ('NEEDS_REVIEW','APPROVED','EXPIRED','REJECTED') THEN RAISE EXCEPTION 'evidence unavailable for hold' USING ERRCODE='P0002'; END IF;
  IF p_revision IS NULL OR evidence.revision<>p_revision THEN RAISE EXCEPTION 'evidence changed before hold' USING ERRCODE='40001'; END IF;
  RETURN jsonb_build_object('tenantId',tenant,'evidenceId',evidence.id,'controlId',evidence.control_id,'contentType',evidence.content_type,'bucket',evidence.evidence_bucket,'key',evidence.object_key,'versionId',evidence.object_version_id);
END; $$;
REVOKE ALL ON FUNCTION scopeproof.customer_legal_hold_target(text,timestamptz,scopeproof.resource_identifier,integer) FROM PUBLIC;

CREATE FUNCTION scopeproof.customer_legal_hold_status(p_subject text,p_authenticated_at timestamptz,p_evidence_id scopeproof.resource_identifier)
RETURNS jsonb LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog,scopeproof AS $$
DECLARE tenant scopeproof.tenant_identifier:=scopeproof.current_tenant_id(); holds jsonb; operations jsonb;
BEGIN
  PERFORM 1 FROM scopeproof.customer_actor(p_subject,p_authenticated_at,ARRAY['admin']);
  IF NOT EXISTS(SELECT 1 FROM scopeproof.evidence_artifacts WHERE tenant_id=tenant AND id=p_evidence_id) THEN RAISE EXCEPTION 'evidence unavailable' USING ERRCODE='P0002'; END IF;
  SELECT coalesce(jsonb_agg(value ORDER BY created_at DESC,id),'[]'::jsonb) INTO holds FROM (
    SELECT created_at,id,jsonb_build_object('id',id,'kind',kind,'reason',reason,'status',s3_legal_hold_status,'revision',revision,'createdAt',created_at,'releasedAt',released_at) AS value
    FROM scopeproof.retention_holds WHERE tenant_id=tenant AND evidence_id=p_evidence_id ORDER BY created_at DESC,id LIMIT 51
  ) page;
  SELECT coalesce(jsonb_agg(value ORDER BY changed_at DESC,id),'[]'::jsonb) INTO operations FROM (
    SELECT changed_at,id,jsonb_build_object('id',id,'holdId',hold_id,'kind',hold_kind,'status',desired_status,'state',operation_state,'revision',revision,'requestDigest',request_digest,'requestedBy',requested_by,'approvedBy',approved_by,'changedAt',changed_at,'approvedAt',approved_at,'appliedAt',applied_at,'reason',reason) AS value
    FROM scopeproof.legal_hold_operations WHERE tenant_id=tenant AND evidence_id=p_evidence_id ORDER BY changed_at DESC,id LIMIT 51
  ) page;
  RETURN jsonb_build_object('tenantId',tenant,'evidenceId',p_evidence_id,'holds',CASE WHEN jsonb_array_length(holds)>50 THEN holds-50 ELSE holds END,'operations',CASE WHEN jsonb_array_length(operations)>50 THEN operations-50 ELSE operations END,'truncated',jsonb_array_length(holds)>50 OR jsonb_array_length(operations)>50);
END; $$;
REVOKE ALL ON FUNCTION scopeproof.customer_legal_hold_status(text,timestamptz,scopeproof.resource_identifier) FROM PUBLIC;

-- Correct immutable historical001 PL/pgSQL multi-row INTO without rewriting its bytes.
CREATE OR REPLACE FUNCTION scopeproof.append_signed_api_audit_event(
  p_outbox_id scopeproof.resource_identifier,
  p_lease_token text,
  p_sequence bigint,
  p_event_id scopeproof.resource_identifier,
  p_occurred_at timestamptz,
  p_actor jsonb,
  p_action text,
  p_resource_type text,
  p_resource_id scopeproof.resource_identifier,
  p_request_id text,
  p_outcome text,
  p_details jsonb,
  p_previous_hash text,
  p_event_hash text,
  p_canonical_event text,
  p_receipt_payload jsonb,
  p_canonical_receipt text,
  p_receipt_payload_sha256 text,
  p_signing_key_arn text,
  p_signing_algorithm text,
  p_signature text,
  p_signed_at timestamptz
)
RETURNS TABLE (
  committed_sequence bigint,
  committed_event_hash text,
  was_created boolean,
  committed_canonical_receipt text,
  committed_receipt_payload_sha256 text,
  committed_signature text,
  committed_signed_at timestamptz
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();
  queued scopeproof.api_audit_outbox%ROWTYPE;
  work scopeproof.api_audit_outbox_work%ROWTYPE;
  expected_actor jsonb;
  expected_details jsonb;
  expected_event_id scopeproof.resource_identifier;
  expected_outbox_id scopeproof.resource_identifier;
  expected_outbox_digest text;
  appended_sequence bigint;
  appended_event_hash text;
  appended_was_created boolean;
  appended_canonical_receipt text;
  appended_receipt_payload_sha256 text;
  appended_signature text;
  appended_signed_at timestamptz;
BEGIN
  IF active_tenant IS NULL OR
     p_outbox_id IS NULL OR p_outbox_id NOT LIKE 'aob\_%' ESCAPE '\' OR
     p_lease_token IS NULL OR p_lease_token !~ '^[A-Za-z0-9_-]{16,128}$' THEN
    RAISE EXCEPTION 'API audit append lease is invalid' USING ERRCODE = '22023';
  END IF;

  SELECT queued_row.* INTO STRICT queued
    FROM scopeproof.api_audit_outbox AS queued_row
   WHERE queued_row.tenant_id = active_tenant AND queued_row.id = p_outbox_id;
  SELECT work_row.* INTO STRICT work
    FROM scopeproof.api_audit_outbox_work AS work_row
   WHERE work_row.tenant_id = active_tenant AND work_row.outbox_id = p_outbox_id
   FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'API audit outbox work was not found' USING ERRCODE = '40001';
  END IF;

  expected_outbox_digest := encode(sha256(convert_to(
    'scopeproof-api-audit-outbox-v1' || chr(10) ||
    active_tenant::text || chr(10) || queued.actor_user_id::text || chr(10) ||
    queued.membership_id::text || chr(10) || queued.action || chr(10) ||
    queued.resource_type || chr(10) || queued.resource_id || chr(10) ||
    queued.idempotency_key || chr(10) || queued.details::text,
    'UTF8'
  )), 'hex');
  expected_outbox_id := ('aob_' || substr(expected_outbox_digest, 1, 32))::scopeproof.resource_identifier;
  expected_event_id := ('evt_' || substr(expected_outbox_digest, 1, 32))::scopeproof.resource_identifier;
  expected_actor := jsonb_build_object(
    'type', 'user',
    'userId', queued.actor_user_id,
    'membershipId', queued.membership_id
  );
  expected_details := queued.details || jsonb_build_object(
    'scopeproofOutboxId', queued.id,
    'scopeproofOutboxDigest', queued.event_digest::text,
    'scopeproofMembershipId', queued.membership_id
  );
  IF queued.id IS DISTINCT FROM expected_outbox_id OR
     queued.event_digest::text IS DISTINCT FROM expected_outbox_digest OR
     p_event_id IS DISTINCT FROM expected_event_id OR
     p_occurred_at IS DISTINCT FROM queued.occurred_at OR
     p_actor IS DISTINCT FROM expected_actor OR
     p_action IS DISTINCT FROM queued.action OR
     p_resource_type IS DISTINCT FROM queued.resource_type OR
     p_resource_id::text IS DISTINCT FROM queued.resource_id OR
     p_request_id IS DISTINCT FROM queued.request_id OR
     p_outcome IS DISTINCT FROM queued.outcome OR
     p_details IS DISTINCT FROM expected_details THEN
    RAISE EXCEPTION 'signed API audit event does not match its immutable outbox row' USING ERRCODE = '42501';
  END IF;

  IF work.completed_at IS NOT NULL THEN
    IF work.audit_event_id IS DISTINCT FROM p_event_id OR
       work.audit_event_hash::text IS DISTINCT FROM p_event_hash THEN
      RAISE EXCEPTION 'completed API audit event conflicts with replay' USING ERRCODE = '23505';
    END IF;
    RETURN QUERY
    SELECT event.sequence, event.event_hash::text, false,
           event.canonical_receipt, event.receipt_payload_sha256::text,
           event.kms_signature, event.signed_at
      FROM scopeproof.audit_events AS event
     WHERE event.tenant_id = active_tenant AND event.id = p_event_id;
    IF NOT FOUND THEN
      RAISE EXCEPTION 'completed API audit event is missing' USING ERRCODE = '40001';
    END IF;
    RETURN;
  END IF;
  IF work.dead_lettered_at IS NOT NULL OR work.lease_token IS DISTINCT FROM p_lease_token THEN
    RAISE EXCEPTION 'API audit outbox lease changed' USING ERRCODE = '40001';
  END IF;

  SELECT * INTO STRICT
    appended_sequence, appended_event_hash, appended_was_created,
    appended_canonical_receipt, appended_receipt_payload_sha256,
    appended_signature, appended_signed_at
    FROM scopeproof.append_signed_audit_event(
      p_sequence, p_event_id, p_occurred_at, p_actor, p_action,
      p_resource_type, p_resource_id, p_request_id, p_outcome, p_details,
      p_previous_hash, p_event_hash, p_canonical_event, p_receipt_payload,
      p_canonical_receipt, p_receipt_payload_sha256, p_signing_key_arn,
      p_signing_algorithm, p_signature, p_signed_at
    );

  UPDATE scopeproof.api_audit_outbox_work
     SET lease_token = NULL,
         lease_expires_at = NULL,
         completed_at = clock_timestamp(),
         audit_event_id = p_event_id,
         audit_event_hash = appended_event_hash
   WHERE tenant_id = active_tenant
     AND outbox_id = p_outbox_id
     AND lease_token = p_lease_token
     AND completed_at IS NULL
     AND dead_lettered_at IS NULL;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'API audit outbox completion transition changed' USING ERRCODE = '40001';
  END IF;

  RETURN QUERY SELECT appended_sequence, appended_event_hash,
    appended_was_created, appended_canonical_receipt,
    appended_receipt_payload_sha256, appended_signature, appended_signed_at;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.append_signed_api_audit_event(
  scopeproof.resource_identifier, text, bigint, scopeproof.resource_identifier,
  timestamptz, jsonb, text, text, scopeproof.resource_identifier, text, text,
  jsonb, text, text, text, jsonb, text, text, text, text, text, timestamptz
) FROM PUBLIC;

INSERT INTO scopeproof.customer_control_catalogs(id,framework,version,title,controls,digest_sha256) VALUES ('pci-dss-4.0.1-scopeproof-operations-v1','PCI DSS','4.0.1','PCI DSS 4.0.1 · Scopeproof operations catalog','[{"id":"1.2.5","requirement":"Requirement 1","title":"Maintain an inventory of network security controls","defaultEvidence":"Current network security control inventory and reviewed configuration."},{"id":"2.2.1","requirement":"Requirement 2","title":"Configuration standards cover all system components","defaultEvidence":"Approved configuration standard and implementation evidence for each scoped component."},{"id":"3.5.1.1","requirement":"Requirement 3","title":"Cryptographic keys are stored in the fewest locations","defaultEvidence":"Key inventory, location, custodian, and access-control evidence."},{"id":"4.2.1","requirement":"Requirement 4","title":"Strong cryptography protects PAN during transmission","defaultEvidence":"Transport configuration proving approved protocol and cipher enforcement."},{"id":"6.3.2","requirement":"Requirement 6","title":"Software inventory identifies custom and third-party components","defaultEvidence":"Versioned software inventory or SBOM bound to an immutable source revision."},{"id":"7.2.5","requirement":"Requirement 7","title":"Application and system accounts are reviewed periodically","defaultEvidence":"Dated access review with population, reviewer, exceptions, and disposition."},{"id":"8.3.6","requirement":"Requirement 8","title":"Authentication factors are protected from misuse","defaultEvidence":"Authentication policy and enforcement configuration for scoped identities."},{"id":"10.4.1","requirement":"Requirement 10","title":"Audit logs are reviewed at least once daily","defaultEvidence":"Review schedule, alert configuration, and completed review record."},{"id":"11.3.1","requirement":"Requirement 11","title":"Internal vulnerability scans occur every three months","defaultEvidence":"Authenticated scan results, scope, date, and remediation disposition."},{"id":"12.3.1","requirement":"Requirement 12","title":"Targeted risk analyses document required elements","defaultEvidence":"Approved targeted risk analysis with scope, assumptions, frequency, and owner."}]'::jsonb,encode(sha256(convert_to(('[{"id":"1.2.5","requirement":"Requirement 1","title":"Maintain an inventory of network security controls","defaultEvidence":"Current network security control inventory and reviewed configuration."},{"id":"2.2.1","requirement":"Requirement 2","title":"Configuration standards cover all system components","defaultEvidence":"Approved configuration standard and implementation evidence for each scoped component."},{"id":"3.5.1.1","requirement":"Requirement 3","title":"Cryptographic keys are stored in the fewest locations","defaultEvidence":"Key inventory, location, custodian, and access-control evidence."},{"id":"4.2.1","requirement":"Requirement 4","title":"Strong cryptography protects PAN during transmission","defaultEvidence":"Transport configuration proving approved protocol and cipher enforcement."},{"id":"6.3.2","requirement":"Requirement 6","title":"Software inventory identifies custom and third-party components","defaultEvidence":"Versioned software inventory or SBOM bound to an immutable source revision."},{"id":"7.2.5","requirement":"Requirement 7","title":"Application and system accounts are reviewed periodically","defaultEvidence":"Dated access review with population, reviewer, exceptions, and disposition."},{"id":"8.3.6","requirement":"Requirement 8","title":"Authentication factors are protected from misuse","defaultEvidence":"Authentication policy and enforcement configuration for scoped identities."},{"id":"10.4.1","requirement":"Requirement 10","title":"Audit logs are reviewed at least once daily","defaultEvidence":"Review schedule, alert configuration, and completed review record."},{"id":"11.3.1","requirement":"Requirement 11","title":"Internal vulnerability scans occur every three months","defaultEvidence":"Authenticated scan results, scope, date, and remediation disposition."},{"id":"12.3.1","requirement":"Requirement 12","title":"Targeted risk analyses document required elements","defaultEvidence":"Approved targeted risk analysis with scope, assumptions, frequency, and owner."}]'::jsonb)::text,'UTF8')),'hex'));

CREATE OR REPLACE FUNCTION scopeproof.list_unaudited_applied_legal_holds(
  p_limit integer
)
RETURNS TABLE (
  canonical_request text,
  request_digest text,
  applied_at timestamptz,
  audit_canonical_event text,
  audit_canonical_receipt text,
  audit_receipt_payload_sha256 text,
  audit_signing_key_arn text,
  audit_signing_algorithm text,
  audit_signature text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, scopeproof
AS $$
DECLARE
  active_tenant scopeproof.tenant_identifier := scopeproof.current_tenant_id();
BEGIN
  IF active_tenant IS NULL THEN
    RAISE EXCEPTION 'tenant context is required' USING ERRCODE = '42501';
  END IF;
  IF p_limit NOT BETWEEN 1 AND 100 THEN
    RAISE EXCEPTION 'legal hold audit sweep bound is invalid' USING ERRCODE = '22023';
  END IF;

  RETURN QUERY
  SELECT operation.canonical_request,
         operation.request_digest::text,
         operation.applied_at,
         event.canonical_event,
         event.canonical_receipt,
         event.receipt_payload_sha256::text,
         event.signing_key_arn,
         event.signing_algorithm,
         event.kms_signature
    FROM scopeproof.legal_hold_operations AS operation
    LEFT JOIN scopeproof.audit_events AS event
      ON event.tenant_id = operation.tenant_id
     AND event.id = ('evt_' || substr(encode(sha256(
       convert_to('scopeproof-legal-hold-audit-v1', 'UTF8') || decode('00', 'hex') ||
       convert_to(operation.id::text, 'UTF8')
     ), 'hex'), 1, 32))::scopeproof.resource_identifier
     AND event.resource_type = 'legal_hold_operation'
     AND event.resource_id = operation.id
     AND event.action = 'evidence.legal_hold_applied'
     AND event.outcome = 'succeeded'
   WHERE operation.tenant_id = active_tenant
     AND operation.operation_state = 'APPLIED'
     AND operation.recovery_published_at IS NULL
   ORDER BY operation.applied_at, operation.id
   LIMIT p_limit;
END;
$$;

REVOKE ALL ON FUNCTION scopeproof.list_unaudited_applied_legal_holds(
  integer
) FROM PUBLIC;

INSERT INTO scopeproof.schema_migrations(version,name) VALUES(5,'customer_runtime');
COMMIT;
