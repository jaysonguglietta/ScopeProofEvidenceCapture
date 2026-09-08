-- Synthetic data only. The runner refuses a nonempty or non-local test database.
BEGIN;
SELECT set_config('scopeproof.tenant_id', 'ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', true);
INSERT INTO scopeproof.tenant_identity (
 tenant_id, slug, display_name, status, canonical_hostname, retention_days, retention_mode,
 aws_account_id, aws_region, quarantine_bucket, evidence_bucket, evidence_kms_key_arn, audit_signing_key_arn
) VALUES (
 'ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'test', 'Synthetic test tenant', 'ACTIVE', 'test.example.com', 365, 'COMPLIANCE',
 '111111111111', 'us-east-1', 'scopeproof-test-quarantine', 'scopeproof-test-evidence',
 'arn:aws:kms:us-east-1:111111111111:key/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
 'arn:aws:kms:us-east-1:111111111111:key/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb'
);
INSERT INTO scopeproof.principals (tenant_id,id,cognito_sub,email,display_name)
VALUES ('ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','usr_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','synthetic-subject','test@example.com','Synthetic user');
INSERT INTO scopeproof.memberships (tenant_id,id,principal_id,role,status)
VALUES ('ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','mem_cccccccccccccccccccccccccccccccc','usr_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','admin','ACTIVE');

DO $$
DECLARE old_auth timestamptz := clock_timestamp() - interval '1 minute';
BEGIN
  IF scopeproof.evidence_reader_role('usr_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb') <> 'admin' THEN RAISE EXCEPTION 'valid admin missing'; END IF;
  BEGIN
    PERFORM scopeproof.evidence_reader_role('usr_00000000000000000000000000000000');
    RAISE EXCEPTION 'NULL actor was authorized';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
  IF (SELECT count(*) FROM scopeproof.resolve_active_session_membership('synthetic-subject', old_auth)) <> 1 THEN RAISE EXCEPTION 'fresh session missing'; END IF;
  PERFORM scopeproof.revoke_own_sessions('synthetic-subject', old_auth, 'request-revoke-12345678');
  IF EXISTS (SELECT 1 FROM scopeproof.resolve_active_session_membership('synthetic-subject', old_auth)) THEN RAISE EXCEPTION 'revoked session survived'; END IF;
  IF (SELECT count(*) FROM scopeproof.api_audit_outbox WHERE action = 'session.all_revoked') <> 1 THEN RAISE EXCEPTION 'revocation audit missing'; END IF;
  IF NOT EXISTS (SELECT 1 FROM scopeproof.resolve_active_session_membership('synthetic-subject', clock_timestamp() + interval '1 second')) THEN RAISE EXCEPTION 'reauthentication blocked'; END IF;
END;
$$;

INSERT INTO scopeproof.device_enrollments (tenant_id,id,principal_id,device_public_key_sha256,display_name)
VALUES ('ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','dev_dddddddddddddddddddddddddddddddd','usr_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',repeat('1',64),'Synthetic device');
INSERT INTO scopeproof.assessments (tenant_id,id,name,framework,period_start,period_end,owner_id,status,controls)
VALUES ('ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','asm_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee','Synthetic assessment','PCI DSS',current_date,current_date+1,'usr_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','ACTIVE','["PCI-DSS-10.2.1"]');

DO $$
DECLARE
  reserved timestamptz := date_trunc('milliseconds',clock_timestamp()) - interval '6 minutes';
  manifest text;
  metadata jsonb;
  proof jsonb;
  created boolean;
BEGIN
  manifest := jsonb_build_object(
    'schemaVersion',1,'tenantId','ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    'userId','usr_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','deviceId','dev_dddddddddddddddddddddddddddddddd',
    'assessmentId','asm_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee','controlId','PCI-DSS-10.2.1',
    'evidenceId','evd_ffffffffffffffffffffffffffffffff','expectedSha256',repeat('2',64),'expectedSize',4096,
    'contentType','image/png','capturedAt',to_char(reserved AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"'),
    'challenge','synthetic-challenge','nonce',repeat('3',43),'sequence',1,
    'signedAt',to_char(reserved AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  )::text;
  proof := jsonb_build_object(
    'schemaVersion',1,'algorithm','ECDSA_P256_SHA256','canonicalManifest',manifest,
    'manifestDigest',encode(sha256(convert_to('scopeproof-device-upload-manifest-v1'||chr(10)||manifest,'UTF8')),'hex'),
    'signature',repeat('A',86),'publicKeySha256',repeat('1',64),
    'challengeDigest',encode(sha256(convert_to('scopeproof-device-token-challenge-v1'||chr(10)||'synthetic-challenge','UTF8')),'hex'),
    'nonceDigest',encode(sha256(convert_to('scopeproof-device-upload-nonce-v1'||chr(10)||repeat('3',43),'UTF8')),'hex'),
    'sequence',1,'signedAt',to_char(reserved AT TIME ZONE 'UTC','YYYY-MM-DD"T"HH24:MI:SS.MS"Z"')
  );
  metadata := jsonb_build_object('scopeproofDeviceProof',proof);
  SELECT was_created INTO created FROM scopeproof.repair_upload_intent(
    'upl_11111111111111111111111111111111',repeat('4',64),'usr_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'dev_dddddddddddddddddddddddddddddddd','asm_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee','evd_ffffffffffffffffffffffffffffffff',
    'tenants/ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/controls/PCI-DSS-10.2.1/quarantine/upl_11111111111111111111111111111111.upload',
    'tenants/ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/controls/PCI-DSS-10.2.1/evidence/evd_ffffffffffffffffffffffffffffffff.png',
    'image/png',4096,repeat('2',64),reserved+interval '10 minutes',reserved+interval '365 days',
    'PCI-DSS-10.2.1','Synthetic recovery','Synthetic evidence recovery','SCREENSHOT','synthetic','test',
    reserved,reserved+interval '365 days',metadata,reserved
  );
  IF created IS DISTINCT FROM true THEN RAISE EXCEPTION 'six-minute repair did not create exact projection'; END IF;
  SELECT was_created INTO created FROM scopeproof.create_upload_intent(
    'upl_11111111111111111111111111111111',repeat('4',64),'usr_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
    'dev_dddddddddddddddddddddddddddddddd','asm_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee','evd_ffffffffffffffffffffffffffffffff',
    'tenants/ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/controls/PCI-DSS-10.2.1/quarantine/upl_11111111111111111111111111111111.upload',
    'tenants/ten_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/controls/PCI-DSS-10.2.1/evidence/evd_ffffffffffffffffffffffffffffffff.png',
    'image/png',4096,repeat('2',64),reserved+interval '10 minutes',reserved+interval '365 days',
    'PCI-DSS-10.2.1','Synthetic recovery','Synthetic evidence recovery','SCREENSHOT','synthetic','test',
    reserved,reserved+interval '365 days',metadata
  );
  IF created IS DISTINCT FROM false THEN RAISE EXCEPTION 'committed retry was not idempotent'; END IF;
END;
$$;
-- Exercise the actual operation-specific grant reset, not a mocked ACL check.
SET LOCAL ROLE tenant_scopeproof_test_runtime;
DO $$
DECLARE table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY['schema_migrations', 'tenant_identity', 'tenant_domains', 'principals', 'memberships', 'evidence_artifacts'] LOOP
    BEGIN
      EXECUTE format('SELECT 1 FROM scopeproof.%I LIMIT 1', table_name);
      RAISE EXCEPTION 'runtime could select protected table %', table_name;
    EXCEPTION WHEN insufficient_privilege THEN NULL; END;
  END LOOP;
  BEGIN
    PERFORM scopeproof.repair_upload_intent(
      NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL,NULL
    );
    RAISE EXCEPTION 'public runtime could execute privileged repair';
  EXCEPTION WHEN insufficient_privilege THEN NULL; END;
END;
$$;
RESET ROLE;
COMMIT;
SELECT 'scopeproof semantic checks passed';
