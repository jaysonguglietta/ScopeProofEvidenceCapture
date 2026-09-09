import { createHash } from "node:crypto";

// Preserve the reviewed historical bytes. PostgreSQL exposed a compile-time
// multi-record INTO defect in its original audit function. Only this exact
// baseline may be staged with body validation deferred until the correcting
// forward migration is installed. No application grants precede revalidation.
export const historicalBaselineSha256 = "be0798f20decabb911f0187c8ee499b5277b313500658d4bce99a935724785df";
export function executableHistoricalBaseline(sql) {
  if (createHash("sha256").update(sql).digest("hex") !== historicalBaselineSha256) throw new Error("Historical baseline bytes differ from the reviewed bootstrap lineage.");
  if (!/^BEGIN;$/m.test(sql)) throw new Error("Historical baseline transaction is missing.");
  return sql.replace(/^BEGIN;$/m, "BEGIN;\nSET LOCAL check_function_bodies = off;");
}

export const validateInstalledFunctionsSql = `DO $validate_scopeproof$
DECLARE definition text;
BEGIN
  IF current_setting('check_function_bodies') <> 'on' THEN
    RAISE EXCEPTION 'function body validation must be enabled';
  END IF;
  FOR definition IN
    SELECT pg_get_functiondef(p.oid) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace
     WHERE n.nspname='scopeproof' ORDER BY p.oid
  LOOP
    EXECUTE definition;
  END LOOP;
END;
$validate_scopeproof$`;
