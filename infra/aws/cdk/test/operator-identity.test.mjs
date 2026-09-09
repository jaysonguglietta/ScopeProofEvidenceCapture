import assert from "node:assert/strict";
import test from "node:test";
import { exactOperatorIdentity } from "../runtime/restore-operator/contract.mjs";
test("operator identity treats IAM punctuation literally, never as a regular expression", () => {
  const account = "111111111111";
  for (const name of ["restore.operator", "restore+operator", "restore_operator"]) {
    const role = `arn:aws:iam::${account}:role/scopeproof/recovery/${name}`;
    const identity = { Account: account, Arn: `arn:aws:sts::${account}:assumed-role/${name}/session-1` };
    assert.equal(exactOperatorIdentity(identity, account, role), true);
    assert.equal(exactOperatorIdentity({ ...identity, Arn: `arn:aws:sts::${account}:assumed-role/restoreXoperator/session-1` }, account, role), false);
    assert.equal(exactOperatorIdentity({ ...identity, Account: "222222222222" }, account, role), false);
    assert.equal(exactOperatorIdentity({ ...identity, Arn: identity.Arn + "/extra" }, account, role), false);
  }
});
