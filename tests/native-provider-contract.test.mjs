import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { join } from 'node:path';
import test from 'node:test';

test('Native provider fixtures track the actual hosted/Jira response constructors', () => {
  const root = fileURLToPath(new URL('..', import.meta.url));
  const script = join(root, 'Scripts/generate-native-provider-contract-fixtures.mjs');
  const generated = spawnSync(process.execPath, [script, root], { encoding: 'utf8', timeout: 10_000, maxBuffer: 512 * 1024 });
  assert.equal(generated.status, 0, generated.stderr || generated.error?.message);
  const fixture = readFileSync(join(root, 'macos/ScopeproofCapture/Tests/ScopeproofCaptureTests/ProviderContractFixture.swift'), 'utf8');
  assert.equal(generated.stdout.trimEnd(), fixture.trimEnd(),
    'Native provider wire contract drifted. Review the response change, regenerate ProviderContractFixture.swift with the script, then rerun native receipt tests.');
});
