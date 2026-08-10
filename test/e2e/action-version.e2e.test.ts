import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync } from 'node:child_process';
import { chmodSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

// The action pins the dephawk version from its own reference, and nothing else
// exercises that: the `action` job in CI passes `bin`, which skips the whole
// branch. So run the real `action/run.sh` with a fake `npx` on PATH — the script
// echoes the command line it is about to run, which is the resolved
// `dephawk@<spec>` we want to assert.
const runScript = resolve('action/run.sh');
const harness = join(tmpdir(), `dephawk-action-version-${process.pid}`);
const fakeBin = join(harness, 'bin');

// Windows has no bash to run the action body with.
const onPosix = process.platform !== 'win32';

beforeAll(() => {
  mkdirSync(fakeBin, { recursive: true });
  // Stands in for npx: never installs anything, always succeeds.
  const npx = join(fakeBin, 'npx');
  writeFileSync(npx, '#!/bin/sh\necho "fake-npx $*"\nexit 0\n');
  chmodSync(npx, 0o755);
});

afterAll(() => {
  rmSync(harness, { recursive: true, force: true });
});

/** The `dephawk@<spec>` the action would install for a given action reference. */
function resolveSpec(actionRef: string): string {
  const result = spawnSync('bash', [runScript], {
    encoding: 'utf8',
    env: {
      ...process.env,
      PATH: `${fakeBin}:${process.env['PATH'] ?? ''}`,
      GITHUB_ACTION_REF: actionRef,
      RUNNER_TEMP: harness,
      GITHUB_OUTPUT: join(harness, 'output.txt'),
      IN_SUBCOMMAND: 'run',
      IN_MODE: 'observe',
      IN_FAIL_ON: 'none',
      IN_COMMAND: 'true',
      IN_VERSION: '',
      IN_BIN: '',
      IN_CONFIG: '',
      IN_SARIF: '',
      IN_SUMMARY: 'false',
    },
  });
  const match = /dephawk@(\S+)/.exec(result.stdout);
  return match?.[1] ?? `NO MATCH (stdout: ${result.stdout}${result.stderr})`;
}

describe.skipIf(!onPosix)('e2e: the action pins dephawk from its own reference', () => {
  it('runs the exact release named by a full version tag', () => {
    expect(resolveSpec('v1.2.3')).toBe('1.2.3');
  });

  it('keeps a floating MAJOR tag inside that major', () => {
    // The regression this test exists for: `@v0` used to resolve to `latest`,
    // so the day 1.0 shipped every workflow pinned to `@v0` would have jumped
    // to 1.x — across exactly the boundary where the action's inputs may change.
    expect(resolveSpec('v0')).toBe('0');
    expect(resolveSpec('v1')).toBe('1');
  });

  it('keeps a floating MINOR tag inside that minor', () => {
    expect(resolveSpec('v0.6')).toBe('0.6');
  });

  it('falls back to latest for a reference that names no version', () => {
    // A branch or a SHA has nothing to pin to.
    expect(resolveSpec('main')).toBe('latest');
    expect(resolveSpec('0f1e2d3c4b5a')).toBe('latest');
    expect(resolveSpec('')).toBe('latest');
  });
});
