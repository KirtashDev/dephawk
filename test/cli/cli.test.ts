import { describe, it, expect, beforeAll } from 'vitest';
import { execSync, spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { run } from '../../src/cli.js';

const builtCli = resolve('dist/cli.js');

// The CLI spawns children with `--import dist/register.js`, so the build must
// exist for the spawning tests.
beforeAll(() => {
  if (!existsSync(resolve('dist/register.js'))) {
    execSync('npm run build', { stdio: 'ignore' });
  }
}, 180_000);

describe('cli argument handling', () => {
  it('prints help and exits 0 for --help', async () => {
    expect(await run(['--help'])).toBe(0);
  });

  it('exits 1 for an unknown subcommand', async () => {
    expect(await run(['frobnicate'])).toBe(1);
  });

  it('exits 1 when run has no command', async () => {
    expect(await run(['run'])).toBe(1);
  });

  it('exits 1 for an unknown option', async () => {
    expect(await run(['run', '--frobnicate', 'node'])).toBe(1);
  });
});

describe('cli process spawning', () => {
  // These exercise the real --import path, so they run the *built* CLI.
  it('propagates the child exit code', () => {
    const result = spawnSync(
      process.execPath,
      [builtCli, 'run', process.execPath, '-e', 'process.exit(7)'],
      { encoding: 'utf8', env: { ...process.env, NO_COLOR: '1' } },
    );
    expect(result.status).toBe(7);
  }, 30_000);

  it('returns 127 when the command cannot be started', async () => {
    const code = await run(['run', 'definitely-not-a-real-binary-xyz-123']);
    expect(code).toBe(127);
  }, 30_000);
});
