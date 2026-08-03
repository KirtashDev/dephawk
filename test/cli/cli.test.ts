import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { execSync, spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { run } from '../../src/cli.js';

const builtCli = resolve('dist/cli.js');

// The CLI writes its reports into the working directory, so the spawning tests
// get a throwaway one rather than scattering artifacts through the repo.
let workDir: string;

// The CLI spawns children with `--import dist/register.js`, so the build must
// exist for the spawning tests.
beforeAll(() => {
  if (!existsSync(resolve('dist/register.js'))) {
    execSync('npm run build', { stdio: 'ignore' });
  }
  workDir = mkdtempSync(join(tmpdir(), 'dephawk-cli-test-'));
}, 180_000);

afterAll(() => {
  rmSync(workDir, { recursive: true, force: true });
});

/** Run the built CLI in `cwd`, defaulting to the shared throwaway directory. */
function cliIn(
  cwd: string,
  ...args: string[]
): { status: number | null; stderr: string } {
  const result = spawnSync(process.execPath, [builtCli, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
  });
  return { status: result.status, stderr: result.stderr };
}

function cli(...args: string[]): { status: number | null; stderr: string } {
  return cliIn(workDir, ...args);
}

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

  it('exits 1 for an unknown --fail-on level', async () => {
    expect(await run(['run', '--fail-on', 'catastrophic', 'node'])).toBe(1);
  });

  it('exits 1 when --fail-on has no level', async () => {
    expect(await run(['run', '--fail-on'])).toBe(1);
  });

  it('exits 1 when --out has no path', async () => {
    expect(await run(['init', '--out'])).toBe(1);
    expect(await run(['init', '--out', '--force', 'node'])).toBe(1);
  });

  it('exits 1 when --sarif has no path', async () => {
    expect(await run(['run', '--sarif'])).toBe(1);
    // A following flag is not a path — that would silently write to "--enforce".
    expect(await run(['run', '--sarif', '--enforce', 'node'])).toBe(1);
  });
});

describe('cli process spawning', () => {
  // These exercise the real --import path, so they run the *built* CLI.
  it('propagates the child exit code', () => {
    expect(cli('run', process.execPath, '-e', 'process.exit(7)').status).toBe(7);
  }, 30_000);

  it('returns 127 when the command cannot be started', async () => {
    const code = await run(['run', 'definitely-not-a-real-binary-xyz-123']);
    expect(code).toBe(127);
  }, 30_000);

  it('writes no report for a command that never started', () => {
    // Its own directory: the other tests here run successfully and leave a
    // report behind in the shared one.
    const emptyDir = mkdtempSync(join(tmpdir(), 'dephawk-cli-nostart-'));
    try {
      const result = cliIn(emptyDir, 'run', 'definitely-not-a-real-binary-xyz-123');

      expect(result.status).toBe(127);
      expect(result.stderr).not.toContain('dephawk report');
      expect(existsSync(join(emptyDir, '.dephawk'))).toBe(false);
    } finally {
      rmSync(emptyDir, { recursive: true, force: true });
    }
  }, 30_000);

  it('exits 0 on a clean run even with the strictest threshold', () => {
    const result = cli('run', '--fail-on', 'sensitive', process.execPath, '-e', '1');
    expect(result.status).toBe(0);
  }, 30_000);

  it('lets the command’s own failure win over the findings exit code', () => {
    const result = cli(
      'run',
      '--fail-on',
      'sensitive',
      process.execPath,
      '-e',
      'process.exit(7)',
    );
    expect(result.status).toBe(7);
  }, 30_000);

  it('writes a SARIF file where asked', () => {
    const sarifPath = join(workDir, 'out.sarif');
    const result = cli('run', '--sarif', sarifPath, process.execPath, '-e', '1');

    expect(result.status).toBe(0);
    expect(result.stderr).toContain('SARIF report written');
    const sarif = JSON.parse(readFileSync(sarifPath, 'utf8')) as { version: string };
    expect(sarif.version).toBe('2.1.0');
  }, 30_000);

  // Every package manager installs a `bin` as a symlink — node_modules/.bin, the
  // global bin directory, npx's cache — and the entrypoint check compared
  // argv[1] (the link) against import.meta.url (the file it points at). Every
  // installed copy therefore did nothing at all: exit 0, no output, no
  // monitoring. Invoking by path, which is all the rest of this suite does, hid
  // it completely.
  it('runs when invoked through a bin symlink, as npx and a global install do', () => {
    const link = join(workDir, 'dephawk-bin-link');
    rmSync(link, { force: true });
    symlinkSync(builtCli, link);

    const result = spawnSync(
      process.execPath,
      [link, 'run', process.execPath, '-e', '1'],
      {
        cwd: workDir,
        encoding: 'utf8',
        env: { ...process.env, NO_COLOR: '1' },
      },
    );

    expect(result.status).toBe(0);
    expect(result.stderr).toContain('dephawk report');
  }, 30_000);
});
