import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import {
  cpSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');

// A project with one dependency, and a "version bump" of that dependency that
// quietly starts doing more. Nothing here is denied by policy — the point is
// that a diff catches the change where a permission check never would.
const projectDir = join(tmpdir(), `dephawk-baseline-e2e-${process.pid}`);
const baselinePath = '.dephawk/baseline.json';

/** The dependency as it behaves today. */
const ORIGINAL = [
  "const dns = require('node:dns');",
  'exports.go = () => {',
  "  dns.lookup('api.example.com', () => {});",
  '};',
].join('\n');

/** The same dependency after a bump: a new host and a config file read. */
const BUMPED = [
  "const dns = require('node:dns');",
  "const fs = require('node:fs');",
  "const path = require('node:path');",
  'exports.go = () => {',
  "  dns.lookup('api.example.com', () => {});",
  "  dns.lookup('telemetry.vendor.example', () => {});",
  "  fs.readFileSync(path.join(__dirname, '..', '..', '.npmrc'), 'utf8');",
  '};',
].join('\n');

const dependency = join(projectDir, 'node_modules', 'httpclient', 'index.js');

beforeAll(() => {
  if (!existsSync(cliPath) || !existsSync(registerPath)) {
    execSync('npm run build', { stdio: 'ignore' });
  }

  mkdirSync(join(projectDir, 'node_modules', 'httpclient'), { recursive: true });
  writeFileSync(join(projectDir, '.npmrc'), 'registry=https://registry.npmjs.org/\n');
  writeFileSync(dependency, ORIGINAL);
  writeFileSync(join(projectDir, 'app.js'), "require('httpclient').go();\n");
}, 180_000);

afterAll(() => {
  rmSync(projectDir, { recursive: true, force: true });
});

function dephawk(
  cwd: string,
  ...args: string[]
): { status: number | null; stderr: string } {
  const result = spawnSync(
    process.execPath,
    [cliPath, 'run', ...args, 'node', 'app.js'],
    {
      cwd,
      encoding: 'utf8',
      env: { ...process.env, NO_COLOR: '1' },
    },
  );
  return { status: result.status, stderr: result.stderr };
}

describe('e2e: --record / --replay catch what a policy cannot', () => {
  it('records the run and says the file is meant to be committed', () => {
    const result = dephawk(projectDir, '--record', baselinePath);

    expect(result.status).toBe(0);
    expect(result.stderr).toContain('recorded');
    expect(result.stderr).toContain('Commit it');

    const baseline = JSON.parse(readFileSync(join(projectDir, baselinePath), 'utf8')) as {
      version: number;
      behaviours: { package: string; detail: string }[];
    };

    expect(baseline.version).toBe(1);
    expect(baseline.behaviours.some((b) => b.detail === 'api.example.com')).toBe(true);
  }, 60_000);

  it('replays clean when nothing changed', () => {
    const result = dephawk(projectDir, '--replay', baselinePath, '--fail-on', 'new');

    expect(result.status).toBe(0);
    expect(result.stderr).toContain('no change');
  }, 60_000);

  it('reports exactly what a dependency bump added, and fails on it', () => {
    writeFileSync(dependency, BUMPED);
    const result = dephawk(projectDir, '--replay', baselinePath, '--fail-on', 'new');

    expect(result.status).toBe(2);
    expect(result.stderr).toContain('2 new behaviours');
    expect(result.stderr).toContain('telemetry.vendor.example');
    expect(result.stderr).toContain('./.npmrc');
    // The host it always used is not news.
    expect(result.stderr).not.toContain('+ httpclient  →  dns api.example.com');
  }, 60_000);

  it('does not fail the run without --fail-on new, it just reports', () => {
    const result = dephawk(projectDir, '--replay', baselinePath);

    expect(result.status).toBe(0);
    expect(result.stderr).toContain('2 new behaviours');
  }, 60_000);

  it('matches from a different checkout path, which is why it can be committed', () => {
    writeFileSync(dependency, ORIGINAL);
    dephawk(projectDir, '--record', baselinePath);

    const elsewhere = join(tmpdir(), `dephawk-baseline-elsewhere-${process.pid}`);
    rmSync(elsewhere, { recursive: true, force: true });
    cpSync(projectDir, elsewhere, { recursive: true });

    try {
      const result = dephawk(elsewhere, '--replay', baselinePath, '--fail-on', 'new');
      expect(result.status).toBe(0);
      expect(result.stderr).toContain('no change');
    } finally {
      rmSync(elsewhere, { recursive: true, force: true });
    }
  }, 60_000);

  it('a dependency cannot poison the baseline to hide its own change', () => {
    // The whole point of --replay is to catch a behaviour change. A dependency
    // that overwrites the committed baseline mid-run — to include the very host
    // it just started resolving — would erase the evidence. The baseline is a
    // protected path, so that write is refused and the diff still fires.
    writeFileSync(dependency, ORIGINAL);
    dephawk(projectDir, '--record', baselinePath);
    const before = readFileSync(join(projectDir, baselinePath), 'utf8');

    const poisoner = [
      "const dns = require('node:dns');",
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      'exports.go = () => {',
      "  dns.lookup('exfil.attacker.example', () => {});",
      "  const bl = path.join(__dirname, '..', '..', '.dephawk', 'baseline.json');",
      '  const poisoned = {',
      '    version: 1,',
      '    recordedAt: new Date().toISOString(),',
      '    behaviours: [',
      "      { package: 'httpclient', origin: 'dependency', capability: 'net.resolve',",
      "        detail: 'exfil.attacker.example' },",
      '    ],',
      '  };',
      '  try { fs.writeFileSync(bl, JSON.stringify(poisoned)); } catch {}',
      '};',
    ].join('\n');
    writeFileSync(dependency, poisoner);

    const result = dephawk(projectDir, '--replay', baselinePath, '--fail-on', 'new');

    expect(result.status).toBe(2);
    expect(result.stderr).toContain('exfil.attacker.example');
    // And the file on disk was not tampered with.
    expect(readFileSync(join(projectDir, baselinePath), 'utf8')).toBe(before);
  }, 60_000);

  it('refuses to compare against a baseline it cannot read', () => {
    // Treating a broken file as empty would report "no change" for a run that
    // was never actually checked.
    writeFileSync(join(projectDir, 'broken.json'), '{ not a baseline');
    const result = dephawk(projectDir, '--replay', 'broken.json');

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('not a dephawk baseline');
  }, 60_000);

  it('says so when the baseline does not exist yet', () => {
    const result = dephawk(projectDir, '--replay', 'nope.json');

    expect(result.status).toBe(1);
    expect(result.stderr).toContain('cannot read the baseline');
  }, 60_000);
});
