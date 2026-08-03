import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');

// A project with one dependency that reads a key it has no business reading.
// The key is a fake local file; nothing leaves the machine.
const projectDir = join(tmpdir(), `dephawk-failon-e2e-${process.pid}`);
const sarifPath = join(projectDir, 'dephawk.sarif');

interface SarifResult {
  readonly ruleId: string;
  readonly level: string;
  readonly message: { readonly text: string };
  readonly locations: readonly {
    readonly physicalLocation: {
      readonly artifactLocation: { readonly uri: string };
      readonly region: { readonly startLine: number };
    };
  }[];
}

beforeAll(() => {
  if (!existsSync(cliPath) || !existsSync(registerPath)) {
    execSync('npm run build', { stdio: 'ignore' });
  }

  const sneakyDir = join(projectDir, 'node_modules', 'sneaky');
  mkdirSync(sneakyDir, { recursive: true });
  writeFileSync(join(projectDir, 'id_rsa'), 'fake-private-key\n');
  writeFileSync(
    join(sneakyDir, 'index.js'),
    [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      "exports.steal = () => fs.readFileSync(path.join(__dirname, '..', '..', 'id_rsa'), 'utf8');",
    ].join('\n'),
  );
  writeFileSync(join(projectDir, 'app.js'), "require('sneaky').steal();\n");
  writeFileSync(join(projectDir, 'clean.js'), "console.log('nothing to see');\n");
}, 180_000);

afterAll(() => {
  rmSync(projectDir, { recursive: true, force: true });
});

function dephawk(...args: string[]): { status: number | null; stderr: string } {
  const result = spawnSync(process.execPath, [cliPath, 'run', ...args], {
    cwd: projectDir,
    encoding: 'utf8',
    env: { ...process.env, DEPHAWK_MODE: 'observe', NO_COLOR: '1' },
  });
  return { status: result.status, stderr: result.stderr };
}

describe('e2e: --fail-on gates the command', () => {
  it('exits 0 without the flag, however bad the findings', () => {
    const result = dephawk('node', 'app.js');

    expect(result.stderr).toContain('sneaky');
    expect(result.status).toBe(0);
  }, 60_000);

  it('exits 2 at --fail-on violation, in observe mode', () => {
    // The whole point: observe mode blocks nothing, yet the pull request fails.
    const result = dephawk('--fail-on', 'violation', 'node', 'app.js');

    expect(result.status).toBe(2);
    expect(result.stderr).toContain('policy violation');
    expect(result.stderr).toContain('--fail-on violation');
  }, 60_000);

  it('exits 0 at --fail-on blocked, because observe mode blocked nothing', () => {
    const result = dephawk('--fail-on', 'blocked', 'node', 'app.js');
    expect(result.status).toBe(0);
  }, 60_000);

  it('exits 0 on a clean run at the strictest threshold', () => {
    const result = dephawk('--fail-on', 'sensitive', 'node', 'clean.js');
    expect(result.status).toBe(0);
  }, 60_000);
});

describe('e2e: --sarif describes the finding for code scanning', () => {
  it('names the rule, the package and the dependency file that did it', () => {
    const result = dephawk('--sarif', sarifPath, 'node', 'app.js');
    expect(result.status).toBe(0);

    const sarif = JSON.parse(readFileSync(sarifPath, 'utf8')) as {
      version: string;
      runs: readonly {
        tool: { driver: { name: string; rules: readonly { id: string }[] } };
        results: readonly SarifResult[];
      }[];
    };

    expect(sarif.version).toBe('2.1.0');
    const run = sarif.runs[0]!;
    expect(run.tool.driver.name).toBe('dephawk');
    expect(run.tool.driver.rules.map((rule) => rule.id)).toContain('fs.read');

    const finding = run.results.find((r) => r.ruleId === 'fs.read')!;
    expect(finding.level).toBe('error');
    expect(finding.message.text).toContain('sneaky');
    expect(finding.message.text).toContain('id_rsa');

    // A repository-relative path, or GitHub cannot map the alert to a file.
    const location = finding.locations[0]!.physicalLocation;
    expect(location.artifactLocation.uri).toBe('node_modules/sneaky/index.js');
    expect(location.artifactLocation.uri.startsWith('/')).toBe(false);
    expect(location.region.startLine).toBeGreaterThan(0);
  }, 60_000);

  it('combines with --fail-on so the artifact survives the failure', () => {
    rmSync(sarifPath, { force: true });
    const result = dephawk(
      '--fail-on',
      'violation',
      '--sarif',
      sarifPath,
      'node',
      'app.js',
    );

    expect(result.status).toBe(2);
    expect(existsSync(sarifPath)).toBe(true);
  }, 60_000);
});
