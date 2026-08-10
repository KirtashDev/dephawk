import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawnSync, execSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');

// Node compiles its bundled undici/llhttp HTTP parser to WebAssembly the first
// time `fetch` is used. The wasm interceptor blocks dynamic wasm by default —
// so it must NOT block the runtime's own parser, or `fetch` breaks and Node's
// plumbing shows up as an invented finding. A fresh process guarantees llhttp
// is compiled here rather than cached from an earlier test.
const projectDir = join(tmpdir(), `dephawk-wasm-skip-e2e-${process.pid}`);

beforeAll(() => {
  if (!existsSync(cliPath) || !existsSync(registerPath)) {
    execSync('npm run build', { stdio: 'ignore' });
  }
  mkdirSync(projectDir, { recursive: true });
  // Deny-by-default, enforce: eval (and thus wasm) is refused for everyone.
  writeFileSync(
    join(projectDir, 'dephawk.config.js'),
    'export default { mode: "enforce", default: { eval: false }, packages: {} };\n',
  );
  // The app makes a real fetch to a closed local port. It must fail with a
  // NETWORK error, not a dephawk wasm block: reaching the connection at all
  // proves llhttp compiled.
  writeFileSync(
    join(projectDir, 'app.js'),
    [
      'fetch("http://127.0.0.1:1/")',
      '  .then(() => console.log("UNEXPECTED_OK"))',
      '  .catch((e) => console.log("FETCH_ERR:" + e.message));',
    ].join('\n'),
  );
}, 180_000);

afterAll(() => {
  rmSync(projectDir, { recursive: true, force: true });
});

describe("e2e: the runtime's own wasm (undici/llhttp) is not blocked", () => {
  it('lets fetch compile its parser and reach the network', () => {
    const result = spawnSync(process.execPath, [cliPath, 'run', 'node', 'app.js'], {
      cwd: projectDir,
      encoding: 'utf8',
      env: { ...process.env, NO_COLOR: '1' },
    });

    const output = `${result.stdout}\n${result.stderr}`;
    // fetch failed for a network reason (or was blocked at the net layer), not
    // because its wasm parser was refused.
    expect(output).not.toContain('WebAssembly execution');
    expect(output).toContain('FETCH_ERR:');
    // No eval finding was invented for the runtime's own parser.
    expect(output).not.toMatch(/eval\s+WebAssembly/);
  }, 60_000);
});
