import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import { spawn, execSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

// The MCP server lets an AI agent ask dephawk to audit what a command's
// dependencies do at runtime. Drive the real built server over stdio.
const cliPath = resolve('dist/cli.js');
const registerPath = resolve('dist/register.js');
const projectDir = join(tmpdir(), `dephawk-mcp-e2e-${process.pid}`);

beforeAll(() => {
  if (!existsSync(cliPath) || !existsSync(registerPath)) {
    execSync('npm run build', { stdio: 'ignore' });
  }
  const evilDir = join(projectDir, 'node_modules', 'evil-dep');
  mkdirSync(evilDir, { recursive: true });
  writeFileSync(join(projectDir, 'secret-key'), 'fake-secret\n');
  writeFileSync(
    join(evilDir, 'package.json'),
    JSON.stringify({ name: 'evil-dep', version: '1.0.0', main: 'index.js' }),
  );
  writeFileSync(
    join(evilDir, 'index.js'),
    [
      "const fs = require('node:fs');",
      "const path = require('node:path');",
      // Read a browser-credential-shaped path so it registers as sensitive.
      "try { fs.readFileSync(path.join(require('node:os').homedir(), '.aws', 'credentials')); } catch {}",
      "try { require('node:dns').resolve('mainnet.infura.io', () => {}); } catch {}",
    ].join('\n'),
  );
  writeFileSync(join(projectDir, 'app.js'), "require('evil-dep');\n");
}, 180_000);

afterAll(() => rmSync(projectDir, { recursive: true, force: true }));

/** Send JSON-RPC lines to `dephawk mcp` and collect id-addressed replies. */
function driveMcp(
  requests: unknown[],
  waitForId: number,
): Promise<Map<number, Record<string, unknown>>> {
  return new Promise((resolvePromise, reject) => {
    const child = spawn(process.execPath, [cliPath, 'mcp'], {
      stdio: ['pipe', 'pipe', 'ignore'],
    });
    const replies = new Map<number, Record<string, unknown>>();
    let buffer = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error('MCP server timed out'));
    }, 30_000);
    child.stdout.on('data', (chunk: Buffer) => {
      buffer += chunk.toString('utf8');
      let newline = buffer.indexOf('\n');
      while (newline !== -1) {
        const line = buffer.slice(0, newline).trim();
        buffer = buffer.slice(newline + 1);
        if (line.length > 0) {
          const message = JSON.parse(line) as Record<string, unknown>;
          if (typeof message['id'] === 'number') {
            replies.set(message['id'], message);
          }
        }
        newline = buffer.indexOf('\n');
      }
      if (replies.has(waitForId)) {
        clearTimeout(timer);
        child.stdin.end();
        child.kill();
        resolvePromise(replies);
      }
    });
    for (const request of requests) {
      child.stdin.write(`${JSON.stringify(request)}\n`);
    }
  });
}

describe('e2e: dephawk mcp audits a command for an AI agent', () => {
  it('reports the sensitive calls a dependency made', async () => {
    const replies = await driveMcp(
      [
        { jsonrpc: '2.0', id: 1, method: 'initialize', params: {} },
        {
          jsonrpc: '2.0',
          id: 2,
          method: 'tools/call',
          params: {
            name: 'audit_command',
            arguments: { command: ['node', 'app.js'], cwd: projectDir },
          },
        },
      ],
      2,
    );

    const result = replies.get(2)?.['result'] as { content: { text: string }[] };
    const report = JSON.parse(result.content[0]!.text) as {
      packagesTouchingSensitive: string[];
      recognisedTechniques: string[];
      findings: { detail: string }[];
    };
    expect(report.packagesTouchingSensitive).toContain('evil-dep');
    expect(report.recognisedTechniques).toContain('dead-drop-c2');
    expect(report.findings.some((f) => f.detail.includes('credentials'))).toBe(true);
  }, 60_000);
});
