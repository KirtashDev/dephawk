import { describe, it, expect } from 'vitest';
import { PassThrough } from 'node:stream';
import { startMcpServer } from '../../../src/adapters/mcp/server.js';

/** Drive the server over in-memory streams and collect the JSON-RPC replies. */
async function driveServer(
  requests: unknown[],
  expectedIds: number[],
): Promise<Map<number, Record<string, unknown>>> {
  const stdin = new PassThrough();
  const stdout = new PassThrough();
  void startMcpServer({
    version: '9.9.9',
    registerUrl: 'file:///nowhere/register.js',
    stdin,
    stdout,
  });

  const replies = new Map<number, Record<string, unknown>>();
  const done = new Promise<void>((resolve) => {
    let buffer = '';
    stdout.on('data', (chunk: Buffer) => {
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
      if (expectedIds.every((id) => replies.has(id))) {
        resolve();
      }
    });
  });

  for (const request of requests) {
    stdin.write(`${JSON.stringify(request)}\n`);
  }
  await done;
  return replies;
}

describe('MCP server — protocol', () => {
  it('answers initialize with dephawk server info and tools capability', async () => {
    const replies = await driveServer(
      [{ jsonrpc: '2.0', id: 1, method: 'initialize', params: {} }],
      [1],
    );
    const result = replies.get(1)?.['result'] as Record<string, unknown>;
    expect((result['serverInfo'] as Record<string, unknown>)['name']).toBe('dephawk');
    expect((result['serverInfo'] as Record<string, unknown>)['version']).toBe('9.9.9');
    expect(result['capabilities']).toHaveProperty('tools');
  });

  it('lists the audit and technique tools', async () => {
    const replies = await driveServer(
      [{ jsonrpc: '2.0', id: 2, method: 'tools/list' }],
      [2],
    );
    const result = replies.get(2)?.['result'] as { tools: { name: string }[] };
    const names = result.tools.map((tool) => tool.name);
    expect(names).toContain('list_attack_techniques');
    expect(names).toContain('audit_command');
    expect(names).toContain('audit_package');
  });

  it('returns the technique glossary from list_attack_techniques (no child spawned)', async () => {
    const replies = await driveServer(
      [
        {
          jsonrpc: '2.0',
          id: 3,
          method: 'tools/call',
          params: { name: 'list_attack_techniques', arguments: {} },
        },
      ],
      [3],
    );
    const result = replies.get(3)?.['result'] as {
      content: { type: string; text: string }[];
    };
    const payload = JSON.parse(result.content[0]!.text) as {
      techniques: Record<string, string>;
    };
    expect(payload.techniques).toHaveProperty('editor-hook-persistence');
    expect(payload.techniques).toHaveProperty('dead-drop-c2');
  });

  it('reports a tool error inside the result rather than as a protocol error', async () => {
    const replies = await driveServer(
      [
        {
          jsonrpc: '2.0',
          id: 4,
          method: 'tools/call',
          params: { name: 'audit_command', arguments: { command: [] } },
        },
      ],
      [4],
    );
    const result = replies.get(4)?.['result'] as {
      isError?: boolean;
      content: { text: string }[];
    };
    expect(result.isError).toBe(true);
    expect(result.content[0]!.text).toMatch(/non-empty array/);
  });

  it('returns method-not-found for an unknown method', async () => {
    const replies = await driveServer(
      [{ jsonrpc: '2.0', id: 5, method: 'does/not/exist' }],
      [5],
    );
    expect((replies.get(5)?.['error'] as Record<string, unknown>)['code']).toBe(-32601);
  });
});
