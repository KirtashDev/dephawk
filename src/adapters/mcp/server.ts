import type { DhEvent } from '../../domain/event.js';
import { PERMISSIVE_POLICY } from '../../domain/policy.js';
import {
  TECHNIQUE_GLOSS,
  detectExfilChains,
  detectTechnique,
} from '../../domain/threat.js';
import { auditCommand } from '../../composition/monitored-run.js';
import { examinePackage } from '../../composition/examine-package.js';

/**
 * A Model Context Protocol server that exposes dephawk to an AI coding agent, so
 * the agent can watch what a command's dependencies actually *do* at runtime —
 * the surface it otherwise installs and runs blind. Speaks the MCP stdio
 * transport (newline-delimited JSON-RPC 2.0) by hand: dephawk ships zero runtime
 * dependencies, and a security tool adding an SDK to its own supply chain would
 * be the joke writing itself. stdout is the protocol channel; every diagnostic
 * goes to stderr.
 */
export interface McpServerOptions {
  readonly version: string;
  /** `file://` URL of dephawk's `register.js`, for the audited child. */
  readonly registerUrl: string;
  /** Overridable for tests. Defaults to the real process streams. */
  readonly stdin?: NodeJS.ReadableStream;
  readonly stdout?: NodeJS.WritableStream;
}

interface JsonRpcRequest {
  readonly jsonrpc: '2.0';
  readonly id?: string | number | null;
  readonly method: string;
  readonly params?: Record<string, unknown>;
}

const PROTOCOL_VERSION = '2024-11-05';

const TOOLS = [
  {
    name: 'list_attack_techniques',
    description:
      'List the supply-chain attack techniques dephawk recognises at runtime (cloud-metadata SSRF, dead-drop C2, CI/git/editor-hook persistence, registry self-publish, credential exfiltration), each with a plain-English gloss. No arguments. Use it to explain what a dephawk finding means.',
    inputSchema: { type: 'object', properties: {}, additionalProperties: false },
  },
  {
    name: 'audit_package',
    description:
      'Vet a single npm package BEFORE trusting it: install it in a throwaway sandbox, run it (install scripts + import) under dephawk, and report what it actually does — secrets read, hosts reached, processes spawned, recognised attack techniques, likely exfiltration. Call this before adding a dependency you are unsure about. Accepts a registry name, name@version, or a local path/tarball.',
    inputSchema: {
      type: 'object',
      properties: {
        package: {
          type: 'string',
          description: 'The package spec, e.g. "left-pad", "chalk@5", or "./local-pkg".',
        },
      },
      required: ['package'],
      additionalProperties: false,
    },
  },
  {
    name: 'audit_command',
    description:
      'Run a command (e.g. an install or a build/test script) under dephawk and report what its npm dependencies actually did at runtime — files read/written, network reached, processes spawned, secrets touched, and any recognised attack technique. Runs in OBSERVE mode: it records, it does not block (use `dephawk run --enforce` to block). Use this before trusting freshly-installed packages, or to investigate a suspicious dependency.',
    inputSchema: {
      type: 'object',
      properties: {
        command: {
          type: 'array',
          items: { type: 'string' },
          minItems: 1,
          description: 'Argv to run, e.g. ["npm","ci"] or ["node","index.js"].',
        },
        cwd: {
          type: 'string',
          description: 'Working directory. Defaults to the current one.',
        },
      },
      required: ['command'],
      additionalProperties: false,
    },
  },
] as const;

/** Start the MCP server; resolves when stdin closes. */
export function startMcpServer(options: McpServerOptions): Promise<void> {
  const stdin = options.stdin ?? process.stdin;
  const stdout = options.stdout ?? process.stdout;

  const send = (message: unknown): void => {
    stdout.write(`${JSON.stringify(message)}\n`);
  };
  const reply = (id: JsonRpcRequest['id'], result: unknown): void => {
    send({ jsonrpc: '2.0', id, result });
  };
  const fail = (id: JsonRpcRequest['id'], code: number, message: string): void => {
    send({ jsonrpc: '2.0', id, error: { code, message } });
  };

  const handle = async (request: JsonRpcRequest): Promise<void> => {
    const { id, method } = request;
    switch (method) {
      case 'initialize':
        reply(id, {
          protocolVersion:
            asString(request.params?.['protocolVersion']) ?? PROTOCOL_VERSION,
          capabilities: { tools: {} },
          serverInfo: { name: 'dephawk', version: options.version },
        });
        return;
      case 'notifications/initialized':
      case 'notifications/cancelled':
        return; // notifications: no response
      case 'ping':
        reply(id, {});
        return;
      case 'tools/list':
        reply(id, { tools: TOOLS });
        return;
      case 'tools/call': {
        const name = asString(request.params?.['name']);
        const args = (request.params?.['arguments'] as Record<string, unknown>) ?? {};
        try {
          const text = await callTool(name, args, options);
          reply(id, { content: [{ type: 'text', text }] });
        } catch (error) {
          // A tool failure is reported inside the result (isError), not as a
          // protocol error, so the agent sees the message.
          reply(id, {
            content: [{ type: 'text', text: `dephawk: ${describeError(error)}` }],
            isError: true,
          });
        }
        return;
      }
      default:
        if (id !== undefined && id !== null) {
          fail(id, -32601, `method not found: ${method}`);
        }
    }
  };

  return new Promise<void>((resolve) => {
    let buffer = '';
    stdin.setEncoding?.('utf8');
    stdin.on('data', (chunk: string) => {
      buffer += chunk;
      let newline = buffer.indexOf('\n');
      while (newline !== -1) {
        const line = buffer.slice(0, newline).trim();
        buffer = buffer.slice(newline + 1);
        if (line.length > 0) {
          let request: JsonRpcRequest | null = null;
          try {
            request = JSON.parse(line) as JsonRpcRequest;
          } catch {
            request = null; // ignore a malformed line rather than crash the server
          }
          if (request !== null && typeof request.method === 'string') {
            void handle(request);
          }
        }
        newline = buffer.indexOf('\n');
      }
    });
    stdin.on('end', () => resolve());
    stdin.on('close', () => resolve());
  });
}

async function callTool(
  name: string | undefined,
  args: Record<string, unknown>,
  options: McpServerOptions,
): Promise<string> {
  switch (name) {
    case 'list_attack_techniques':
      return JSON.stringify(
        {
          techniques: TECHNIQUE_GLOSS,
          note: 'dephawk also flags "likely credential exfiltration": the same dependency reads a secret and then reaches the network.',
        },
        null,
        2,
      );
    case 'audit_command':
      return auditCommandTool(args, options);
    case 'audit_package':
      return auditPackageTool(args, options);
    default:
      throw new Error(`unknown tool: ${String(name)}`);
  }
}

async function auditPackageTool(
  args: Record<string, unknown>,
  options: McpServerOptions,
): Promise<string> {
  const spec = asString(args['package']);
  if (spec === undefined || spec.length === 0) {
    throw new Error(
      '`package` must be a non-empty string, e.g. "left-pad" or "chalk@5".',
    );
  }
  const result = await examinePackage(spec, {
    registerUrl: options.registerUrl,
    mode: 'observe',
  });
  if (!result.installed) {
    throw new Error(`could not install package: ${spec}`);
  }
  const core = summariseEvents(result.events);
  return JSON.stringify(
    {
      package: result.package,
      mode: 'observe',
      verdict:
        core.recognisedTechniques.length > 0
          ? 'recognised attack technique — treat with suspicion'
          : core.findings.length > 0
            ? 'touched something sensitive — review before trusting'
            : 'nothing sensitive observed',
      ...core,
    },
    null,
    2,
  );
}

async function auditCommandTool(
  args: Record<string, unknown>,
  options: McpServerOptions,
): Promise<string> {
  const command = args['command'];
  if (!Array.isArray(command) || command.length === 0 || typeof command[0] !== 'string') {
    throw new Error('`command` must be a non-empty array of strings, e.g. ["npm","ci"].');
  }
  const argv = command.map((part) => String(part));
  const cwd = asString(args['cwd']);

  const outcome = await auditCommand(argv[0] as string, argv.slice(1), {
    policy: PERMISSIVE_POLICY,
    registerUrl: options.registerUrl,
    mode: 'observe',
    ...(cwd === undefined ? {} : { cwd }),
  });

  if (!outcome.started) {
    throw new Error(`could not start command: ${argv.join(' ')}`);
  }
  return JSON.stringify(summarise(argv, outcome.exitCode, outcome.events), null, 2);
}

interface Finding {
  readonly package: string | null;
  readonly capability: string;
  readonly detail: string;
  readonly technique: string | null;
  readonly sensitive: boolean;
}

interface EventSummary {
  readonly packagesTouchingSensitive: string[];
  readonly recognisedTechniques: string[];
  readonly likelyCredentialExfiltration: {
    package: string;
    readSecret: string;
    thenReached: string;
  }[];
  readonly findings: Finding[];
  readonly dependencyCallCount: number;
}

/** The shared, deduplicated core summary of what dependencies did. */
function summariseEvents(events: readonly DhEvent[]): EventSummary {
  const dependencyEvents = events.filter((event) => event.origin === 'dependency');
  const sensitive: Finding[] = [];
  const seen = new Set<string>();
  const techniques = new Set<string>();
  const packages = new Set<string>();

  for (const event of dependencyEvents) {
    const technique = detectTechnique(event.capability, event.detail);
    if (technique !== null) {
      techniques.add(technique);
    }
    if (!event.sensitive && technique === null) {
      continue;
    }
    if (event.package !== null) {
      packages.add(event.package);
    }
    const key = `${event.package}|${event.capability}|${event.detail}`;
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    sensitive.push({
      package: event.package,
      capability: event.capability,
      detail: event.detail,
      technique,
      sensitive: event.sensitive,
    });
  }

  return {
    packagesTouchingSensitive: [...packages].sort(),
    recognisedTechniques: [...techniques].sort(),
    likelyCredentialExfiltration: detectExfilChains(events).map((chain) => ({
      package: chain.package,
      readSecret: chain.secret,
      thenReached: chain.sink,
    })),
    findings: sensitive,
    dependencyCallCount: dependencyEvents.length,
  };
}

/** Turn the raw events of an audited command into an agent-friendly summary. */
function summarise(
  argv: readonly string[],
  exitCode: number,
  events: readonly DhEvent[],
): unknown {
  const core = summariseEvents(events);
  return {
    command: argv.join(' '),
    exitCode,
    mode: 'observe',
    summary:
      core.findings.length === 0
        ? 'No dependency touched anything sensitive.'
        : `${core.packagesTouchingSensitive.length} dependency package(s) touched something sensitive across ${core.findings.length} call(s).`,
    ...core,
  };
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' ? value : undefined;
}

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
