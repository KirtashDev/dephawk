import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import { FsInterceptor, type FsInterceptorOptions } from './fs.interceptor.js';
import { captureMonitoringEnv, restoreMonitoring } from './monitored-env.js';
import {
  asRuntimeInternals,
  blockedError,
  report,
  restorer,
  type AnyFn,
  type RecordFn,
} from './support.js';

/** What the Bun interceptor can be told. */
export interface BunInterceptorOptions extends FsInterceptorOptions {
  /** `register.js`'s URL, so a `Bun.spawn` child keeps monitoring. */
  readonly registerUrl?: string;
}

type BunGlobal = Record<string, unknown>;

/**
 * Bun's own runtime API — the door that goes around every other interceptor.
 *
 * Bun implements `node:fs`, `node:child_process` and friends, and those are
 * watched like on Node. But it also ships native equivalents on the `Bun`
 * global that never touch them:
 *
 * ```js
 * await Bun.file(`${home}/.ssh/id_rsa`).text();          // no fs call
 * Bun.spawn(['sh', '-c', 'curl … | sh']);                // no child_process
 * await Bun.$`cat ~/.aws/credentials`;                    // a whole shell
 * Bun.serve({ port: 4444, fetch: backdoor });              // no net.Server
 * ```
 *
 * Under 0.14 each of these ran with no event at all. They are recorded here as
 * the same capabilities their Node counterparts produce, so policy, the report
 * and technique naming apply unchanged. `import { file } from 'bun'` is a live
 * binding to the global's property, so patching the global covers it.
 *
 * The properties are writable but **not configurable**, so they are assigned
 * rather than redefined (`patchMethod`'s `defineProperty` would throw).
 *
 * A no-op outside Bun.
 */
export class BunInterceptor implements CapabilityInterceptor {
  readonly name = 'bun';
  private readonly options: BunInterceptorOptions;

  constructor(options: BunInterceptorOptions = {}) {
    this.options = options;
  }

  install(record: RecordFn): Disposable {
    const bun = (globalThis as { Bun?: BunGlobal }).Bun;
    if (bun === undefined || bun === null) {
      return restorer([]);
    }
    const fs = new FsInterceptor(this.options);
    const monitoring = captureMonitoringEnv(process.env, this.options.registerUrl);
    const restores: (() => void)[] = [];

    const patch = (key: string, wrap: (original: AnyFn) => AnyFn): void => {
      const original = bun[key];
      if (typeof original !== 'function') {
        return;
      }
      try {
        bun[key] = wrap(original as AnyFn);
        restores.push(() => {
          bun[key] = original;
        });
      } catch {
        // Read-only in this Bun build — nothing to patch.
      }
    };

    const judge = (capability: Parameters<typeof report>[1], detail: string): void => {
      const decision = report(record, capability, detail);
      if (!decision.allow) {
        throw blockedError(`${capability} of ${detail}`, decision.reason);
      }
    };

    // Lazy file handles: judged when the handle is made, on the path — the
    // same moment and the same rules as `fs.open`.
    patch(
      'file',
      (original) =>
        function (this: unknown, ...args: unknown[]): unknown {
          const path = pathOf(args[0]);
          if (path !== null) {
            fs.checkPath(record, 'fs.read', path);
          }
          return Reflect.apply(original, this, args);
        },
    );
    patch(
      'write',
      (original) =>
        function (this: unknown, ...args: unknown[]): unknown {
          const path = pathOf(args[0]);
          if (path !== null) {
            fs.checkPath(record, 'fs.write', path);
          }
          return Reflect.apply(original, this, args);
        },
    );

    for (const key of ['spawn', 'spawnSync']) {
      patch(
        key,
        (original) =>
          function (this: unknown, ...args: unknown[]): unknown {
            const restored = reattachBunSpawn(args, monitoring);
            const note =
              restored.length > 0 ? ` [dephawk re-attached: ${restored.join(', ')}]` : '';
            judge('process.spawn', `${describeBunCommand(args)}${note}`);
            // Bun copies `process.env` to build the child's environment; those
            // reads are the runtime's plumbing, not the caller's.
            return asRuntimeInternals(() => Reflect.apply(original, this, args));
          },
      );
    }

    // `Bun.$` is a tagged template that runs a whole shell script. It carries
    // its own API (`$.escape`, `$.Shell`, `$.braces`) and does not inherit
    // `Function.prototype`, so it is wrapped in a Proxy that keeps all of that
    // and intercepts only the call.
    patch(
      '$',
      (original) =>
        new Proxy(original, {
          apply(target, thisArg, args: unknown[]): unknown {
            judge('process.spawn', `$ ${describeTemplate(args)}`);
            return asRuntimeInternals(() => Reflect.apply(target, thisArg, args));
          },
        }),
    );

    patch(
      'serve',
      (original) =>
        function (this: unknown, ...args: unknown[]): unknown {
          judge('net.listen', describeEndpoint(args[0], '', 3000));
          return Reflect.apply(original, this, args);
        },
    );
    patch(
      'listen',
      (original) =>
        function (this: unknown, ...args: unknown[]): unknown {
          judge('net.listen', describeEndpoint(args[0], '', 0));
          return Reflect.apply(original, this, args);
        },
    );
    patch(
      'udpSocket',
      (original) =>
        function (this: unknown, ...args: unknown[]): unknown {
          judge('net.listen', `udp:${describeEndpoint(args[0], '', 0)}`);
          return Reflect.apply(original, this, args);
        },
    );
    patch(
      'connect',
      (original) =>
        function (this: unknown, ...args: unknown[]): unknown {
          judge('net.connect', describeEndpoint(args[0], 'localhost', 0));
          return Reflect.apply(original, this, args);
        },
    );

    return restorer(restores);
  }
}

/** A filesystem path from what `Bun.file`/`Bun.write` accept, or null (fd, Blob, Response). */
function pathOf(target: unknown): string | null {
  try {
    if (typeof target === 'string') {
      return resolve(target.startsWith('file:') ? fileURLToPath(target) : target);
    }
    if (target instanceof URL) {
      return target.protocol === 'file:' ? resolve(fileURLToPath(target)) : null;
    }
    // A `BunFile` passed as `Bun.write`'s destination carries its path as `name`.
    if (typeof target === 'object' && target !== null) {
      const name = (target as { name?: unknown }).name;
      return typeof name === 'string' ? resolve(name) : null;
    }
  } catch {
    // An unparseable URL is not a path; nothing to judge.
  }
  return null;
}

/** `Bun.spawn(['a', 'b'])` / `Bun.spawn({ cmd: [...] })` as one command line. */
export function describeBunCommand(args: readonly unknown[]): string {
  const first = args[0];
  const cmd = Array.isArray(first)
    ? first
    : typeof first === 'object' && first !== null
      ? (first as { cmd?: unknown }).cmd
      : undefined;
  if (Array.isArray(cmd)) {
    return cmd.map((part) => String(part)).join(' ');
  }
  return typeof first === 'string' ? first : '<unknown command>';
}

/** A tagged template call's text, values in place. */
export function describeTemplate(args: readonly unknown[]): string {
  const strings = args[0];
  if (!Array.isArray(strings)) {
    return String(strings);
  }
  let out = '';
  strings.forEach((part: unknown, i: number) => {
    out += String(part);
    if (i + 1 < args.length) {
      const value = args[i + 1];
      out += Array.isArray(value) ? value.map(String).join(' ') : String(value);
    }
  });
  return out.trim();
}

/** `{ hostname, port }` / `{ unix }` as `host:port`, the detail Node's interceptors use. */
export function describeEndpoint(
  options: unknown,
  defaultHost: string,
  defaultPort: number,
): string {
  if (typeof options !== 'object' || options === null) {
    return `${defaultHost}:${defaultPort}`;
  }
  const o = options as Record<string, unknown>;
  if (typeof o['unix'] === 'string') {
    return o['unix'];
  }
  const host = typeof o['hostname'] === 'string' ? o['hostname'] : defaultHost;
  const port =
    typeof o['port'] === 'number' || typeof o['port'] === 'string'
      ? String(o['port'])
      : String(defaultPort);
  return `${host}:${port}`;
}

/**
 * Put monitoring back into an explicit `env` on a `Bun.spawn` call — the Bun
 * form of the env-strip bypass (`Bun.spawn(cmd, { env: {} })` would start an
 * unmonitored child). Mutates the options in place, like the Node reattach.
 */
function reattachBunSpawn(
  args: unknown[],
  monitoring: ReturnType<typeof captureMonitoringEnv>,
): readonly string[] {
  const index = Array.isArray(args[0]) ? 1 : 0;
  const options = args[index];
  if (typeof options !== 'object' || options === null || Array.isArray(options)) {
    return [];
  }
  const env = (options as { env?: unknown }).env;
  if (typeof env !== 'object' || env === null) {
    return []; // inherits process.env, which already carries monitoring
  }
  const { env: patched, restored } = restoreMonitoring(
    env as NodeJS.ProcessEnv,
    monitoring,
  );
  if (restored.length > 0) {
    args[index] = { ...(options as Record<string, unknown>), env: patched };
  }
  return restored;
}
