import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import {
  blockedError,
  patchMethod,
  prototypeOf,
  report,
  restorer,
  type RecordFn,
  loadBuiltin,
} from './support.js';

const vm = loadBuiltin('node:vm');

import { noteCompiledFilename } from '../attribution/compiled-context.js';

/** Module-level entrypoints that compile and run a source string directly. */
const VM_FUNCTIONS = [
  'runInThisContext',
  'runInNewContext',
  'runInContext',
  'compileFunction',
] as const;

/** `vm.Script` prototype run methods (source was compiled in the constructor). */
const SCRIPT_RUN_METHODS = [
  'runInThisContext',
  'runInNewContext',
  'runInContext',
] as const;

const MAX_SNIPPET = 80;

/**
 * Intercepts dynamic code execution through the `vm` module
 * (`vm.runInThisContext`, `vm.runInNewContext`, `vm.runInContext`,
 * `vm.compileFunction`, and `vm.Script.prototype.run*`). Recorded as
 * `code.eval`; disallowed by default and blocked in enforce mode.
 *
 * Running compiled code from a string is how obfuscated payloads execute: the
 * malicious logic ships as an encoded blob and is decoded then handed to `vm`
 * at runtime, so static scanning of the published package sees nothing. A
 * dependency reaching for `vm` is almost always doing something it should
 * declare.
 *
 * The convenience functions delegate to `Script.prototype` internally, which
 * dephawk also patches (to catch code that compiles a `Script` explicitly). A
 * re-entrancy depth guard makes each logical `vm` call report exactly once: the
 * convenience function reports with the source snippet, and the nested
 * prototype call it triggers is suppressed. A standalone `new vm.Script(code)`
 * is still caught at the prototype, labelled `<compiled vm.Script>`.
 *
 * Limitations:
 * - The `eval()` and `new Function()` intrinsics are language primitives, not
 *   module methods, and cannot be monkey-patched — this covers the `vm`
 *   surface, which is the deliberate, high-volume path for staged code.
 * - The depth guard cannot tell a convenience fn's own internal delegation from
 *   a genuinely separate `vm.Script` execution that the *running* code starts
 *   synchronously inside it; the latter is suppressed. Erring toward one event
 *   per top-level call, this trades a rare missed nested record for no double
 *   counting on the common path.
 */
export class VmInterceptor implements CapabilityInterceptor {
  readonly name = 'vm';

  install(record: RecordFn): Disposable {
    const restores: (() => void)[] = [];
    const mod = vm as unknown as Record<string, unknown>;
    const state = { depth: 0 };

    for (const key of VM_FUNCTIONS) {
      this.patchModuleFn(mod, key, record, restores, state);
    }

    // `vm.createScript(code, { filename })` is a legacy alias that builds a
    // `Script` through the module-internal binding, so the `Script` constructor
    // subclass never sees its `filename` option — a script could then claim a
    // victim package's filename and launder its frames. The resulting script's
    // run methods are still gated at the prototype; wrapping createScript only
    // records the filename so the attributor distrusts frames that claim it.
    const createRestore = patchMethod(
      mod,
      'createScript',
      (original) =>
        function (this: unknown, ...args: unknown[]): unknown {
          noteFilenameFrom(args);
          return (original as (...a: unknown[]) => unknown).apply(this, args);
        },
    );
    if (createRestore) {
      restores.push(createRestore);
    }

    const proto = prototypeOf((vm as unknown as { Script?: unknown }).Script);
    if (proto) {
      for (const key of SCRIPT_RUN_METHODS) {
        this.patchScriptFn(proto, key, record, restores, state);
      }
    }

    // `new vm.Script(code, { filename })` names the script at construction, and
    // the run methods above never see that option — so the constructor is
    // wrapped too. A subclass rather than a function wrapper, so `prototype`,
    // `instanceof` and `new.target` all keep working.
    const scriptRestore = this.patchScriptConstructor(mod);
    if (scriptRestore) {
      restores.push(scriptRestore);
    }

    // The ESM equivalent, behind `--experimental-vm-modules`:
    // `new vm.SourceTextModule(src)` compiles a source string and `.evaluate()`
    // runs it, entirely outside the `Script` surface above — a dependency with
    // `eval: false` could execute compiled code through it. `SyntheticModule` is
    // the same primitive without the string. Gated at construction as
    // `code.eval`, deny-by-default, like every other `vm` entry.
    for (const key of ['SourceTextModule', 'SyntheticModule'] as const) {
      const restore = this.patchModuleConstructor(mod, key, record);
      if (restore) {
        restores.push(restore);
      }
    }

    return restorer(restores);
  }

  /**
   * Gate a `vm` module constructor (`SourceTextModule`/`SyntheticModule`) as
   * `code.eval`: constructing one declares the intent to run compiled code, so
   * it is refused before `super()` in enforce mode. A subclass keeps
   * `instanceof`/`prototype` intact.
   */
  private patchModuleConstructor(
    mod: Record<string, unknown>,
    key: string,
    record: RecordFn,
  ): (() => void) | null {
    const Original = mod[key];
    if (typeof Original !== 'function') {
      return null; // not on this runtime / flag not set
    }
    const Base = Original as unknown as new (...args: unknown[]) => object;
    const detail = `vm.${key}`;
    class WatchedModule extends Base {
      constructor(...args: unknown[]) {
        const decision = report(record, 'code.eval', detail);
        if (!decision.allow) {
          throw blockedError(`dynamic code execution via ${detail}`, decision.reason);
        }
        super(...args);
      }
    }
    Object.defineProperty(WatchedModule, 'name', { value: key });
    mod[key] = WatchedModule;
    return () => {
      mod[key] = Original;
    };
  }

  /** Remember the `filename` a `vm.Script` was constructed with. */
  private patchScriptConstructor(mod: Record<string, unknown>): (() => void) | null {
    const Original = mod['Script'];
    if (typeof Original !== 'function') {
      return null;
    }
    const Base = Original as unknown as new (...args: unknown[]) => object;
    class WatchedScript extends Base {
      constructor(...args: unknown[]) {
        noteFilenameFrom(args);
        super(...args);
      }
    }
    Object.defineProperty(WatchedScript, 'name', { value: 'Script' });
    mod['Script'] = WatchedScript;
    return () => {
      mod['Script'] = Original;
    };
  }

  /** A convenience fn: always reports (with a snippet) and guards nested runs. */
  private patchModuleFn(
    target: Record<string, unknown>,
    key: string,
    record: RecordFn,
    restores: (() => void)[],
    state: { depth: number },
  ): void {
    const restore = patchMethod(
      target,
      key,
      (original) =>
        function (this: unknown, ...args: unknown[]): unknown {
          noteFilenameFrom(args);
          const decision = report(record, 'code.eval', snippet(args[0]));
          if (!decision.allow) {
            throw blockedError('dynamic code execution', decision.reason);
          }
          state.depth += 1;
          try {
            return (original as (...a: unknown[]) => unknown).apply(this, args);
          } finally {
            state.depth -= 1;
          }
        },
    );
    if (restore) {
      restores.push(restore);
    }
  }

  /** A `Script.prototype` run method: reports only when not reached via a module fn. */
  private patchScriptFn(
    target: Record<string, unknown>,
    key: string,
    record: RecordFn,
    restores: (() => void)[],
    state: { depth: number },
  ): void {
    const restore = patchMethod(
      target,
      key,
      (original) =>
        function (this: unknown, ...args: unknown[]): unknown {
          if (state.depth === 0) {
            const decision = report(record, 'code.eval', '<compiled vm.Script>');
            if (!decision.allow) {
              throw blockedError('dynamic code execution', decision.reason);
            }
          }
          // Increment across the call so a run method that delegates to another
          // patched prototype method internally (runInNewContext -> runInContext)
          // does not report a second time.
          state.depth += 1;
          try {
            return (original as (...a: unknown[]) => unknown).apply(this, args);
          } finally {
            state.depth -= 1;
          }
        },
    );
    if (restore) {
      restores.push(restore);
    }
  }
}

/**
 * Record any `filename` option handed to `vm`, so the attributor can refuse to
 * believe frames that claim to come from it. Scans the arguments rather than
 * indexing a fixed position: the option sits third for `runInNewContext` and
 * `runInContext`, second for `runInThisContext`, `compileFunction` and the
 * `Script` constructor.
 */
function noteFilenameFrom(args: readonly unknown[]): void {
  for (const arg of args) {
    if (typeof arg === 'object' && arg !== null && !Array.isArray(arg)) {
      const filename = (arg as { filename?: unknown }).filename;
      if (typeof filename === 'string') {
        noteCompiledFilename(filename);
      }
    }
  }
}

function snippet(code: unknown): string {
  if (typeof code !== 'string') {
    return '<non-string source>';
  }
  const oneLine = code.replace(/\s+/g, ' ').trim();
  return oneLine.length <= MAX_SNIPPET
    ? oneLine
    : `${oneLine.slice(0, MAX_SNIPPET - 1)}…`;
}
