import vm from 'node:vm';
import type { CapabilityInterceptor, Disposable } from '../../application/ports.js';
import {
  blockedError,
  patchMethod,
  prototypeOf,
  report,
  restorer,
  type RecordFn,
} from './support.js';

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
 * Limitation: the `eval()` and `new Function()` intrinsics are language
 * primitives, not module methods, and cannot be monkey-patched — this covers
 * the `vm` surface, which is the deliberate, high-volume path for staged code.
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

    const proto = prototypeOf((vm as unknown as { Script?: unknown }).Script);
    if (proto) {
      for (const key of SCRIPT_RUN_METHODS) {
        this.patchScriptFn(proto, key, record, restores, state);
      }
    }

    return restorer(restores);
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
          return (original as (...a: unknown[]) => unknown).apply(this, args);
        },
    );
    if (restore) {
      restores.push(restore);
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
