/**
 * The environment that attaches dephawk to a process tree, for every runtime it
 * supports. One place, so `dephawk run`/`guard`, `init` and the MCP server's
 * `audit_command` cannot drift apart.
 *
 * - **Node** loads `register.js` from `NODE_OPTIONS=--import <url>`.
 * - **Bun** ignores `NODE_OPTIONS` but honours `BUN_OPTIONS=--preload <url>`.
 *   It also needs `BUN_JSC_useTailCalls=false`: JavaScriptCore implements ES2015
 *   proper tail calls, so `return f()` *removes the caller's frame* — and Bun's
 *   transpiler rewrites `const s = f(); return s;` into exactly that. With tail
 *   calls on, a dependency's own frame can vanish from the stack between its
 *   code and the intercepted call, which is the frame attribution rests on. See
 *   {@link import('../adapters/interceptors/support.js').FRAMES_ELIDED}.
 * - **Deno** (2.x) runs `--preload` from its own command line; nothing to
 *   inject, and its stacks are V8's.
 */

/** Append `fragment` to a space-separated options string unless already present. */
function withFragment(existing: string | undefined, fragment: string): string {
  if (existing !== undefined && existing.includes(fragment)) {
    return existing;
  }
  return [existing, fragment]
    .filter((part): part is string => part !== undefined && part.length > 0)
    .join(' ');
}

/** The runtime-loader variables that put `registerUrl` into every child. */
export function runtimeLoaderEnv(
  base: NodeJS.ProcessEnv,
  registerUrl: string,
): Record<string, string> {
  return {
    NODE_OPTIONS: withFragment(base['NODE_OPTIONS'], `--import ${registerUrl}`),
    BUN_OPTIONS: withFragment(base['BUN_OPTIONS'], `--preload ${registerUrl}`),
    BUN_JSC_useTailCalls: 'false',
  };
}

/** `deno` subcommands that execute a module and accept `--preload`. */
const DENO_RUNNERS: ReadonlySet<string> = new Set(['run', 'test', 'serve', 'bench']);

/**
 * The argv that attaches dephawk to a top-level `deno` command. Deno reads no
 * `NODE_OPTIONS` and has no environment variable for a preload, so the only
 * way in is its own `--preload` flag, inserted right after the subcommand:
 * `deno run -A app.ts` → `deno run --preload <register> -A app.ts`.
 *
 * Anything else — not `deno`, a subcommand that runs nothing (`fmt`, `lint`),
 * or a command that already preloads dephawk — is returned unchanged.
 */
export function withDenoPreload(
  command: string,
  args: readonly string[],
  registerUrl: string,
): string[] {
  const name = command
    .replace(/\\/g, '/')
    .split('/')
    .pop()
    ?.replace(/\.exe$/i, '');
  const sub = args[0];
  if (name !== 'deno' || sub === undefined || !DENO_RUNNERS.has(sub)) {
    return [...args];
  }
  if (args.includes(registerUrl)) {
    return [...args];
  }
  return [sub, '--preload', registerUrl, ...args.slice(1)];
}
