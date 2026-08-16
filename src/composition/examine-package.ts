import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import type { DhEvent } from '../domain/event.js';
import type { Mode } from '../domain/policy.js';
import { PERMISSIVE_POLICY } from '../domain/policy.js';
import { auditCommand } from './monitored-run.js';

export interface ExamineOptions {
  readonly registerUrl: string;
  /** `observe` (default) records; `enforce` blocks anything sensitive. */
  readonly mode?: Mode;
}

export interface ExamineResult {
  /** The package name (version/tag stripped from the spec). */
  readonly package: string;
  /** Whether `npm install` actually ran. */
  readonly installed: boolean;
  /** Every event from installing *and* importing the package. */
  readonly events: DhEvent[];
}

/**
 * Install a package into a throwaway sandbox and run it under dephawk, so a
 * report can say what it *actually does* — the install-time lifecycle scripts
 * (`preinstall`/`postinstall`, where many attacks fire) and its import-time
 * behaviour (where a runtime stealer runs). The empty-allowlist policy means
 * `observe` records everything and `enforce` blocks everything sensitive
 * (deny-by-default). The sandbox is a temp directory, removed on the way out.
 *
 * This deliberately *executes* the package: that is the only way to see what it
 * does. Run it on packages you are investigating, and prefer `enforce` for ones
 * you do not trust.
 */
export async function examinePackage(
  spec: string,
  options: ExamineOptions,
): Promise<ExamineResult> {
  const directory = realpathSync(mkdtempSync(join(tmpdir(), 'dephawk-x-')));
  try {
    writeFileSync(
      join(directory, 'package.json'),
      JSON.stringify({ name: 'dephawk-examine', private: true, version: '0.0.0' }),
    );

    const shared = {
      policy: PERMISSIVE_POLICY,
      registerUrl: options.registerUrl,
      cwd: directory,
      ...(options.mode === undefined ? {} : { mode: options.mode }),
    };

    // A local path/tarball spec is relative to the caller's cwd, but npm runs in
    // the sandbox — resolve it to an absolute path first.
    const installSpec = isLocalSpec(spec) ? resolve(spec) : spec;

    // Install (covers pre/postinstall lifecycle scripts) — with `--save`, so the
    // real installed name lands in package.json even for a tag/range/file/git
    // spec, which is what we then import.
    const install = await auditCommand(
      'npm',
      [
        'install',
        '--no-audit',
        '--no-fund',
        '--silent',
        // Copy a local (`file:`) package into node_modules instead of symlinking
        // it, so its code runs from `node_modules/<pkg>` and is attributed to the
        // dependency — a symlinked path resolves outside node_modules and would
        // be miscredited to "your code".
        '--install-links',
        installSpec,
      ],
      shared,
    );
    const name = installedName(directory) ?? packageNameOf(spec);

    // … then import it, which runs the module's top-level code (`import()`
    // handles both ESM and CommonJS; the errors are swallowed — a package that
    // needs config to load still revealed its load-time behaviour).
    const imported = install.started
      ? await auditCommand(
          'node',
          [
            '--input-type=module',
            '-e',
            `import(${JSON.stringify(name)}).then(() => {}, () => {})`,
          ],
          shared,
        )
      : { started: false, exitCode: 0, events: [] as DhEvent[] };

    // Keep only what a *dependency* did that reaches *outside* the throwaway
    // sandbox. Two kinds of noise are dropped:
    //   - npm's own install toolchain (`@npmcli/*`, `pacote`, `graceful-fs`, …)
    //     reaching the registry and reading its config while it installs;
    //   - filesystem access confined to the sandbox itself — npm extracting the
    //     tarball, Node loading the module. Those are not the package reaching
    //     for anything of yours.
    // What survives is the high-signal behaviour: reading your secrets, egress,
    // spawning processes, native/eval — the moves an audit actually cares about.
    const inSandbox = (detail: string): boolean =>
      detail === directory || detail.startsWith(`${directory}/`);
    const events = [...install.events, ...imported.events].filter((event) => {
      if (event.origin !== 'dependency' || isNpmToolchain(event.package)) {
        return false;
      }
      if (
        (event.capability === 'fs.read' || event.capability === 'fs.write') &&
        inSandbox(event.detail)
      ) {
        return false;
      }
      return true;
    });

    return { package: name, installed: install.started, events };
  } finally {
    try {
      rmSync(directory, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup.
    }
  }
}

/**
 * npm's own install machinery, which runs (monitored) during `npm install` and
 * would otherwise pollute the report with npm reaching the registry and reading
 * its own config. The whole `@npmcli` scope plus the fetch/install utilities that
 * touch the network, filesystem or environment. Benign npm deps (string utils,
 * etc.) never surface anyway — they touch nothing sensitive.
 */
const NPM_TOOLCHAIN: ReadonlySet<string> = new Set([
  'npm',
  'npx',
  'pacote',
  'cacache',
  'node-gyp',
  'make-fetch-happen',
  'minipass-fetch',
  'npm-registry-fetch',
  'npm-package-arg',
  'read-package-json',
  'read-package-json-fast',
  'ssri',
  'sigstore',
  'bin-links',
  'proc-log',
]);

/** A local path or tarball spec (relative to the caller), not a registry name. */
function isLocalSpec(spec: string): boolean {
  return (
    spec.startsWith('.') ||
    spec.startsWith('/') ||
    spec.startsWith('~') ||
    spec.endsWith('.tgz') ||
    spec.endsWith('.tar.gz')
  );
}

/** The name npm just added to the sandbox's dependencies (the real installed name). */
function installedName(directory: string): string | undefined {
  try {
    const manifest = JSON.parse(
      readFileSync(join(directory, 'package.json'), 'utf8'),
    ) as {
      dependencies?: Record<string, unknown>;
    };
    const names = Object.keys(manifest.dependencies ?? {});
    return names[0];
  } catch {
    return undefined;
  }
}

function isNpmToolchain(pkg: string | null): boolean {
  if (pkg === null) {
    return false;
  }
  return (
    pkg.startsWith('@npmcli/') || pkg.startsWith('@sigstore/') || NPM_TOOLCHAIN.has(pkg)
  );
}

/**
 * The bare package name from an install spec: `lodash@4` → `lodash`,
 * `@scope/pkg@1.2.3` → `@scope/pkg`. A leading `@` is the scope, so the version
 * separator is the *next* `@`.
 */
export function packageNameOf(spec: string): string {
  const scoped = spec.startsWith('@');
  const at = spec.indexOf('@', scoped ? 1 : 0);
  return at === -1 ? spec : spec.slice(0, at);
}
