/**
 * Declarative policy types. Plain immutable data — no behaviour lives here.
 *
 * A {@link Policy} is what a user writes in `dephawk.config.js`. It is resolved
 * once at startup and handed to the {@link import('./policy-engine.js').RulePolicyEngine}.
 */

/** Whether dephawk merely records (`observe`) or actively blocks (`enforce`). */
export type Mode = 'observe' | 'enforce';

/**
 * Env access policy for a package.
 * - `true`  — may read any environment variable (including secrets).
 * - `false` — may not read *secret* variables (mundane vars stay allowed).
 * - array   — may read secret variables whose names are listed.
 */
export type EnvPolicy = boolean | readonly string[];

/** Filesystem access policy: allowlists of path prefix-globs for sensitive paths. */
export interface FsPolicy {
  /** Sensitive read paths this package may read (prefix globs, see {@link import('./path-glob.js')}). */
  readonly read?: readonly string[];
  /** Sensitive write paths this package may write. */
  readonly write?: readonly string[];
}

/** Network access policy: allowlist of host patterns. */
export interface NetPolicy {
  /**
   * Host patterns this package may connect to (`api.x.com`, `*.x.com`). The
   * same allowlist governs DNS resolution (`net.resolve`) — resolving a host is
   * a connection precursor, so a package that may connect to a host may resolve
   * it too, with no separate configuration.
   */
  readonly connect?: readonly string[];
  /**
   * Whether the package may open an inbound listener (`server.listen`,
   * `dgram.bind`). Defaults to false: a dependency binding a port is opening a
   * backdoor/C2 channel, which almost nothing legitimate does. It is a boolean
   * rather than a port allowlist because ports are usually ephemeral (`:0`) and
   * the meaningful decision is "may this package listen at all".
   */
  readonly listen?: boolean;
}

/** The effective policy for a single package (or the default bucket). */
export interface PackagePolicy {
  readonly net?: NetPolicy;
  readonly fs?: FsPolicy;
  /** Whether the package may spawn child processes (and worker threads). Defaults to false. */
  readonly spawn?: boolean;
  /** Whether the package may load native addons (`.node`). Defaults to false. */
  readonly native?: boolean;
  /** Whether the package may execute dynamically compiled code (`vm`). Defaults to false. */
  readonly eval?: boolean;
  /**
   * Whether the package may dump process memory or the whole environment — a
   * heap snapshot (`v8.writeHeapSnapshot`) or a diagnostic report
   * (`process.report.getReport`), both of which expose every in-memory secret
   * and every environment variable without touching `fs` or `process.env`.
   * Defaults to false.
   */
  readonly memory?: boolean;
  /** Env access policy. Defaults to false (no secret env). */
  readonly env?: EnvPolicy;
}

/** The whole resolved policy. */
export interface Policy {
  readonly mode: Mode;
  /** Applied to any package not named in {@link packages}. */
  readonly default: PackagePolicy;
  /** Per-package overrides, keyed by package name. */
  readonly packages: Readonly<Record<string, PackagePolicy>>;
}

/**
 * The permissive default policy used when the user ships no config: observe
 * everything, block nothing, but still flag sensitive access in the report.
 */
export const PERMISSIVE_POLICY: Policy = {
  mode: 'observe',
  default: {},
  packages: {},
};
