import { fileURLToPath } from 'node:url';
import type { Origin } from '../../domain/origin.js';
import type { Attribution, Attributor } from '../../application/ports.js';

/**
 * Attributes a call to the package that made it by parsing the raw stack trace.
 *
 * Strategy: walk frames top-down and classify each one. The first frame that
 * resolves to a `node_modules/<package>` path (that is not dephawk itself) is
 * the culprit. With no dependency frame, the presence of a frame from a real
 * source file decides between `application` (your code) and `unknown`
 * (runtime internals only — attribution failed, nobody is accountable).
 *
 * That last distinction is load-bearing: `unknown` is what a deferred,
 * detached call looks like (`setTimeout(fs.readFileSync, 0, secret)`), and the
 * policy engine evaluates it against the default bucket instead of waving it
 * through as "your code". See {@link import('../../domain/origin.js').Origin}.
 *
 * Scoped packages (`@scope/name`) and nested `node_modules` are handled. Apart
 * from resolving dephawk's own directory once at load, this is a pure string
 * transform — no filesystem access — which makes it fast and trivially testable.
 *
 * Limits (see docs/adr/0002): a determined attacker can rewrite `Error.stack`
 * or run native code with no JS frame. Attribution is high-signal, not
 * tamper-proof — but losing a frame now costs the attacker the *benefit of the
 * doubt* rather than granting it.
 */
const NODE_MODULES = 'node_modules/';

export interface StackAttributorOptions {
  /** dephawk's own package name, whose frames are skipped. */
  readonly selfPackage?: string;
  /**
   * Directory prefix holding dephawk's own code, whose frames are skipped.
   * Only needed when dephawk does not live under `node_modules` (running from
   * a checkout, or `node --import ./dist/register.js`); otherwise
   * {@link selfPackage} already covers it. Defaults to this module's directory.
   */
  readonly selfRoot?: string | null;
  /** Max frames to retain for display. */
  readonly maxFrames?: number;
}

/** How a single stack frame is accounted for. */
type FrameKind =
  | { readonly kind: 'dependency'; readonly package: string }
  | { readonly kind: 'application' }
  /** Runtime internals, native frames, or anything unattributable. */
  | { readonly kind: 'internal' }
  /** dephawk's own frames — dropped from the display stack entirely. */
  | { readonly kind: 'self' };

const APPLICATION: FrameKind = { kind: 'application' };
const INTERNAL: FrameKind = { kind: 'internal' };
const SELF: FrameKind = { kind: 'self' };

export class StackAttributor implements Attributor {
  private readonly selfPackage: string;
  private readonly selfRoot: string | null;
  private readonly maxFrames: number;

  constructor(options: StackAttributorOptions = {}) {
    this.selfPackage = options.selfPackage ?? 'dephawk';
    this.selfRoot = options.selfRoot === undefined ? selfDirectory() : options.selfRoot;
    this.maxFrames = options.maxFrames ?? 12;
  }

  attribute(rawStack: string): Attribution {
    const frames: string[] = [];
    let attributed: string | null = null;
    let sawApplication = false;

    for (const line of rawStack.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed.startsWith('at ')) {
        continue; // "Error" header, blank lines, etc.
      }

      const kind = this.classify(trimmed.replace(/\\/g, '/'));
      if (kind.kind === 'self') {
        continue; // never blame dephawk for what dephawk observes
      }

      // Keep scanning past maxFrames: the cap is about how much stack we show,
      // not how far we look for an owner.
      if (frames.length < this.maxFrames) {
        frames.push(trimmed);
      }
      if (kind.kind === 'dependency') {
        attributed ??= kind.package;
      } else if (kind.kind === 'application') {
        sawApplication = true;
      }
    }

    const origin: Origin =
      attributed !== null ? 'dependency' : sawApplication ? 'application' : 'unknown';
    return { package: attributed, origin, frames };
  }

  private classify(frame: string): FrameKind {
    if (isForgedEvalFrame(frame)) {
      return INTERNAL; // location is the evaluated code's own claim — untrusted
    }

    const location = locationOf(frame);

    if (location.startsWith('node:')) {
      return INTERNAL; // node:internal/timers, node:fs, …
    }
    if (hasForeignScheme(location)) {
      return INTERNAL; // data:, blob:, http: — evaluated code, not a file on disk
    }
    if (this.selfRoot !== null && location.includes(this.selfRoot)) {
      return SELF;
    }
    if (location.includes(NODE_MODULES)) {
      const name = packageFromLocation(location);
      if (name === null) {
        return INTERNAL; // malformed node_modules path — attributable to nobody
      }
      return name === this.selfPackage ? SELF : { kind: 'dependency', package: name };
    }
    return isSourceLocation(location) ? APPLICATION : INTERNAL;
  }
}

/**
 * Whether an `eval` frame reports a location the *evaluated code chose for
 * itself*, rather than the one V8 recorded.
 *
 * V8 writes an eval frame two ways, and only one can be trusted:
 *
 * - `at eval (eval at run (/p/node_modules/staged/i.js:3:9), <anonymous>:1:1)`
 *   — the `eval at` clause is V8's own note of where the eval was called from.
 *   That inner path is real, and naming the package that staged the code is
 *   exactly right.
 * - `at eval (/app/node_modules/innocent/index.js:2:26)` — a `//# sourceURL=…`
 *   comment inside the evaluated source replaced the location wholesale.
 *
 * The second is a forgery: `eval` and `new Function` are language intrinsics
 * that cannot be patched, so a dependency can evaluate
 * `//# sourceURL=…/node_modules/innocent/index.js` and have its call attributed
 * to *another package* — one that may be allowlisted, which then lends it the
 * permission. Reproduced reading a real secret under `--enforce`: the report
 * blamed `innocent` and the read went through.
 *
 * Treating a forged frame as internal takes nothing the caller was entitled to.
 * Attribution falls through to the next frame — the package that actually
 * called `eval` — which is the correct culprit either way.
 *
 * Limitation: `vm` lets the caller name the script outright
 * (`runInThisContext(code, { filename })`), producing a frame with no `eval`
 * marker at all. That path is covered instead by `vm` being intercepted as
 * `code.eval` and denied by default.
 */
function isForgedEvalFrame(frame: string): boolean {
  if (!frame.startsWith('at eval (') && !frame.startsWith('at async eval (')) {
    return false;
  }
  return !frame.includes('eval at ');
}

/**
 * The file location inside a frame: `at fn (LOC)` → `LOC`, `at LOC` → `LOC`.
 * Uses the *first* parenthesis so `eval at x (/p/a.js:1:1)` still exposes the
 * underlying file rather than an opaque `<anonymous>`.
 */
function locationOf(frame: string): string {
  const open = frame.indexOf('(');
  if (open !== -1 && frame.endsWith(')')) {
    return frame.slice(open + 1, -1);
  }
  return frame.slice('at '.length);
}

/** Matches a bare `file.js:12:34` location with no directory part. */
const FILE_LOCATION = /\.[cm]?[jt]sx?:\d+:\d+$/;

/** True for anything that names a real source file rather than an internal. */
function isSourceLocation(location: string): boolean {
  return location.includes('/') || FILE_LOCATION.test(location);
}

/**
 * A URL scheme of two or more characters, with no `.` in it. Excludes
 * single-letter Windows drives (`C:`) and bare filenames whose extension puts a
 * dot before the `:line:col` (`bundle.js:1:1`) — the schemes that matter
 * (`data`, `blob`, `http`, `https`, `ws`, `node`, `file`) contain none.
 */
const URL_SCHEME = /^([a-z][a-z0-9+-]+):/i;

/**
 * Whether a frame location is a URL with a scheme other than `file:` —
 * `data:`, `blob:`, `http:`, … Such a frame is *evaluated code*, not a file on
 * disk: `import('data:text/javascript,…')` runs a module whose frames read
 * `data:text/javascript,…:3:15`. The `/` in the MIME type made
 * {@link isSourceLocation} return true, so a deferred call from inside such a
 * module — with no importer frame left on the stack — classified as
 * `application` and was waved through under `--enforce`, blaming "your code".
 * Reproduced: a dependency `import()`ed a data: URL that read `/etc/passwd`
 * from a `setTimeout`, and the report credited the read to your own code.
 * Worse, the data body can contain the literal `node_modules/<pkg>/` to forge a
 * dependency frame, so this is checked *before* the `node_modules` match.
 *
 * Treated as internal: nobody is accountable, so the call is evaluated against
 * the default bucket rather than trusted. A `file:` URL is a real on-disk module
 * and is deliberately allowed through; Windows drive letters (`C:/…`) are a
 * single character and do not match {@link URL_SCHEME}, so real paths still
 * count as source.
 */
function hasForeignScheme(location: string): boolean {
  const scheme = URL_SCHEME.exec(location)?.[1];
  return scheme !== undefined && scheme.toLowerCase() !== 'file';
}

/** Extract the owning package name from a (normalised) frame location. */
function packageFromLocation(location: string): string | null {
  // The *last* node_modules segment is the immediately-executing package.
  const index = location.lastIndexOf(NODE_MODULES);
  if (index === -1) {
    return null;
  }
  const after = location.slice(index + NODE_MODULES.length);
  const segments = after.split('/');
  const first = segments[0];
  if (first === undefined || first.length === 0) {
    return null;
  }
  if (first.startsWith('@')) {
    const second = segments[1];
    if (second === undefined || second.length === 0) {
      return null; // malformed scoped path
    }
    return `${first}/${second}`;
  }
  return first;
}

/**
 * The directory this module was loaded from, normalised with a trailing slash.
 * In the shipped bundle every dephawk frame lives under it, so it identifies
 * dephawk's own frames even when dephawk is not inside `node_modules`.
 */
function selfDirectory(): string | null {
  try {
    const path = fileURLToPath(import.meta.url).replace(/\\/g, '/');
    const slash = path.lastIndexOf('/');
    return slash === -1 ? null : path.slice(0, slash + 1);
  } catch {
    return null; // exotic runtime with no file URL — fall back to selfPackage
  }
}
