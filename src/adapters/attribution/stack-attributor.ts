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
    const location = locationOf(frame);

    if (location.startsWith('node:')) {
      return INTERNAL; // node:internal/timers, node:fs, …
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
