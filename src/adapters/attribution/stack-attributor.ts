import type { Attribution, Attributor } from '../../application/ports.js';

/**
 * Attributes a call to the package that made it by parsing the raw stack trace.
 *
 * Strategy: walk frames top-down; the first frame that resolves to a
 * `node_modules/<package>` path (that is not dephawk itself) is the culprit.
 * Scoped packages (`@scope/name`) and nested `node_modules` are handled. This
 * is implemented as a pure string transform — no filesystem access — which
 * makes it fast and trivially testable.
 *
 * Limits (see docs/adr/0002): a determined attacker can rewrite `Error.stack`,
 * schedule work so the originating frame is gone (detached timers), or run
 * native code with no JS frame. Attribution is high-signal, not tamper-proof.
 */
const NODE_MODULES = 'node_modules/';

export interface StackAttributorOptions {
  /** dephawk's own package name, whose frames are skipped. */
  readonly selfPackage?: string;
  /** Max frames to retain for display. */
  readonly maxFrames?: number;
}

export class StackAttributor implements Attributor {
  private readonly selfPackage: string;
  private readonly maxFrames: number;

  constructor(options: StackAttributorOptions = {}) {
    this.selfPackage = options.selfPackage ?? 'dephawk';
    this.maxFrames = options.maxFrames ?? 12;
  }

  attribute(rawStack: string): Attribution {
    const frames: string[] = [];
    let attributed: string | null = null;

    for (const line of rawStack.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed.startsWith('at ')) {
        continue; // "Error" header, blank lines, etc.
      }

      const framePackage = packageFromFrame(trimmed.replace(/\\/g, '/'));
      if (framePackage === this.selfPackage) {
        continue; // never blame dephawk for what dephawk observes
      }

      frames.push(trimmed);
      if (attributed === null && framePackage !== null) {
        attributed = framePackage;
      }
      if (frames.length >= this.maxFrames) {
        break;
      }
    }

    return { package: attributed, frames };
  }
}

/** Extract the owning package name from a single (normalised) stack frame. */
function packageFromFrame(frame: string): string | null {
  // The *last* node_modules segment is the immediately-executing package.
  const index = frame.lastIndexOf(NODE_MODULES);
  if (index === -1) {
    return null;
  }
  const after = frame.slice(index + NODE_MODULES.length);
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
