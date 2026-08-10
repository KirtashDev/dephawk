import type { Attribution, Attributor } from '../../application/ports.js';
import { StackAttributor } from './stack-attributor.js';
import { isCompiledFilename } from './compiled-context.js';

/**
 * An {@link Attributor} that will not credit a frame to a package when the
 * frame's location is a name `vm` was told to use for compiled code.
 *
 * `vm.runInThisContext(code, { filename: '…/node_modules/innocent/index.js' })`
 * makes compiled code report frames at a path its caller chose, and those
 * frames are shaped exactly like that package's real ones — so unlike the
 * `//# sourceURL` forgery, which
 * {@link import('./stack-attributor.js') the stack attributor} recognises by
 * its `eval` marker, this cannot be caught by reading the stack more carefully.
 * Left alone it hands the call to an innocent package, along with that
 * package's allowlist, and poisons the report: `dephawk init` would then draft
 * that package a permission it never asked for.
 *
 * So the disguised frames are dropped before attribution runs, and the blame
 * falls through to the next real frame — which, for code compiled and run by a
 * dependency, is that dependency. You ran it, you own it.
 *
 * The dropped frames are removed from the *reported* stack too. They describe a
 * file that never executed anything, so showing them would only mislead.
 */
export class CompiledAttributor implements Attributor {
  private readonly inner: Attributor;

  constructor(inner: Attributor = new StackAttributor()) {
    this.inner = inner;
  }

  attribute(rawStack: string): Attribution {
    return this.inner.attribute(withoutDisguisedFrames(rawStack));
  }
}

/** Drop every frame sitting at a filename `vm` was handed. */
function withoutDisguisedFrames(rawStack: string): string {
  const lines = rawStack.split('\n');
  const kept = lines.filter((line) => {
    const trimmed = line.trim();
    if (!trimmed.startsWith('at ')) {
      return true; // the "Error" header and blank lines are not frames
    }
    return !isCompiledFilename(locationOf(trimmed.replace(/\\/g, '/')));
  });
  return kept.length === lines.length ? rawStack : kept.join('\n');
}

/** The file location inside a frame: `at fn (LOC)` → `LOC`, `at LOC` → `LOC`. */
function locationOf(frame: string): string {
  const open = frame.indexOf('(');
  if (open !== -1 && frame.endsWith(')')) {
    return frame.slice(open + 1, -1);
  }
  return frame.slice('at '.length);
}
