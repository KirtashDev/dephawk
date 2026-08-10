/**
 * The filenames `vm` has been asked to pretend compiled code came from.
 *
 * `vm` lets the caller name the script outright —
 * `runInThisContext(code, { filename: '…/node_modules/innocent/index.js' })` —
 * and V8 stamps that name onto every frame the compiled code produces. The
 * result is indistinguishable from that package's real frames, so unlike the
 * `//# sourceURL` forgery it cannot be spotted by reading the stack: the
 * running code simply claims to be a package it is not, and would borrow that
 * package's allowlist.
 *
 * What *is* knowable is which names were handed to `vm` in the first place, so
 * they are recorded here as they are used and
 * {@link import('./compiled-attributor.js').CompiledAttributor} refuses to
 * attribute anything to a frame sitting at one of them.
 *
 * A plain set rather than an `AsyncLocalStorage` context, deliberately: a first
 * attempt scoped this to the duration of the `vm` call and missed the obvious
 * evasion, since `runInThisContext` can *return a closure* that runs later —
 * outside any such scope — carrying the forged filename in its frames forever.
 * A name, once used to disguise code, stays untrustworthy for the life of the
 * process.
 */
const compiledFilenames = new Set<string>();

/** Record a filename `vm` was told to report compiled code as coming from. */
export function noteCompiledFilename(filename: string): void {
  if (filename.length > 0) {
    compiledFilenames.add(filename.replace(/\\/g, '/'));
  }
}

/** Whether a frame location is a name `vm` was given for compiled code. */
export function isCompiledFilename(location: string): boolean {
  if (compiledFilenames.size === 0) {
    return false; // the common case: nothing has used `vm` at all
  }
  for (const filename of compiledFilenames) {
    // A frame location carries `:line:column`, so match the leading path.
    if (location === filename || location.startsWith(`${filename}:`)) {
      return true;
    }
  }
  return false;
}

/** Testing seam: forget every recorded filename. */
export function resetCompiledFilenames(): void {
  compiledFilenames.clear();
}
