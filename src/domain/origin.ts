/**
 * Where a capability call came from, as far as attribution could tell.
 *
 * The three cases are deliberately distinct, because two of them look identical
 * from a package name alone (both have `package: null`) yet must be treated in
 * opposite ways:
 *
 * - `dependency`  — a `node_modules/<name>` frame was found; `package` names it.
 * - `application` — no dependency frame, but a frame from the user's own source
 *   files. This is you. dephawk watches dependencies, not you, so it passes.
 * - `unknown`     — *attribution failed*: no dependency frame and no application
 *   frame either, only runtime internals. Nobody's name is on the call.
 *
 * Collapsing `unknown` into `application` (dephawk ≤ 0.2) was a bypass: a
 * dependency only had to launder a call across an async boundary with a callback
 * it did not define — `setTimeout(fs.readFileSync, 0, '/etc/passwd')` — for the
 * originating frame to disappear from the stack. The call was then credited to
 * "your code" and allowed unconditionally, even under `--enforce`. An `unknown`
 * origin is now evaluated against the default policy instead of trusted.
 */
export type Origin = 'dependency' | 'application' | 'unknown';
