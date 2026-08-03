/**
 * The pure policy decision for a single capability request.
 *
 * `allowed` is *mode-independent*: it answers "does policy permit this action?"
 * regardless of whether dephawk is observing or enforcing. The application layer
 * combines this with the active {@link import('./policy.js').Mode} to decide
 * whether to actually block the call.
 */
export interface Verdict {
  /** Whether policy permits the action (independent of observe/enforce). */
  readonly allowed: boolean;
  /** Whether the request touches something intrinsically sensitive. */
  readonly sensitive: boolean;
  /** Human-readable justification when `allowed` is false. */
  readonly reason?: string;
  /**
   * Deny even in observe mode. Reserved for dephawk defending its own
   * integrity — see {@link import('./protected-path.js')} — where merely
   * *recording* the attempt would be useless, because the thing being attacked
   * is the record itself. Ordinary policy denials are never mandatory: observe
   * mode exists precisely to let them through.
   */
  readonly mandatory?: boolean;
}
