import type { DhEvent } from './event.js';

/**
 * How much dephawk has to see before it fails the command.
 *
 * Without this, dephawk could never gate anything. `run` returned only the
 * child's exit code, so an observe-mode run that watched a dependency read
 * `~/.ssh/id_rsa` still exited 0 and a green tick appeared on the pull request.
 * Enforce mode failed builds only as a side effect — the blocked call threw
 * inside the program, which is a crash, not a verdict.
 *
 * - `none`      — never fail on findings (the default; exit code is the
 *                 command's own, exactly as before).
 * - `blocked`   — fail when a call was actually prevented. Only enforce mode
 *                 blocks, so this is the strictest thing observe mode can never
 *                 trigger.
 * - `violation` — fail when policy denied anything, whether or not the call was
 *                 stopped. This is the useful one in CI: observe mode records
 *                 what *would* be blocked, so a pull request fails on the
 *                 finding without enforcement having to break the build first.
 * - `sensitive` — fail when anything sensitive was touched at all, even where
 *                 policy allowed it.
 * - `new`       — fail when `--replay` found behaviour the recorded baseline
 *                 did not have. Orthogonal to the others: it asks whether
 *                 anything *changed*, not whether anything is permitted, so a
 *                 dependency bump that adds an outbound host trips it even
 *                 where policy allows the host.
 */
export const FAILURE_THRESHOLDS = [
  'none',
  'blocked',
  'violation',
  'sensitive',
  'new',
] as const;

export type FailureThreshold = (typeof FAILURE_THRESHOLDS)[number];

export function isFailureThreshold(value: string): value is FailureThreshold {
  return (FAILURE_THRESHOLDS as readonly string[]).includes(value);
}

/**
 * Whether these events are bad enough to fail the command at `threshold`.
 *
 * `newBehaviours` is how many things `--replay` found that the baseline did
 * not; it is only consulted by the `new` threshold, and defaults to none so
 * every other caller is unaffected.
 */
export function failsThreshold(
  events: readonly DhEvent[],
  threshold: FailureThreshold,
  newBehaviours = 0,
): boolean {
  switch (threshold) {
    case 'none':
      return false;
    case 'new':
      return newBehaviours > 0;
    case 'blocked':
      return events.some((event) => event.blocked);
    case 'violation':
      return events.some((event) => !event.allowed);
    case 'sensitive':
      // A denial is not always sensitive — an unlisted outbound connection is a
      // violation with nothing intrinsically secret about it — so the loosest
      // threshold has to cover both, or it would miss what a stricter one catches.
      return events.some((event) => !event.allowed || event.sensitive);
  }
}

/** The reason the command failed, for the message dephawk prints. */
export function describeFailure(
  events: readonly DhEvent[],
  threshold: FailureThreshold,
  newBehaviours = 0,
): string {
  if (threshold === 'new') {
    return `${String(newBehaviours)} new behaviour${newBehaviours === 1 ? '' : 's'}`;
  }
  const count = events.filter((event) => {
    switch (threshold) {
      case 'none':
        return false;
      case 'blocked':
        return event.blocked;
      case 'violation':
        return !event.allowed;
      case 'sensitive':
        return !event.allowed || event.sensitive;
    }
  }).length;

  const noun =
    threshold === 'blocked'
      ? 'blocked call'
      : threshold === 'violation'
        ? 'policy violation'
        : 'sensitive call';
  return `${count} ${noun}${count === 1 ? '' : 's'}`;
}
