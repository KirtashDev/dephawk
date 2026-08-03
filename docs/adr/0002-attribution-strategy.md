# 2. Attribution by stack trace, and its limits

- Status: accepted, amended by [ADR 0004](0004-async-attribution-and-unknown-origin.md)
- Date: 2026-07-24

## Context

The product promise is "attribute each sensitive action to the **exact
package**". When an interceptor fires, we must decide who is responsible: the
user's own code, or some dependency (and which one).

Options considered:

1. **Stack-trace parsing** — capture the call stack, find the first
   `node_modules/<package>` frame.
2. **`package.json` walking** — for each frame's file, walk up to the nearest
   `package.json` and read its `name`.
3. **AsyncLocalStorage tagging** — wrap module loading to tag execution context
   per package.

## Decision

Use **stack-trace parsing** (`StackAttributor`), implemented as a **pure string
transform** with no filesystem access:

- Walk frames top-down; the first frame resolving to `node_modules/<pkg>` that is
  not dephawk itself is the culprit.
- Handle scoped packages (`@scope/name`) and nested `node_modules` (deepest wins,
  i.e. the immediately-executing package).
- Skip dephawk's own frames so we never blame the watcher.

Rationale: it is fast (no `fs` per call), dependency-free, trivially unit-tested
against fixture strings, and correct for the overwhelmingly common case where
dependencies live in `node_modules`. `package.json` walking adds `fs` I/O to a
hot path and pulls impurity into attribution; ALS tagging is heavier and still
evadable.

## Consequences / honest limits

Attribution is **high-signal, not tamper-proof**. A determined attacker can:

- rewrite `Error.stack` or set `Error.prepareStackTrace`;
- defer work to a detached callback/timer so the originating frame is gone;
- run in a worker/native addon with no JS frame;
- ship code that isn't under a `node_modules/<pkg>` path.

Async gaps can also drop the originating frame. This ADR originally accepted
that as a reporting loss; it was in fact a policy bypass, because `package:
null` also meant "the user's own code" and was allowed unconditionally.
[ADR 0004](0004-async-attribution-and-unknown-origin.md) splits that value into
`application` and `unknown`, trusts only the former, and restores the name via
scheduling context. The remaining limits above stand, and we state them plainly
in the README. dephawk is a tripwire and policy layer; for a hard boundary, combine
it with OS-level isolation. The interceptor pre-filter (only capturing stacks for
sensitive paths/secret env vars) keeps overhead low, at the cost of not counting
mundane calls — an intentional trade for a quiet, fast hot path.
