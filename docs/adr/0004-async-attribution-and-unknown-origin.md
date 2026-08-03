# 4. Unknown origin, and attribution across async boundaries

- Status: accepted
- Date: 2026-08-03
- Amends: [ADR 0002](0002-attribution-strategy.md)

## Context

ADR 0002 accepted "defer work to a detached callback/timer so the originating
frame is gone" as a known limit of stack-trace attribution, on the reasoning
that the result — `package: null` — merely costs us a name in the report.

That reasoning was wrong, and the gap was not cosmetic. `package: null` was also
the value for the user's own code, and the policy engine short-circuited on it:

```ts
if (req.package === null) {
  return { allowed: true, sensitive }; // dephawk watches dependencies, not you
}
```

So losing the originating frame did not merely blur attribution — it granted an
unconditional allow, in `--enforce` as much as in observe. A dependency reached
it in one line, without touching `Error.stack` or anything else exotic:

```js
setTimeout(fs.readFileSync, 0, '/home/you/.ssh/id_rsa');
Promise.resolve(secretPath).then(fs.readFileSync);
```

Because the callback is a function the package did not define, no frame of the
package is live when the read happens; the stack holds only `node:internal`
timer frames. The call was reported as `(your code)` and allowed.

The trick works on any capability, needs no privileged position, and reads as
ordinary asynchronous code.

## Decision

Two changes, one closing the hole and one keeping the reports useful.

### 1. `unknown` is a distinct origin, and it is not trusted

`Attribution`, `CapabilityRequest` and `DhEvent` carry an
[`Origin`](../../src/domain/origin.ts): `dependency`, `application`, or
`unknown`. The attributor classifies each frame rather than only scanning for
`node_modules`:

- a `node_modules/<pkg>` frame ⇒ `dependency`;
- otherwise, a frame naming a real source file ⇒ `application`;
- otherwise (runtime internals, native and anonymous frames only) ⇒ `unknown`.

Only `application` gets the unconditional allow. `unknown` is evaluated against
the **default policy bucket**, exactly like an unlisted package. Attribution
failure now costs the caller the benefit of the doubt instead of granting it.

This alone closes the hole: with no config, or with any deny-by-default bucket,
the laundered read above is denied.

dephawk's own frames must not read as `application`, or the deferred call would
be credited to dephawk's dist file and trusted again. They are recognised two
ways: by `node_modules/dephawk` when installed normally, and by the directory
the attributor module itself was loaded from when it is not (a checkout, or
`node --import ./dist/register.js`).

### 2. Scheduling context restores the name

Denied-but-anonymous is safe yet unhelpful: the report says `(unattributed)` and
the user cannot tell which dependency to remove. So a `SchedulerInterceptor`
patches `setTimeout`/`setInterval`/`setImmediate` (on `globalThis` and
`node:timers`), `queueMicrotask`, `process.nextTick` and
`Promise.prototype.then`. When the callback handed to one of them **is an
intercepted built-in**, it captures the stack at the scheduling site — where the
culprit is still visible — into an `AsyncLocalStorage` context that travels with
the callback. `DeferredAttributor` consults that context only when the live
stack comes back `unknown`, and the report shows both halves of the trace
separated by `--- scheduled from ---`.

ADR 0002 rejected ALS tagging as "heavier and still evadable". Both remain true;
the difference is that ALS is no longer the _boundary_ — the `unknown` origin is.
ALS only improves the reporting of calls that are already being denied, so it can
be best-effort without weakening anything.

## Consequences

**Cost.** The scheduler patch pays one `WeakSet` lookup per callback argument
and captures a stack only for the detached-built-in case, so ordinary scheduling
is unaffected. Measured on Node 22: `+22 ns` per **explicit** `.then()` call
(~34% of a 64 ns baseline); timers and `process.nextTick` are within measurement
noise. `await` on a native promise does not route through
`Promise.prototype.then` at all (verified: 0 interceptions across 10 000
awaits), so async/await-heavy code pays nothing on that path.

**Behaviour change.** Deferred, detached calls that used to be silently allowed
are now evaluated. Under `--enforce` with a deny-by-default bucket they are
blocked, which is the point — but a project relying on the old behaviour will
see new denials. Calls the _application_ schedules keep their `application`
origin through the same mechanism, so this should be rare in practice.

**Still open.** The escape hatches ADR 0002 lists remain: rewriting
`Error.stack`, native addons, code outside `node_modules`. And laundering
through a _different_ dependency's callback attributes the call to that
dependency rather than the instigator. What changed is only that losing your
name is no longer a way to gain trust.

`patchMethod` now copies the original's own properties onto each wrapper, so
API that Node hangs off built-ins (`setTimeout[util.promisify.custom]`,
`fs.realpath.native`) survives interception. That was a latent bug for every
interceptor, surfaced by patching the schedulers.
