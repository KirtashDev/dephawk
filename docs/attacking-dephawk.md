# Three ways out of a runtime supply-chain monitor

dephawk watches what your npm dependencies do while they run. It patches the
sensitive Node built-ins, captures a stack trace on every call that touches
something it cares about, walks the stack to find the first
`node_modules/<package>` frame, and checks that package against your policy. In
`--enforce` mode it throws instead of letting the call through.

The pitch is a screenshot: a package reads `~/.ssh/id_rsa`, and dephawk names it.

This is the story of finding out that a dependency could opt out of all of it
with one line, and of the two further ways out we found once we started looking
properly. All three were reproduced end to end before anything was changed, and
each is now covered by a regression test that fails without its fix.

## One line

```js
setTimeout(fs.readFileSync, 0, '/home/you/.ssh/id_rsa');
```

That is the whole thing. No `Error.prepareStackTrace`, no native addon, no
obfuscation. A dependency that runs this reads your private key, and dephawk —
in enforce mode, with a deny-by-default policy — reports it as _your own code_
and allows it.

The reason is what is missing rather than what is there. `setTimeout` is handed
`fs.readFileSync` itself, not a closure that calls it. When the timer fires, the
stack looks like this:

```
at readFileSync (node:fs:…)
at listOnTimeout (node:internal/timers:581:17)
at process.processTimers (node:internal/timers:519:7)
```

There is no frame belonging to the package, because no function of the package
is on the stack. Its involvement ended when it scheduled the call.

## A sentinel that meant two things

Losing the frame should have cost the attacker a name in a report. Instead it
bought them a pass, because of this:

```ts
attribute(rawStack: string): Attribution {
  let attributed: string | null = null;
  // …walk frames, set `attributed` on the first node_modules/<pkg> frame…
  return { package: attributed, frames };
}
```

`null` when no dependency frame was found. And then, in the policy engine:

```ts
evaluate(req: CapabilityRequest): Verdict {
  const sensitive = detectSensitive(req);

  if (req.package === null) {
    return { allowed: true, sensitive };
  }

  const pkg = this.policy.packages[req.package] ?? this.policy.default;
  return evaluateCapability(req, pkg, sensitive);
}
```

Both of those are individually reasonable. `null` for "no package frame" is the
obvious return value. Allowing `null` unconditionally follows from a real design
decision, stated in the README: _your own application code is never flagged —
dephawk watches dependencies, not you._ A tool that flagged your own code every
time you read a `.env` file would be unusable.

The bug is in the seam. `null` was carrying two meanings — **"this is the
application"** and **"attribution failed"** — and the engine trusted the first
reading for both. Every capability was affected: filesystem, network, spawn,
`process.env`. Deferring through a callback the package did not define was
enough for any of them, and `.then(fs.readFileSync)` works the same way.

## The part that stings

None of this was hidden. dephawk's own architecture decision record, written
when attribution was designed, lists the escape hatches:

> Attribution is **high-signal, not tamper-proof**. A determined attacker can:
> […] defer work to a detached callback/timer so the originating frame is gone;
> […]
>
> Async gaps can also drop the originating frame, yielding `package: null`
> (attributed to "your code"). We accept these limits and state them plainly in
> the README.

The behaviour was known, documented, and **classified as a reporting loss**. The
sentence even names the consequence — "attributed to 'your code'" — without
following it one step further to what the policy engine does with that. Writing
the limitation down had made it feel handled.

That is the part worth generalising. An accepted limitation is a decision, and
decisions age. This one was fine on the day it was written and stopped being
fine the moment `package: null` became load-bearing for a trust decision. Nobody
re-read it, because it was already in the docs, and things in the docs feel
settled.

## The fix that mattered, and the one that made it useful

Two changes, and only the first is a security fix.

**Attribution now has three outcomes, not two.** `Origin` is `dependency`,
`application`, or `unknown`. A frame naming a real source file means the
application; runtime internals, native and anonymous frames only means nobody
could be identified. Only `application` keeps the unconditional allow;
`unknown` is evaluated against the **default policy bucket**, exactly like an
unlisted package.

That alone closes it. With any deny-by-default configuration — including
dephawk's own default when you ship no config — the laundered read is denied.
Losing your name now costs you the benefit of the doubt instead of granting it.

One trap on the way: dephawk's own frames must not read as `application`, or a
deferred call gets credited to dephawk's `dist/` file and trusted all over
again. They are recognised two ways — by `node_modules/dephawk` when installed
normally, and by the directory the attributor module itself was loaded from when
it is not, which is the case when running from a checkout.

**Then, the reporting.** Denied-but-anonymous is safe and useless: the report
says `(unattributed)` and you cannot tell which dependency to remove. So a
scheduler interceptor patches `setTimeout`/`setInterval`/`setImmediate`,
`queueMicrotask`, `process.nextTick` and `Promise.prototype.then`. When the
callback handed to one of them _is an intercepted built-in_, it captures the
stack at the scheduling site — where the culprit is still plainly visible — into
an `AsyncLocalStorage` context that travels with the callback. The attributor
consults it only when the live stack comes back `unknown`, and the report shows
both halves of the trace.

The original ADR had rejected `AsyncLocalStorage` tagging as "heavier and still
evadable". Both are still true. The difference is that ALS is no longer the
boundary — the `unknown` origin is. ALS only improves the naming of calls that
are already being denied, so it is free to be best-effort.

Cost, measured rather than assumed: the stack is captured only when the callback
is an intercepted built-in, so ordinary scheduling pays one `WeakSet` lookup per
callback argument. On Node 22 that is **+22 ns per explicit `.then()`** (~34% of
a 64 ns baseline), with timers and `process.nextTick` inside measurement noise.
`await` on a native promise does not route through `Promise.prototype.then` at
all — verified at 0 interceptions across 10 000 awaits — so async/await-heavy
code pays nothing on that path.

## Two more, once we were looking

Finding one bypass by attacking rather than reading suggested doing more of it.

**The audit log was writable by the thing being audited.** `dephawk guard`
monitors an install by aggregating every spawned process into one shared JSONL
sink. The sink's path has to reach processes dephawk never spawns itself — the
package manager's lifecycle children — so it travels in an environment variable,
`DEPHAWK_SINK`, that every monitored process can read. The file sits in the temp
directory, so it was not "sensitive" and the filesystem interceptor never looked
at it. A lifecycle script needed one call:

```js
fs.truncateSync(process.env.DEPHAWK_SINK, 0);
```

Reproduced: a script that read an SSH key, followed by one that truncated the
sink, produced an aggregated report with no trace of the key read. Worse,
`unlink`, `rm`, `truncate` and `rename` were not intercepted at all, so a
sensitive file could be destroyed silently too.

Writing to dephawk's own files is now refused for every origin — the application
included — and in **both** modes. Observe mode exists to let policy denials
through, but recording an attempt to destroy the recording is worthless, so this
one denial is marked mandatory. dephawk writes the sink through a descriptor
opened before the `fs` surface is patched, which means it needs no exemption for
itself; an exemption would have to rest on stack attribution, the very thing an
attacker manipulates.

**Monitoring spread by inheritance, so it could be declined.** dephawk reaches a
process tree by putting `--import …/register.js` in `NODE_OPTIONS`. Anything a
process can inherit, it can also decline to pass on:

```js
const clean = { ...process.env };
delete clean.NODE_OPTIONS;
delete clean.DEPHAWK_SINK;
spawnSync(process.execPath, ['payload.js'], { env: clean });
```

The spawn was recorded. Everything the child then did was invisible, because no
interceptor was ever installed in it. Deleting the same variables from
`process.env` and spawning with no `env` option does the same thing.

The fix is to **restore, not refuse**. Building a clean environment for a child
is ordinary, legitimate behaviour — reproducible builds do exactly this — and
nothing distinguishes it from an escape attempt. Blocking it would break honest
callers to stop an attacker who could take a different route anyway. So dephawk
puts the missing pieces back into every child it lets through, keeping whatever
else the caller set, and the spawn's report line names what had to be restored:

```
sneaky → spawn  node payload.js [dephawk re-attached: DEPHAWK_SINK, NODE_OPTIONS]
```

That work turned up a false positive worth mentioning, because it is a class
rather than an instance. Node copies the whole of `process.env` inside
`normalizeSpawnArguments` to build a child's environment, and dephawk's
`process.env` proxy saw that as the calling package reading every secret in the
environment. One `execSync('echo hi')` invented five findings. It now suppresses
reads made by another built-in's own implementation — plumbing, not anyone's
decision — while a secret the caller reads in its own code before spawning is
still caught. If you patch a built-in that internally touches another patched
surface, you will have this bug.

## What we would take from it

**A sentinel that means two things will eventually mean the wrong one.** `null`
for "the application" and `null` for "I don't know" were the same value for as
long as nothing important depended on telling them apart. The fix is not
cleverness, it is a third case.

**Fail closed on ignorance.** "I could not attribute this" should cost the
caller trust, not grant it. The version of this rule that generalises: when your
system cannot answer a question it needs answered, the safe default is the
answer that assumes the worst, not the one that is quietest.

**Re-read your own accepted limitations.** The bypass was documented as
acceptable in a file written to record exactly that kind of decision. It was
acceptable, right up until another change made it load-bearing, and nothing
prompts a re-read of a decision that already looks settled.

**Attack it, don't audit it.** Every one of these was found by trying to defeat
the tool, and none by reading the code looking for bugs. The reading had already
happened; the code was well covered by tests, and all three bypasses passed
every one of them. Tests written from the design will confirm the design.

The fixes are in dephawk 0.3.0 and later, with the full reasoning in
[ADR 0004](adr/0004-async-attribution-and-unknown-origin.md),
[ADR 0005](adr/0005-protecting-the-guard-audit-log.md) and
[ADR 0006](adr/0006-re-attaching-monitoring-to-children.md).

None of this makes dephawk a sandbox. Attribution still rests on stack traces,
which a determined attacker can obscure; native addons run outside the JS
surface entirely; `eval()` and `new Function()` are language primitives and
cannot be patched. It remains a high-signal tripwire and policy layer, and for a
hard boundary you want OS-level isolation underneath it. What changed is that
the cheapest way out — the one that needed no privileged position and read like
ordinary asynchronous code — is closed.
