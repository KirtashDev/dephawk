# 6. Re-attaching monitoring to spawned children

- Status: accepted
- Date: 2026-08-03
- Follows: [ADR 0005](0005-protecting-the-guard-audit-log.md)

## Context

`dephawk run` and `dephawk guard` monitor a process _tree_. There is only one
mechanism for that: the CLI puts `--import …/register.js` in `NODE_OPTIONS` and
dephawk's settings in `DEPHAWK_*`, and children inherit them. It has to work
that way — `guard` must reach lifecycle scripts that npm spawns, and dephawk
never sees that call to hand anything over directly.

Inheritance is also the weakness. Anything a process can inherit, it can
decline to pass on:

```js
const clean = { ...process.env };
delete clean.NODE_OPTIONS;
delete clean.DEPHAWK_SINK;
spawnSync(process.execPath, ['payload.js'], { env: clean });
```

Reproduced end to end: the spawn was recorded, and the SSH key the grandchild
read did not appear in the report at all. No interceptors were ever installed
in that process. Deleting the same variables from `process.env` and spawning
with no `env` option does the same thing, since the child then inherits the
poisoned parent environment.

Neither shape needs `enforce` to be off — in observe mode, dephawk's default,
the spawn is allowed by design, so this is the path of least resistance for
anything that wants to work unobserved.

## Decision

`ChildProcessInterceptor` **re-attaches monitoring to every child it lets
through**. It snapshots what monitoring needs (`--import` fragments and every
`DEPHAWK_*` variable) at install time — before any dependency has run, so the
snapshot is what dephawk was actually started with rather than whatever the
environment has since been edited into — and guarantees it in the child:

- the caller passed `options.env` → their object is copied and the missing
  pieces added, preserving everything else they set, including their own
  `NODE_OPTIONS` flags;
- the caller passed none → the child will inherit `process.env`, so the missing
  pieces are put back _there_ instead of materialising a copy. That keeps the
  caller's semantics and avoids reading every variable through the env
  interceptor's proxy, which would report a secret read on every spawn.

**Restore, do not refuse.** Building a clean environment for a child is
ordinary, legitimate behaviour — reproducible builds do exactly this — and
nothing distinguishes it from an escape attempt. Blocking would break honest
callers to stop an attacker who could simply take a different route. Restoring
costs the honest caller nothing: they get a monitored child, which is what
running under dephawk means. The spawn's report line notes what had to be put
back (`node payload.js [dephawk re-attached: DEPHAWK_SINK, NODE_OPTIONS]`), so
the attempt is visible without inventing a capability that would inevitably
fire on innocent code.

The options object is located by scanning the arguments for the only plain
object among them, rather than a table of positions per entrypoint — `spawn`,
`exec`, `execFile` and `fork` each place it differently, and only the callback
(a function) and the argument list (an array) compete with it. When the caller
passed no options at all, nothing is inserted, so a trailing callback cannot be
mistaken for options.

`register.ts` also passes its own `import.meta.url` down, so the documented
`node --import dephawk/register app.js` form propagates too — there the flag
was on the command line and never appears in `NODE_OPTIONS` to be found.

## Consequences

Children of a monitored process are now monitored even when the parent tried to
prevent it, in both modes. Under `guard` their events flow into the shared sink
and aggregate normally; under `run` each monitored process still prints its own
report, as it always has.

A child that was given a deliberately minimal environment now also receives
`NODE_OPTIONS` and `DEPHAWK_*`. For a Node child that is the point. For a
non-Node child the variables are inert.

**Still open.** `worker_threads` is recorded as `process.spawn` but workers are
threads, not processes, and their `execArgv` handling is not covered here.
Native code that forks via libuv or `posix_spawn` bypasses the `child_process`
surface entirely, as ADR 0002 already notes. And a child can still _read_
`DEPHAWK_SINK` — see [ADR 0005](0005-protecting-the-guard-audit-log.md) — it
simply cannot write to it or escape it.
