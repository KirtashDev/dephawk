# 5. Protecting the guard audit log

- Status: accepted
- Date: 2026-08-03
- Builds on: [ADR 0002](0002-attribution-strategy.md)

## Context

`dephawk guard` monitors an install by aggregating every spawned process into
one shared JSONL sink. The sink's location has to reach processes dephawk never
spawns itself — the package manager's own lifecycle children — so it travels in
`DEPHAWK_SINK`, an environment variable every monitored process can read.

That makes the audit log reachable by exactly the code it is auditing, and it
was unprotected on three counts:

1. **Erasable.** The file sits in the temp directory, so `isSensitivePath` is
   false and the fs interceptor never even looked at it. A lifecycle script only
   had to run `fs.truncateSync(process.env.DEPHAWK_SINK, 0)` to delete every
   event its predecessors had recorded. Reproduced: a script that read an SSH
   key, followed by one that truncated the sink, produced a report with no trace
   of the key read.
2. **Unreachable by the interceptor anyway.** `unlink`, `rm`, `truncate` and
   `rename` were not patched at all, so even a sensitive path could be destroyed
   silently.
3. **Squattable.** The name was `dephawk-guard-<pid>-<Date.now()>.jsonl`
   directly in the world-writable temp directory. The pid is public and the
   timestamp spans a few thousand candidates, so a local attacker could
   pre-create every one of them as a symlink and have the guard append
   attacker-influenced content to a file of their choosing.

## Decision

**Protected paths are a domain concept, not a policy setting.**
[`protected-path.ts`](../../src/domain/protected-path.ts) matches a path against
dephawk's own files, including any enclosing directory so that removing the
containing directory counts as tampering. `RulePolicyEngine` consults it ahead
of every other rule and refuses `fs.write` to a protected path for _every_
origin — the application included. This is not policy about the monitored
program; it is dephawk keeping its own record.

**The refusal is mandatory.** `Verdict` gains `mandatory`, and the Monitor
blocks when `!allowed && (mode === 'enforce' || mandatory)`. Observe mode
deliberately lets policy denials through — that is its whole purpose — but
recording an attempt to destroy the recording is worthless: by the time the
report is written, the evidence is gone. So this one denial holds in both modes.
No other verdict sets `mandatory`, and none should.

**dephawk writes through a descriptor, not a path.** `JsonlSinkReporter` opens
the sink once in its constructor, which runs before `monitor.start()` and
therefore before the fs surface is patched, and writes with `writeSync`. That
keeps dephawk's own writes off the intercepted API, so the interceptor can
refuse the sink to _everyone_ without dephawk needing to exempt itself by name —
an exemption that would have to be identified by stack attribution, the very
thing an attacker manipulates. The descriptor is `O_APPEND`, so the several
processes an install spawns still interleave cleanly, and it is deliberately
never closed: `exit` listeners run in registration order, so a close registered
at construction fires before the flush and turns every write into `EBADF`.

**The interceptor covers destruction.** `unlink`, `rm`, `rmdir`, `truncate`,
`rename` and `copyFile` are patched as `fs.write` (with `copyFile` recording a
read of its source and a write of its destination, and `rename` checking both
paths). This protects the sink, and closes the same gap for `~/.ssh` and every
other sensitive path.

**The sink lives in a private directory.** `mkdtempSync` gives an unguessable
name and mode 0700, so neither the directory nor the file inside it can be
squatted. The parent removes the whole directory after reporting.

## Consequences

A write to the sink is now refused in observe mode. This is the only thing
dephawk blocks without being asked to, and it is documented in the README next
to the mode descriptions.

**Still open.** `DEPHAWK_SINK` remains readable, so monitored code can still
learn the sink's location and read what has been recorded; there is no channel
that reaches package-manager grandchildren without going through the
environment. Related and not yet addressed: a process can strip `DEPHAWK_SINK`
or `NODE_OPTIONS` from the environment it passes to _its own_ children, leaving
that subtree unmonitored. Since `child_process` is already intercepted, dephawk
can re-inject both and record when they were removed — the next piece of work
on this seam.
