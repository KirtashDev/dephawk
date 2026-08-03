# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.3.0] — 2026-08-03

Three ways a dependency could get out from under dephawk, each reproduced end to
end and each now covered by a regression test. If you rely on dephawk to gate
anything, upgrade.

### Security

- **Attribution bypass.** A dependency could evade policy entirely — including
  under `--enforce` — by deferring a sensitive call through a callback it did
  not define, e.g. `setTimeout(fs.readFileSync, 0, '~/.ssh/id_rsa')` or
  `.then(fs.readFileSync)`. No frame of the package survived to the moment of
  the call, and the resulting `package: null` was indistinguishable from "your
  own code", which policy allows unconditionally. Attribution now reports a
  third origin, `unknown`, which is evaluated against the default policy bucket
  instead of being trusted. See
  [ADR 0004](docs/adr/0004-async-attribution-and-unknown-origin.md).
- **Guard audit-log tampering.** The shared sink `dephawk guard` writes to lives
  in the temp directory and its path is handed to every monitored process in
  `DEPHAWK_SINK`, so a malicious lifecycle script could
  `fs.truncateSync(process.env.DEPHAWK_SINK, 0)` and erase every event its
  predecessors had recorded — the aggregated report then came back clean.
  Writing to dephawk's own files is now refused for every origin and in **both**
  modes, and dephawk writes the sink through a descriptor opened before the `fs`
  surface is patched so it needs no exemption for itself. The sink also moved
  into a `mkdtemp` 0700 directory: the old `dephawk-guard-<pid>-<now>.jsonl`
  name was guessable enough to be pre-created as a symlink by a local attacker.
  See [ADR 0005](docs/adr/0005-protecting-the-guard-audit-log.md).
- **Spawning out of monitoring.** dephawk reaches a process tree by inheritance,
  so a dependency could leave a whole subtree unwatched by spawning with
  `NODE_OPTIONS` and `DEPHAWK_*` deleted — from the child's environment, or from
  `process.env` before spawning with none. The spawn was recorded and everything
  the child then did was invisible. Monitoring is now restored into every child
  that is allowed to start, preserving whatever else the caller set, and the
  spawn's report line names what had to be put back. See
  [ADR 0006](docs/adr/0006-re-attaching-monitoring-to-children.md).

### Added

- `SchedulerInterceptor` — records the stack at the point a detached built-in is
  scheduled (`setTimeout`/`setInterval`/`setImmediate`, `queueMicrotask`,
  `process.nextTick`, `Promise.prototype.then`) and carries it through
  `AsyncLocalStorage`, so deferred calls are still attributed to the package
  that armed them rather than merely denied as anonymous. Costs one `WeakSet`
  lookup per callback argument; stacks are captured only for the detached case.
- `fs` interception now covers the destructive members — `unlink`, `rm`,
  `rmdir`, `truncate`, `rename` and `copyFile` — as `fs.write`. Deleting a
  sensitive file used to pass unseen.
- Reports distinguish `(your code)` from `(unattributed)`.

### Fixed

- Wrappers installed over Node built-ins now inherit the original's own
  properties, so API hung off them (`setTimeout[util.promisify.custom]`,
  `fs.realpath.native`) keeps working while dephawk is active.

### Changed

Nothing changes for `dephawk run`/`guard` users. These affect code that composes
a `Monitor` through the programmatic API:

- **Breaking.** `Attribution`, `CapabilityRequest` and `DhEvent` carry an
  `origin` (`dependency` | `application` | `unknown`). Consumers that build
  these values directly must supply it.
- **Breaking.** `JsonlSinkReporter`'s injectable `AppendFn` takes only the data
  now; the path is bound when the sink is opened.
- `Verdict` carries an optional `mandatory` flag, meaning "deny regardless of
  mode". Reserved for dephawk protecting its own audit log.
- `createInterceptors` accepts options (`protectedPaths`, `registerUrl`), and
  `buildMonitor` forwards them.

## [0.2.0] — 2026-07-25

### Added

- `dephawk guard <command>` — install-time guard. Runs an install (e.g.
  `npm ci`) and monitors every Node process it spawns, including dependency
  `pre`/`post`/`install` lifecycle scripts, aggregating them into one report via
  a shared JSONL sink (`DEPHAWK_SINK`). Catches attacks that run before your own
  code executes. Events are flushed on process `exit`, so a call blocked in
  `--enforce` is still recorded even though it crashes the offending script.
- Five new capability interceptors:
  - `net.resolve` — DNS (`dns.lookup`/`resolve*`/`reverse`, `dns.promises`, and
    `dns.Resolver`), gated by the same host allowlist as `net.connect`. Catches
    reconnaissance and DNS-tunnel exfiltration.
  - Raw sockets — `net.connect`/`createConnection`, `tls.connect`, and UDP
    (`dgram`), recorded as `net.connect`. Closes the raw-socket gap around HTTP.
  - `process.native` — native-addon loading via `process.dlopen`. New `native`
    per-package policy (default deny).
  - `code.eval` — dynamic code execution through the `vm` module. New `eval`
    per-package policy (default deny).
  - `worker_threads` — `new Worker(...)`, recorded as `process.spawn` (also an
    attribution-evasion vector), gated by the existing `spawn` policy.

## [0.1.1] — 2026-07-24

### Added

- `repository`, `homepage`, `bugs` and `author` metadata for the npm page.
- Refined npm keywords for discoverability.

### Changed

- `git`-based installs now build `dist/` automatically via a `prepare` script.

## [0.1.0] — 2026-07-24

### Added

- Initial release. Runtime supply-chain tripwire for Node.js dependencies.
- Capability interceptors: `fs.read`, `fs.write`, `net.connect`
  (http/https/fetch), `process.spawn`, `env.read`, `os.info`.
- `observe` and `enforce` modes; per-package declarative policy
  (`dephawk.config.js`) with host/path globs and env allowlists.
- Stack-trace attribution to the exact package (scoped + nested aware).
- Console report + self-contained shareable `.dephawk/report.html`.
- `dephawk run <cmd>` CLI and `--import dephawk/register` entrypoint.
- Hexagonal architecture, zero runtime dependencies, ≥90% core coverage.

[0.2.0]: https://github.com/KirtashDev/dephawk/releases/tag/v0.2.0
[0.1.1]: https://github.com/KirtashDev/dephawk/releases/tag/v0.1.1
[0.1.0]: https://github.com/KirtashDev/dephawk/releases/tag/v0.1.0
