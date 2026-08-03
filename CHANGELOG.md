# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Fixed

- **Attribution bypass (security).** A dependency could evade policy entirely —
  including under `--enforce` — by deferring a sensitive call through a callback
  it did not define, e.g. `setTimeout(fs.readFileSync, 0, '~/.ssh/id_rsa')` or
  `.then(fs.readFileSync)`. No frame of the package survived to the moment of
  the call, and the resulting `package: null` was indistinguishable from "your
  own code", which policy allows unconditionally. Attribution now reports a
  third origin, `unknown`, which is evaluated against the default policy bucket
  instead of being trusted. See
  [ADR 0004](docs/adr/0004-async-attribution-and-unknown-origin.md).
- Wrappers installed over Node built-ins now inherit the original's own
  properties, so API hung off them (`setTimeout[util.promisify.custom]`,
  `fs.realpath.native`) keeps working while dephawk is active.

### Added

- `SchedulerInterceptor` — records the stack at the point a detached built-in is
  scheduled (`setTimeout`/`setInterval`/`setImmediate`, `queueMicrotask`,
  `process.nextTick`, `Promise.prototype.then`) and carries it through
  `AsyncLocalStorage`, so deferred calls are still attributed to the package
  that armed them rather than merely denied as anonymous. Costs one `WeakSet`
  lookup per callback argument; stacks are captured only for the detached case.
- Reports distinguish `(your code)` from `(unattributed)`.

### Changed

- `Attribution`, `CapabilityRequest` and `DhEvent` carry an `origin`
  (`dependency` | `application` | `unknown`). Programmatic consumers that build
  these values directly must supply it.

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
