# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

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

[0.1.1]: https://github.com/kellendir/dephawk/releases/tag/v0.1.1
[0.1.0]: https://github.com/kellendir/dephawk/releases/tag/v0.1.0
