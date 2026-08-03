# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [Unreleased]

### Added

- **`dephawk init <command>`** — watches a run and writes the
  `dephawk.config.js` that would have let it pass. Enforcing was easy to
  describe and miserable to start: every dependency that legitimately reaches
  the network, shells out or reads `.npmrc` needed a hand-written rule before
  the first green run, which is what kept `--enforce` switched off. The draft
  grants what the run **did**, not what is safe — so it carries the observations
  that produced each rule, lists open-ended grants (`spawn`, `native`, `eval`)
  at the top for review, and never grants anything it could not attribute to a
  package. Refuses to overwrite an existing config without `--force`; `--out`
  chooses the path.
- Filesystem patterns in a policy may start with `~/`, expanded on load, so a
  committed config is not tied to one machine's home directory.
- **`--fail-on <level>`** — dephawk can now fail a command on what it found,
  which it previously could not do at all: `run` returned only the child's exit
  code, so an observe-mode run that watched a dependency read `~/.ssh/id_rsa`
  still exited 0. Levels are `none` (default), `blocked`, `violation` and
  `sensitive`; findings at or above the level exit **2**, while a command that
  failed on its own terms keeps its own exit code. `violation` is the one for
  CI: it fires on what _would_ be blocked, so a pull request fails on the
  finding without enforcement having to break the build first.
- **`--sarif <path>`** — SARIF 2.1.0 output for GitHub code scanning, so
  findings become annotations on the pull request instead of something to go and
  read in a log. Results carry the offending dependency's file and line where
  that file is inside the project, and stable fingerprints so a finding is not
  reopened on every run. Validated against the SARIF multitool.

- Releases are published from a tagged GitHub Actions workflow using npm
  **trusted publishing** (OIDC) and **provenance**
  (`publishConfig.provenance`). There is no npm token anywhere — not in a
  secret, not on a laptop: npm trusts this repository and this workflow file
  directly, and the runner proves who it is on each run. Every tarball carries a
  signed attestation linking it to the commit and workflow run that produced it,
  which `npm audit signatures` verifies. The workflow re-runs the full check
  suite against the tag rather than trusting `main`, and refuses to publish when
  the tag disagrees with `package.json`.

  Both mechanisms require a supported CI, so `npm publish` from a laptop now
  fails rather than shipping something unattested.

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

- Reads of `process.env` made by Node's own implementation of an intercepted
  built-in are no longer attributed to the caller. `child_process` copies the
  whole environment inside `normalizeSpawnArguments` to build a child's env, so
  one `execSync('echo hi')` invented an `env.read` finding for every secret in
  the environment — and a drafted policy would then hand that package all of
  them. A secret the caller reads in its own code before spawning is still
  caught.
- Wrappers installed over Node built-ins now inherit the original's own
  properties, so API hung off them (`setTimeout[util.promisify.custom]`,
  `fs.realpath.native`) keeps working while dephawk is active.

### Changed

- `dephawk run` now aggregates the whole monitored tree and reports **once**,
  from the CLI, the way `guard` already did. Previously every monitored process
  printed its own report over the others, and — more to the point — the CLI
  never saw the events, so it could not decide an exit code or write SARIF. A
  command that never starts no longer produces an empty report.

Nothing else changes for `dephawk run`/`guard` users. These affect code that composes
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
