# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.5.0] — 2026-08-03

Dependency changes become reviewable: dephawk can now say what a package started
doing, not only whether it was allowed to.

### Added

- **`--record <path>` / `--replay <path>`** — a behavioural baseline for
  dependency changes. A policy answers "is this permitted?"; a baseline answers
  "is this _new_?", which is the question a dependency bump actually raises. A
  package that used to resolve one host and now resolves two trips the diff even
  where policy allows both. The file is canonicalised (project root to `.`, home
  to `~`, no counts or timestamps) so it can be committed like a lockfile and
  still match on another machine, and an unreadable baseline is an error rather
  than a silent "no change". `--fail-on new` gates on it, reusing the existing
  mechanism instead of adding a second way to fail a build.

## [0.4.3] — 2026-08-03

Two holes found by attacking dephawk rather than reading it. Both reproduced
first, both closed with a regression test that fails without the fix.

### Security

- **`fs.cp` copied a whole secret directory, invisibly.** One call —
  `fs.cpSync('~/.ssh', '/tmp/loot', { recursive: true })` — took the entire
  directory while the report said "nothing sensitive touched", **in enforce
  mode**. `copyFile`/`copyFileSync` were patched; `cp`/`cpSync`, their recursive
  successors, were not, and `cp` does not route through `copyFile`, so patching
  that one was never enough. Now covered on both arguments (read the source,
  write the destination) across the sync, callback and `fs.promises` surfaces.
  `glob`/`globSync` are covered too — `glob('~/.ssh/*')` is `readdir` with a
  filter — including every pattern in a list, since a list whose entries were
  never resolved would have been a free pass of its own.
- **A worker thread could decline monitoring.** `new Worker(f, { execArgv: [] })`
  ran completely unmonitored on the `node --import dephawk/register` path: the
  worker was recorded as a spawn, and everything it then did — reading
  `~/.ssh/id_rsa` included — was invisible. `{ env: {} }` did the same by
  dropping `NODE_OPTIONS`. Both are now put back, with the same
  restore-don't-refuse reasoning as
  [ADR 0006](docs/adr/0006-re-attaching-monitoring-to-children.md) and the same
  note on the report line (`[dephawk re-attached: execArgv]`). The CLI was never
  affected — there `--import` travels in `NODE_OPTIONS`, which a worker inherits
  whatever it does to `execArgv`.

### Fixed

- The report no longer tells you to enforce when you already are. "Run in enforce
  mode to block these" was printed whenever nothing had been blocked, reading the
  count instead of the mode — so an enforce run where policy happened to permit
  everything advised itself.
- **Your own code is no longer counted as a culprit package.** dephawk watches
  dependencies, but reading your own `.env` still produced "1 package touched
  something sensitive" pointing at `(your code)`. Culprits now count dependencies
  and unattributed calls only; when the only flagged rows are yours, the report
  says so instead of naming a package count. Your rows are still listed —
  silence would be worse than a wrong number.

## [0.4.2] — 2026-08-03

### Security

- **dephawk could leak a secret through its own report.** A `process.spawn`
  event's detail is the entire command line, recorded verbatim — so
  `exec('curl -H "Authorization: Bearer ghp_…"')` wrote that token into the
  console report, `.dephawk/report.html`, the SARIF and the JSONL sink.
  Reproduced with 0.4.1: the token appears twice in the SARIF and once in the
  HTML. 0.4.0 made it worse by publishing those places — the GitHub Action puts
  the report in the **job summary**, which is public on a public repository, and
  `upload-sarif: true` puts it in code scanning. A tool whose whole claim is that
  your secrets stay put must not be the thing that moves one.

  Secret-looking values are now redacted out of every recorded `detail` and
  `reason`, and out of the blocked-call error that reaches stderr: by name
  (`--token=***`, `NPM_TOKEN=***`, `?access_token=***`, reusing the same
  name heuristic as env detection), by credential syntax (`Bearer ***`,
  `https://user:***@host`), and by known token shape (`ghp_***`,
  `github_pat_***`, `npm_***`, `glpat-***`, `xoxb-***`, `sk-***`, `AKIA***`,
  `eyJ***`). The prefix survives, because knowing _which_ kind of token was on
  the command line is the part you can act on.

  Redaction happens in `createEvent` — after policy has evaluated the real
  request, so rules still match what actually happened, and before any reporter
  sees it. Stack frames are left alone (paths and line numbers). It is a
  heuristic like every other rule in `domain/`: it catches the common forms, and
  the README now says plainly that the artifacts remain sensitive.

## [0.4.1] — 2026-08-03

### Fixed

- **`npx dephawk …` did nothing at all.** Neither did a global install, nor
  `node_modules/.bin/dephawk`: exit 0, no output, nothing monitored. Every
  package manager installs a `bin` as a symlink, and the CLI's "am I the program
  being run?" check compared `process.argv[1]` (the link) against
  `import.meta.url` (the file it points at, because Node resolves the main
  module's real path). That was false for every installed copy since 0.1.0. It
  only ever worked when invoked by path — which is how the test suite and
  `npm run demo` invoke it, so nothing caught it. The check now compares real
  paths, and a regression test runs the built CLI through a symlink.

## [0.4.0] — 2026-08-03

Adoption. 0.3.0 closed the holes; this release is about the tool being reachable:
two lines to gate a pull request, a policy dephawk drafts for you instead of a
blank file, and coverage for the recon step and the credential stores recent npm
attacks actually go for.

### Added

- **A published GitHub Action.** Adopting dephawk in CI is now two lines —
  `uses: actions/checkout@v4` and `uses: KirtashDev/dephawk@vX.Y.Z` — instead of
  a hand-written `npx` step plus the `continue-on-error` dance needed to make the
  SARIF upload survive a failing gate. The action captures dephawk's exit code,
  writes the report to the **job summary** (no permissions required), optionally
  uploads the SARIF to code scanning, and only then fails the job. Its defaults
  cannot turn a passing build red: `fail-on` starts at `blocked`, which observe
  mode never triggers. The dephawk version comes from the action reference
  (`@v1.2.3` runs `dephawk@1.2.3`), so pinning the action pins the tool. See
  [ADR 0007](docs/adr/0007-a-published-github-action.md).
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

- **Reconnaissance is now watched** as `fs.read`: directory listing (`readdir`,
  `opendir`) and symlink targets (`readlink`), in their sync, callback and
  `fs.promises` forms. Listing `~/.ssh` names every key on the machine and every
  host in `known_hosts` without opening one of them — the step before the theft,
  and previously invisible on two counts: the members were not patched, and the
  sensitivity rules only matched paths _inside_ a secret directory, never the
  directory itself. `realpath` stays uncovered on purpose: module resolution
  calls it constantly, so it would report far more than it caught.

### Changed

- **Sensitivity rules cover what recent npm attacks actually go for.** New:
  `.git-credentials`, `~/.config/gh/hosts.yml` (a GitHub token), `~/.azure`,
  `.pypirc`, key material by extension (`*.pem`, `*.key`, `*.p12`, `*.pfx`,
  `*.jks`, `*.keystore`, `*.ppk`, `*.kdbx`), OS credential stores (macOS
  keychains, GNOME Keyring, Windows Credential Manager and DPAPI master keys),
  **crypto wallets** (geth keystores, Electrum, Monero, Solana, NEAR, Exodus,
  `wallet.dat`, and browser-extension vaults such as MetaMask and Phantom),
  `/proc/*/environ` (every environment variable in one read, without touching
  `process.env`), per-environment dotenv files (`.env.production`, not just
  `.env`), and the remaining SSH key names (`id_dsa`, `id_ecdsa`). `~/.kube` and
  `~/.docker` are now sensitive as directories rather than only through one file
  each.

  Matching is now **case-insensitive**: macOS and Windows filesystems are, so
  `~/library/keychains/…` opened the same file as `~/Library/Keychains/…` and a
  case-sensitive list handed anyone a one-character bypass.

  The extension tier deliberately does **not** apply inside `node_modules`: a
  `.pem` shipped with a package is a CA bundle or a test fixture, not your
  secret, and flagging those would make every TLS-using dependency noisy enough
  to be ignored. Location-based rules still apply there — no package ships your
  SSH key.

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

[0.4.3]: https://github.com/KirtashDev/dephawk/releases/tag/v0.4.3
[0.4.2]: https://github.com/KirtashDev/dephawk/releases/tag/v0.4.2
[0.4.1]: https://github.com/KirtashDev/dephawk/releases/tag/v0.4.1
[0.4.0]: https://github.com/KirtashDev/dephawk/releases/tag/v0.4.0
[0.3.0]: https://github.com/KirtashDev/dephawk/releases/tag/v0.3.0
[0.2.0]: https://github.com/KirtashDev/dephawk/releases/tag/v0.2.0
[0.1.1]: https://github.com/KirtashDev/dephawk/releases/tag/v0.1.1
[0.1.0]: https://github.com/KirtashDev/dephawk/releases/tag/v0.1.0
