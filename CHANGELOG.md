# Changelog

All notable changes to this project are documented here.
The format is based on [Keep a Changelog](https://keepachangelog.com/).

## [0.6.25] — 2026-08-11

### Security

- **The config and baseline could be overwritten through their canonical path
  alias.** dephawk protects `dephawk.config.js` and the behaviour baseline from
  being written by monitored code — rewriting the config grants a dependency
  anything on the next run, rewriting the baseline hides new behaviour from
  `--replay --fail-on new`. But those two paths were only `path.resolve`d, not
  canonicalised (unlike the guard sink, fixed in 0.6.23). On a symlinked location
  — macOS `$TMPDIR`/`/tmp` resolving to `/private/…` — a dependency could write
  the same file through its **canonical** name: the lexical tamper check compared
  against the non-canonical spelling and missed it, and the interceptor's
  `realpath` fallback then saw an already-canonical path resolve to itself and
  let it pass with no event. Reproduced overwriting the config with an allow-all
  policy under `--enforce`. Both spellings of every protected path (sink, config,
  baseline) are now refused: `collectProtectedPaths` records each path as given
  and its canonical form, so a write via either name matches, and a symlink alias
  still resolves into the canonical one.

## [0.6.24] — 2026-08-11

### Security

- **`import()` of a `data:` URL laundered a dependency's actions into "your
  code" — a full deny-by-default bypass.** The attributor decides a stack frame
  is application code when its location "looks like a source file", and that test
  counted any location containing `/`. A `data:text/javascript,…` frame satisfied
  it because of the `/` in the MIME type, so a dependency could
  `import('data:text/javascript,<payload>')` and, from a `setTimeout` inside the
  data module (so no importer frame is left on the stack), read `/etc/passwd`,
  the environment, or open a socket — every call credited to `(your code)` and
  **allowed under `--enforce`**, with the dependency never named. Reproduced
  end-to-end reading a real secret against a deny-by-default policy. The data
  body, being attacker-controlled text, could also contain the literal
  `node_modules/<pkg>/` to forge a specific package.

  Attribution now treats any frame whose location is a URL with a scheme other
  than `file:` (`data:`, `blob:`, `http:`, …) as internal — nobody accountable —
  so the call is evaluated against the default (deny-by-default) bucket instead
  of trusted. Checked before the `node_modules` match, so a forged body cannot
  impersonate a package. Real on-disk modules (`file:` URLs, plain paths, Windows
  `C:\` drives) are unaffected.

## [0.6.23] — 2026-08-11

### Security

- **The audit log could be blinded through a link alias (`dephawk guard`).**
  dephawk refuses writes to its own shared event sink, but the check is by path,
  and a link is a second path to the same bytes. A dependency could
  `link(sink, alias)` and then `writeFileSync(alias, '')` to truncate the log —
  erasing every capability its neighbours had already recorded — because
  `realpath(alias)` is the alias itself, not the sink, so nothing matched it to
  the protected path. A symlink did the same by a different route: the resolved
  target was tested against the sensitivity rules but not against the protected
  paths.

  Three fixes close it: the source of a hard link now counts as a **write** (it
  is a read/write handle to the inode), so aliasing the sink is refused at
  creation; the `realpath` fallback now judges the resolved target against the
  protected paths too, so a symlink alias is caught on write; and the sink path
  is canonicalised when created, so `tmpdir()` being a symlink on macOS
  (`/var` → `/private/var`) can no longer defeat the comparison. The audit log
  stays intact under `--enforce`, verified end-to-end.

## [0.6.22] — 2026-08-10

### Security

- **Writing a shell startup file for persistence went unseen.** A dependency
  could append a line to `~/.bashrc`, `~/.zshrc`, `~/.profile` (or any common
  shell rc/profile) during an install or build and run its payload on every shell
  the developer opened afterwards — persistence that outlives the build. The path
  is neither a secret to read nor inside another package, so nothing flagged it.
  Writing a shell startup file is now treated as a sensitive `fs.write` (append,
  copy, hard link, and symlink destinations all count), denied by default and
  allowlistable per package with an `fs.write` entry for a framework installer
  that legitimately edits one. Reading a shell rc is deliberately left alone —
  persistence is a write-side concern, so there are no new false positives on the
  many tools that read these files.

## [0.6.21] — 2026-08-10

### Security

- **A hard link smuggled a sensitive file past the read rules.**
  `fs.linkSync('~/.ssh/id_rsa', 'notes.txt')` then `readFileSync('notes.txt')`
  read the key with no event recorded, in enforce mode with a deny-by-default
  policy. Symlinks are caught because the interceptor resolves a mundane-looking
  path with `realpath` before judging it — but a hard link is a _co-equal
  directory entry_ for the same bytes, so `realpath('notes.txt')` is `notes.txt`,
  not the key, and nothing downstream flags the read. `link`/`linkSync` (and the
  `fs.promises` form) are now covered like `copyFile`: the source counts as an
  `fs.read` (the caller gains read access to that content) and the destination as
  an `fs.write` (so linking _into_ another package's directory is refused too).
  The alias is now caught the moment it is made, before the invisible read.

- **A symlink could be planted at a sensitive path unseen.** `fs.symlink`/
  `symlinkSync` were not covered, so
  `symlink('/tmp/attacker-key', '~/.ssh/authorized_keys')` — an SSH backdoor, or
  a payload dropped into another package — wrote nothing dephawk could see. The
  destination of a symlink is now judged as an `fs.write` (sensitive-path and
  into-package rules both apply). The target is deliberately _not_ treated as a
  read: a link only points at it, and reading _through_ the link is already
  caught by the read-time `realpath` resolution.

## [0.6.20] — 2026-08-10

### Fixed

- **The env Proxy exposed the wrong prototype, letting a dependency detect it.**
  The decoy target introduced in 0.6.18 is a plain object, so
  `Object.getPrototypeOf(process.env)` returned `Object.prototype` instead of the
  distinct prototype an unwrapped `process.env` has. Beyond the fidelity gap, a
  dependency could test the prototype to notice it was being monitored and go
  dormant — trivial evasion. The Proxy now forwards `getPrototypeOf` and
  `setPrototypeOf` to the real environment, so the prototype is identical to an
  unwrapped `process.env`. (Property access was never affected; the `get` trap
  already resolved the real prototype chain.)

## [0.6.19] — 2026-08-10

### Fixed

- **A dependency could freeze `process.env` into breaking the host app.** The
  env-inspect fix in 0.6.18 wraps the env Proxy over an empty decoy target. If a
  dependency made that decoy non-extensible — `Object.preventExtensions(process.env)`
  or `Object.freeze(process.env)` — the `ownKeys` trap, which returns the real
  environment's variable names (none of which exist on the empty decoy), then
  violated a Proxy invariant and threw `TypeError` on every `Object.keys(process.env)`,
  spread, and `console.log(process.env)` afterwards: a denial of service on the
  program dephawk is protecting. The Proxy now forwards `preventExtensions` to the
  real `process.env`, which refuses it exactly as an unwrapped `process.env` does,
  so the decoy can never be sealed and enumeration keeps working.

## [0.6.18] — 2026-08-10

### Security

- **`util.inspect(process.env)` dumped every secret past the env Proxy.** The env
  interceptor mediates `process.env` through a Proxy, but `util.inspect` — and so
  `console.log(process.env)`, `console.dir`, and every logger that formats an
  object — reads no trap at all: V8 unwraps a Proxy straight to its _target_ via
  the internal `getProxyDetails` and formats the target's own values directly.
  With the real environment as the target, one `console.log(process.env)` handed
  a dependency every variable, secrets included, and dephawk recorded nothing and
  denied nothing.

  The Proxy now sits over an empty _decoy_ target and every trap forwards to the
  real environment, so an unwrap finds no values to print. A `util.inspect.custom`
  hook on the decoy judges the dump: exposing the whole environment at once is the
  same threat as `process.report.getReport()`, so it is recorded as
  `process.memory` and, for a dependency without `memory: true`, replaced by a
  placeholder. Your own code — and a dependency you have allowed — still see the
  real output, so `console.log(process.env)` keeps working when you run it. The
  hook never throws (it runs inside object formatting, where a throw would break
  every `console.log` in the process); a denied dump is hidden, not fatal.

## [0.6.17] — 2026-08-10

### Security

- **Hijacking the module loader ran code as another package.** A dependency that
  reassigned `Module.prototype._compile` (or `Module._load`,
  `Module._resolveFilename`, a `require.extensions` handler) could prepend code
  to the source of every module loaded afterwards, so the injected code ran
  inside — and was attributed to — an innocent, allowlisted package and borrowed
  its permissions. Reproduced: a dependency injected a `readFileSync` into an
  allowlisted package via `_compile` and read a secret it had no rule for, under
  `--enforce` with a deny-by-default policy. The ES-module equivalent,
  `module.register(hook)` (and `registerHooks`), did the same for ESM.

  This cannot be caught in the attributor — the injected code genuinely runs in
  the victim's module — so the _act of hooking the loader_ is now recorded as
  `code.eval` and denied by default. Legitimate transpiler hooks (`ts-node`,
  `@babel/register`, `tsx`) are real code execution and are allowlisted the same
  way any `vm` user is, with `eval: true`.

  Closing the ESM side also required not building the `node:module` ESM facade
  early: `support.ts` now obtains `createRequire` through
  `process.getBuiltinModule` instead of `import`, so a dependency's
  `import { register } from 'node:module'` gets dephawk's patched `register`, not
  the original. (Same facade-snapshot class as the 0.6.13 fix.)

## [0.6.16] — 2026-08-10

### Security

- **Dumping process memory leaked secrets past every interceptor.** Two moves
  bypassed the filesystem and `process.env` surfaces entirely:
  `process.report.getReport()` returns Node's diagnostic report — including an
  `environmentVariables` map of _every_ environment variable — as a plain
  object, no file needed; and `v8.writeHeapSnapshot()` / `getHeapSnapshot()`
  serialise the heap, which holds every decrypted string, token and key. Both
  read a real secret under `--enforce` with a deny-by-default policy, invisible
  in the report. They are now a new **`process.memory`** capability, denied by
  default and allowlisted per package with `memory: true` — covering
  `process.report.getReport`/`writeReport` and `v8.writeHeapSnapshot`/
  `getHeapSnapshot`.

## [0.6.15] — 2026-08-10

### Security

- **`node:sqlite` read files past the filesystem interceptor.** A dependency
  could `new DatabaseSync('…/Login Data')` and `SELECT` the passwords straight
  out of Chrome's saved-password database — or any sensitive SQLite file — with
  nothing recorded and nothing blocked, even under `--enforce`. `node:sqlite`
  (Node 22.5+) opens the file through its own C++ binding, never through `fs`.
  This is exactly what the 2025-26 browser-credential stealers do, and dephawk
  already treated those paths as sensitive — it just could not see this door.
  Opening a database at a sensitive path is now recorded as `fs.read`, gated by
  the same sensitivity rules and `fs.read` allowlist, including the
  `{ open: false }` + `.open()` form; loading a SQLite extension (native code)
  is recorded as `process.native`. In-memory and mundane databases are ignored,
  and the interceptor installs nothing where `node:sqlite` is unavailable, with
  its experimental warning suppressed so a project that never touches SQLite
  does not print it.

## [0.6.14] — 2026-08-10

### Security

- **The ESM named-import fix missed `node:fs/promises`.** 0.6.13 stopped a
  dependency reading a secret with `import { readFileSync } from 'node:fs'`, but
  `import { readFile } from 'node:fs/promises'` still slipped through — reproduced
  reading a real secret under `--enforce`. `node:fs/promises` is a _separate_
  module specifier with its own ESM facade, and two of dephawk's own reporters
  (`html-reporter`, `sarif-reporter`) imported `{ mkdir, writeFile }` from it,
  building that facade with the original functions before the patch. They now
  take those through `require` (`loadBuiltin`) like everything else, so nothing
  in dephawk's own graph builds a built-in facade ahead of patching. Verified
  `node:dns/promises` was already covered, and the HTML/SARIF reports still write.

## [0.6.13] — 2026-08-10

### Security

- **An ESM dependency slipped past every interceptor with named imports.**
  `import { readFileSync } from 'node:fs'` gave a dependency the _original_
  function, not dephawk's patched one — so an ESM package read a secret, spawned
  a process, resolved a host or ran `vm` code with nothing recorded and nothing
  blocked, even under `--enforce` with a deny-by-default policy. This hit nearly
  every capability (`fs`, `net`, `dns`, `child_process`, `vm`, `worker_threads`,
  `inspector`, listeners), and ESM named imports are idiomatic, so it was the
  widest bypass found.

  The cause is how Node builds a built-in's ESM facade: its named exports are
  bound to the functions that exist the moment the facade is first created — a
  snapshot. dephawk imported the built-ins (`import fs from 'node:fs'`), which
  created that facade with the _original_ functions before it patched them.
  Every interceptor now acquires its built-in through `require` instead, which
  does not create the facade, so the facade is built later — by the application
  or a dependency's first `import` — and snapshots the functions dephawk has
  already replaced. Confirmed across fs/net/dns/spawn/vm, and `fetch` and normal
  ESM apps are unaffected.

## [0.6.12] — 2026-08-10

### Security

- **An `eval: true` worker ran unmonitored.** `new Worker(code, { eval: true })`
  escaped monitoring entirely — its reads were neither recorded nor blocked,
  even under `--enforce` with a deny-by-default policy — because such a worker
  does **not** honour `--import` in `execArgv` (verified on Node 20 and 22), and
  with no `execArgv` it inherits `process.execArgv`, whose `--import` is equally
  useless to it. The 0.4.3 worker fix, which re-attaches `--import`, had no
  effect on them. dephawk now re-attaches monitoring to an eval worker with
  `--require` instead, which it does honour, seeding from the caller's or the
  parent's `execArgv` so other flags survive. File-based workers are unchanged —
  `--import` works for them and this is verified in both directions.

  Along the way this corrected a wrong belief in the code's own comments: worker
  threads do **not** re-apply an inherited `NODE_OPTIONS` (they are threads, not
  new processes), so worker monitoring rests entirely on `execArgv`.

## [0.6.11] — 2026-08-10

### Security

- **The behaviour baseline is now protected from the program it monitors.**
  `--replay` reads `.dephawk/baseline.json` back after the run to decide
  `--fail-on new`, so a dependency that overwrote it mid-run — adding the very
  host or path it had just started touching — hid its own change from the diff.
  Reproduced: a dependency resolved a new host, rewrote the baseline to include
  it, and the gate passed (exit 0). The resolved baseline path now travels to
  the whole process tree and writing it is refused for every origin in both
  modes, exactly like the config file and the guard sink. `--record` writes the
  baseline from the un-monitored parent after the run, so recording is
  unaffected.

  The report (`.dephawk/report.html`) and the SARIF file need no such
  protection: the parent writes them from the authoritative event stream after
  the run, overwriting whatever a dependency might have left, so poisoning them
  achieves nothing. Only an artifact that is _read back_ to make a decision — the
  baseline — was exploitable, and it is the last of them.

## [0.6.10] — 2026-08-10

### Security

- **The config file is now protected from the program it monitors.** A
  dependency could overwrite `dephawk.config.js` on disk — it was not among
  dephawk's protected paths — granting itself whatever it liked on the _next_
  run. The CLI now passes the resolved config path to the whole process tree, and
  writing it is refused for every origin in both modes, exactly like the guard
  sink. `dephawk init` is unaffected: it writes the config from the un-monitored
  parent, after the observed run has exited, and never marks it protected. Closes
  the known issue noted in 0.6.9.

  (A relative `--config path` is now resolved to an absolute path before it
  travels, so protection matches the absolute paths the interceptor sees.)

## [0.6.9] — 2026-08-10

Attacks on dephawk's own control plane, not on a capability: if you can stop the
report or run a child out of enforce, no capability bypass is needed. Both
reproduced against the real CLI before being closed.

### Security

- **Removing the exit listeners blinded the whole report.** The aggregated
  `run`/`guard` report was produced from a `process.on('exit')` flush that
  buffered every event until the end. A dependency that read a secret and then
  called `process.removeAllListeners('exit')` erased all of it: the run exited 0
  with "no monitored activity recorded", defeating the `--fail-on` gate along
  with it. Events are now streamed to the shared sink the instant each call is
  decided (`JsonlSink`), so the record is on disk before the code that produced
  it returns — tearing down the exit handler loses nothing the parent has not
  already read.

- **A dependency could spawn a child out of enforce.** `DEPHAWK_MODE` was
  applied on top of the pinned policy every time it was resolved, including in
  children, and only the policy JSON was re-attached to spawned processes — not
  the mode. So a dependency that spawned a child with `DEPHAWK_MODE=observe` in
  its environment downgraded that child out of enforce and ran its
  blocked-by-default calls freely. On the `--import` path `DEPHAWK_MODE` may now
  only _tighten_ the pinned mode (observe → enforce), never loosen it; the CLI's
  own `--observe` flag still loosens where it is meant to, at the top level
  before the policy is pinned.

### Known issues

- A dependency can still **overwrite the config file** (`dephawk.config.js`) on
  disk, poisoning the _next_ run — the file is not among dephawk's protected
  paths. It does not affect the run in progress (the policy is resolved once at
  startup). Tracked for a follow-up.

## [0.6.8] — 2026-08-10

### Security

- **`vm` could pin a call on another package by naming the script.**
  `runInThisContext(code, { filename: '…/node_modules/innocent/index.js' })`
  makes V8 stamp that name onto every frame the compiled code produces, so the
  frames are shaped exactly like that package's real ones. The `//# sourceURL`
  forgery closed in 0.6.4 is recognisable by its `eval` marker; this one is not,
  and could not be caught by reading the stack more carefully. It handed the
  call — and the allowlist — to an innocent package, and poisoned the report, so
  `dephawk init` would then draft that package a permission it never asked for.

  What _is_ knowable is which names were handed to `vm`, so they are recorded as
  they are used and no frame sitting at one of them is credited to a package.
  Blame falls through to the next real frame, which for code a dependency
  compiled and ran is that dependency. Only the exact name given to `vm` is
  distrusted, so the rest of that package's real files are unaffected. The
  `vm.Script` constructor is covered too, since the run methods never see the
  option it was built with.

  A first attempt scoped this to the duration of the `vm` call and was wrong:
  `runInThisContext` can **return a closure** that runs later, carrying the
  forged filename in its frames long after any such scope has ended. A name once
  used to disguise code stays untrustworthy for the life of the process.

  This was the last of the five bypasses found on 2026-08-10; all are now closed.

## [0.6.7] — 2026-08-10

### Security

- **A symlink no longer hides a sensitive path.** Paths were matched as written,
  and `path.resolve` does not follow links, so `readFileSync('notes.txt')` where
  that name pointed at `~/.ssh/id_rsa` read the key with **no event recorded at
  all** — invisible even under `--enforce` with a deny-by-default policy. A path
  that looks mundane is now resolved and judged by what it actually points at.
  Writes are covered too: when the file does not exist yet the parent is
  resolved instead, so creating `assets/authorized_keys` inside a directory that
  links to `~/.ssh` is caught.

  The reported detail stays the **real** path, and stays a bare path: the policy
  engine matches `detail` against the sensitivity rules and the per-package
  allowlists, so annotating it would have broken allowlisting and, worse, made
  the sensitivity test miss.

  0.6.4 deferred this on the grounds that resolving every path would cost ~16 µs
  a call. That estimate was right about the price and wrong about the quantity:
  Node resolves modules through internal bindings rather than the public `fs`
  API, so this interceptor sees **hundreds** of calls where the syscall count is
  millions — measured at 637 for a real `npm ci` and 96 for a `tsup` build. The
  resolution only runs for paths that already look mundane, and `guard npm ci`
  is unchanged at ~1.3 s. Assuming the cost instead of measuring it left a
  critical hole open for three releases.

## [0.6.6] — 2026-08-10

### Fixed

- **`dephawk guard npm ci` now actually runs npm.** It never had. npm exited 1
  in silence under dephawk — no install, no output, not even its own debug log —
  so the command the README leads with was a no-op in every release from 0.4.3
  to 0.6.5, and reported a clean install of nothing.

  The cause was one line of spec behaviour. Assigning to a property that already
  exists on a Proxy re-enters as `[[DefineOwnProperty]]` on the receiver with a
  **value-only** descriptor, and Node's `process.env` refuses partial
  descriptors, throwing `'process.env' only accepts a configurable, writable,
and enumerable data descriptor`. npm sets `env.HOME` while loading its config,
  that threw out of `Config.load`, and npm's exit handler swallowed it. Creating
  a _new_ variable was fine — it builds a full descriptor — which is why nothing
  ever looked wrong in ordinary use. The env Proxy now carries a `set` trap that
  writes straight to the real environment.

  With npm running, the 0.6.5 `node_modules` write rule can finally be measured
  against a real install: `npm ci` produced an 8 KB report with no write noise
  at all, and the events it did record (npm reading `.npmrc`, resolving and
  fetching from the registry) are attributed to the npm packages that made them.

- **The suite now runs a real package manager.** Every other test drives
  dephawk with a `node` script we wrote, and the CI action job uses
  `node --version` — which is exactly why a total failure to run npm went
  unnoticed for five releases. `test/e2e/package-manager.e2e.test.ts` runs
  `npm --version` under the CLI, and fails without this fix.

## [0.6.5] — 2026-08-10

### Security

- **A dependency could take over another package by writing into its
  directory.** Attribution names the first `node_modules/<name>` frame on the
  stack, so a payload written to `node_modules/innocent/.cache.js` and then
  `require`d genuinely runs _as_ `innocent` and inherits whatever the policy
  grants it. Reproduced under `--enforce` with a deny-by-default policy: the
  write was not recorded at all (a `node_modules` path is not sensitive), the
  secret came back, and the report named `innocent` while the attacker appeared
  nowhere. It is persistent — the planted file survives until the next install.

  Nothing about it is forgery, which is why it could not be fixed in the
  attributor: the code really is in that directory. The write is the moment to
  catch it, so writes into an installed package's directory are now reported
  whatever the filename looks like, and refused when the writer is a _different_
  package. A package writing inside its own directory (caches, compiled output,
  downloaded binaries) is untouched, and so is the application — `patch-package`,
  monorepo linkers and build steps keep working.

  Cost: writes into `node_modules` now capture a stack, ~3 µs each. A synthetic
  5 000-file run took 827 ms and produced a 1.9 MB report, so a tool that
  rewrites a whole dependency tree under `dephawk run` will make a large report.

### Known issues

- **`dephawk guard npm ci` did nothing** — npm exited silently under the
  `process.env` Proxy. Diagnosed and fixed in 0.6.6; the entry above is kept as
  written at the time.

## [0.6.4] — 2026-08-10

Two more ways to lie about who made a call, both reproduced against `--enforce`
with a deny-by-default policy before being closed. 0.6.0 stopped a dependency
forging its _own_ innocence; these two let it hand the blame to someone else.

### Security

- **`Error.captureStackTrace` could be hijacked.** 0.6.0 hardened
  `Error.prepareStackTrace` and `Error.stackTraceLimit` during a capture but not
  the function doing the capturing. Replacing it with one that writes a frame
  naming an application file made the call read as _your_ code — which policy
  allows unconditionally — and a real secret came back under a deny-by-default
  `--enforce` policy. dephawk now takes its own reference to `Error` and
  `Error.captureStackTrace` at load, before any dependency has run, and uses
  those; the `prepareStackTrace`/`stackTraceLimit` overrides are set on that
  captured constructor too, so swapping the global out moves nothing.
- **An `eval` frame could pin a call on another package.** `eval` and
  `new Function` are language intrinsics that cannot be patched, and a
  `//# sourceURL=…` comment inside evaluated source replaces that frame's
  location wholesale. Evaluating
  `//# sourceURL=…/node_modules/innocent/index.js` attributed the call to
  `innocent` — which then **lent it that package's allowlist**, so the read was
  permitted, and the report named the wrong dependency to remove. Such a frame
  is no longer trusted for attribution, so the blame falls through to the
  package that actually called `eval`.

  V8's other eval form — `at eval (eval at run (/pkg/i.js:3:9), …)` — keeps
  V8's own record of where the eval came from, so that path is still attributed
  exactly as before; only a self-declared `sourceURL` location is discarded.

### Known, not yet fixed

- A **symlink** at a mundane path pointing to a secret is still read with no
  event recorded. Fixed in 0.6.7, once the cost was measured rather than
  assumed; the reasoning as written at the time is kept above.

## [0.6.3] — 2026-08-10

### Fixed

- **A floating major tag would have jumped across the 1.0 boundary.** The action
  pins dephawk from its own reference, but only a full `vX.Y.Z` tag was
  recognised — anything else, `@v0` included, resolved to `latest`. Since 0.6.2
  the README recommends `@v0`, so the day 1.0 shipped every workflow using it
  would have silently moved to 1.x, across exactly the bump where this action's
  inputs may change. A reference is now turned into the npm range that means the
  same thing: `@v1.2.3` → `1.2.3`, `@v1.2` → newest `1.2.x`, `@v1` → newest
  `1.x`. Branches and SHAs still fall back to `latest`, having nothing to pin to.

  The version derivation had no test at all — CI exercises the action through
  the `bin` input, which skips that branch entirely. It now has one
  (`test/e2e/action-version.e2e.test.ts`) that runs the real `action/run.sh`
  against a stub `npx` and asserts the resolved spec; it fails without this fix.

## [0.6.2] — 2026-08-10

Documentation only — no behaviour changes.

### Fixed

- **The CI examples told you to pin a version from before the 0.6.0 security
  fixes.** They still read `uses: KirtashDev/dephawk@v0.4.3`, and because the
  action runs the dephawk release its own tag names, copying them pinned the
  tool to 0.4.3 — keeping every bypass that 0.6.0 closed. They now use the
  floating **`v0`** tag, which moves to each release, and the surrounding text
  explains when an exact pin is the right choice instead.

### Changed

- `CONTRIBUTING.md` documents how work lands on `main`: trunk-based with
  short-lived `feat/`/`fix/`/`docs/` branches, squash-merged, rather than
  GitFlow — which exists to coordinate several supported versions and several
  people, and this project has one of each. It also records that `main`'s
  protection now applies to the maintainer, that `format:check` is a separate
  gate from `lint`, and that `v0` has to be moved by hand after a release.

## [0.6.1] — 2026-08-10

Housekeeping only — no behaviour changes.

### Added

- **`SECURITY.md`,** and private vulnerability reporting enabled on the
  repository. A tool that tells you to distrust your dependencies needs a way to
  be told it is wrong, and a public issue is the worst place for that. It states
  what counts as a vulnerability here (a dependency doing something sensitive
  that dephawk fails to record or block under `--enforce`), and what is a
  documented limitation rather than a bug (native code, `eval`, bindings
  captured before install).
- A **funding link** (`funding` in `package.json`, plus a Sponsor button via
  `.github/FUNDING.yml`). dephawk is free, MIT-licensed and has no paid tier —
  that does not change.

### Changed

- README and `CONTRIBUTING.md` now say plainly that this is a one-person
  project, so response times read as best-effort rather than as neglect. Issues,
  security reports and attack samples are still welcome.
- The contributing notes no longer describe the GitHub Marketplace as a pending
  release step: it is deliberately unused, because listing there means accepting
  an indemnity for data disclosure caused by the product, and
  `uses: KirtashDev/dephawk@v0.6.0` works without it.

## [0.6.0] — 2026-08-10

Eight escape hatches closed, each reproduced end to end against `--enforce` with
a deny-by-default policy before it was covered — a fake dependency read a real
secret or ran code with an empty report, then couldn't.

### Security

- **Attribution could be forged (the worst of the set).** A dependency that set
  its own `Error.prepareStackTrace` returning a stack string with a fake
  application frame made _every_ laundered call read as the user's own code and
  get allowed unconditionally — reproduced reading `/etc/passwd` under enforce
  with a deny-by-default policy, invisible in the report. `stackTraceLimit = 0`
  was a weaker variant that blinded the capture. dephawk now forces V8's default
  stack formatter and a generous frame budget for the duration of each capture,
  then restores the dependency's values, so the forgery is ignored while the
  app's own error handling (source maps, monitors) is untouched. Reads are now
  blocked _and_ attributed to the real package.
- **A secret could be lifted out of `process.env` through a descriptor.**
  `Object.getOwnPropertyDescriptor(process.env, 'AWS_SECRET_ACCESS_KEY').value`
  reads the value without ever triggering the `get` trap the env Proxy relied
  on. The Proxy now also traps `getOwnPropertyDescriptor`, handing back an
  accessor descriptor for a sensitive variable: enumerating names
  (`Object.keys`, `for…in`) still reports nothing, but pulling the value out
  funnels through the same report/deny path as a plain read.

- **Raw sockets to an IP were invisible.** Only the module-level
  `net.connect`/`net.createConnection`/`tls.connect` were patched, so
  `new net.Socket().connect(port, '93.184.216.34')` — a plain socket straight to
  a hardcoded C2 IP — reached the network with nothing in the report (a
  _hostname_ was caught by DNS in passing; a bare IP was not). Now patched at the
  one chokepoint they all funnel through, `net.Socket.prototype.connect`, which
  covers the module functions, TLS, and `http2` (proper `host:port` detail) as
  well as the raw case.
- **`fs.openAsBlob` read files uncovered.** `openAsBlob('~/.ssh/id_rsa')` returns
  a Blob whose `.text()`/`.stream()` reads the file without calling any named
  read member — it was not in the intercepted set. Now recorded as `fs.read`.

- **`process.binding` bypassed everything.** `process.binding('fs').readFileUtf8`
  (or `'spawn_sync'`, `'tcp_wrap'`, `'cares_wrap'`) hands back Node's raw
  internal C++ bindings, which never touch the `node:*` modules the other
  interceptors patch — one line read any file with nothing in the report. Now
  intercepted (with `process._linkedBinding`) as `process.native`: the same
  raw-runtime-power category as a native addon, default-deny.
- **`node:inspector` was an open debugger backdoor.** A `new inspector.Session()`
  driving `Runtime.evaluate` runs arbitrary code in the process, and
  `inspector.open(port)` exposes a WebSocket for full remote control. Now
  recorded as `code.eval` (default-deny) — nothing legitimate opens a debugger.
- **Inbound listeners were invisible.** The network interceptors watched egress;
  `net.createServer().listen(0)` / `http…listen()` bound a backdoor port and
  produced "no monitored activity recorded". A new **`net.listen`** capability
  covers `net`/`http`/`http2` servers (one patch on `net.Server.prototype.listen`)
  and `dgram.bind`, allowlisted per package with `net: { listen: true }`.
- **WebAssembly ran staged payloads uncovered.** `WebAssembly.instantiate`
  (and the sync `new WebAssembly.Module`/`Instance` path) executes a byte blob
  outside the JS surface, like `vm` one format over. Now recorded as `code.eval`.
  Node's own bundled WASM (undici's `llhttp`, compiled on first `fetch`) is
  recognised as runtime plumbing by its immediate caller and left alone, so the
  coverage does not break `fetch` or invent a finding for the runtime.

### Added

- **Browser credential stores are now sensitive**, driven by the npm stealer
  campaigns of 2025-26 (NodeCordRAT, TrapDoor, the dYdX/Polymarket drainers),
  which target the browser more than `~/.ssh`. Covered by their distinctive file
  names — so a read is caught whatever the OS or profile: Chromium
  (Chrome/Brave/Edge/Electron) `Login Data`, `Local State`, `Web Data`; Firefox
  `logins.json`, `key4.db`, `cookies.sqlite`; plus the browser profile
  directories themselves, so listing one is caught as recon. (MetaMask and other
  extension vaults were already covered under `Local Extension Settings`.)
- Watching a sensitive path (`fs.watch`/`fs.watchFile` on `~/.aws`, `.env`, …)
  is now recorded as `fs.read` — a recon channel that never calls a read member.

### Fixed

- **`server.listen(port, host)` invented a DNS finding.** Node resolves the bind
  address on the way through `listen`, so opening a server reported a
  `net.resolve` against the caller for a lookup it never made. The listen
  interceptor now runs Node's implementation behind the runtime-internals guard,
  and the DNS interceptor honours it — the same treatment `child_process`
  already had for the `process.env` copy it makes internally.

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

[0.6.17]: https://github.com/KirtashDev/dephawk/releases/tag/v0.6.17
[0.6.16]: https://github.com/KirtashDev/dephawk/releases/tag/v0.6.16
[0.6.15]: https://github.com/KirtashDev/dephawk/releases/tag/v0.6.15
[0.6.14]: https://github.com/KirtashDev/dephawk/releases/tag/v0.6.14
[0.6.13]: https://github.com/KirtashDev/dephawk/releases/tag/v0.6.13
[0.6.12]: https://github.com/KirtashDev/dephawk/releases/tag/v0.6.12
[0.6.11]: https://github.com/KirtashDev/dephawk/releases/tag/v0.6.11
[0.6.10]: https://github.com/KirtashDev/dephawk/releases/tag/v0.6.10
[0.6.9]: https://github.com/KirtashDev/dephawk/releases/tag/v0.6.9
[0.6.8]: https://github.com/KirtashDev/dephawk/releases/tag/v0.6.8
[0.6.7]: https://github.com/KirtashDev/dephawk/releases/tag/v0.6.7
[0.6.6]: https://github.com/KirtashDev/dephawk/releases/tag/v0.6.6
[0.6.5]: https://github.com/KirtashDev/dephawk/releases/tag/v0.6.5
[0.6.4]: https://github.com/KirtashDev/dephawk/releases/tag/v0.6.4
[0.6.3]: https://github.com/KirtashDev/dephawk/releases/tag/v0.6.3
[0.6.2]: https://github.com/KirtashDev/dephawk/releases/tag/v0.6.2
[0.6.1]: https://github.com/KirtashDev/dephawk/releases/tag/v0.6.1
[0.6.0]: https://github.com/KirtashDev/dephawk/releases/tag/v0.6.0
[0.5.0]: https://github.com/KirtashDev/dephawk/releases/tag/v0.5.0
[0.4.3]: https://github.com/KirtashDev/dephawk/releases/tag/v0.4.3
[0.4.2]: https://github.com/KirtashDev/dephawk/releases/tag/v0.4.2
[0.4.1]: https://github.com/KirtashDev/dephawk/releases/tag/v0.4.1
[0.4.0]: https://github.com/KirtashDev/dephawk/releases/tag/v0.4.0
[0.3.0]: https://github.com/KirtashDev/dephawk/releases/tag/v0.3.0
[0.2.0]: https://github.com/KirtashDev/dephawk/releases/tag/v0.2.0
[0.1.1]: https://github.com/KirtashDev/dephawk/releases/tag/v0.1.1
[0.1.0]: https://github.com/KirtashDev/dephawk/releases/tag/v0.1.0
