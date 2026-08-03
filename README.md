<div align="center">

# 🦅 dephawk

### A hawk-eyed watch on your npm dependencies.

**See — and block — what your dependencies actually do at runtime:**
reading your SSH keys, phoning home, spawning shells.

[![npm](https://img.shields.io/npm/v/dephawk.svg)](https://www.npmjs.com/package/dephawk)
[![downloads](https://img.shields.io/npm/dm/dephawk.svg)](https://www.npmjs.com/package/dephawk)
[![CI](https://github.com/KirtashDev/dephawk/actions/workflows/ci.yml/badge.svg)](https://github.com/KirtashDev/dephawk/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![node](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](#)
[![stars](https://img.shields.io/github/stars/KirtashDev/dephawk?style=social)](https://github.com/KirtashDev/dephawk)

</div>

---

You install one package. It has 40 transitive dependencies. Any one of them can
read `~/.ssh/id_rsa`, grab your `NPM_TOKEN`, and POST it to a server you've never
heard of — and you'll never know.

`dephawk` circles above your code and **watches every dependency**. The moment one
touches your filesystem, opens a socket, spawns a process, or reads a secret from
the environment, dephawk records it, attributes it to the exact package, and —
if you want — **blocks it**.

```bash
npx dephawk run npm test
```

<div align="center">

![dephawk catching a dependency listing ~/.ssh, reading a crypto wallet key and an npm token, shelling out with a credential, and phoning home — then blocking all of it in enforce mode](assets/demo.gif)

</div>

Those twenty seconds are the pitch. A dependency lists your `~/.ssh`, goes for a
wallet key and your `NPM_TOKEN`, shells out with a bearer token and phones home —
dephawk names it, redacts the token out of its own report, and on the second run
blocks every one of those calls and fails the build with exit code 2.

> 📺 **Run it yourself:** `npm run demo` (observe) and `npm run demo:enforce`
> (block). The recording above is that same demo, made with
> [`vhs`](https://github.com/charmbracelet/vhs): `vhs assets/demo.tape`. The
> sample dependency simulates an attack and exfiltrates nothing — fake key paths,
> a `.invalid` host, a made-up token
> ([see for yourself](examples/demo/node_modules/sneaky-dependency/index.js)).

## Why

Supply-chain attacks on npm are now routine: typosquats, hijacked maintainer
accounts, malicious post-install scripts. Static scanners (Socket, `npm audit`)
help, but they can't see what obfuscated or dynamically-loaded code _does when it
runs_. `dephawk` is the runtime tripwire: it doesn't guess from the source, it
watches the actual behavior.

## Quick start

**Observe mode** (default — records everything, blocks nothing):

```bash
npx dephawk run npm test
npx dephawk run node ./build.js
```

**Enforce mode** (block anything not explicitly allowed):

```bash
npx dephawk run --enforce npm start
# or:  DEPHAWK_MODE=enforce npx dephawk run npm start
```

Or wire it into any Node process directly (honours `DEPHAWK_MODE`):

```bash
node --import dephawk/register ./your-app.js
```

On exit, dephawk prints the summary above and writes a shareable, self-contained
**`.dephawk/report.html`**.

**Guard your install** (the attack surface that runs _before_ your code):

```bash
npx dephawk guard npm ci
```

`guard` runs the install and watches **every Node process it spawns** — the
package manager itself and each dependency's `preinstall`/`postinstall`/`install`
lifecycle script — then prints **one aggregated report** attributing any
capability use to the exact package. This is where a huge share of real
supply-chain attacks fire: a malicious `postinstall` reads your `~/.ssh` key or
`NPM_TOKEN` and phones home the moment you `npm install`, long before your app
ever starts. Add `--enforce` to block it. (Under the hood, `run` monitors one
process; `guard` aggregates across the whole spawned tree via a shared sink.)

The sink is the one thing dephawk defends in **both** modes: a lifecycle script
that tries to write to it — the obvious move for erasing its own tracks — is
refused even under `observe`, and the attempt is reported. Everything the
monitored program does to its _own_ files still merely gets recorded in observe
mode. See
[`docs/adr/0005`](docs/adr/0005-protecting-the-guard-audit-log.md).

## In CI

Two lines, and every install in the repository is watched:

```yaml
- uses: actions/checkout@v4
- uses: KirtashDev/dephawk@v0.4.3
```

That runs `dephawk guard npm ci`, attributes anything sensitive to the
dependency that did it, and writes the report to the **job summary** — no
permissions, no extra steps. It cannot turn a passing build red on its own: the
default `fail-on` is `blocked`, which observe mode never triggers.

When you want a gate, add the two inputs that make one:

```yaml
- uses: KirtashDev/dephawk@v0.4.3
  with:
    command: npm ci # or: npm test, with subcommand: run
    fail-on: violation # fail on what policy denies, blocked or not
    upload-sarif: true # annotations on the pull request
```

`upload-sarif` needs `permissions: { security-events: write }` on the job, which
is why it is opt-in. Every input, including `mode: enforce`, a `config` path and
a `working-directory`, is documented in [`action.yml`](action.yml); the reasoning
is in [`docs/adr/0007`](docs/adr/0007-a-published-github-action.md). The action
runs the dephawk release its own tag names (`@v0.4.3` → `dephawk@0.4.3`), so
pinning the action pins the tool.

### Or wire the CLI up yourself

Observe mode records everything and blocks nothing — which used to mean it could
never fail a build. `--fail-on` gives it a verdict, and `--sarif` turns the
findings into annotations on the pull request:

```bash
npx dephawk run --fail-on violation --sarif dephawk.sarif npm test
```

`--fail-on violation` fails when policy denied anything, **whether or not the
call was actually blocked** — so a pull request that introduces a dependency
reading `~/.ssh` goes red without you having to enforce (and break) the build
first. Levels, loosest last:

| `--fail-on`      | fails when                                        |
| ---------------- | ------------------------------------------------- |
| `none` (default) | never; the exit code is the command's own         |
| `blocked`        | a call was actually prevented (enforce mode only) |
| `violation`      | policy denied a call, blocked or not              |
| `sensitive`      | anything sensitive was touched, even if permitted |

Exit code **2** means findings reached the threshold. If the command itself
failed, its own exit code is returned instead — that is the more immediate thing
to fix.

Wire the SARIF into GitHub code scanning:

```yaml
- run: npx dephawk run --fail-on violation --sarif dephawk.sarif npm test
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: dephawk.sarif
```

`continue-on-error` lets the upload run even when dephawk fails the job, so the
annotations appear on the pull request that caused them. (The action above does
this for you.)

## What it watches

| Capability       | Examples caught                                                                    |
| ---------------- | ---------------------------------------------------------------------------------- |
| `fs.read`        | reading, **listing**, globbing or **copying** `~/.ssh`, keychains, wallets, `.env` |
| `fs.write`       | overwriting or **deleting** `~/.npmrc`, `authorized_keys`, other secret files      |
| `net.connect`    | `http`/`https`/`fetch`, plus raw `net`/`tls` sockets and UDP (`dgram`)             |
| `net.resolve`    | `dns.lookup`/`resolve*` — recon and DNS-tunnel exfil (no TCP to see)               |
| `process.spawn`  | `child_process.exec`/`spawn`/`fork`, and `worker_threads` (the curl-pipe-sh)       |
| `process.native` | `process.dlopen` — loading a native addon (`.node`) that escapes the JS sandbox    |
| `code.eval`      | `vm.runInThisContext`/`Script`/`compileFunction` — running staged payloads         |
| `env.read`       | a dependency reading `NPM_TOKEN`, `AWS_SECRET_ACCESS_KEY`, …                       |
| `os.info`        | `os.userInfo`/`networkInterfaces`/`hostname` host profiling                        |

Each event is **attributed to the specific package** that triggered it, so you
know exactly who's misbehaving.

**What counts as sensitive** — credentials and key material, by location and by
name: `~/.ssh`, `~/.aws`, `~/.azure`, `~/.gnupg`, `~/.kube`, `~/.docker`,
`~/.config/gcloud`, `~/.config/gh` (a GitHub token in `hosts.yml`), OS credential
stores (macOS keychains, GNOME Keyring, Windows DPAPI), **crypto wallets** (geth
keystores, Electrum, Solana, NEAR, Exodus, `wallet.dat`, browser-extension
vaults — the payload of choice in recent npm compromises), `.npmrc`, `.netrc`,
`.env*`, `.git-credentials`, `.pypirc`, `*.pem`/`*.key`/`*.p12`/`*.kdbx` outside
`node_modules`, `/etc/passwd`, and `/proc/*/environ` (every env var in one read).
Matching is case-insensitive, and **listing** one of those directories counts as
reading it — `readdir('~/.ssh')` names every key on the machine without opening
one, and `readlink` says where a key really lives.

## Getting a policy without writing one

Enforcing is easy to describe and miserable to start: a real project has
dependencies that legitimately reach the network, shell out and read `.npmrc`,
and every one of them needs a rule before the first green run. So let dephawk
write the first draft from a run it watched:

```bash
npx dephawk init npm test
```

That writes `dephawk.config.js` granting exactly what happened — then
`--enforce` passes, and anything _new_ a dependency starts doing gets caught.

**Read it before you trust it.** The draft grants what the run **did**, not what
is safe: dephawk cannot tell a legitimate API call from exfiltration, so if
something malicious is already installed, its behaviour is in the file too.
Every entry carries a comment saying what produced it, and grants that hand over
open-ended power (`spawn`, `native`, `eval`) are listed at the top for review.
Calls dephawk could not attribute to a package are reported but never granted —
the only place to put them is the default bucket, which would weaken it for
everything at once.

Paths under your home directory are written as `~/...`, so the file works on
someone else's machine and in CI.

## Policies

Allow only what a package legitimately needs. dephawk looks for
`dephawk.config.js` in the working directory (or pass `--config <path>`):

```js
// dephawk.config.js
export default {
  mode: 'observe', // or 'enforce'

  // applied to any package not listed below
  default: { net: { connect: [] }, spawn: false, env: false },

  packages: {
    'image-optimizer': { spawn: true }, // it genuinely shells out
    '@sentry/node': { net: { connect: ['*.sentry.io'] }, env: ['SENTRY_DSN'] },
    bcrypt: { native: true }, // legitimately loads a native addon
  },
};
```

- `net.connect` — allowlist of hosts. `*.sentry.io` matches the apex and any
  subdomain; an exact host matches only itself. The same list gates DNS
  resolution (`net.resolve`): a host you may connect to, you may resolve.
- `spawn` — `true` to permit child processes **and** worker threads.
- `native` — `true` to permit loading native addons (`.node` via
  `process.dlopen`). Off by default; set it for packages like `bcrypt`, `sharp`.
- `eval` — `true` to permit dynamic code execution through the `vm` module. Off
  by default — most dependencies should never need it.
- `env` — `true` (any secret), `false` (no secrets), or an array of allowed
  secret var names. Non-secret vars (e.g. `NODE_ENV`) are always allowed.
- `fs` — `{ read: [...], write: [...] }` path prefixes for sensitive paths.

The `default` bucket applies to any package not listed **and** to calls dephawk
cannot attribute to anyone — so a deny-by-default `default` is what makes
laundered calls fail closed.

Your own application code is never flagged — dephawk watches dependencies, not you.

## How it works (and what it can't do)

At startup (`--import dephawk/register`) dephawk monkey-patches the sensitive
Node built-ins — `fs`, `http`/`https`/`fetch`, raw `net`/`tls`/`dgram` sockets,
`dns`, `child_process`, `worker_threads`, `process.dlopen`, `vm`, `os`, and
`process.env`. Each patched call captures a stack trace, walks it to find the
first `node_modules/<package>` frame, checks it against your policy, and records
the event. On exit it prints a summary and writes the HTML report.

**Children stay monitored.** Monitoring reaches a process tree by inheritance
(`NODE_OPTIONS`, `DEPHAWK_*`), so a dependency could once blind dephawk for a
whole subtree by spawning with those stripped out. dephawk now puts them back
into every child it lets through, and the report notes when it had to
— `node payload.js [dephawk re-attached: NODE_OPTIONS]`. The same holds for
**worker threads**, which declined monitoring through `{ execArgv: [] }` or
`{ env: {} }` until 0.4.3. See
[`docs/adr/0006`](docs/adr/0006-re-attaching-monitoring-to-children.md).

**Deferred calls still count.** A dependency cannot shed responsibility by
scheduling a built-in instead of calling it — `setTimeout(fs.readFileSync, 0,
'~/.ssh/id_rsa')`. When the stack names nobody, the call is `(unattributed)` and
held to your **default** policy rather than treated as your own code, and
dephawk separately records where the call was scheduled so the report can still
name the package that armed it. (Before 0.3 that pattern was allowed outright,
even under `--enforce` — see
[`docs/adr/0004`](docs/adr/0004-async-attribution-and-unknown-origin.md).)

**This is an honest threat model.** dephawk is a high-signal _tripwire and
policy layer_, not an unbreakable sandbox:

- Attribution uses stack traces, which a determined attacker can obscure
  (rewriting `Error.stack`, running native code). Losing a frame no longer buys
  trust, but it can still cost you the culprit's name.
- Native addons run outside the JS sandbox: dephawk flags the `.node` _load_
  (`process.native`), but what the addon does afterwards is invisible.
- `eval()` and `new Function()` are language primitives and can't be patched;
  the `vm` module — the deliberate path for staged code — is covered.
- HTTP resolves and connects internally, so one request may surface both a
  `net.resolve` and a `net.connect`; identical rows collapse in the report.
- Named imports captured before startup (`import { readFileSync } from 'fs'`)
  can slip past patching; namespace/`require` access is covered.
- `process.env` interception is best-effort; some native reads slip through.
- **The report is itself an artifact worth handling carefully.** It records what
  was touched, not contents: env var _names_ (never values), paths, hosts, and a
  spawn's full command line. Values that look like secrets are redacted
  (`--token=***`, `Bearer ***`, `ghp_***`), by name and by known token shape —
  a heuristic, so treat absolute paths, hostnames and stack frames in
  `.dephawk/report.html`, the SARIF and the job summary as sensitive anyway.

For a hardened boundary you'd combine it with OS-level isolation (containers,
`node --permission`, seccomp). dephawk's job is to make the _common_ attacks loud
and cheap to catch. That's what stops most real-world incidents. See
[`docs/adr/0002`](docs/adr/0002-attribution-strategy.md) for the full analysis.

## Programmatic API

```ts
import { buildMonitor, resolveEnvPolicy } from 'dephawk';

const monitor = buildMonitor({ policy: resolveEnvPolicy(process.env) });
monitor.start();
// … run code …
monitor.stop();
await monitor.report();
```

Every collaborator (interceptors, reporters, attributor, clock, sink) is
overridable — compose your own.

## Runtime support

Built and tested on Node 20 & 22. Bun/Deno provide most of the same built-ins;
dephawk degrades gracefully when a built-in is missing, but full coverage there
is not guaranteed.

## Roadmap

- [x] Shareable HTML report artifact (`.dephawk/report.html`)
- [x] Async config loading + host/path glob matching
- [x] `fs.write` coverage and `os.userInfo`/`networkInterfaces` interception
- [x] DNS (`net.resolve`), raw socket/TLS/UDP, native addon (`process.native`),
      `vm` code-eval (`code.eval`) and `worker_threads` interception
- [x] `postinstall` script guard (`dephawk guard` — catch install-time attacks
      before your code even runs)
- [x] CI gating: `--fail-on` exit codes and SARIF output for code scanning
- [x] A published GitHub Action, so adopting it in CI is two lines
- [ ] `--record`/`--replay` of dependency behavior for CI diffs
- [x] Policy bootstrap (`dephawk init`) — draft a policy from an observed run,
      so enforcing does not start with a wall of hand-written denials

## Releases

Published from a tagged
[release workflow](.github/workflows/release.yml) with
[npm provenance](https://docs.npmjs.com/generating-provenance-statements), and
with no publishing credential in existence: npm trusts the repository and that
workflow file directly over OIDC, so there is no token to leak. Every tarball
carries a signed attestation tying it to the commit and the workflow run that
built it. A tool that asks you to distrust your dependencies should be checkable
itself — so check it:

```bash
npm audit signatures
```

## Contributing

PRs welcome — especially new interceptors and real-world attack samples for the
test suite. See [`CONTRIBUTING.md`](./CONTRIBUTING.md).

## License

MIT
