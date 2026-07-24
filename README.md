<div align="center">

# 🦅 dephawk

### A hawk-eyed watch on your npm dependencies.

**See — and block — what your dependencies actually do at runtime:**
reading your SSH keys, phoning home, spawning shells.

[![npm](https://img.shields.io/npm/v/dephawk.svg)](https://www.npmjs.com/package/dephawk)
[![CI](https://github.com/kellendir/dephawk/actions/workflows/ci.yml/badge.svg)](https://github.com/kellendir/dephawk/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![node](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](#)

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

```
🦅 dephawk report — 1 package touched something sensitive

  🚨  sneaky-dependency  →  read    /Users/you/.ssh/id_rsa_…
  🚨  sneaky-dependency  →  env     NPM_TOKEN
  🚨  sneaky-dependency  →  connect https://collector.dephawk-demo.invalid/exfil

  ✔️  0 other calls looked normal

  Run in enforce mode to block these →  DEPHAWK_MODE=enforce
```

That single screenshot is the pitch. If a package tries to read your keys and
phone home, the hawk spots it in the first three seconds — not after you're on the
news.

> 📺 **Demo:** `npm run demo` (observe) and `npm run demo:enforce` (block).
> _<!-- GIF of the demo goes here -->_

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

## What it watches

| Capability      | Examples caught                                                         |
| --------------- | ----------------------------------------------------------------------- |
| `fs.read`       | reading `~/.ssh`, `~/.aws`, `~/.gnupg`, `.env`, `.npmrc`, `/etc/passwd` |
| `fs.write`      | overwriting `~/.npmrc`, `authorized_keys`, other secret files           |
| `net.connect`   | `http`/`https` requests and `fetch` to unexpected hosts                 |
| `process.spawn` | `child_process.exec`/`spawn`/`fork` (the classic curl-pipe-sh)          |
| `env.read`      | a dependency reading `NPM_TOKEN`, `AWS_SECRET_ACCESS_KEY`, …            |
| `os.info`       | `os.userInfo`/`networkInterfaces`/`hostname` host profiling             |

Each event is **attributed to the specific package** that triggered it, so you
know exactly who's misbehaving.

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
  },
};
```

- `net.connect` — allowlist of hosts. `*.sentry.io` matches the apex and any
  subdomain; an exact host matches only itself.
- `spawn` — `true` to permit child processes.
- `env` — `true` (any secret), `false` (no secrets), or an array of allowed
  secret var names. Non-secret vars (e.g. `NODE_ENV`) are always allowed.
- `fs` — `{ read: [...], write: [...] }` path prefixes for sensitive paths.

Your own application code is never flagged — dephawk watches dependencies, not you.

## How it works (and what it can't do)

At startup (`--import dephawk/register`) dephawk monkey-patches the sensitive
Node built-ins — `fs`, `net`/`http`/`https`/`fetch`, `child_process`, `os`, and
`process.env`. Each patched call captures a stack trace, walks it to find the
first `node_modules/<package>` frame, checks it against your policy, and records
the event. On exit it prints a summary and writes the HTML report.

**This is an honest threat model.** dephawk is a high-signal _tripwire and
policy layer_, not an unbreakable sandbox:

- Attribution uses stack traces, which a determined attacker can obscure
  (rewriting `Error.stack`, deferring work, running native code).
- Native addons and code that bypasses the standard built-ins aren't covered.
- Named imports captured before startup (`import { readFileSync } from 'fs'`)
  can slip past patching; namespace/`require` access is covered.
- `process.env` interception is best-effort; some native reads slip through.

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
- [ ] `--record`/`--replay` of dependency behavior for CI diffs
- [ ] Baseline mode: snapshot normal behavior, alert only on _new_ capabilities
- [ ] `postinstall` script guard (catch attacks before your code even runs)

## Contributing

PRs welcome — especially new interceptors and real-world attack samples for the
test suite. See [`CONTRIBUTING.md`](./CONTRIBUTING.md).

## License

MIT
