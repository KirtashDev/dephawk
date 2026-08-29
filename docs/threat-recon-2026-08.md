# Threat recon — August 2026

Web recon over the 2026 npm/Node supply-chain incidents, mapped against what
dephawk already intercepts. Every gap below was checked against the code, not
assumed; the "already covered" section exists so we don't rebuild what's there.

Sources are named per finding: Microsoft Security, Snyk, Wiz, Socket, Elastic
Security Labs, StepSecurity, JFrog, GitGuardian, Datadog Security Labs, Unit 42,
Cycode, SafeDep, the Node.js July 2026 security release.

## The strategic shift — why runtime observation matters more now

npm v12 (2026-07-08) **disabled lifecycle install scripts by default**. GitHub
called install scripts the ecosystem's largest code-execution surface, and
turning them off moved the attackers rather than stopping them. Every major
2026 compromise since then triggers somewhere npm no longer runs:

- **import-time / require-time payloads** — AsyncAPI/Miasma injected its loader
  into each package's entry point (`index.js`, `src/utils.js`), so it fires the
  moment a build tool `require()`s the module. `npm install --ignore-scripts`
  does nothing. node-ipc 9.1.6/9.2.3/12.0.1 shipped an ~80 KB stealer inside the
  CommonJS bundle itself. jscrambler moved execution to import/CLI _specifically_
  to defeat `--ignore-scripts`.
- **`binding.gyp` command substitution** ("Phantom Gyp") — a 157-byte
  `binding.gyp` with `"<!(node index.js > /dev/null 2>&1 && echo stub.c)"` makes
  `node-gyp rebuild` execute the payload during a native-addon build. No
  lifecycle script involved.
- **editor / AI-agent hooks** — `.vscode/tasks.json` (`runOn: folderOpen`) and
  `.claude/settings.json` (`SessionStart`), planted by the keyv/ChainDrop worm.
  Opening the repo is enough; no install at all.

A scanner that asks "does this package have a postinstall?" is now blind to the
majority of live payload triggers. A runtime tripwire is not. This is worth
saying plainly in the README and on the site.

Second theme, equally important: **valid provenance on malware**. Both the
AsyncAPI and keyv compromises put malicious source in the tagged commit, so the
project's own GitHub Actions release workflow built and cryptographically
attested the malicious tarball. Sigstore/SLSA provenance was genuine. Signature
verification cannot see behaviour.

## Already covered — do not rebuild

Checked against the source; each of these fires today.

| 2026 technique                                                                                            | Where dephawk catches it                                            |
| --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| Shell-rc persistence (`.zshrc`, `.bashrc`, `.bash_profile`) — Miasma, Bitwarden CLI, TrapDoor             | `PERSISTENCE_BASENAMES`, `src/domain/sensitivity.ts:158`            |
| Browser credential theft (`Login Data`, `Local State`, `key4.db`, `cookies.sqlite`) — undicy-http, mastra | `SENSITIVE_BASENAMES`, `src/domain/sensitivity.ts:109`              |
| Crypto-wallet + extension-vault theft (MetaMask et al.) — mastra, undicy-http                             | `SENSITIVE_DIRECTORIES`, `src/domain/sensitivity.ts:60`             |
| Kubernetes service-account token, `/run/secrets` — keyv worm                                              | `src/domain/sensitivity.ts:45`                                      |
| IMDS / ECS / EKS metadata SSRF, incl. `inet_aton` spellings — vpmdhaj                                     | `METADATA_IPS` + `normalizeIpv4`, `src/domain/threat.ts:50`         |
| SSRF via a custom resolver, bound to the resolved IP                                                      | `socket.interceptor.ts` `guardResolver` (0.9.0)                     |
| Editor / AI-agent hook persistence — keyv, Phantom Gyp, Fake Font                                         | `EDITOR_HOOK_PATTERNS`, `src/domain/threat.ts`                      |
| Alt-runtime escape (standalone Bun/Deno stage 2) — keyv, ChainDrop, Nx Console                            | `isAltRuntimeEscape` (0.13.0)                                       |
| TLS teardown via `process.env` — mastra                                                                   | `env.write` capability + `isTlsVerificationDisabled` (0.13.0)       |
| OS service persistence (systemd/launchd/cron/Run key) — Miasma, mastra, TrapDoor                          | `isServicePersistencePath` / `isServicePersistenceCommand` (0.13.0) |
| AI-assistant credential theft — jscrambler, keyv collector                                                | `AI_ASSISTANT_DIRECTORIES`, `isAiCredentialPath` (0.13.0)           |
| CI-workflow + git-hook persistence — Shai-Hulud                                                           | `isCiWorkflowPath` / `isGitHookPath`                                |
| Worm self-publish — ChainDrop                                                                             | `isRegistryPublish`, `src/domain/threat.ts:411`                     |
| Dead-drop C2 over IPFS gateways and Ethereum RPC — ChainDrop, AsyncAPI                                    | `DEAD_DROP_HOSTS`, `src/domain/threat.ts:168`                       |
| `dns.Resolver` class instances (not just top-level `dns.*`)                                               | `dns.interceptor.ts:78` patches `Resolver.prototype`                |
| Read-secret-then-egress chains                                                                            | `detectExfilChains`                                                 |

## Gaps — prioritised backlog

Ranked by impact × reproducibility × low false-positive rate, with a bias toward
gaps whose hook point already exists.

### Tier 1 — **shipped in 0.13.0**

All four landed, plus the Tier 3 host-list additions. Each has a unit repro and,
for the first three, an end-to-end one (`test/e2e/alt-runtime-escape`,
`env-write-guard`, `service-persistence`). One thing the recon did not predict:
`service-persistence` was complete in the domain — predicate, gloss,
`detectTechnique` — and still invisible end to end, because the fs interceptor's
"is this write lexically mundane?" pre-filter listed the CI/git-hook/editor-hook
predicates by hand and returned early on everything else. The three copies of
that list now go through one `isPersistenceWrite`, so a future technique reaches
the filter by itself. **Any new fs.write technique must be added there, not only
to `detectTechnique`.**

**1. `alt-runtime-escape` — a dependency spawning Bun/Deno to escape Node** ✅

The defining evasion of 2026. keyv/cacheable, ChainDrop, vpmdhaj, Phantom Gyp
and the Nx Console backdoor all download the standalone **Bun 1.3.13** release
from GitHub and run the second stage under it — Snyk and Wiz both state the
purpose explicitly: _sidestep Node-level instrumentation_. dephawk sees the
dropper's `spawn` and calls it nothing.

- Hook point: exists. `describeSpawn` already produces the command string;
  this is a pure-domain predicate alongside `isRegistryPublish`
  (`src/domain/threat.ts:411`), wired into `detectTechnique('process.spawn', …)`.
- Match: a `bun`/`deno`/`node` executable resolved from a temp, cache or
  freshly-downloaded path, or a bare `bun`/`deno` spawned by a _dependency_.
- False positives: low. A project that genuinely uses Bun spawns it from
  application origin, which dephawk already distinguishes.
- Why it matters most: in enforce mode this **stops the worm at stage 1**,
  before the credential collector ever runs. It is also the cleanest story
  dephawk has — the technique designed to defeat runtime monitoring, caught by
  runtime monitoring.
- Repro: a fixture package that `spawn`s `./.cache/bun install` from its module
  body.

**2. `env.write` capability — TLS teardown and sandbox spoofing** ✅

`process.env` writes are currently a **silent hole**: the Proxy's `set` trap
(`env.interceptor.ts:129`) and `defineProperty` trap (`:156`) forward to the
real environment and record nothing.

- mastra (2026-06, Sapphire Sleet) sets `NODE_TLS_REJECT_UNAUTHORIZED='0'` to
  disable certificate validation process-wide.
- vpmdhaj (2026-05) rewrites `process.env.CI = 'false'` to mislead build-aware
  code paths after using `CI` for sandbox detection.
- Self-defense angle: the same trap is how a dependency could scrub
  `NODE_OPTIONS` / `DEPHAWK_*` in-process. `child-process.interceptor.ts`
  re-attaches monitoring for _children_, but nothing watches the in-process
  write.
- Scope it to a denylist of security-relevant names
  (`NODE_TLS_REJECT_UNAUTHORIZED`, `NODE_OPTIONS`, `NODE_EXTRA_CA_CERTS`,
  `DEPHAWK_*`, `CI`) rather than recording every write — that keeps FP at zero
  and the hot path clean.
- New technique: `tls-verification-disabled`. Near-zero FP, high severity.

**3. `service-persistence` — systemd / LaunchAgent / Run key / cron** ✅

`isPersistenceTarget` (`sensitivity.ts:271`) covers shell rc files only. The
2026 campaigns overwhelmingly use the OS service managers instead:

- Miasma: `miasma-monitor.service` (systemd user unit) + `HKCU\…\Run`.
- mastra: LaunchAgent plist, HKCU Run key, systemd user unit with 5s restart.
- keyv worm: `gh-token-monitor` as `.plist` / `.service` — a _token death watch_
  that fires when the stolen credential stops working, surviving rotation.
- TrapDoor: cron jobs, systemd services, SSH `authorized_keys`.

Two halves: path patterns (`~/.config/systemd/user/*.service`,
`~/Library/LaunchAgents/*.plist`, `/etc/cron.d/*`, `~/.ssh/authorized_keys`) and
spawn-side verbs (`launchctl load`, `systemctl --user enable`, `crontab -`,
`reg add …\Run`, `schtasks /create`). Near-zero FP from a dependency.

**4. `ai-credential-theft` — reading the AI assistants' credential stores** ✅

dephawk guards _writes_ to `.claude/settings.json`. It does not treat _reads_ of
`~/.claude/.credentials.json`, `~/.codex/auth.json`, `~/.cursor/`, Windsurf's
config, `~/.config/github-copilot/`, `~/.gemini/` or
`~/Library/Application Support/Claude/` as sensitive.

jscrambler (2026-07) reached into exactly these; the keyv collector scans 300+
credential patterns including Anthropic/Claude/Codex/Cursor/OpenAI/Gemini. This
is a list addition to `SENSITIVE_DIRECTORIES` / `SENSITIVE_BASENAMES`, near-zero
FP, and squarely on the AI-agent-security positioning.

### Tier 2 — **shipped in 0.14.0**

All four landed. Two notes worth keeping:

- `local-service-pivot` needs loopback _names_ (`localhost`), and those are
  resolved inside the pivot check rather than in `isInternalTarget`.
  `isInternalTarget` is IP-only by contract and also decides whether the SSRF
  resolver guard bothers wrapping a dependency-supplied `lookup` — it skips a
  host that is already an internal literal. Teaching it `localhost` would let an
  allowlisted `localhost` plus a custom `lookup` redirect somewhere else
  unwatched. **Do not widen `isInternalTarget`.**
- `node:trace_events` cannot be loaded eagerly:
  `require('node:trace_events')` _throws_ inside a worker thread, and an
  unguarded load took dephawk's whole register down with it, leaving every worker
  unmonitored. Guarded now. The unit tests were green; the eval-worker e2e caught
  it. Second time in two releases that only an end-to-end repro found a real
  regression.

### Tier 2 — original notes

**5. `detached-process`** — `describeSpawn` (`child-process.interceptor.ts:267`)
records the command and args and **drops the options object entirely**, so
`{ detached: true, stdio: 'ignore', windowsHide: true }` followed by `.unref()`
is invisible. That triad is the "outlive the installer" signature of AsyncAPI,
the moika 45-package campaign, and mastra. Same shape as the 0.7.x `open()`
flags work: make the detail options-aware. FP low-medium.

**6. `local-service-pivot` + the Docker socket** — the 36 Strapi packages probed
a locally reachable Redis (`INFO`, `DBSIZE`, `KEYS`), injected a crontab through
it, then went at PostgreSQL directly with hardcoded credentials. dephawk records
`net.connect 127.0.0.1:6379` and names nothing. Add well-known local infra ports
(6379, 5432, 3306, 27017, 2375/2376, 8500, 2379, 10250) as a named technique.
Separately, `/var/run/docker.sock` is **not** in `SENSITIVE_DIRECTORIES` (only
`~/.docker` is) and writing to it is a container escape. Keep the DB ports
observe-only — an app's own dependency legitimately connects to Redis.

**7. `manifest-tamper`** — ChainDrop's propagation step downloads each victim
package's tarball, **rewrites its `package.json` to inject a `preinstall` hook**,
bumps the patch version and republishes: 444 packages / 2,212 versions in under
four hours. dephawk catches the second half (`registry-publish`) but not the
first. Scope to writes under `node_modules/**/package.json` — near-zero FP. The
root `package.json` stays out, as the earlier backlog concluded (`npm version`
and changesets write it legitimately).

**8. `dns-tunnel-exfil` + `resolver.setServers`** — node-ipc 2026 globs 90+
credential categories, gzips them, splits the archive into base64 chunks sized
to DNS labels, and exfiltrates over TXT queries — pointing its own
`dns.Resolver` at 1.1.1.1/8.8.8.8 so host-level DNS monitoring never sees the
traffic. The Flooding Dropper (~1,033 packages) downloads its second stage the
same way, as numbered TXT records.

`setServers` is **not** in `DNS_METHODS` (`dns.interceptor.ts:21-38`), so the
resolver redirect is unrecorded — recording it is trivial and near-zero FP, and
should land on its own. The label-entropy heuristic is the FP-prone half (DKIM,
ACME challenges and CDN hashes all look like tunnels), so gate it on _many
unique long labels under one apex_, never a single query.

### Tier 3 — **shipped in 0.13.0** (list extensions, cheap, same PR)

Add to `DEAD_DROP_HOSTS` (`threat.ts:168`):

- Ephemeral tunnels and serverless relays: `workers.dev` (Flooding Dropper,
  ~1,033 packages), `ngrok-free.app`, `ngrok.io`, `trycloudflare.com`,
  `webhook.site`, `loca.lt`, `serveo.net`, `pipedream.net`, `deno.dev`.
- More chains, since the dead drop has clearly generalised beyond Ethereum:
  Solana (`api.mainnet-beta.solana.com` — GlassWorm encodes C2 in transaction
  memo fields), Internet Computer (`ic0.app`, `icp0.io` — CanisterWorm is the
  first npm malware to anchor C2 in an ICP canister), `getblock.io`.
- Nostr relays (`relay.damus.io`, `nos.lol`, `relay.snort.social`) — AsyncAPI's
  Miasma keeps one of four fallback C2 channels over Nostr, via WebSocket.

Also worth noting for the glossary: GlassWorm additionally used **Google
Calendar event titles** as a Base64 dead drop, and Shai-Hulud exfiltrates by
creating **fresh repositories under the victim's own GitHub account** — traffic
to `api.github.com` with a legitimate token, indistinguishable from normal
developer activity by host alone. The latter is only reachable through the
exfil-chain signal (secret read → egress), not a host list.

### Tier 4 — **shipped in 0.14.0** (self-audit, prompted by Node's own CVE)

Outcome: `pathMatches` and `examinePackage`'s sandbox filter were **already**
boundary-correct — both append the separator before the prefix test — and now
have sibling-prefix repros saying so. `protectedPathAffectedBy` was sibling-safe
but one-directional (file + ancestors, never a path _inside_ a protected path);
fixed, though every protected path is a file today, so it is a guarantee for the
next one rather than a live fix. `node:trace_events` is covered.

### Tier 4 — original notes

**10. Prefix-boundary containment (the CVE-2026-58043 class)**

Node's July 2026 release fixed the Permission Model over-granting filesystem
access because its radix tree matched a granted `/home/app/data` against a
never-allowlisted sibling `/home/app/data-secrets` that merely shared the string
prefix (HIGH). Two sibling bypasses shipped in the same release: `process.report`
(CVE-2026-58039) and `trace_events` (CVE-2026-56847) both write outside
`--allow-fs-write`.

dephawk does the same _shape_ of matching in several places and should be
audited for the sibling-prefix case in **both** directions — over-granting
(treating `data-secrets` as allowed) and under-detecting (a sandbox filter that
swallows an event it should have kept):

- `protectedPathAffectedBy` (`protected-path.ts:26`) — checks
  `candidate.startsWith(`${path}/`)` in one direction only.
- `examinePackage`'s "inside the sandbox" filter in
  `src/composition/examine-package.ts`.
- Any allowlist path matching in the policy engine.

Each site deserves its own repro test with a sibling-prefix path. Related minor
item: `node:trace_events` (`createTracing().enable()`) is an fs-write sink that
the process-memory interceptor does not appear to cover.

## Out of scope — deliberately

Recorded so they don't get re-proposed:

- **Node core CVEs in the HTTP stack** (CVE-2026-58044 header-truncation request
  smuggling, the HTTP/2 pair, the HTTPS Agent mTLS reuse pair) and the undici
  `Set-Cookie` percent-decoding injection (CVE-2026-9679). These are
  vulnerabilities _in_ a dependency, which is SCA/CVE territory — dephawk
  observes what a dependency _does_, not which flawed version it is.
- **Open VSX / VS Code marketplace worms** (77 evil-twin extensions, the Nx
  Console backdoor). The payload ships inside an IDE extension and runs under
  the extension host, not the project's dependency graph.
- **Node SEA-packaged malware** (Stealit) — a distribution format for standalone
  binaries, unrelated to a project's dependencies.
- **Provenance abuse** — not observable at runtime, and the point cuts in
  dephawk's favour rhetorically rather than technically.
- **Rust `build.rs` implants** — different ecosystem; kept only because the
  persistence trio (LaunchAgent / systemd unit / Run key) matches gap 3.

## Suggested release shape

- **0.13.0** — ✅ shipped. Tier 1 (`alt-runtime-escape`, `env.write` +
  `tls-verification-disabled`, `service-persistence`, `ai-credential-theft`) plus
  the Tier 3 host-list additions. Four named techniques, all reproduce-first,
  all near-zero FP. This is a strong release note on its own: it covers the exact
  moves of the keyv/ChainDrop worm, Miasma, mastra and jscrambler.
- **0.13.x / 0.14.0** — ✅ shipped. Tier 2 landed together rather than one PR
  each: they share `threat.ts` and stacking four PRs read worse than four
  reviewable commits.
- **0.14.0** — ✅ Tier 4 containment audit, in the same release.
- **Separate hardening PR** — ✅ Tier 4, with a repro test per containment site.

**The backlog is now empty.** The next recon should start from what has changed
since 2026-08-28 rather than from this file.
