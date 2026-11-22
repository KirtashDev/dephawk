# Threat recon — 2026-11

Picks up where [`threat-recon-2026-08.md`](threat-recon-2026-08.md) closed its
backlog: what changed in npm supply-chain attacks between 2026-08-28 and
2026-11-22, checked against what dephawk 0.14.0 actually does — every gap below
was reproduced against the published 0.14.0 build before anything was written.

## Campaigns in the window

| When        | Campaign                                                         | Runtime moves that matter here                                                                                                                                                                                                                                                                                                |
| ----------- | ---------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 2026-08-28  | `@7nohe/openapi-react-query-codegen` (Mini Shai-Hulud, ~150k/wk) | `binding.gyp` → `preinstall`; XOR loader writes an AES-GCM payload to a temp file, runs it, deletes it; detached relaunch; AI-agent session hooks; `/proc` memory scraping; exfil to attacker GitHub repos                                                                                                                    |
| 2026-09-07  | Shai-Hulud payload returns after 111 days                        | Identical hash got past npm's publish-time scanning; `bun run index.js` from `preinstall`; `.vscode/tasks.json` + `.claude/settings.json`                                                                                                                                                                                     |
| 2026-09     | `indexed-btree` + 9 siblings (Checkmarx)                         | **No install script at all** — loader inside `BTree.prototype.set()`, fires when the app calls it; host profiling via `os`; exfil to hardcoded **Slack + Telegram**; stage 2 from a **Sepolia** contract (X25519 + AES); self-deleting on command                                                                             |
| 2026-09     | Signed `node.exe` as a LOLBin (Symantec)                         | A trusted, signed Node used as the malware's interpreter; Run-key persistence; blockchain-RPC C2                                                                                                                                                                                                                              |
| 2026-10-08  | Tensorlake compromise (Shai-Hulud family)                        | Same toolchain                                                                                                                                                                                                                                                                                                                |
| 2026-10-19… | "testmetest" worm, 42 armed GitHub repos (JFrog/SafeDep)         | Miasma/Phantom Gyp code + Mini Shai-Hulud's **token-revocation wiper** (`rm -rf ~/` once the stolen token returns 40x); hooks for Claude, Gemini, Cursor, VS Code; **12.9–13.7 MB polymorphic wrappers** to dodge GitHub code search; native add-on loader; CI/sandbox/debugger checks; forks + detaches a hard-coded command |
| 2026-11-15  | keyv/cacheable again, valid provenance                           | ChainDrop toolchain                                                                                                                                                                                                                                                                                                           |

Carried forward from the 2026-08 window and still not named by 0.14: ChainDrop's
**OIDC → npm trusted-publishing exchange** with genuine Sigstore provenance, the
TanStack chain's **Session-network** exfil (`getsession.org`) and `catbox.moe`
second stage, and TrapDoor's **zero-width instructions in `CLAUDE.md` /
`.cursorrules`**.

## What 0.14.0 did with them

Reproduced with one fixture dependency under `dephawk run` (observe) and the
SARIF output:

| Move                                                                              | 0.14.0                                               |
| --------------------------------------------------------------------------------- | ---------------------------------------------------- |
| `fs.rmSync(os.homedir(), { recursive: true })`                                    | **no event — home directory deleted, report silent** |
| write `CLAUDE.md`, `AGENTS.md`, `.cursorrules`, `.github/copilot-instructions.md` | **no event**                                         |
| write `.mcp.json`, `.vscode/mcp.json`                                             | **no event**                                         |
| write `~/.gemini/settings.json`                                                   | recorded as a sensitive write, not named             |
| `sh -c 'rm -rf ~/'`                                                               | recorded as a spawn, not named                       |
| read `ACTIONS_ID_TOKEN_REQUEST_URL`                                               | recorded (name contains `TOKEN`), never named        |
| read `CI_JOB_JWT_V2`, `SYSTEM_OIDCREQUESTURI`                                     | **no event** — not secret-shaped by name             |
| fetch `…/-/npm/v1/oidc/token/exchange/…`                                          | recorded as a connect, not named                     |
| `hooks.slack.com`, `getsession.org`, `catbox.moe`, Sepolia RPC                    | recorded as connects, not named                      |

## Tier 1 — shipped on this branch

All reproduce-first, all with a unit test, a `technique-coverage` fixture
through the real interceptor, and an e2e through the CLI in enforce mode
(`test/e2e/recon-2026-11.e2e.test.ts`, which fails on 0.14.0).

1. **`destructive-wipe`.** `isWipeTarget` (home dirs, their parent, `/`, the
   Windows equivalents — lexical, never anything _inside_ a home) wired into the
   fs pre-filter, so the call is finally recorded and, under enforce, refused.
   `isWipeCommand` covers the shell form (`rm -rf ~/`, `$HOME`, `Remove-Item
-Recurse $env:USERPROFILE`, `rd /s /q %USERPROFILE%`), tokenised so wrapping
   and flag order don't matter.
2. **`agent-instruction-tamper`.** `CLAUDE.md`/`CLAUDE.local.md`/`AGENTS.md`/
   `GEMINI.md`, `.cursorrules`/`.windsurfrules`/`.clinerules`, `.cursor/rules`,
   `.windsurf/rules`, Copilot's instructions and prompt files, and
   `.claude/{commands,agents,skills}`. Excludes `node_modules` (a package's own
   CLAUDE.md is documentation). Joins `isPersistenceWrite`, so the pre-filter
   sees it.
3. **`editor-hook-persistence`, widened** to every agent's MCP/hook config:
   `.mcp.json`, `~/.claude.json`, `.vscode/mcp.json`, `.gemini/settings.json`,
   `.codex/config.toml`, `.cursor/hooks.json`, Amazon Q, Kiro.
4. **`ci-oidc-token-theft`.** GitHub's OIDC request pair and
   `ACTIONS_RUNTIME_TOKEN`, GitLab job JWTs, Azure's `SYSTEM_OIDCREQUESTURI` —
   added to the env interceptor's pre-filter, since the last two are not
   secret-shaped by name — plus `net.connect` to npm's trusted-publishing exchange. The gloss
   says plainly that release tooling legitimately does this.
5. **`dead-drop-c2` hosts**: `hooks.slack.com`, `getsession.org`, `catbox.moe`,
   `sepolia.org`.

## Tier 2 — next, each needs a decision first

6. **Refuse a home wipe even in observe mode.** Observe promises to block
   nothing, and the one exception today is the audit sink (ADR 0005). A home
   wipe is the other thing that cannot be undone and that no dependency does
   legitimately. Proposal: a second mandatory refusal, same mechanism as the
   sink, with an ADR. Needs the maintainer's call because it changes what
   "observe" means.
7. **`provenance-forgery`** — a dependency reaching `fulcio.sigstore.dev` /
   `rekor.sigstore.dev` (ChainDrop signed its poisoned tarball with a fresh
   Fulcio cert). Cheap, but the npm CLI does the same during
   `npm publish --provenance`, so it needs origin-gating checked against
   `guard npm publish` first.
8. **`registry-enumeration`** — `registry.npmjs.org/-/v1/search?text=maintainer:`
   is the TanStack worm finding every package to republish. Needs the URL path
   in the detail (fetch has it; raw `https.request` with an options object only
   has `path`, which `describeHttp` keeps).
9. **Drop-run-delete** — write to a temp dir, spawn it, unlink it (the
   openapi-react-query-codegen loader). A cross-event detector in the style of
   `detectExfilChains`: same package, `fs.write` under tmp → `process.spawn`
   naming that path → `fs.write` (unlink) of it. Temp writes are mundane today,
   so the pre-filter would need a cheap "under tmpdir and executable-looking"
   case.
10. **Agent identity forgery** — commits authored as
    `claude <claude@users.noreply.github.com>`. Spawn-side
    (`git -c user.email=…`, `GIT_AUTHOR_EMAIL` env write). Low cost; low value
    until someone is matching on it.

## Tier 3 — research, not code yet

- **Anti-analysis gates** (Russian-locale exit, <4 CPUs, EDR process/path
  probes, CI/container/debugger checks). Each probe alone is ordinary; the
  signal is a dependency doing several and then _exiting_. Risky FP profile —
  needs a corpus before a rule.
- **Runtime-only triggers** (`indexed-btree`). Not a gap — dephawk is a runtime
  monitor, which is exactly why this one is caught when it fires — but worth a
  README line: npm v12 turning scripts off does not help against it, dephawk
  does.

## Out of scope — deliberately

- **12–13 MB polymorphic wrappers.** A static-scanner evasion; dephawk never
  reads the source.
- **Signed `node.exe` as a LOLBin.** Host EDR territory — outside any project's
  dependency graph.
- **Native add-on loaders.** Already `process.native`; what the add-on then does
  is below JS and is a documented limitation.

## Workstreams opened alongside this recon

The maintainer asked for two further directions in the same pass. Recorded here
so the plan lives next to the evidence that motivated it.

### Bun / Deno

The 2026 worms run stage 2 under Bun _to escape Node instrumentation_; 0.13's
`alt-runtime-escape` names and refuses the spawn, but a project that _is_ on Bun
or Deno gets no coverage. Plan:

1. **Inventory**: run the existing interceptor unit suite under `bun test` and
   `deno test --allow-all` (both have node-compat `fs`, `child_process`, `net`,
   `dns`, `http`) to get the real pass/fail map, rather than guessing.
2. **Entry point**: Bun loads `--preload`; Deno has no preload, so the entry is
   a wrapper module (`deno run -A npm:dephawk/deno ./app.ts`) that installs
   interceptors and then dynamic-imports the target.
3. **Attribution** is the hard part: Bun's `Error.stack` frames and Deno's
   `file://`/`npm:` specifiers differ from V8-in-Node; the stack attributor
   needs a per-runtime frame parser behind the existing port.
4. **Deno's own permission model** is a better enforcement layer than ours there;
   dephawk's value on Deno is _attribution_ (which package asked), so enforce
   could map a policy to `--allow-*` flags instead of interception.
5. CI matrix: add Bun and Deno jobs, observe-only at first, with a documented
   coverage table generated from the inventory.

### More AI agents

Today: an MCP server any client can use, and `dephawk hooks install` for Claude
Code only. Plan:

1. ✅ **shipped on this branch.** **`dephawk hooks install --agent <claude|cursor|gemini|codex>`**: Cursor's
   `hooks.json` (`beforeShellExecution`), Gemini CLI's `settings.json` hooks and
   Codex's approval policy each offer a pre-command hook that can rewrite or
   refuse `npm install`; same routing logic as the Claude hook.
2. **MCP: `audit_lockfile_diff`** — given a base ref, audit only the packages a
   PR adds or bumps, which is what an agent actually needs before it says
   "dependencies updated".
3. ✅ **covered by the dependency side** (`.codex/hooks.json` added; every other file was already in the list). **Self-protection**: this recon's `agent-instruction-tamper` and widened MCP
   config list are the same surface seen from the attacker's side — the
   guardrail dephawk installs is itself one of those files, so `hooks install`
   should register it as a protected path.
