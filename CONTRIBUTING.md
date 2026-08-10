# Contributing to dephawk

dephawk is written and maintained by one person — [Alberto
(KirtashDev)](https://github.com/KirtashDev). There is no team and no support
rota behind it, which is worth knowing before you spend an evening on a change:
I answer when I can, not on a schedule.

That said, the door is open, and two things are genuinely valuable:

- **Security reports.** A tool that tells you to distrust your dependencies has
  to be checkable itself. If you find a way past dephawk, that is the most
  useful thing you can send — see [`SECURITY.md`](./SECURITY.md) for how to
  report it privately.
- **Real-world attack samples.** A fixture reproducing something a published
  package actually did is worth more than a feature request.

For anything larger than a bug fix, open an issue before writing code, so
neither of us discovers a disagreement about the design at review time.

If dephawk saved you an incident, you can also [buy me a
coffee](https://buymeacoffee.com/kirtashDev). Entirely optional, and it buys no
priority over anyone else's issue.

## Setup

```bash
npm install
npm run build
npm test
```

Node **>= 20** is required.

## Project layout

dephawk uses hexagonal architecture (see [`docs/adr/0001`](docs/adr/0001-hexagonal-architecture.md)).
The dependency rule points inward: `adapters → application → domain`.

```
src/
  domain/        pure logic (no Node). policy engine, sensitivity, types
  application/   Monitor orchestrator + ports (interfaces)
  adapters/      the only place that touches Node built-ins
    interceptors/  one adapter per capability
    reporting/     console + HTML reporters
    config/        policy loading
  composition/   the wiring (composition root)
  register.ts    the --import entrypoint
  cli.ts         the `dephawk run` / `dephawk guard` CLI
action.yml       the GitHub Action (composite; must stay at the repo root)
action/run.sh    its body, so the logic is readable and runnable outside Actions
```

## The rules that keep this trustworthy

- **Zero runtime dependencies.** `dependencies` stays empty. It's a security
  tool; the whole install must be auditable.
- **No Node in domain/application.** Those layers must never import `node:*`.
  If you need I/O, put it behind a port and implement it in an adapter.
- **Everything typed.** `strict` + `noUncheckedIndexedAccess` +
  `exactOptionalPropertyTypes`. `any` is allowed only inside adapters, at the
  monkey-patch boundary, and must be localised.
- **Honest threat model.** Never describe dephawk as a sandbox or claim total
  isolation. It's a tripwire + policy layer.

## Adding a new interceptor

1. Write a behaviour fixture test first (`test/adapters/interceptors/…`): prove
   it catches the abuse **and** ignores legitimate use. Stub real network/spawn
   so tests never open sockets or start processes.
2. Implement a `CapabilityInterceptor` in `src/adapters/interceptors/`. Use the
   shared `support.ts` helpers (`patchMethod`, `captureStack`, `report`,
   `restorer`). Restore originals on `dispose`.
3. Register it in `src/adapters/interceptors/index.ts`. Nothing in the core
   changes.

## Changing the GitHub Action

`action.yml`'s inputs are a public API: renaming one breaks other people's
workflows silently. The `action` job in CI runs the action against the build from
the current commit (via the `bin` input), which is the only test that covers the
YAML and the shell — run it by pushing, and keep it green. Reasoning behind the
defaults is in
[`docs/adr/0007`](docs/adr/0007-a-published-github-action.md).

Two notes on releasing it:

- **The Marketplace is deliberately unused.** Listing the action there means
  accepting the GitHub Developer Agreement, whose §9(c) makes the developer
  indemnify GitHub for loss or disclosure of data caused by their product —
  which is precisely the failure mode of a tool that reads a report full of
  secrets. `uses: KirtashDev/dephawk@v0.6.0` works without it, so there is
  nothing lost. (It would be a checkbox on the release in the web UI, which
  `gh release create` cannot set anyway.)
- **The floating tag.** If you keep a `v0`/`v1` tag pointing at the newest
  release, move it by hand. The release workflow deliberately triggers on
  `v*.*.*` so moving it does not attempt a publish.

The action does not pin a dephawk version — it derives one from its own
reference — so there is nothing to bump here when you release.

## Before you push

```bash
npm run typecheck
npm run lint
npm run format:check
npm run build
npm run test:coverage
```

Coverage must stay ≥ 90% in `domain` and `application`. Commit messages follow
[Conventional Commits](https://www.conventionalcommits.org/).

## Safety of test/demo attack samples

Attack samples must **simulate**, never exfiltrate: use fake filenames,
non-resolvable `.invalid` hosts, and env reads that go nowhere. See
`examples/demo/node_modules/sneaky-dependency` for the pattern.
