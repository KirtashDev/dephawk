# Contributing to dephawk

Thanks for helping make supply-chain attacks loud and cheap to catch. PRs are
especially welcome for **new interceptors** and **real-world attack samples** for
the test suite.

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
  cli.ts         the `dephawk run` CLI
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
