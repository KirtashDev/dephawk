# 1. Hexagonal architecture (ports and adapters)

- Status: accepted
- Date: 2026-07-24

## Context

dephawk is a security tool. Its value depends on being **auditable** (a reviewer
can read the whole thing and trust it) and **testable** (its decisions are
provably correct). The interesting logic — "is this call sensitive? does policy
allow it? which package did it?" — is pure. The dangerous, hard-to-test part —
monkey-patching `fs`, `net`, `child_process`, `process.env` — is I/O at the edge.

If those two concerns are tangled, the pure logic can only be tested by patching
Node globals, which is slow, flaky, and leaks state between tests.

## Decision

Adopt hexagonal architecture with a strict dependency rule pointing inward:

```
adapters → application → domain
```

- **domain/** — pure. Capability vocabulary, the immutable `DhEvent`, `Policy`
  types, and `RulePolicyEngine`. No `import` of anything from Node or outer
  layers. Deterministic; tested with plain function calls.
- **application/** — the `Monitor` orchestrator and the **ports** (`EventSink`,
  `Attributor`, `Clock`, `CapabilityInterceptor`, `Reporter`, `PolicyLoader`).
  Depends only on interfaces. Tested with in-memory fakes.
- **adapters/** — the only place that touches Node built-ins. Each implements a
  port. Tested with behaviour fixtures.
- **composition/** + `register.ts`/`cli.ts` — the single composition root where
  concrete classes are wired together.

The core `CapabilityRequest`/`Verdict`/`PolicyEngine` contracts live in the
domain (not the application) so the domain owns the evaluation contract without
importing outward; `application/ports.ts` re-exports them so consumers still get
"all the ports" from one place.

## Consequences

- Domain and application reach ≥90% coverage with fast, deterministic tests and
  **zero global patching**.
- Adding a capability = adding one `CapabilityInterceptor` adapter and one entry
  in the interceptor factory. The Monitor and domain never change (OCP).
- The indirection costs a little ceremony (an interface per boundary), which is
  a good trade for a tool that must be trusted and heavily tested.
- Zero runtime dependencies: nothing in `dependencies`, so the install is small
  and reviewable end-to-end.
