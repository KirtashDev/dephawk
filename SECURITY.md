# Security policy

## What dephawk is, and what it is not

Read this before relying on dephawk to stop anything.

**dephawk is a tripwire, not a sandbox.** It works by patching the specific Node
built-ins that reach a sensitive capability — `fs`, `net`, `child_process`,
`vm`, and the rest — and checking each call against a policy. That is
detection-and-policy at named choke points, not containment. It is genuinely
useful: it makes the common supply-chain moves loud, attributes them to the
exact package, and can block them in `--enforce`. It is **not** a guarantee that
a dependency cannot do a thing.

Why it cannot be a guarantee, plainly:

- **Patching is inherently incomplete.** Node exposes a large and growing
  surface — many different APIs reach the same syscall, and new ones arrive with
  every release (`node:sqlite`, `WebAssembly`, worker threads, and more). Each
  dephawk release covers the doors known at the time; the runtime keeps adding
  doors. Closing bypasses is ongoing, not finished.
- **Native code and language intrinsics are out of reach.** A native addon runs
  outside JavaScript entirely; `eval`/`new Function` are language primitives that
  cannot be patched (see the out-of-scope list below).
- **A determined attacker who already controls a dependency has many moves.**
  dephawk raises the cost and the visibility of those moves; it does not remove
  them.

So treat dephawk as **defence in depth and high-signal detection**, alongside —
not instead of — lockfiles, `npm audit`/Socket-style scanning, least-privilege
CI credentials, and review of what you install. If you need true isolation, run
untrusted code in a real sandbox (a container, a VM, a locked-down user), and use
dephawk to see and gate what happens inside it.

That the project keeps finding and closing bypasses is the model working as
intended, and also the reason for this warning: a tool you can keep finding holes
in is not one to stake total protection on. Each fix raises the bar. None of them
make the bar a ceiling.

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub's
[private vulnerability reporting](https://github.com/KirtashDev/dephawk/security/advisories/new)
— the "Report a vulnerability" button under the repository's **Security** tab.
It goes straight to me and nobody else can read it, and it keeps the discussion
attached to the repository rather than scattered across email.

dephawk is maintained by one person, so treat response times as best-effort: I
aim to acknowledge a report within a few days. If a report turns out to be a
real bypass, the fix ships with a regression test that fails without it, and the
release notes describe what was possible — see the
[0.6.0 notes](CHANGELOG.md) for the shape of that.

## What counts as a vulnerability here

dephawk's job is to see what a dependency does at runtime and hold it to a
policy. So the interesting reports are the ones where **a dependency does
something sensitive and dephawk fails to record or block it** under a
deny-by-default policy in `--enforce`. Concretely:

- Reaching a capability through a surface dephawk does not patch (a filesystem
  read, an outbound connection, a spawn, a secret read that produces no event).
- Escaping attribution — making a call read as the application's own code, or as
  a different package, so policy waves it through.
- Tampering with dephawk itself: erasing or editing the `guard` audit log,
  stripping monitoring from a child process, disabling an interceptor.
- Anything in the report or the SARIF that leaks a secret it should have
  redacted.

A working proof of concept — a fixture package that performs the abuse, run
against the real CLI — makes a report immediately actionable. That is how most
of the bypasses fixed so far were found.

## What is out of scope

These are documented limitations, not vulnerabilities. They are stated plainly
in the README's threat model, and dephawk is a **tripwire and policy layer, not
a sandbox**:

- **Native code.** An addon loaded via `process.dlopen` runs outside the
  JavaScript surface. dephawk records the load; what the binary then does is
  invisible.
- **`eval()` and `new Function()`.** Language intrinsics, not module methods, so
  they cannot be patched. The `vm` module, `WebAssembly` and `node:inspector` —
  the deliberate paths for staged code — are covered.
- **Bindings captured before dephawk installs.** Code that runs _before_ the
  register entrypoint and squirrels away a reference to a built-in holds the
  original. A dependency cannot do this — it loads after the register — and an
  ESM dependency's `import { readFileSync } from 'node:fs'` is covered as of
  0.6.13. It applies only to something loaded ahead of dephawk, which on the
  `dephawk run`/`guard` path is nothing.
- **Freezing the `Error` globals** as non-configurable to defeat the
  stack-capture hardening. Narrower and far more conspicuous than the plain
  assignment it replaced, and accepted.
- **A malicious _application_.** dephawk watches dependencies on behalf of the
  application it runs inside. Code you wrote is trusted by design.

If you are unsure whether something is in scope, report it privately anyway. A
report that turns out to be a documented limitation costs a short reply; a real
bypass that went unreported because it looked out of scope costs a lot more.

## Supported versions

Fixes land on the latest published minor. dephawk is pre-1.0 and moves quickly —
older versions are not patched, so upgrade rather than pin.

Every release is published from a tagged workflow with
[npm provenance](https://docs.npmjs.com/generating-provenance-statements) and no
publishing credential in existence (npm trusts the repository over OIDC). You
can verify what you installed came from this repository:

```bash
npm audit signatures
```
