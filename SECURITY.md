# Security policy

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
- **Bindings captured before dephawk installs.** A named import
  (`import { readFileSync } from 'node:fs'`) resolved before the register
  entrypoint runs holds a reference to the original.
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
