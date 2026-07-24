# 3. Async config loading across the `--import` boundary

- Status: accepted
- Date: 2026-07-24

## Context

Interceptors must be installed **before** any application code runs, which means
during evaluation of the module loaded via `node --import dephawk/register`. That
evaluation must be effectively synchronous with respect to installation — if we
`await` before patching, dependency code can run first and slip past us.

But the user's policy lives in `dephawk.config.js`, an **ESM module** that can
only be loaded with `await import()`. So we cannot load the config file inside
`register.ts` without either (a) risking a gap before installation, or (b)
relying on top-level `await` semantics that are subtle and easy to get wrong.

## Decision

**Resolve the config in the CLI parent, pass the resolved policy to the child as
JSON.**

- `dephawk run <cmd>` (the CLI) loads the config with `FileConfigPolicyLoader`
  (async `import()`), normalises it to a plain-data `Policy`, and serialises it
  into the `DEPHAWK_POLICY` environment variable. It then spawns the child with
  `--import dephawk/register` injected into `NODE_OPTIONS`.
- `register.ts` calls `resolveEnvPolicy(process.env)` — a **synchronous**
  function that parses `DEPHAWK_POLICY` and applies the `DEPHAWK_MODE` override —
  then installs interceptors immediately, with no `await` and no microtask gap.

This works because `Policy` is pure JSON-serialisable data (allowlists, booleans,
strings); no functions cross the boundary.

## Consequences

- No async config import happens on the critical path in `register.ts`;
  installation is guaranteed before app code runs.
- Config files are a **CLI feature**. Running `node --import dephawk/register`
  directly (without the CLI) honours `DEPHAWK_MODE` and any preset
  `DEPHAWK_POLICY`, but does not itself read a config file. This is documented.
- The two loaders (`FileConfigPolicyLoader` for the CLI, `EnvPolicyLoader` /
  `resolveEnvPolicy` for register) share the same defensive `normalizePolicy`, so
  malformed config degrades to the permissive policy instead of crashing a run.
