# 7. A published GitHub Action

- Status: accepted
- Date: 2026-08-03
- Follows: [ADR 0005](0005-protecting-the-guard-audit-log.md)

## Context

Everything needed to gate a pull request already existed — `guard`, `--fail-on`,
`--sarif` — and adopting it still meant reading the README, understanding four
flags, and hand-writing a step that captures the exit code so the SARIF upload
survives a failure:

```yaml
- run: npx dephawk guard --fail-on violation --sarif dephawk.sarif npm ci
  continue-on-error: true
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: dephawk.sarif
```

That is the whole adoption funnel for a CI tool, and it leaks two things a user
should not have to know: that the findings report is written by the parent
process (so the exit code must be captured, not propagated), and that a step
which fails stops the steps after it (so the upload has to be decoupled from the
run). Both are dephawk's problems, not the user's.

The remaining question was what kind of action. A JavaScript action means
committing a bundled `dist/` of action code to the repository — a second build
output, checked in, for a project whose pitch is that its install is auditable
and has zero dependencies. A Docker action means a container build per run for a
tool that only needs Node, which every runner already has.

## Decision

A **composite action at the repository root** (`action.yml`), so the whole thing
is two lines in a workflow:

```yaml
- uses: actions/checkout@v4
- uses: KirtashDev/dephawk@v0.4.0
```

It installs nothing into the repository: the tool comes from npm through `npx`,
which is what a user would have typed anyway. `action.yml` stays declarative and
the logic lives in [`action/run.sh`](../../action/run.sh), which can be read,
shell-checked and run outside Actions — and is, by the `action` job in CI, which
points the action at the build from the current commit through the `bin` input.
No unit test reaches YAML.

Four decisions inside it are worth recording.

**The run never fails; a later step does.** `run.sh` captures dephawk's exit code
into a step output and exits 0. The SARIF upload and the job summary run next,
and only then does a final step re-exit with the captured code. This is the
`continue-on-error` dance from the README, done once, in the action, instead of
in every workflow that adopts it. It is also why the logic cannot live in a
single step: composite actions do not support `continue-on-error` on their own
steps, so the ordering has to be explicit.

**`fail-on` defaults to `blocked`, not `violation`.** With no policy file the
default bucket denies everything sensitive, and a real `npm ci` spawns processes
and reads `.npmrc` legitimately — so `violation` would fail the first build in
most repositories, on findings that are noise until a policy exists. `blocked`
cannot fire in observe mode at all, which makes the two-line form safe to add to
any repository: it reports, and it stays green. The documented path is then
`dephawk init` → commit the policy → `fail-on: violation`. A gate that cries wolf
on day one gets deleted on day two.

**Uploading to code scanning is opt-in.** It needs `security-events: write` in
the job and code scanning available on the repository; neither is guaranteed, and
a composite action cannot swallow the failure of a `uses:` step. Defaulting it on
would turn a permissions gap into a red build with an error about the uploader
rather than about dependencies. The report reaches the user anyway through the
job summary, which needs no permissions at all.

**The version comes from the action reference.** `uses: …/dephawk@v1.2.3` runs
`dephawk@1.2.3`; a branch or a SHA reference falls back to `latest`, and the
`version` input overrides either. The alternative — a default version written
into `action.yml` — is a second place to bump on every release and a silent
mismatch when someone forgets. Deriving it from `GITHUB_ACTION_REF` means the
reference the user pinned is the only source of truth.

Because a floating `v0`/`v1` tag may now be moved onto a release, the release
workflow triggers on `v*.*.*` rather than `v*`: moving `v1` must not try to
publish a version called "1".

## Consequences

Adopting dephawk in CI is `uses:` plus a checkout, and the default configuration
cannot turn a passing build red. The upgrade path to an actual gate is two
documented inputs.

Because the verdict is a separate step, a failing gate leaves everything behind
it intact: the SARIF and the HTML report are on disk, and the action's outputs
are still readable from a later `if: always()` step. The CI job asserts both
after a deliberately failed gate, since that is the case a workflow author is
most likely to depend on and least likely to test.

The action is a fourth public surface to keep honest alongside the CLI, the
`--import` entrypoint and the programmatic API: inputs are an API, and renaming
one breaks workflows silently. The CI job covers the wiring, not every input.

**Still open.** Publishing to the GitHub Marketplace is a one-time manual step on
a release in the web UI, which `gh release create` cannot do — so the release
workflow cannot own it. The action assumes Node on the runner (every
GitHub-hosted image has it) and says so with a clear error when it is missing.
