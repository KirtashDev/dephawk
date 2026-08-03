#!/usr/bin/env bash
#
# The body of dephawk's GitHub Action — see ../action.yml.
#
# It lives in a script rather than inline in the YAML so that it can be read,
# shell-checked and run outside Actions. Every input arrives through the
# environment: nothing from the workflow is interpolated into this file, so a
# workflow expression cannot inject shell here.
#
# Deliberately no `set -e`: dephawk's exit code is the payload of this step, not
# a reason to abort it. Reporting the findings and uploading the SARIF has to
# happen before the job is failed, which the caller does in a later step.
set -uo pipefail

fail() {
  echo "::error::dephawk: $1"
  exit 1
}

# Print an existing path as an absolute one.
absolute() {
  (cd "$(dirname "$1")" && printf '%s/%s\n' "$(pwd)" "$(basename "$1")")
}

# ------------------------------------------------------------------ inputs ----

case "$IN_SUBCOMMAND" in
  run | guard) ;;
  *) fail "subcommand must be 'run' or 'guard' (got '$IN_SUBCOMMAND')" ;;
esac

case "$IN_MODE" in
  observe | enforce) ;;
  *) fail "mode must be 'observe' or 'enforce' (got '$IN_MODE')" ;;
esac

case "$IN_FAIL_ON" in
  none | blocked | violation | sensitive) ;;
  *) fail "fail-on must be none, blocked, violation or sensitive (got '$IN_FAIL_ON')" ;;
esac

[ -n "$IN_COMMAND" ] || fail "command must not be empty"

# ----------------------------------------------------------------- the tool ---

if [ -n "$IN_BIN" ]; then
  # An explicit executable: a dephawk already installed on a locked-down runner,
  # or a local build when this repository tests its own action.
  read -r -a runner <<< "$IN_BIN"
else
  command -v node > /dev/null 2>&1 ||
    fail "needs Node >= 20 on the runner — add actions/setup-node before this step"

  version="$IN_VERSION"
  if [ -z "$version" ]; then
    # Self-pinning: `uses: KirtashDev/dephawk@v1.2.3` runs dephawk 1.2.3. The
    # action reference is the only source of truth for which version runs, so
    # there is no default written down here to drift out of step with releases.
    # A reference that is not a version tag (a branch, a commit SHA) has nothing
    # to pin to and falls back to the newest release.
    case "${GITHUB_ACTION_REF:-}" in
      v[0-9]*.[0-9]*.[0-9]*) version="${GITHUB_ACTION_REF#v}" ;;
      *) version="latest" ;;
    esac
  fi
  runner=(npx --yes "dephawk@$version")
fi

args=("$IN_SUBCOMMAND" "--$IN_MODE" --fail-on "$IN_FAIL_ON")
if [ -n "$IN_CONFIG" ]; then
  args+=(--config "$IN_CONFIG")
fi
if [ -n "$IN_SARIF" ]; then
  args+=(--sarif "$IN_SARIF")
fi

# `command` is a command line, so it is split the way a shell splits one, quotes
# included. It is the workflow author's own string naming the program they are
# asking dephawk to watch.
if ! eval "monitored=($IN_COMMAND)" 2> /dev/null; then
  fail "could not parse command: $IN_COMMAND"
fi

# ------------------------------------------------------------------ the run ---

output="${RUNNER_TEMP:-/tmp}/dephawk-output.txt"

echo "+ ${runner[*]} ${args[*]} ${monitored[*]}"
"${runner[@]}" "${args[@]}" "${monitored[@]}" 2>&1 | tee "$output"
code=${PIPESTATUS[0]}
echo "dephawk exited $code"

# --------------------------------------------------------------- artifacts ----

sarif_file=""
if [ -n "$IN_SARIF" ] && [ -f "$IN_SARIF" ]; then
  sarif_file="$(absolute "$IN_SARIF")"
fi

report_file=""
if [ -f .dephawk/report.html ]; then
  report_file="$(absolute .dephawk/report.html)"
fi

{
  echo "exit-code=$code"
  echo "sarif-file=$sarif_file"
  echo "report-file=$report_file"
} >> "${GITHUB_OUTPUT:-/dev/null}"

if [ "$IN_SUMMARY" = true ] && [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  esc="$(printf '\033')"
  {
    echo '## 🦅 dephawk'
    echo
    echo '```'
    # The report is the last thing dephawk writes, and the summary has a 1 MiB
    # budget an install log would happily eat — so keep the tail. Colour codes
    # are stripped because a summary is markdown, not a terminal.
    tail -n 400 "$output" | sed "s/${esc}\[[0-9;]*m//g"
    echo '```'
  } >> "$GITHUB_STEP_SUMMARY"
fi

exit 0
