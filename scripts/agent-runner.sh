#!/usr/bin/env bash
set -Eeuo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$project_dir"
command -v codex >/dev/null || { echo 'codex is not installed or not in PATH' >&2; exit 1; }
command -v flock >/dev/null || { echo 'flock is required' >&2; exit 1; }
command -v timeout >/dev/null || { echo 'timeout is required' >&2; exit 1; }
if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
  echo 'Working tree has changes; refusing an unattended run.' >&2
  exit 1
fi
mkdir -p data/agent-runner
chmod 700 data/agent-runner
exec 9>data/agent-runner/runner.lock
flock -n 9 || { echo 'An agent run is already in progress.' >&2; exit 1; }
log="data/agent-runner/$(date -u +%Y%m%dT%H%M%SZ)-$$.log"
umask 077
printf 'Starting bounded run; log: %s\n' "$log"
timeout --signal=TERM --kill-after=30s 30m codex exec --sandbox workspace-write --cd "$project_dir" - \
  >"$log" 2>&1 <<'PROMPT'
Read AGENTS.md, PROJECT_PLAN.md, STATE.md and git status. Advance the highest-priority
unfinished task by one small, testable increment. Preserve the user's changes. Write and
run meaningful tests and lint, update documentation and STATE.md with accurate progress
and blockers. Do not claim untested work is complete. Do not publish, push, change GitHub,
send messages, install system packages, access unrelated projects, modify scheduler or
runner configuration, or spend money. Do not disable security or sandbox controls. Stop
when blocked, when tests fail without an immediate fix, or after one increment. Leave a
clear report. Commit only if all checks pass and permissions allow it; otherwise leave
changes for review. Do not start or schedule further agents.
PROMPT
