#!/usr/bin/env bash
# Point this clone at the tracked git hooks (pre-commit, commit-msg, pre-push, post-commit).
# Run once after cloning. Every hook calls tools/publiccheck.py; see its docstring for what is refused.
#   tools/install-hooks.sh              # gates only
#   tools/install-hooks.sh --autopush   # also push every commit as soon as it lands (still gated by pre-push)
set -eu
cd "$(git rev-parse --show-toplevel)"
chmod +x tools/githooks/*
git config core.hooksPath tools/githooks
if [ "${1:-}" = "--autopush" ]; then git config local-llm-mcp.autopush true; fi
auto=$(git config --bool --get local-llm-mcp.autopush 2>/dev/null || echo false)
echo "git hooks installed: core.hooksPath=tools/githooks (pre-commit, commit-msg, pre-push; autopush=$auto)"
[ -n "$(git config --get user.email || true)" ] || echo "warning: no user.email configured for this repository — commits will be refused until one is set" >&2
