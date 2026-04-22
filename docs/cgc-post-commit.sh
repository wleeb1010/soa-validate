#!/usr/bin/env bash
# CodeGraphContext post-commit hook template for soa-validate.
#
# Install: cp docs/cgc-post-commit.sh .git/hooks/post-commit && chmod +x .git/hooks/post-commit
#
# Runs a forced re-index in the background after each commit so CGC
# queries stay in sync with HEAD. Logs to .git/hooks/post-commit.log.
# PYTHONIOENCODING=utf-8 works around a cgc CLI emoji-encoding crash on
# Windows (cp1252); indexing itself succeeds either way.

REPO_ROOT="$(git rev-parse --show-toplevel)"
LOG="$REPO_ROOT/.git/hooks/post-commit.log"

{
  echo "--- $(date -Iseconds) reindexing $REPO_ROOT ---"
  PYTHONIOENCODING=utf-8 cgc index --force "$REPO_ROOT" 2>&1
  echo "--- $(date -Iseconds) done ---"
} >>"$LOG" 2>&1 &

exit 0
