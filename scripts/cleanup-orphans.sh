#!/bin/bash
# Cleanup orphaned audit directories older than 2 hours.
# Run via cron: 0 * * * * /app/scripts/cleanup-orphans.sh

WORK_DIR="${WORK_DIR:-/workdir}"
MAX_AGE_MINUTES=120

if [ -d "$WORK_DIR" ]; then
  count=$(find "$WORK_DIR" -maxdepth 1 -mindepth 1 -type d -mmin +$MAX_AGE_MINUTES | wc -l)
  if [ "$count" -gt 0 ]; then
    echo "[cleanup] Removing $count orphaned directories older than ${MAX_AGE_MINUTES}min"
    find "$WORK_DIR" -maxdepth 1 -mindepth 1 -type d -mmin +$MAX_AGE_MINUTES -exec rm -rf {} +
  fi
fi
