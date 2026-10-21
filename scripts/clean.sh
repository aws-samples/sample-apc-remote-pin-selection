#!/bin/sh
# Removes regenerable build output and caches. Keeps backend/.env.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

rm -rf \
  "$repo_root/backend/bin" \
  "$repo_root/frontend/.dart_tool" \
  "$repo_root/frontend/build" \
  "$repo_root/frontend/coverage" \
  "$repo_root/.local"

find "$repo_root" -name .DS_Store -type f -delete
find "$repo_root/backend" -type f \
  \( -name '*.test' -o -name 'coverage*.out' -o -name '*.prof' \) -delete

echo "Removed build output and caches. backend/.env was kept."
