#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
echo "Installing Egret v12 on Linux"
python "$ROOT/scripts/finalize_release_candidate.py" --skip-tests
python "$ROOT/scripts/install_preflight.py" "$@"
