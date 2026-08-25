$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
Write-Host "Installing Egret v12 on Windows"
python "$Root/scripts/finalize_release_candidate.py" --skip-tests
python "$Root/scripts/install_preflight.py" @args
