# Starts the AegisFlow API locally in mock mode (no external services needed).
# Usage:  .\run.ps1
$ErrorActionPreference = "Stop"

Set-Location -Path (Join-Path $PSScriptRoot "backend")

if (-not (Test-Path ".venv")) {
    Write-Host "Creating virtual environment..." -ForegroundColor Cyan
    python -m venv .venv
    .\.venv\Scripts\python.exe -m pip install --upgrade pip | Out-Null
    .\.venv\Scripts\python.exe -m pip install -e ".[dev]"
}

$env:AEGIS_ENV = "local"
$env:AEGIS_CONNECTOR_MODE = "mock"
$env:AEGIS_AUTH_DEV_BYPASS = "true"

Write-Host "AegisFlow API -> http://localhost:8000  (docs: /docs)" -ForegroundColor Green
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload
