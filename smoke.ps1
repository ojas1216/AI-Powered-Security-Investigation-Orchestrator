# Fires the sample phishing alert at a running AegisFlow API and pretty-prints the
# resulting investigation package. Start the API first with .\run.ps1 (separate terminal).
# Usage:  .\smoke.ps1
$ErrorActionPreference = "Stop"

$path = Join-Path $PSScriptRoot "backend\seed\sample_phishing_alert.json"
# Read raw UTF-8 bytes and send them verbatim. (Get-Content -Raw + a string body
# would let Windows PowerShell 5.1 re-encode non-ASCII chars and corrupt the JSON.)
$bytes = [System.IO.File]::ReadAllBytes($path)

$resp = Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/v1/alerts/ingest" `
    -ContentType "application/json" `
    -Headers @{
        "Authorization" = "Bearer dev"
        "X-Tenant-ID"   = "acme"
        "X-Roles"       = "tier3_analyst"
    } `
    -Body $bytes

Write-Host ("Verdict : {0}" -f $resp.overall_verdict) -ForegroundColor Yellow
Write-Host ("Risk    : {0} ({1})" -f $resp.risk.score, $resp.risk.severity) -ForegroundColor Yellow
Write-Host ("IOCs    : {0}" -f $resp.iocs.Count)
Write-Host ("Hosts   : {0}" -f ($resp.affected_hosts -join ", "))
Write-Host ("MITRE   : {0}" -f (($resp.mitre | ForEach-Object { $_.technique_id }) -join ", "))
Write-Host ("Ticket  : {0}" -f $resp.tickets[0].ticket_id)
Write-Host "`n--- Executive summary ---" -ForegroundColor Cyan
Write-Host $resp.executive_summary
