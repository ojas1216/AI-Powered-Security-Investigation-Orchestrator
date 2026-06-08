# Fires the sample phishing alert at a running AegisFlow API and pretty-prints the
# resulting investigation package. Start the API first with .\run.ps1 (separate terminal).
# Usage:  .\smoke.ps1
$ErrorActionPreference = "Stop"

$body = Get-Content -Raw (Join-Path $PSScriptRoot "backend\seed\sample_phishing_alert.json")

$resp = Invoke-RestMethod -Method Post -Uri "http://localhost:8000/api/v1/alerts/ingest" `
    -Headers @{
        "Content-Type"  = "application/json"
        "Authorization" = "Bearer dev"
        "X-Tenant-ID"   = "acme"
        "X-Roles"       = "tier3_analyst"
    } `
    -Body $body

Write-Host ("Verdict : {0}" -f $resp.overall_verdict) -ForegroundColor Yellow
Write-Host ("Risk    : {0} ({1})" -f $resp.risk.score, $resp.risk.severity) -ForegroundColor Yellow
Write-Host ("IOCs    : {0}" -f $resp.iocs.Count)
Write-Host ("Hosts   : {0}" -f ($resp.affected_hosts -join ", "))
Write-Host ("MITRE   : {0}" -f (($resp.mitre | ForEach-Object { $_.technique_id }) -join ", "))
Write-Host ("Ticket  : {0}" -f $resp.tickets[0].ticket_id)
Write-Host "`n--- Executive summary ---" -ForegroundColor Cyan
Write-Host $resp.executive_summary
