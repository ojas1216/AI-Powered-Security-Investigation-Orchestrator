# Builds AegisFlow.exe from installer/AegisFlow.cs using the C# compiler that
# ships with the Windows .NET Framework — no downloads or extra tooling needed.
#
# Usage:  .\installer\build.ps1     (or double-click after right-click > Run with PowerShell)
$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$src  = Join-Path $PSScriptRoot "AegisFlow.cs"
$out  = Join-Path $root "AegisFlow.exe"

$csc = @(
    "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\csc.exe",
    "$env:WINDIR\Microsoft.NET\Framework\v4.0.30319\csc.exe"
) | Where-Object { Test-Path $_ } | Select-Object -First 1

if (-not $csc) {
    throw "csc.exe (.NET Framework C# compiler) not found. Install the .NET Framework 4.x developer pack."
}

Write-Host "Compiling with $csc" -ForegroundColor Cyan
& $csc /nologo /optimize+ /target:exe /out:"$out" "$src"
if ($LASTEXITCODE -ne 0) { throw "Compilation failed." }

Write-Host "Built: $out" -ForegroundColor Green
Write-Host "Double-click AegisFlow.exe (in the project root) to launch the platform." -ForegroundColor Green
