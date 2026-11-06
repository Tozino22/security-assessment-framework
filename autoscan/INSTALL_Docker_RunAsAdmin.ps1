# ============================================================
#  AutoScan prerequisites installer
#  RIGHT-CLICK this file  ->  "Run with PowerShell"  (as Administrator)
#  or open an elevated PowerShell and run:  .\INSTALL_Docker_RunAsAdmin.ps1
# ============================================================

# Self-elevate if not already admin
$id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
$pr = New-Object System.Security.Principal.WindowsPrincipal($id)
if (-not $pr.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "Requesting administrator privileges..." -ForegroundColor Yellow
    Start-Process powershell "-ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
    exit
}

Write-Host "==============================================" -ForegroundColor Cyan
Write-Host " AutoScan setup: WSL2 + Docker Desktop" -ForegroundColor Cyan
Write-Host "==============================================" -ForegroundColor Cyan

# 1. Install WSL2 (Windows Subsystem for Linux)
Write-Host "`n[1/2] Installing WSL2..." -ForegroundColor Green
wsl --install --no-distribution

# 2. Install Docker Desktop (skips if winget already placed it)
Write-Host "`n[2/2] Installing Docker Desktop..." -ForegroundColor Green
winget install --id Docker.DockerDesktop --accept-package-agreements --accept-source-agreements --silent

Write-Host "`n==============================================" -ForegroundColor Cyan
Write-Host " DONE. You MUST REBOOT now for WSL2 to activate." -ForegroundColor Yellow
Write-Host ""
Write-Host " After reboot:" -ForegroundColor Cyan
Write-Host "   1. Launch Docker Desktop (Start menu). Wait for 'Engine running'."
Write-Host "   2. Open a terminal in the autoscan folder and run:"
Write-Host "        python autoscan.py check" -ForegroundColor White
Write-Host "==============================================" -ForegroundColor Cyan
Read-Host "`nPress Enter to close"
