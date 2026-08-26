# =====================================================================
#  MEDSHIELD DEMO STARTUP  (Windows side)
# =====================================================================
#  Run in PowerShell:   .\demo_start_windows.ps1
#
#  Brings up the Windows-side piece of MedShield -- the IP reputation
#  backend -- and one public tunnel, then prints the URL your team and
#  the dashboard use. Safe to run repeatedly: it stops the previous
#  run first, so you never accumulate duplicate tunnels.
#
#  What it starts:
#    1. Reputation backend  (uvicorn, port 8088)
#    2. ONE cloudflared tunnel -> public https URL
#
#  What it does NOT start (by design):
#    - the ML API, collector, Suricata : those run on the VM.
#      Start them there with demo_start_vm.sh.
#
#  EDIT THIS if your path differs:
$BackendDir = "D:\Med Lab Project\medshield-ip-reputation\backend"
$Port       = 8088
# =====================================================================

$ErrorActionPreference = "Continue"

function Say  ($m) { Write-Host "`n==> $m" -ForegroundColor Cyan }
function OK   ($m) { Write-Host "    OK  $m" -ForegroundColor Green }
function Warn ($m) { Write-Host "    !!  $m" -ForegroundColor Yellow }

# ---------------------------------------------------------------------
# 0. Clean up any previous run
# ---------------------------------------------------------------------
Say "Cleaning up previous run"
Get-Process cloudflared -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
# stop any uvicorn already holding the port
$inUse = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction SilentlyContinue
if ($inUse) {
    $inUse | ForEach-Object {
        Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue
    }
    OK "freed port $Port"
} else {
    OK "port $Port was free"
}
Start-Sleep -Seconds 2

# ---------------------------------------------------------------------
# 1. Preconditions
# ---------------------------------------------------------------------
Say "Checking prerequisites"
$cf = Get-Command cloudflared -ErrorAction SilentlyContinue
if (-not $cf) {
    $cfPath = "C:\Program Files (x86)\cloudflared\cloudflared.exe"
    if (Test-Path $cfPath) { $cf = $cfPath } else {
        $cfPath = "C:\Program Files\cloudflared\cloudflared.exe"
        if (Test-Path $cfPath) { $cf = $cfPath } else {
            Warn "cloudflared not found. Install: winget install --id Cloudflare.cloudflared"
            exit 1
        }
    }
} else { $cf = "cloudflared" }
OK "cloudflared found"

if (-not (Test-Path (Join-Path $BackendDir "app.py"))) {
    Warn "Backend not found at $BackendDir. Edit `$BackendDir at the top of this script."
    exit 1
}
OK "backend found"

# ---------------------------------------------------------------------
# 2. Reputation backend
# ---------------------------------------------------------------------
Say "Starting reputation backend (port $Port)"
$logDir = Join-Path $env:USERPROFILE "medshield_logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
$apiLog = Join-Path $logDir "reputation_api.log"

# Prefer the venv python if present, else system python
$venvPy = Join-Path $BackendDir ".venv\Scripts\python.exe"
if (Test-Path $venvPy) { $py = $venvPy } else { $py = "python" }

Start-Process -FilePath $py `
    -ArgumentList "-m","uvicorn","app:app","--host","0.0.0.0","--port","$Port" `
    -WorkingDirectory $BackendDir `
    -RedirectStandardOutput $apiLog `
    -RedirectStandardError (Join-Path $logDir "reputation_api.err.log") `
    -WindowStyle Hidden

# wait for health
$up = $false
for ($i = 0; $i -lt 20; $i++) {
    try {
        $r = Invoke-WebRequest -Uri "http://127.0.0.1:$Port/docs" -UseBasicParsing -TimeoutSec 2
        if ($r.StatusCode -eq 200) { $up = $true; break }
    } catch { Start-Sleep -Seconds 1 }
}
if ($up) { OK "reputation backend up" }
else { Warn "backend did not respond -- see $apiLog"; }

# ---------------------------------------------------------------------
# 3. ONE tunnel
# ---------------------------------------------------------------------
Say "Starting public tunnel for reputation service"
$tunLog = Join-Path $logDir "tunnel_reputation.log"
if (Test-Path $tunLog) { Remove-Item $tunLog -Force }

Start-Process -FilePath $cf `
    -ArgumentList "tunnel","--url","http://localhost:$Port" `
    -RedirectStandardOutput $tunLog `
    -RedirectStandardError (Join-Path $logDir "tunnel_reputation.err.log") `
    -WindowStyle Hidden

$repUrl = $null
for ($i = 0; $i -lt 25; $i++) {
    Start-Sleep -Seconds 1
    $logText = ""
    if (Test-Path $tunLog) { $logText += Get-Content $tunLog -Raw -ErrorAction SilentlyContinue }
    $errLog = Join-Path $logDir "tunnel_reputation.err.log"
    if (Test-Path $errLog) { $logText += Get-Content $errLog -Raw -ErrorAction SilentlyContinue }
    $m = [regex]::Match($logText, "https://[a-z0-9-]+\.trycloudflare\.com")
    if ($m.Success) { $repUrl = $m.Value; break }
}
if ($repUrl) { OK "tunnel up" } else { Warn "tunnel URL not found -- see $tunLog" }

# ---------------------------------------------------------------------
# 4. Summary
# ---------------------------------------------------------------------
Write-Host "`n===================================================================" -ForegroundColor Cyan
Write-Host "  MEDSHIELD WINDOWS SERVICE IS UP" -ForegroundColor Cyan
Write-Host "===================================================================`n" -ForegroundColor Cyan
Write-Host "  Reputation (public) : $repUrl" -ForegroundColor Green
Write-Host "  lookup endpoint     : $repUrl/api/v1/reputation/lookup"
Write-Host "  API docs            : $repUrl/docs`n"
Write-Host "  method POST, body   : {`"ip`": `"8.8.8.8`"}`n"
Write-Host "  logs                : $logDir"
Write-Host "  stop everything     : Get-Process cloudflared,python | Stop-Process -Force`n"
Write-Host "  NOTE: the ML API + collector + Suricata run on the VM."
Write-Host "  NOTE: this trycloudflare URL changes every run. Share the one above.`n"

# Save for the team
$urlFile = Join-Path $env:USERPROFILE "demo_urls_windows.json"
@{ reputation_url = $repUrl; generated = (Get-Date).ToUniversalTime().ToString("s") + "Z" } |
    ConvertTo-Json | Set-Content $urlFile
OK "URL saved to $urlFile"

# Quick self-test
if ($repUrl) {
    Say "Self-test: looking up 8.8.8.8 through the tunnel"
    try {
        $test = Invoke-RestMethod -Uri "$repUrl/api/v1/reputation/lookup" `
            -Method POST -Body '{"ip":"8.8.8.8"}' -ContentType "application/json" -TimeoutSec 15
        OK "reputation lookup returned a response (service is reachable end-to-end)"
    } catch {
        Warn "self-test lookup failed: $($_.Exception.Message)"
    }
}
