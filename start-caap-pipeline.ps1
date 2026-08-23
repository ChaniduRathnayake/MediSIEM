# start-caap-pipeline.ps1
#
# Brings up the CAAP live pipeline's HOST-side services, in order, each in its
# own labeled window so you can watch every stage during a demo:
#   [1/4] Wazuh Indexer check   -- your existing single-node-wazuh stack, NOT
#                                  started by this script (it's managed
#                                  separately -- this just confirms it's up)
#   [2/4] Flask AI server       -- ai_server/src/app.py, real RF/IF/K-Means /predict
#   [3/4] Node backend          -- backend/server.js, polls the indexer, Socket.IO push
#   [4/4] React dashboard       -- frontend/, live alert table
#
# attack_simulator.py, live_feature_extractor.py, and flow_consumer.py are NOT
# started by this script -- per your lab setup they run inside an isolated VM
# (raw-socket traffic gen + live packet capture shouldn't run on your main
# host). This script prints the exact commands to run there once the host
# side is up.
#
# Usage:
#   powershell -ExecutionPolicy Bypass -File .\start-caap-pipeline.ps1

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot

function Write-Stage($msg) {
    Write-Host ""
    Write-Host "==> $msg" -ForegroundColor Cyan
}

function Wait-Http($url, $label, $timeoutSec = 90, $curlArgs = @()) {
    Write-Host "    waiting for $label ($url)..." -NoNewline
    $elapsed = 0
    while ($elapsed -lt $timeoutSec) {
        $null = & curl.exe -sk -m 3 @curlArgs $url 2>$null
        if ($LASTEXITCODE -eq 0) {
            Write-Host " up." -ForegroundColor Green
            return $true
        }
        Start-Sleep -Seconds 2
        $elapsed += 2
        Write-Host "." -NoNewline
    }
    Write-Host ""
    Write-Host "    TIMEOUT waiting for $label -- check its window for errors." -ForegroundColor Red
    return $false
}

# Read WAZUH_INDEXER_USER / WAZUH_INDEXER_PASS straight out of backend/.env so
# this script never hardcodes a credential that can drift out of sync with it.
function Read-EnvVar($name, $default) {
    $line = Get-Content "$root\backend\.env" | Where-Object { $_ -match "^$name=" } | Select-Object -First 1
    if ($line) { return ($line -split '=', 2)[1].Trim() }
    return $default
}
$indexerUser = Read-EnvVar "WAZUH_INDEXER_USER" "admin"
$indexerPass = Read-EnvVar "WAZUH_INDEXER_PASS" "changeme"
$indexerUrl  = Read-EnvVar "WAZUH_INDEXER_URL" "https://localhost:9200"

# ─── [1/4] Wazuh Indexer (managed separately -- just verify it's reachable) ──
Write-Stage "[1/4] Checking Wazuh Indexer at $indexerUrl"
$indexerUp = Wait-Http $indexerUrl "Wazuh Indexer" 15 @("-u", "$($indexerUser):$($indexerPass)")
if (-not $indexerUp) {
    Write-Host "    Not reachable with the current backend/.env credentials." -ForegroundColor Red
    Write-Host "    This script does NOT start your Wazuh stack -- it's the existing" -ForegroundColor Red
    Write-Host "    single-node-wazuh containers (docker ps to check). Start those first," -ForegroundColor Red
    Write-Host "    or fix WAZUH_INDEXER_USER/PASS in backend/.env, then re-run." -ForegroundColor Red
    exit 1
}

# ─── [2/4] Flask AI server ─────────────────────────────────────────────────
# Bound to 0.0.0.0, not app.py's own 127.0.0.1 default -- lab VMs reach this
# over the network as a separate host, not localhost, so a loopback-only bind
# here silently makes /predict unreachable from every VM with no error at all
# (the VM's flow_consumer.py just never gets a response). Cost this exact
# failure a full debugging session once already -- don't drop this line.
Write-Stage "[2/4] Starting Flask AI server (ai_server/src/app.py, port 5001, bound to 0.0.0.0 for VM reachability)"
Start-Process powershell -ArgumentList @(
    "-NoExit", "-Command",
    "`$host.UI.RawUI.WindowTitle = 'CAAP [2/4] Flask AI server :5001'; " +
    "cd '$root\ai_server'; .\venv\Scripts\Activate.ps1; `$env:AI_SERVER_HOST='0.0.0.0'; python src\app.py"
)
Wait-Http "http://localhost:5001/health" "Flask AI server" | Out-Null

# ─── [3/4] Node backend ────────────────────────────────────────────────────
Write-Stage "[3/4] Starting Node backend (backend/server.js, port 5000)"
Start-Process powershell -ArgumentList @(
    "-NoExit", "-Command",
    "`$host.UI.RawUI.WindowTitle = 'CAAP [3/4] Node backend :5000'; " +
    "cd '$root\backend'; npm run dev"
)
Wait-Http "http://localhost:5000/api/health" "Node backend" | Out-Null

# ─── [4/4] React dashboard ──────────────────────────────────────────────────
Write-Stage "[4/4] Starting React dashboard (frontend/, port 5173)"
Start-Process powershell -ArgumentList @(
    "-NoExit", "-Command",
    "`$host.UI.RawUI.WindowTitle = 'CAAP [4/4] React dashboard :5173'; " +
    "cd '$root\frontend'; npm run dev -- --host"
)

# ─── Host IP for the VM side ────────────────────────────────────────────────
Write-Stage "Host side is up. Next: run the VM-side capture."
$hostIp = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object {
    $_.IPAddress -like "192.168.56.*" -or $_.IPAddress -like "192.168.*"
} | Select-Object -First 1 -ExpandProperty IPAddress)
if (-not $hostIp) { $hostIp = "<host-only-adapter-ip>  (run ipconfig, find the VirtualBox/VMware Host-Only adapter)" }

Write-Host ""
Write-Host "Detected possible host-only IP: $hostIp" -ForegroundColor Yellow
Write-Host "If that's wrong, run 'ipconfig' and use the IPv4 address of your" -ForegroundColor Yellow
Write-Host "VirtualBox Host-Only / VMware Host-Only adapter instead." -ForegroundColor Yellow
Write-Host ""
Write-Host "Inside the victim lab VM:" -ForegroundColor Cyan
Write-Host "  pip install -r 'ml-pipeline/requirements.txt'"
Write-Host "  python 'ml-pipeline/live_feature_extractor.py' --iface `"<vm-iface-name>`" --out-dir ./cicflowmeter_output"
Write-Host "  python 'ml-pipeline/flow_consumer.py' --flow-dir ./cicflowmeter_output \"
Write-Host "      --caap-url http://$hostIp`:5001 --indexer-url https://$hostIp`:9200 \"
Write-Host "      --indexer-user $indexerUser --indexer-pass $indexerPass"
Write-Host ""
Write-Host "Inside the attacker lab VM:" -ForegroundColor Cyan
Write-Host "  sudo python 'Extra_Material/Demo_Attack/attack_simulator.py' --target <victim-vm-ip> --scenario all"
Write-Host "  # or, to sweep every VM device in one run:"
Write-Host "  sudo python 'Extra_Material/Demo_Attack/multi_target_attack_simulator.py' --scenario all"
Write-Host ""
Write-Host "Dashboard: http://localhost:5173 (log in, alerts appear as flow_consumer.py indexes them)" -ForegroundColor Green
