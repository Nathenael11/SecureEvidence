# stop_local_node.ps1
$ErrorActionPreference = "SilentlyContinue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$PidFile = Join-Path $ScriptDir "hardhat_node.pid"

if (Test-Path $PidFile) {
    $pidToKill = Get-Content $PidFile -ErrorAction SilentlyContinue
    if ($pidToKill) {
        # Kill the process tree
        taskkill /PID $pidToKill /T /F | Out-Null
        Stop-Process -Id $pidToKill -Force -ErrorAction SilentlyContinue
    }
    Remove-Item $PidFile -Force -ErrorAction SilentlyContinue
}

# Also verify port 8545
$conns = Get-NetTCPConnection -LocalPort 8545 -State Listen -ErrorAction SilentlyContinue
foreach ($conn in $conns) {
    if ($conn.OwningProcess) {
        taskkill /PID $conn.OwningProcess /T /F | Out-Null
        Stop-Process -Id $conn.OwningProcess -Force -ErrorAction SilentlyContinue
    }
}

Write-Host "Hardhat local node stopped."
