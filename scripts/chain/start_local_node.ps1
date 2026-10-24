# start_local_node.ps1
$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectDir = Split-Path -Parent $ScriptDir
$PidFile = Join-Path $ScriptDir "hardhat_node.pid"
$LogFile = Join-Path $ScriptDir "hardhat_node.log"
$ErrFile = Join-Path $ScriptDir "hardhat_node.err"

function Test-NodeRpc {
    try {
        $body = '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
        $resp = Invoke-RestMethod -Uri "http://127.0.0.1:8545" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 2 -ErrorAction Stop
        if ($resp -and $resp.result) {
            $chainId = [Convert]::ToInt32($resp.result, 16)
            return $chainId
        }
    } catch {
        return $null
    }
    return $null
}

$existingChainId = Test-NodeRpc
if ($null -ne $existingChainId) {
    Write-Host "Local node already running. Chain ID: $existingChainId"
    exit 0
}

# Start node process detached via Win32_Process
$cmdLine = "cmd.exe /c cd /d `"$ProjectDir`" && npx hardhat node > `"$LogFile`" 2> `"$ErrFile`""
$res = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{ CommandLine = $cmdLine }
$procId = $res.ProcessId

if ($procId) {
    $procId | Out-File -FilePath $PidFile -Encoding ascii
}

# Wait until eth_chainId answers
$maxAttempts = 60
$attempt = 0
$startedChainId = $null

while ($attempt -lt $maxAttempts) {
    Start-Sleep -Milliseconds 500
    $startedChainId = Test-NodeRpc
    if ($null -ne $startedChainId) {
        break
    }
    $attempt++
}

if ($null -eq $startedChainId) {
    Write-Error "Timed out waiting for Hardhat node to start. Check $LogFile and $ErrFile."
    exit 1
}

Write-Host "Hardhat local node started. PID: $procId. Chain ID: $startedChainId"
