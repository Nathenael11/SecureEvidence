# status.ps1
$ErrorActionPreference = "SilentlyContinue"

try {
    $body = '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}'
    $resp = Invoke-RestMethod -Uri "http://127.0.0.1:8545" -Method Post -Body $body -ContentType "application/json" -TimeoutSec 2 -ErrorAction Stop
    if ($resp -and $resp.result) {
        $chainId = [Convert]::ToInt32($resp.result, 16)

        $blockBody = '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":2}'
        $blockResp = Invoke-RestMethod -Uri "http://127.0.0.1:8545" -Method Post -Body $blockBody -ContentType "application/json" -TimeoutSec 2 -ErrorAction Stop
        $blockNum = [Convert]::ToInt32($blockResp.result, 16)

        Write-Host "Status: Running | Chain ID: $chainId | Latest Block: $blockNum"
        exit 0
    }
} catch {
}

Write-Host "Status: Stopped"
exit 0
