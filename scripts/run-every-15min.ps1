param(
    [int]$EveryMins = 15,
    [bool]$Sort = $true
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$seconds = [Math]::Max(1, $EveryMins * 60)
$runOnce = Join-Path $PSScriptRoot 'run-once.ps1'

while ($true) {
    try {
        & $runOnce -Sort:$Sort
    }
    catch {
        Write-Error $_
    }

    Start-Sleep -Seconds $seconds
}
