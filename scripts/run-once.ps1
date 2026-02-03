param(
    [bool]$Sort = $true
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$repoRoot = Resolve-Path (Join-Path $PSScriptRoot '..')

function Resolve-GoCommand {
    $cmd = Get-Command go -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }

    $fallbacks = @(
        'C:\Program Files\Go\bin\go.exe',
        'C:\Go\bin\go.exe'
    )
    foreach ($path in $fallbacks) {
        if (Test-Path $path) { return $path }
    }

    throw "Go is not installed or not on PATH. Install Go 1.22+ and re-open your terminal."
}

function Normalize-ProxyUrl {
    param([Parameter(Mandatory = $true)][string]$Value)

    $v = $Value.Trim()
    if ($v -match '^[a-zA-Z][a-zA-Z0-9+.-]*://') { return $v }
    return "http://$v"
}

function Apply-WindowsProxyEnvIfMissing {
    if ($env:HTTP_PROXY -or $env:HTTPS_PROXY) { return }

    $settings = Get-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings' -ErrorAction SilentlyContinue
    if (-not $settings) { return }
    if ($settings.ProxyEnable -ne 1) { return }
    if (-not $settings.ProxyServer) { return }

    $proxyServer = [string]$settings.ProxyServer

    # ProxyServer can be a single "host:port" or a semicolon-separated list like:
    # "http=host:port;https=host:port;socks=host:port"
    $http = $null
    $https = $null

    if ($proxyServer -match '=') {
        foreach ($entry in ($proxyServer -split ';')) {
            if (-not $entry) { continue }
            $kv = $entry -split '=', 2
            if ($kv.Count -ne 2) { continue }
            $scheme = $kv[0].Trim().ToLowerInvariant()
            $value = $kv[1].Trim()
            if (-not $value) { continue }

            switch ($scheme) {
                'http' { $http = Normalize-ProxyUrl -Value $value }
                'https' { $https = Normalize-ProxyUrl -Value $value }
            }
        }
    } else {
        $http = Normalize-ProxyUrl -Value $proxyServer
        $https = $http
    }

    if ($http) { $env:HTTP_PROXY = $http }
    if ($https) { $env:HTTPS_PROXY = $https }
}

$go = Resolve-GoCommand
Apply-WindowsProxyEnvIfMissing

Push-Location $repoRoot
try {
    & $go mod download

    $goArgs = @('run', '.')
    if ($Sort) { $goArgs += '-sort' }
    & $go @goArgs
}
finally {
    Pop-Location
}
