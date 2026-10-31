param(
    [ValidateSet('socks5', 'http', 'both')] [string]$Protocol = 'both',
    [string]$OutDir = (Join-Path $PSScriptRoot '..\..\dist'),
    [int]$Max = 1500,
    [int]$Lanes = 40,
    [int]$Timeout = 6
)

$ErrorActionPreference = 'SilentlyContinue'
if (-not (Test-Path $OutDir)) { New-Item -ItemType Directory -Force $OutDir | Out-Null }

$sources = @{
    socks5 = @(
        'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt',
        'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/socks5.txt',
        'https://raw.githubusercontent.com/hookzof/socks5_list/master/proxy.txt',
        'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=socks5&timeout=10000&country=all&ssl=all&anonymity=all'
    )
    http = @(
        'https://api.proxyscrape.com/v2/?request=displayproxies&protocol=http&timeout=10000&country=all&ssl=all&anonymity=all',
        'https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt',
        'https://raw.githubusercontent.com/monosans/proxy-list/main/proxies/http.txt',
        'https://raw.githubusercontent.com/proxifly/free-proxy-list/main/proxies/protocols/http/data.txt'
    )
}

$targets = if ($Protocol -eq 'both') { @('socks5', 'http') } else { @($Protocol) }
$myIp = (& curl.exe -s --max-time 10 https://api.ipify.org).Trim()

$worker = {
    param($chunk, $timeout, $scheme)
    $good = @()
    foreach ($p in $chunk) {
        $lat = @()
        $ip = ''
        $ok = $true
        for ($r = 0; $r -lt 2; $r++) {
            $sw = [Diagnostics.Stopwatch]::StartNew()
            $body = & curl.exe -s --max-time $timeout --connect-timeout ($timeout - 1) -x ($scheme + $p) 'https://api.ipify.org'
            $code = $LASTEXITCODE
            $sw.Stop()
            if ($code -eq 0 -and $body -match '^\d{1,3}(\.\d{1,3}){3}$') {
                $lat += $sw.ElapsedMilliseconds
                $ip = $body.Trim()
            } else {
                $ok = $false
                break
            }
        }
        if ($ok -and $ip) {
            $avg = [int](($lat | Measure-Object -Average).Average)
            $good += ("{0}`t{1}`t{2}" -f $p, $avg, $ip)
        }
    }
    $good
}

foreach ($proto in $targets) {
    Write-Host "== $proto: collecting"
    $all = New-Object System.Collections.Generic.List[string]
    foreach ($u in $sources[$proto]) {
        $raw = & curl.exe -s --max-time 20 $u
        foreach ($line in ($raw -split "`n")) {
            $line = $line.Trim()
            if ($line -match '^\d{1,3}(\.\d{1,3}){3}:\d{2,5}$') { $all.Add($line) }
        }
    }
    $uniq = @($all | Sort-Object -Unique)
    $picked = if ($uniq.Count -gt $Max) { $uniq | Get-Random -Count $Max } else { $uniq }
    Write-Host ("   {0} candidates, testing {1}" -f $uniq.Count, $picked.Count)

    $chunks = @()
    $size = [Math]::Ceiling([Math]::Max(1, $picked.Count) / $Lanes)
    for ($i = 0; $i -lt $picked.Count; $i += $size) {
        $chunks += , @($picked[$i..([Math]::Min($i + $size - 1, $picked.Count - 1))])
    }

    $pool = [runspacefactory]::CreateRunspacePool(1, $Lanes)
    $pool.Open()
    $jobs = foreach ($c in $chunks) {
        $ps = [powershell]::Create()
        $ps.RunspacePool = $pool
        $null = $ps.AddScript($worker).AddArgument($c).AddArgument($Timeout).AddArgument("${proto}://")
        [pscustomobject]@{ PS = $ps; H = $ps.BeginInvoke() }
    }
    $found = foreach ($j in $jobs) {
        $o = $j.PS.EndInvoke($j.H)
        $j.PS.Dispose()
        $o
    }
    $pool.Close()
    $pool.Dispose()

    $found = @($found | Where-Object { $_ } | Sort-Object -Unique | Sort-Object { [int](($_ -split "`t")[1]) })
    $name = if ($proto -eq 'socks5') { 'live-socks5.tsv' } else { 'live-proxies.tsv' }
    $path = Join-Path $OutDir $name
    $stamp = (Get-Date).ToString('yyyy-MM-dd HH:mm:ss')
    "# $proto verified $stamp by refresh-proxies.ps1 (2x CONNECT, direct IP $myIp)" | Set-Content $path -Encoding UTF8
    $found | Add-Content $path -Encoding UTF8
    Write-Host ("   saved {0} working proxies -> {1}" -f $found.Count, $path)
}
