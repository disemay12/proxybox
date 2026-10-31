# Build proxybox GUI (Rust, eframe/egui) -> ..\dist\proxybox.exe
#   powershell -ExecutionPolicy Bypass -File build.ps1
$ErrorActionPreference = 'Stop'

$cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
if (Test-Path $cargoBin) { $env:PATH = "$cargoBin;$env:PATH" }
if ($env:MINGW64_BIN) { $env:PATH = "$env:MINGW64_BIN;$env:PATH" }

$dist = Join-Path $PSScriptRoot '..\dist'

Push-Location $PSScriptRoot
try {
    cargo build --release
    if ($LASTEXITCODE -ne 0) { throw "cargo build failed" }
    New-Item -ItemType Directory -Force $dist | Out-Null
    Copy-Item "target\release\proxybox.exe" (Join-Path $dist 'proxybox.exe') -Force
    $exe = Get-Item (Join-Path $dist 'proxybox.exe')
    Write-Host ("built: proxybox.exe  {0} KB" -f [math]::Round($exe.Length / 1KB))
}
finally {
    Pop-Location
}
