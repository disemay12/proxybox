# Build native part: injector + hook for x64 and x86 (WOW64).
# GUI is built separately by proxybox-rs.
#   powershell -ExecutionPolicy Bypass -File build.ps1
#
# Toolchains: x86_64-w64-mingw32 and i686-w64-mingw32 gcc/g++ in PATH,
# or point MINGW64_BIN / MINGW32_BIN at their bin directories.
$ErrorActionPreference = 'Stop'

$root = $PSScriptRoot
$mh = if ($env:MINHOOK_DIR) { $env:MINHOOK_DIR } else { Join-Path $root '..\third_party\minhook' }

if (-not (Test-Path (Join-Path $mh 'include\MinHook.h'))) {
    throw "MinHook not found at $mh (set MINHOOK_DIR)"
}
if ($env:MINGW32_BIN) { $env:PATH = "$env:MINGW32_BIN;$env:PATH" }
if ($env:MINGW64_BIN) { $env:PATH = "$env:MINGW64_BIN;$env:PATH" }

$cc64  = 'x86_64-w64-mingw32-gcc'
$cxx64 = 'x86_64-w64-mingw32-g++'
$cc32  = 'i686-w64-mingw32-gcc'
$cxx32 = 'i686-w64-mingw32-g++'
$ar    = if (Get-Command 'x86_64-w64-mingw32-ar' -ErrorAction SilentlyContinue) {
    'x86_64-w64-mingw32-ar'
} else {
    'ar'
}
foreach ($exe in @($cc64, $cxx64, $cc32, $cxx32, $ar)) {
    if (-not (Get-Command $exe -ErrorAction SilentlyContinue)) {
        throw "$exe not found in PATH (set MINGW64_BIN / MINGW32_BIN)"
    }
}

$src   = Join-Path $root 'src'
$build = Join-Path $root 'build'
$dist  = Join-Path $root '..\dist'

New-Item -ItemType Directory -Force $build | Out-Null
New-Item -ItemType Directory -Force $dist  | Out-Null

function Invoke-Step($name, $exe, [string[]]$argList) {
    Write-Host "==> $name"
    & $exe @argList
    if ($LASTEXITCODE -ne 0) { throw "$name failed ($LASTEXITCODE)" }
}

function Build-Arch([string]$arch, [string]$cc, [string]$cxx, [string]$dllOut, [string]$injectorOut) {
    $objDir = Join-Path $build "mh-$arch"
    New-Item -ItemType Directory -Force $objDir | Out-Null

    $sources = @(
        "$mh\src\hook.c", "$mh\src\trampoline.c", "$mh\src\buffer.c",
        "$mh\src\hde\hde32.c", "$mh\src\hde\hde64.c"
    )
    $objects = @()
    foreach ($c in $sources) {
        $o = Join-Path $objDir ((Split-Path $c -Leaf) -replace '\.c$', '.o')
        Invoke-Step "$arch gcc $(Split-Path $c -Leaf)" $cc @('-c', $c, '-o', $o, '-O2', '-masm=intel',
            "-I$mh\include", "-I$mh\src", '-D_WIN32_WINNT=0x0601')
        $objects += $o
    }
    $lib = Join-Path $objDir 'libminhook.a'
    if (Test-Path $lib) { Remove-Item $lib }
    Invoke-Step "$arch ar libminhook.a" $ar (@('rcs', $lib) + $objects)

    Invoke-Step $dllOut $cxx (@(
        '-shared', '-O2', '-std=c++17', '-D_WIN32_WINNT=0x0601',
        "-I$mh\include",
        (Join-Path $src 'hook\dllmain.cpp'),
        $lib,
        '-o', (Join-Path $dist $dllOut),
        '-lws2_32', '-lole32', '-static', '-static-libgcc', '-static-libstdc++',
        '-Wl,--exclude-all-symbols'
    ))

    Invoke-Step $injectorOut $cxx (@(
        '-O2', '-std=c++17', '-municode', '-mconsole',
        '-D_WIN32_WINNT=0x0601',
        (Join-Path $src 'injector\main.cpp'),
        '-o', (Join-Path $dist $injectorOut),
        '-static', '-static-libgcc', '-static-libstdc++'
    ))
}

Build-Arch 'x64' $cc64 $cxx64 'pbhook64.dll' 'pbinject.exe'
Build-Arch 'x86' $cc32 $cxx32 'pbhook32.dll' 'pbinject32.exe'

Write-Host "`nbuilt:"
Get-ChildItem -Path (Join-Path $dist '*') -Include 'pbinject*.exe','pbhook*.dll' -File |
    ForEach-Object { "  $($_.Name)  $([math]::Round($_.Length/1KB)) KB" }
