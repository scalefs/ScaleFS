<#
.SYNOPSIS
Run the full local validation gate: formatting, lints, and tests.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) {
    $cargoBin = Join-Path $env:USERPROFILE '.cargo\bin'
    if (Test-Path (Join-Path $cargoBin 'cargo.exe')) {
        $env:PATH = "$cargoBin;$env:PATH"
    } else {
        throw 'cargo was not found; install Rust from https://rustup.rs'
    }
}

# Some Visual Studio installations lack the desktop MSVC libraries on the
# default search path; detect that case and provide an explicit LIB.
if (-not $env:LIB) {
    $desktop = Get-ChildItem "$env:ProgramFiles\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\lib\x64\msvcrt.lib" -ErrorAction SilentlyContinue
    if (-not $desktop) {
        $onecore = Get-ChildItem "$env:ProgramFiles\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\lib\onecore\x64\msvcrt.lib" -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Select-Object -First 1
        $ucrt = Get-ChildItem "${env:ProgramFiles(x86)}\Windows Kits\10\Lib\*\ucrt\x64\ucrt.lib" -ErrorAction SilentlyContinue |
            Sort-Object FullName -Descending | Select-Object -First 1
        if ($onecore -and $ucrt) {
            $msvcLib = Split-Path -Parent $onecore.FullName            # ...\lib\onecore\x64
            $ucrtDir = Split-Path -Parent $ucrt.FullName               # ...\<sdk>\ucrt\x64
            $sdkVersionDir = Split-Path -Parent (Split-Path -Parent $ucrtDir)
            $umDir = Join-Path $sdkVersionDir 'um\x64'
            $env:LIB = "$msvcLib;$ucrtDir;$umDir"
            Write-Host 'validate: using onecore MSVC libraries via LIB'
        }
    }
}

Set-Location (Split-Path -Parent $PSScriptRoot)

Write-Host '== cargo fmt --all --check'
cargo fmt --all --check
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host '== cargo clippy --workspace --all-targets -- -D warnings'
cargo clippy --workspace --all-targets -- -D warnings
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host '== cargo test --workspace'
cargo test --workspace
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

Write-Host 'validate: all checks passed'
