param(
    [ValidateSet("check", "test", "dev", "build")]
    [string]$Task = "check"
)

$ErrorActionPreference = "Stop"

$vswhere = Join-Path ${env:ProgramFiles(x86)} "Microsoft Visual Studio\Installer\vswhere.exe"
if (-not (Test-Path -LiteralPath $vswhere)) {
    throw "Microsoft Visual Studio Build Tools were not found. Install the Desktop development with C++ workload."
}

$installationPath = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (-not $installationPath) {
    throw "The Visual C++ x64 toolchain is not installed."
}

$devShell = Join-Path $installationPath "Common7\Tools\Launch-VsDevShell.ps1"
& $devShell -Arch amd64 -HostArch amd64 -SkipAutomaticLocation

$projectRoot = Split-Path -Parent $PSScriptRoot
Push-Location $projectRoot
try {
    switch ($Task) {
        "check" { & cargo check --manifest-path "src-tauri\Cargo.toml" }
        "test" { & cargo test --manifest-path "src-tauri\Cargo.toml" }
        "dev" { & npm run tauri dev }
        "build" { & npm run tauri build }
    }
    exit $LASTEXITCODE
}
finally {
    Pop-Location
}
