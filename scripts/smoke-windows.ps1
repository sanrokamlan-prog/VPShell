param(
    [string]$Executable = "src-tauri\target\release\vpshell.exe"
)

$ErrorActionPreference = "Stop"
$projectRoot = Split-Path -Parent $PSScriptRoot
$resolvedExecutable = Join-Path $projectRoot $Executable

if (-not (Test-Path -LiteralPath $resolvedExecutable)) {
    throw "VPShell executable was not found: $resolvedExecutable"
}

$process = Start-Process -FilePath $resolvedExecutable -PassThru -WindowStyle Hidden
try {
    Start-Sleep -Seconds 3
    if ($process.HasExited) {
        throw "VPShell exited during startup with code $($process.ExitCode)."
    }
    Write-Output "VPShell startup smoke test passed (PID $($process.Id))."
}
finally {
    if (-not $process.HasExited) {
        Stop-Process -Id $process.Id
        $process.WaitForExit()
    }
}
