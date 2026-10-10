#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidateSet('arm64', 'amd64', 'x64')]
    [string]$Architecture
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false
$originalLocation = Get-Location
$temporaryDirectory = $null
$temporaryDirectoryCreated = $false
$process = $null
$stdoutRead = $null
$stderrRead = $null

function Stop-OwnedProbe {
    param([Diagnostics.Process]$OwnedProcess)
    if (-not $OwnedProcess.HasExited) {
        try {
            # This handle belongs to the process started below. Never terminate
            # other COMPAT16 instances by executable name or an unowned PID.
            $OwnedProcess.Kill($true)
        } catch {
            if (-not $OwnedProcess.HasExited) { throw }
        }
        if (-not $OwnedProcess.WaitForExit(5000)) {
            throw 'The owned dialog probe process tree did not stop after termination.'
        }
    }
}

function Write-ProbeDiagnostic {
    param([string]$Path, [string]$Label)
    Write-Host "::group::$Label"
    try {
        if (Test-Path -LiteralPath $Path -PathType Leaf) {
            Get-Content -LiteralPath $Path | ForEach-Object { Write-Host $_ }
        } else {
            Write-Host '(not produced)'
        }
    } finally {
        Write-Host '::endgroup::'
    }
}

try {
    if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)) {
        throw 'The generated Win16 dialog probe requires native Windows AMD64 or ARM64.'
    }
    $architectureName = if ($Architecture -eq 'arm64') { 'arm64' } else { 'x64' }
    $nativeArchitecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
    if ($architectureName -ne $nativeArchitecture) {
        throw 'Run the probe on the selected native Windows architecture.'
    }
    $target = if ($architectureName -eq 'arm64') { 'aarch64-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }
    $vsArchitecture = if ($architectureName -eq 'arm64') { 'arm64' } else { 'amd64' }
    $projectRoot = (Resolve-Path -LiteralPath (Join-Path $PSScriptRoot '..')).Path
    Set-Location -LiteralPath $projectRoot
    $runtimeDirectory = Join-Path $projectRoot "dist\$architectureName"
    # Execute the staged launcher in place: all four native files stay together.
    foreach ($file in @('compat16.exe', 'compat16w.exe', 'compat16.dll', 'compat16host.exe')) {
        if (-not (Test-Path -LiteralPath (Join-Path $runtimeDirectory $file) -PathType Leaf)) {
            throw "Missing staged runtime file: dist/$architectureName/$file. Run scripts/build.ps1 first."
        }
    }
    $temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) ('compat16-dialog-' + [Guid]::NewGuid().ToString('N'))
    $program = Join-Path $temporaryDirectory 'DIALOG.EXE'
    $instructionTrace = Join-Path $temporaryDirectory 'instructions.log'
    $win16Trace = Join-Path $temporaryDirectory 'win16-io.log'
    $stdoutPath = Join-Path $temporaryDirectory 'stdout.log'
    $stderrPath = Join-Path $temporaryDirectory 'stderr.log'
    New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
    $temporaryDirectoryCreated = $true

    $cargo = (Get-Command cargo.exe -CommandType Application -ErrorAction Stop).Source
    $compiler = @(rustc --version --verbose)
    if ($LASTEXITCODE -ne 0 -or $compiler -notcontains "host: $target") {
        throw "The pinned Rust compiler must run natively on $target."
    }
    # build.ps1 restores its environment. Configure MSVC only in the generator
    # subprocess, without changing the caller or installing/downloading tools.
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
        throw 'Visual Studio discovery tool was not found.'
    }
    $installations = @(& $vswhere -latest -products '*' -prerelease -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath)
    if ($LASTEXITCODE -ne 0 -or $installations.Count -eq 0) {
        throw 'Visual Studio C++ tools were not found.'
    }
    $vsDevCmd = Join-Path ([string]$installations[0]).Trim() 'Common7\Tools\VsDevCmd.bat'
    if (-not (Test-Path -LiteralPath $vsDevCmd -PathType Leaf)) {
        throw 'Visual Studio developer command script was not found.'
    }
    $command = 'call "{0}" -arch={1} -host_arch={1} && "{2}" run --offline --locked --target {3} -p build-tools -- win16-dialog-probe --output "{4}"' -f $vsDevCmd, $vsArchitecture, $cargo, $target, $program
    & $env:ComSpec /d /c $command
    if ($LASTEXITCODE -ne 0) { throw 'Generating the Win16 dialog probe failed.' }
    if (-not (Test-Path -LiteralPath $program -PathType Leaf)) { throw 'The generator did not produce DIALOG.EXE.' }

    $start = [Diagnostics.ProcessStartInfo]::new()
    $start.FileName = Join-Path $runtimeDirectory 'compat16.exe'
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    $start.WorkingDirectory = $temporaryDirectory
    $start.RedirectStandardOutput = $true
    $start.RedirectStandardError = $true
    foreach ($argument in @('--max-instructions', '1000000', '--trace-file', $instructionTrace, '--trace-win16-io-complete', $win16Trace, $program)) {
        $start.ArgumentList.Add($argument)
    }
    Write-Host 'Running the generated NE dialog/icon guest with a 30-second external timeout; no visible windows or input.'
    $process = [Diagnostics.Process]::Start($start)
    # Drain both pipes concurrently so diagnostics cannot deadlock the guest.
    $stdoutRead = $process.StandardOutput.ReadToEndAsync()
    $stderrRead = $process.StandardError.ReadToEndAsync()
    if (-not $process.WaitForExit(30000)) {
        throw 'The Win16 dialog probe exceeded its 30-second external timeout.'
    }
    $exitCode = $process.ExitCode
    Write-Host "Generated dialog guest exit code: $exitCode"
    if ($exitCode -ne 0) { throw "The generated dialog guest failed (exit $exitCode)." }
    if (-not (Test-Path -LiteralPath $win16Trace -PathType Leaf)) {
        throw 'The guest exited without producing its Win16 service/callback trace.'
    }
    $trace = Get-Content -LiteralPath $win16Trace -Raw
    # Match the complete trace's @sequence prefix and the actual Display
    # formats in runtime/win16_io_trace.rs and host/windows/win16_io_trace.rs.
    # A DOS stub exiting zero cannot satisfy these NE service/callback checks.
    # Service markers do not include arguments/results: guest assertions check
    # STM_GETICON (0401), a nonzero child/icon and the EndDialog result of 17.
    foreach ($ordinal in @(87, 91, 111, 88)) {
        foreach ($stage in @('dispatch-enter', 'dispatch-return')) {
            $pattern = '(?m)^@\d+ service-boundary stage={0} module=USER name=\S+ ordinal={1} instruction=\d+ guest=[0-9A-F]{{4}}:[0-9A-F]{{4}}\r?$' -f $stage, $ordinal
            if ($trace -cnotmatch $pattern) { throw "Missing USER ordinal $ordinal $stage trace evidence." }
        }
    }
    if ($trace -cmatch '(?m)^@\d+ service-boundary stage=dispatch-error ') {
        throw 'The Win16 service trace contains a failed dispatch.'
    }
    $initialization = [regex]::Match($trace, '(?m)^@\d+ window-callback phase=guest-entry procedure=dlgproc callback=(\d+) window=([0-9A-F]{4}) message=0110 return=pending dialog-msgresult=\S+\r?$')
    if (-not $initialization.Success) { throw 'Missing WM_INITDIALOG guest callback entry.' }
    $callback = $initialization.Groups[1].Value
    $window = $initialization.Groups[2].Value
    $returnPattern = '(?m)^@\d+ window-callback phase=guest-return procedure=dlgproc callback={0} window={1} message=0110 return=DLGPROC16:0001 dialog-msgresult=\S+\r?$' -f $callback, $window
    if ($trace.Substring($initialization.Index + $initialization.Length) -cnotmatch $returnPattern) {
        throw 'Missing the matching WM_INITDIALOG guest return after stack validation.'
    }
    Write-Host 'PASS: generated NE dialog/icon guest exited zero with USER 87/91/111/88 service boundaries and a validated WM_INITDIALOG callback return.'
} finally {
    # No started process needs termination. Once one exists, retain this run's
    # files unless its exit can be verified after any necessary tree cleanup.
    $terminationVerified = $null -eq $process
    if ($null -ne $process) {
        try {
            Stop-OwnedProbe $process
            $terminationVerified = $process.HasExited
        } catch { Write-Warning $_.Exception.Message }
        foreach ($capture in @(@($stdoutRead, $stdoutPath), @($stderrRead, $stderrPath))) {
            try {
                if ($null -ne $capture[0] -and $capture[0].Wait(5000)) {
                    [IO.File]::WriteAllText($capture[1], $capture[0].GetAwaiter().GetResult())
                } else { Write-Warning 'A redirected probe output stream did not finish.' }
            } catch { Write-Warning ("Could not capture probe output: " + $_.Exception.Message) }
        }
        $process.Dispose()
    }
    if ($temporaryDirectoryCreated) {
        # Preserve successful and failing evidence in the workflow log before
        # removing only this run's generated executable and diagnostics.
        try {
            Write-ProbeDiagnostic $stdoutPath 'Generated dialog probe stdout'
            Write-ProbeDiagnostic $stderrPath 'Generated dialog probe stderr'
            Write-ProbeDiagnostic $win16Trace 'Generated dialog probe Win16 trace'
            Write-ProbeDiagnostic $instructionTrace 'Generated dialog probe instruction trace (failure only)'
        } finally {
            if ($terminationVerified) {
                Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force -ErrorAction Continue
            } else {
                Write-Warning "Probe termination could not be verified; diagnostics retained at $temporaryDirectory"
            }
        }
    }
    Set-Location -LiteralPath $originalLocation.Path
}
