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

function Assert-ProbeTrace {
    param([string]$Trace, [System.Collections.IDictionary]$ServiceCounts, [int]$InitializationCount)
    # Match the complete trace's @sequence prefix and the actual Display
    # formats in runtime/win16_io_trace.rs and host/windows/win16_io_trace.rs.
    # A DOS stub exiting zero cannot satisfy these NE service/callback checks.
    # Service markers omit arguments/results; the guest asserts those values.
    foreach ($ordinal in $ServiceCounts.Keys) {
        $expectedCount = $ServiceCounts[[string]$ordinal]
        foreach ($stage in @('dispatch-enter', 'dispatch-return')) {
            $pattern = '(?m)^@\d+ service-boundary stage={0} module=USER name=\S+ ordinal={1} instruction=\d+ guest=[0-9A-F]{{4}}:[0-9A-F]{{4}}\r?$' -f $stage, $ordinal
            $observed = [regex]::Matches($Trace, $pattern).Count
            if ($observed -ne $expectedCount) {
                throw "Expected $expectedCount USER ordinal $ordinal $stage markers; observed $observed."
            }
        }
    }
    if ($Trace -cmatch '(?m)^@\d+ service-boundary stage=dispatch-error ') {
        throw 'The Win16 service trace contains a failed dispatch.'
    }
    $callbackPattern = '(?m)^@\d+ window-callback phase={0} procedure=dlgproc callback=(\d+) window=([0-9A-F]{{4}}) message=0110 return=(\S+) dialog-msgresult=\S+\r?$'
    $initializations = [regex]::Matches($Trace, ($callbackPattern -f 'guest-entry'))
    $returns = [regex]::Matches($Trace, ($callbackPattern -f 'guest-return'))
    if ($initializations.Count -ne $InitializationCount -or $returns.Count -ne $InitializationCount) {
        throw "Expected exactly $InitializationCount WM_INITDIALOG entries and returns; observed $($initializations.Count) entries and $($returns.Count) returns."
    }
    $matchedReturns = [Collections.Generic.HashSet[int]]::new()
    foreach ($initialization in $initializations) {
        if ($initialization.Groups[3].Value -cne 'pending') {
            throw 'WM_INITDIALOG entry did not have a pending guest return.'
        }
        $callback = $initialization.Groups[1].Value
        $window = $initialization.Groups[2].Value
        $matchingReturns = @($returns | Where-Object {
            $_.Index -ge ($initialization.Index + $initialization.Length) -and
            $_.Groups[1].Value -ceq $callback -and $_.Groups[2].Value -ceq $window
        })
        if ($matchingReturns.Count -ne 1 -or
            $matchingReturns[0].Groups[3].Value -cne 'DLGPROC16:0001' -or
            -not $matchedReturns.Add($matchingReturns[0].Index)) {
            throw "Missing a unique, matching WM_INITDIALOG guest return after stack validation (callback $callback, window $window)."
        }
    }
    # Numeric HWND bits may be reused between modeless cycles. Match each
    # callback to its return without requiring different window bits per cycle.
}

function Invoke-ProbeCase {
    param(
        [string]$Name,
        [string]$Generator,
        [string]$ProgramName,
        [System.Collections.IDictionary]$ServiceCounts,
        [int]$InitializationCount,
        [string]$RuntimeDirectory,
        [string]$VsDevCmd,
        [string]$VsArchitecture,
        [string]$Cargo,
        [string]$Target
    )
    $temporaryDirectory = Join-Path ([IO.Path]::GetTempPath()) ("compat16-$Name-" + [Guid]::NewGuid().ToString('N'))
    $program = Join-Path $temporaryDirectory $ProgramName
    $instructionTrace = Join-Path $temporaryDirectory 'instructions.log'
    $win16Trace = Join-Path $temporaryDirectory 'win16-io.log'
    $stdoutPath = Join-Path $temporaryDirectory 'stdout.log'
    $stderrPath = Join-Path $temporaryDirectory 'stderr.log'
    $temporaryDirectoryCreated = $false
    $process = $null
    $stdoutRead = $null
    $stderrRead = $null
    $failures = @()
    try {
        New-Item -ItemType Directory -Path $temporaryDirectory | Out-Null
        $temporaryDirectoryCreated = $true
        # build.ps1 restores its environment. Configure MSVC only in each
        # generator subprocess, without changing the caller or installing tools.
        $command = 'call "{0}" -arch={1} -host_arch={1} && "{2}" run --offline --locked --target {3} -p build-tools -- {4} --output "{5}"' -f $VsDevCmd, $VsArchitecture, $Cargo, $Target, $Generator, $program
        & $env:ComSpec /d /c $command
        if ($LASTEXITCODE -ne 0) { throw "Generating the $Name Win16 probe failed." }
        if (-not (Test-Path -LiteralPath $program -PathType Leaf)) { throw "The generator did not produce $ProgramName." }

        $start = [Diagnostics.ProcessStartInfo]::new()
        $start.FileName = Join-Path $RuntimeDirectory 'compat16.exe'
        $start.UseShellExecute = $false
        $start.CreateNoWindow = $true
        $start.WorkingDirectory = $temporaryDirectory
        $start.RedirectStandardOutput = $true
        $start.RedirectStandardError = $true
        foreach ($argument in @('--max-instructions', '1000000', '--trace-file', $instructionTrace, '--trace-win16-io-complete', $win16Trace, $program)) {
            $start.ArgumentList.Add($argument)
        }
        Write-Host "Running the generated $Name NE dialog/icon guest with a 30-second external timeout; no visible windows or input."
        $process = [Diagnostics.Process]::Start($start)
        # Drain both pipes concurrently so diagnostics cannot deadlock the guest.
        $stdoutRead = $process.StandardOutput.ReadToEndAsync()
        $stderrRead = $process.StandardError.ReadToEndAsync()
        if (-not $process.WaitForExit(30000)) {
            throw "The $Name Win16 probe exceeded its 30-second external timeout."
        }
        $exitCode = $process.ExitCode
        Write-Host "Generated $Name guest exit code: $exitCode"
        if ($exitCode -ne 0) { throw "The generated $Name guest failed (exit $exitCode)." }
        if (-not (Test-Path -LiteralPath $win16Trace -PathType Leaf)) {
            throw 'The guest exited without producing its Win16 service/callback trace.'
        }
        Assert-ProbeTrace -Trace (Get-Content -LiteralPath $win16Trace -Raw) -ServiceCounts $ServiceCounts -InitializationCount $InitializationCount
    } catch {
        $failures += $_.Exception.Message
    } finally {
        # Once a process exists, retain this case's files unless its exit and
        # redirected-stream completion are verified after owned-tree cleanup.
        $terminationVerified = $null -eq $process
        if ($null -ne $process) {
            try {
                Stop-OwnedProbe $process
                $terminationVerified = $process.HasExited
            } catch {
                $failures += $_.Exception.Message
                Write-Warning $_.Exception.Message
            }
            foreach ($capture in @(@($stdoutRead, $stdoutPath), @($stderrRead, $stderrPath))) {
                try {
                    if ($null -ne $capture[0] -and $capture[0].Wait(5000)) {
                        [IO.File]::WriteAllText($capture[1], $capture[0].GetAwaiter().GetResult())
                    } else {
                        $terminationVerified = $false
                        throw 'A redirected probe output stream did not finish; process-tree completion is unverified.'
                    }
                } catch {
                    $terminationVerified = $false
                    $failures += ('Could not capture probe output: ' + $_.Exception.Message)
                    Write-Warning $failures[-1]
                }
            }
            $process.Dispose()
        }
        if ($temporaryDirectoryCreated) {
            # Log both cases' service/callback evidence. Instruction traces are
            # verbose and needed only for a failed case, before owned cleanup.
            try {
                Write-ProbeDiagnostic $stdoutPath "Generated $Name probe stdout"
                Write-ProbeDiagnostic $stderrPath "Generated $Name probe stderr"
                Write-ProbeDiagnostic $win16Trace "Generated $Name probe Win16 trace"
                if ($failures.Count -gt 0) {
                    Write-ProbeDiagnostic $instructionTrace "Generated $Name probe instruction trace (failure only)"
                }
            } finally {
                if ($terminationVerified) {
                    Remove-Item -LiteralPath $temporaryDirectory -Recurse -Force -ErrorAction Continue
                } else {
                    Write-Warning "Probe termination could not be verified; diagnostics retained at $temporaryDirectory"
                }
            }
        }
    }
    if ($failures.Count -gt 0) { throw ($failures -join '; ') }
    Write-Host "PASS: generated $Name NE dialog/icon guest exited zero with exact USER service counts and $InitializationCount validated WM_INITDIALOG callback returns."
}

try {
    if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)) {
        throw 'The generated Win16 dialog probes require native Windows AMD64 or ARM64.'
    }
    $architectureName = if ($Architecture -eq 'arm64') { 'arm64' } else { 'x64' }
    $nativeArchitecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
    if ($architectureName -ne $nativeArchitecture) {
        throw 'Run the probes on the selected native Windows architecture.'
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
    $cargo = (Get-Command cargo.exe -CommandType Application -ErrorAction Stop).Source
    $compiler = @(rustc --version --verbose)
    if ($LASTEXITCODE -ne 0 -or $compiler -notcontains "host: $target") {
        throw "The pinned Rust compiler must run natively on $target."
    }
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
    $cases = @(
        @{
            Name = 'modal'
            Generator = 'win16-dialog-probe'
            ProgramName = 'DIALOG.EXE'
            ServiceCounts = [ordered]@{ '87' = 1; '91' = 1; '111' = 1; '88' = 1 }
            InitializationCount = 1
        },
        @{
            Name = 'modeless'
            Generator = 'win16-modeless-probe'
            ProgramName = 'MODELESS.EXE'
            ServiceCounts = [ordered]@{ '89' = 2; '91' = 2; '111' = 2; '174' = 4; '53' = 2; '47' = 2 }
            InitializationCount = 2
        }
    )
    # Modal: GetDlgItem/STM_GETICON and EndDialog result 17. Modeless: two
    # CreateDialog/destroy cycles check immediate IsWindow=false and shared
    # LoadIcon identity survival. Cache equality is a runtime identity regression
    # check, not a universal historical contract. Guests assert arguments/results.
    $failedCases = @()
    foreach ($case in $cases) {
        try {
            Invoke-ProbeCase @case -RuntimeDirectory $runtimeDirectory -VsDevCmd $vsDevCmd -VsArchitecture $vsArchitecture -Cargo $cargo -Target $target
        } catch {
            $failedCases += ($case.Name + ': ' + $_.Exception.Message)
            Write-Warning $failedCases[-1]
        }
    }
    if ($failedCases.Count -gt 0) {
        throw ('Generated Win16 dialog acceptance failed: ' + ($failedCases -join '; '))
    }
} finally {
    Set-Location -LiteralPath $originalLocation.Path
}
