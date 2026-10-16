#Requires -Version 7.0
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('x64', 'arm64')][string]$Architecture,
    [Parameter(Mandatory)][ValidateSet('windows-2022', 'windows-11-arm')][string]$RunnerLabel,
    [ValidateRange(1000, 10000000)][int]$InstructionLimit = 100000,
    [ValidateRange(1, 120)][int]$TimeoutSeconds = 30
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
# This guard is a CI capability check, not a security boundary. The disposable
# VM is the boundary: neither Compat16 nor a Job Object is a filesystem sandbox.
if (-not $IsWindows -or $env:GITHUB_ACTIONS -cne 'true' -or
    $env:RUNNER_ENVIRONMENT -cne 'github-hosted' -or $env:RUNNER_OS -cne 'Windows') {
    throw 'BLOCKED: real Win16 diagnostics require a disposable GitHub-hosted Windows runner.'
}
$expected = if ($Architecture -ceq 'x64') { 'X64' } else { 'Arm64' }
$expectedLabel = if ($Architecture -ceq 'x64') { 'windows-2022' } else { 'windows-11-arm' }
if ($RunnerLabel -cne $expectedLabel -or $env:RUNNER_ARCH -ine $expected -or
    [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -cne $expected -or
    [Runtime.InteropServices.RuntimeInformation]::ProcessArchitecture.ToString() -cne $expected) {
    throw 'BLOCKED: the runner label, requested architecture, OS and PowerShell must agree natively.'
}
$repositoryRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$runtimeDirectory = Join-Path $repositoryRoot "dist/$Architecture"
$runtimeFiles = @('compat16.exe', 'compat16w.exe', 'compat16.dll', 'compat16host.exe')
foreach ($name in $runtimeFiles) {
    if (-not (Test-Path -LiteralPath (Join-Path $runtimeDirectory $name) -PathType Leaf)) {
        throw "BLOCKED: missing staged runtime file $name; build with scripts/build.ps1 first."
    }
}
if ([string]::IsNullOrWhiteSpace($env:RUNNER_TEMP) -or -not [IO.Path]::IsPathFullyQualified($env:RUNNER_TEMP)) {
    throw 'BLOCKED: an absolute RUNNER_TEMP directory is required.'
}
$scratch = Join-Path $env:RUNNER_TEMP ('compat16-pfe-' + [Guid]::NewGuid().ToString('N'))
if ($scratch -match '[^\x20-\x7E]' -or $scratch.Contains('"') -or (Test-Path -LiteralPath $scratch)) {
    throw 'BLOCKED: the fresh fixture path must contain only printable ASCII without quotes.'
}
$resultsDirectory = Join-Path $scratch 'results'
$originalDirectory = Join-Path $scratch 'original'
$workingDirectory = Join-Path $scratch 'work'
$rawDirectory = Join-Path $scratch 'raw'
$profileDirectory = Join-Path $scratch 'profile'
foreach ($directory in @($resultsDirectory, $originalDirectory, $workingDirectory, $rawDirectory,
        $profileDirectory, (Join-Path $profileDirectory 'AppData/Roaming'), (Join-Path $profileDirectory 'AppData/Local'))) {
    [void][IO.Directory]::CreateDirectory($directory)
}
# Only this directory is eligible for CI artifact upload; never upload $scratch.
if ($env:GITHUB_OUTPUT) { "results-directory=$resultsDirectory" >> $env:GITHUB_OUTPUT }
Add-Type -Path (Join-Path $PSScriptRoot 'win16-startup/ContainedProcess.cs')
Add-Type -Path (Join-Path $PSScriptRoot 'win16-startup/WindowReadiness.cs')
Import-Module (Join-Path $PSScriptRoot 'win16-startup/pfe-evidence.psm1') -Force
Import-Module (Join-Path $PSScriptRoot 'win16-startup/source-curl.psm1') -Force

$source = 'https://www.lancaster.ac.uk/~steveb/cpaap/pfe/pfe101.zip'
$archiveHash = '75156260f361e3dc88dbbf340edc36369d8f80bac658482b5c680e1da8985288'
$executableHash = '2affadbd7ad74f63311c72b099a73ca536c0980f07b064432e980cfea3a9388f'
$result = [ordered]@{
    fixture = 'PFE 1.01 Win16'; status = 'harness-failed'; scope = 'startup message loop and WndProc responsiveness only'
    architecture = $Architecture; runner = $RunnerLabel; source = $source
    archiveSha256 = $archiveHash; executableSha256 = $executableHash
    instructionLimit = $InstructionLimit; timeoutSeconds = $TimeoutSeconds
    sourceCommit = $env:GITHUB_SHA; exitCode = $null; elapsedMilliseconds = $null
    processTreeCleaned = $false; initTaskCrossing = $false; warnings = @(); error = $null
    sourceOutcome = 'not-attempted'; sourceVerified = $false; sourceAttempts = @()
    sourceDnsObservation = $null; sourceTransportObservation = $null; executionAttempted = $false
    windowObservation = $null; startupEvidence = $null
}
function Protect-ResultText([string]$Text) {
    foreach ($pair in @(@($scratch, '<fixture>'), @($repositoryRoot, '<repository>'),
            @($env:RUNNER_TEMP, '<runner-temp>'), @($env:USERPROFILE, '<runner-profile>'))) {
        if (-not [string]::IsNullOrEmpty($pair[0])) {
            $Text = $Text.Replace($pair[0], $pair[1]).Replace($pair[0].Replace('\', '\\'), $pair[1])
        }
    }
    return $Text
}
function Get-SourceFailure([Exception]$Exception) {
    $tls = $false; $timeout = $false; $dns = $false; $socketError = $null
    # PowerShell's MethodInvocationException and Task's AggregateException can
    # wrap HttpRequestException. Classification never matches localized text.
    for ($cause = $Exception; $null -ne $cause; $cause = $cause.InnerException) {
        if ($cause -is [Security.Authentication.AuthenticationException]) { $tls = $true }
        if ($cause -is [TimeoutException] -or $cause -is [OperationCanceledException]) { $timeout = $true }
        if ($cause -is [Net.Sockets.SocketException]) { $socketError = $cause.SocketErrorCode.ToString() }
        $requestError = $cause.PSObject.Properties['HttpRequestError']
        if ($null -ne $requestError) {
            if ([string]$requestError.Value -eq 'SecureConnectionError') { $tls = $true }
            if ([string]$requestError.Value -eq 'NameResolutionError') { $dns = $true }
        }
    }
    $outcome = 'nonretryable-source-failure'; $retryable = $false
    if ($tls) { $outcome = 'tls-rejected' }
    elseif ($timeout -or $socketError -eq 'TimedOut') { $outcome = 'timeout'; $retryable = $true }
    elseif ($socketError -in @('HostNotFound', 'TryAgain', 'NoData') -or ($dns -and $null -eq $socketError)) {
        $outcome = 'dns-failure'; $retryable = $true
    } elseif ($socketError -in @('NetworkDown', 'NetworkUnreachable', 'NetworkReset',
            'ConnectionAborted', 'ConnectionReset', 'ConnectionRefused', 'HostDown', 'HostUnreachable')) {
        $outcome = 'connection-failure'; $retryable = $true
    }
    # Network exception messages can contain proxy addresses or credentials.
    # Preserve only the typed classification, never the original message/URI.
    $message = "Source failure classified as $outcome; detailed exception text omitted."
    return [pscustomobject]@{ outcome = $outcome; retryable = $retryable
        exceptionType = $Exception.GetType().FullName; socketError = $socketError; error = $message }
}
function Get-SourceDnsObservation {
    $observation = [ordered]@{ host = ([Uri]$source).DnsSafeHost; outcome = 'timeout'
        ipv4Count = 0; ipv6Count = 0; error = $null }
    try {
        # Observe the same system resolver only; never select an address,
        # change DNS/network settings, or use another host for the download.
        $lookup = [Net.Dns]::GetHostAddressesAsync($observation.host)
        if ($lookup.Wait(3000)) {
            $addresses = @($lookup.GetAwaiter().GetResult())
            $observation.outcome = if ($addresses.Count) { 'resolved' } else { 'no-addresses' }
            $observation.ipv4Count = @($addresses | Where-Object AddressFamily -eq InterNetwork).Count
            $observation.ipv6Count = @($addresses | Where-Object AddressFamily -eq InterNetworkV6).Count
        }
        # A timed-out observation does not claim the OS lookup was canceled.
    } catch {
        $failure = Get-SourceFailure $_.Exception
        $observation.outcome = $failure.outcome
        $observation.error = $failure.error
    }
    return $observation
}
function Get-SourceTransportObservation {
    $presence = [ordered]@{}
    # Windows environment names are case-insensitive. Record only state flags;
    # never enumerate the environment or retain/log these values in the receipt.
    foreach ($name in (Get-PfeTransportEnvironmentNames)) {
        $value = [Environment]::GetEnvironmentVariable($name, 'Process')
        $presence[$name] = [ordered]@{ present = $null -ne $value; nonempty = -not [string]::IsNullOrEmpty($value) }
        $value = $null
    }
    $observation = [ordered]@{
        powerShellVersion = $PSVersionTable.PSVersion.ToString()
        dotNetVersion = [Environment]::Version.ToString()
        supportsIPv4 = [Net.Sockets.Socket]::OSSupportsIPv4
        supportsIPv6 = [Net.Sockets.Socket]::OSSupportsIPv6
        environmentVariablePresence = $presence
        defaultProxyRoute = 'timeout'; proxyImplementation = $null
        exceptionType = $null; observationDeadlineMilliseconds = 3000
        alternateTransport = 'not-attempted'; alternateTransportReason = 'equivalent-controls-not-implemented'
    }
    try {
        # Use a managed worker: PAC discovery/GetProxy can block. The worker
        # returns only categorical information, never a proxy URI/credentials.
        # This samples the existing policy without replacing it. A snapshot is
        # not proof of the route taken by a previous or future HTTP request.
        Add-Type -TypeDefinition @'
using System;
using System.Net.Http;
using System.Threading.Tasks;
namespace Compat16.PfeProbe {
    public sealed class SourceRouteObservation {
        public string Route, Implementation, ExceptionType;
    }
    public static class SourceRouting {
        public static Task<SourceRouteObservation> ObserveAsync(string source) {
            return Task.Run(() => {
                var result = new SourceRouteObservation();
                try {
                    var destination = new Uri(source);
                    var proxy = HttpClient.DefaultProxy;
                    string type = proxy.GetType().FullName;
                    result.Implementation = type == "System.Net.Http.HttpEnvironmentProxy" ? "environment" :
                        type == "System.Net.Http.HttpWindowsProxy" ? "windows" : "other";
                    // Windows' proxy can return false from IsBypassed and null
                    // from GetProxy for direct routing. Do not equate false
                    // from IsBypassed alone with an actual proxy selection.
                    bool bypassed = proxy.IsBypassed(destination);
                    Uri selected = bypassed ? null : proxy.GetProxy(destination);
                    result.Route = bypassed || selected == null || selected.Equals(destination) ?
                        "direct-observed" : "proxy-observed";
                } catch (Exception error) {
                    result.Route = "observation-failed";
                    result.ExceptionType = error.GetType().FullName;
                }
                return result;
            });
        }
    }
}
'@
        $lookup = [Compat16.PfeProbe.SourceRouting]::ObserveAsync($source)
        if ($lookup.Wait(3000)) {
            $route = $lookup.GetAwaiter().GetResult()
            $observation.defaultProxyRoute = $route.Route
            $observation.proxyImplementation = $route.Implementation
            $observation.exceptionType = $route.ExceptionType
        }
        # A timeout bounds observation only, not the OS/PAC worker's lifetime.
        # The failure path ends this disposable PowerShell process afterwards.
    } catch {
        $observation.defaultProxyRoute = 'observation-failed'
        $observation.exceptionType = $_.Exception.GetType().FullName
    }
    return $observation
}

try {
    # No redirects, credentials, alternate mirrors, certificate bypass, or
    # unbounded response buffering. Only typed transport/DNS/timeouts retry.
    # Bounded HTTP attempts, observations and one equivalent OS transport
    # leave room for the default 30s guest run inside the 3-minute CI step.
    $archiveBytes = $null
    # Resolve the fixed origin once before opening its HTTPS connection. Cold
    # Windows runners can otherwise report transient NoData while a separate
    # DNS observation immediately succeeds. This only warms the same OS cache;
    # the request still uses the original hostname, routing and TLS checks.
    $result.sourceDnsObservation = Get-SourceDnsObservation
    for ($number = 1; $number -le 3; $number++) {
        $attempt = [ordered]@{ number = $number; source = $source; transport = 'dotnet-http'
            startedUtc = [DateTime]::UtcNow.ToString('o'); elapsedMilliseconds = $null
            outcome = 'requesting'; retryable = $false; httpStatus = $null
            exceptionType = $null; socketError = $null; error = $null }
        $timer = [Diagnostics.Stopwatch]::StartNew()
        $handler = [Net.Http.HttpClientHandler]::new()
        $handler.AllowAutoRedirect = $false
        $handler.UseDefaultCredentials = $false
        $client = [Net.Http.HttpClient]::new($handler)
        $client.Timeout = [TimeSpan]::FromSeconds(15)
        $client.MaxResponseContentBufferSize = 558157
        $response = $null
        try {
            # GetAsync buffers the complete bounded body. The outer timed wait
            # also bounds the caller if a platform DNS cancellation is delayed.
            $request = $client.GetAsync($source)
            if (-not $request.Wait(16000)) { throw [TimeoutException]::new('Source request exceeded its observation deadline.') }
            $response = $request.GetAwaiter().GetResult()
            $attempt.httpStatus = [int]$response.StatusCode
            if ($attempt.httpStatus -ne 200) {
                $attempt.outcome = 'http-rejected'
                throw [IO.InvalidDataException]::new('Source returned an unexpected HTTP status; no redirect or status retry is allowed.')
            }
            if ($response.Content.Headers.ContentLength -ne 558157) {
                $attempt.outcome = 'size-rejected'
                throw 'Source response is not the pinned 558157-byte archive.'
            }
            $archiveBytes = $response.Content.ReadAsByteArrayAsync().GetAwaiter().GetResult()
            $attempt.outcome = 'downloaded'
        } catch {
            $archiveBytes = $null
            $failure = Get-SourceFailure $_.Exception
            if ($attempt.outcome -eq 'requesting') {
                $attempt.outcome = $failure.outcome
                $attempt.retryable = $failure.retryable
            }
            $attempt.exceptionType = $failure.exceptionType
            $attempt.socketError = $failure.socketError
            $attempt.error = $failure.error
        } finally {
            if ($null -ne $response) { $response.Dispose() }
            $client.Dispose()
            $attempt.elapsedMilliseconds = $timer.ElapsedMilliseconds
            $result.sourceAttempts += [pscustomobject]$attempt
            $result.sourceOutcome = $attempt.outcome
            Write-Host ("PFE source attempt {0}/3: {1}" -f $number, $attempt.outcome)
        }
        if ($attempt.outcome -eq 'downloaded') { break }
        if (-not $attempt.retryable -or $number -eq 3) {
            $result.status = if ($attempt.retryable) { 'source-unavailable' } else { 'source-rejected' }
            if ($attempt.retryable) {
                $result.sourceDnsObservation = Get-SourceDnsObservation
                $result.sourceTransportObservation = Get-SourceTransportObservation
            }
            break
        }
        Start-Sleep -Seconds (2 * $number)
    }
    if ($null -eq $archiveBytes -and $attempt.outcome -ceq 'dns-failure') {
        $fallback = Invoke-PfeSystemCurl -Source $source -RawDirectory $rawDirectory -ProfileDirectory $profileDirectory `
            -Observation $result.sourceTransportObservation -FailureOutcome $attempt.outcome
        $result.sourceTransportObservation.alternateTransportReason = $fallback.policy
        if ($fallback.attempted) {
            $result.sourceTransportObservation.alternateTransport = $fallback.transport
            $result.sourceTransportObservation['alternateAddressFamily'] = $fallback.addressFamily
            $result.sourceAttempts += [pscustomobject]@{ number = $result.sourceAttempts.Count + 1; source = $source
                transport = $fallback.transport; elapsedMilliseconds = $fallback.elapsedMilliseconds
                outcome = $fallback.outcome; exitCode = $fallback.exitCode }
            $result.sourceOutcome = $fallback.outcome
            if ($fallback.outcome -ceq 'downloaded') { $archiveBytes = $fallback.bytes }
        }
    }
    if ($null -eq $archiveBytes) {
        $result.status = if ($result.sourceOutcome -in @('dns-failure','connection-failure','timeout','alternate-unavailable')) {
            'source-unavailable'
        } else { 'source-rejected' }
        throw "PFE source retrieval stopped before execution: $($result.sourceOutcome)."
    }
    $archivePath = Join-Path $scratch 'pfe101.zip'
    try { $archiveBytes = Get-PfePinnedArchiveBytes $archiveBytes 558157 $archiveHash }
    catch {
        $result.status = 'source-rejected'; $result.sourceOutcome = 'integrity-rejected'
        throw 'Archive identity mismatch; refusing extraction and execution.'
    }
    [IO.File]::WriteAllBytes($archivePath, $archiveBytes)
    $members = @{
        'CHANGES.TXT' = 89057; 'FAQ.TXT' = 26401; 'FILE.DIZ' = 288
        'PFE.EXE' = 555520; 'PFE.HLP' = 358924; 'PFEDOS.EXE' = 13747
        'PFEDOS.PIF' = 545; 'PROBLEMS.TXT' = 729; 'README.TXT' = 11783; 'YEAR2000.TXT' = 1080
    }
    $zip = [IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
        if ($zip.Entries.Count -ne $members.Count) { throw 'Unexpected archive member count.' }
        $seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
        foreach ($entry in $zip.Entries) {
            $name = $entry.FullName
            if ($name -cnotmatch '^[A-Z0-9]+\.[A-Z0-9]+$' -or -not $members.ContainsKey($name) -or
                -not $seen.Add($name) -or $entry.Length -ne $members[$name]) {
                throw 'Unexpected archive name, duplicate, directory or decompressed size.'
            }
            $inputStream = $entry.Open()
            $outputStream = [IO.File]::Open((Join-Path $originalDirectory $name), [IO.FileMode]::CreateNew)
            try {
                $buffer = [byte[]]::new(8192)
                $total = 0
                while (($count = $inputStream.Read($buffer, 0, $buffer.Length)) -gt 0) {
                    $total += $count
                    if ($total -gt $members[$name]) { throw 'Archive decompression exceeded its member limit.' }
                    $outputStream.Write($buffer, 0, $count)
                }
                if ($total -ne $members[$name]) { throw 'Truncated archive member.' }
            } finally { $inputStream.Dispose(); $outputStream.Dispose() }
        }
    } finally { $zip.Dispose() }
    $originalExe = Join-Path $originalDirectory 'PFE.EXE'
    if ((Get-FileHash -LiteralPath $originalExe).Hash -ine $executableHash) { throw 'PFE.EXE hash mismatch.' }
    $image = [IO.File]::ReadAllBytes($originalExe)
    $ne = [BitConverter]::ToUInt32($image, 0x3C)
    if ($image[0] -ne 0x4D -or $image[1] -ne 0x5A -or $ne -ne 0x400 -or
        $image[$ne] -ne 0x4E -or $image[$ne + 1] -ne 0x45 -or $image[$ne + 0x36] -ne 2 -or
        [BitConverter]::ToUInt16($image, $ne + 0x3E) -ne 0x030A -or
        [BitConverter]::ToUInt16($image, $ne + 0x1C) -ne 100 -or
        [BitConverter]::ToUInt16($image, $ne + 0x16) -ne 98 -or
        [BitConverter]::ToUInt16($image, $ne + 0x14) -ne 0x001A) {
        throw 'PFE.EXE is not the pinned Windows NE image and startup entry.'
    }
    foreach ($name in $members.Keys) {
        [IO.File]::Copy((Join-Path $originalDirectory $name), (Join-Path $workingDirectory $name), $false)
    }
    $result.sourceVerified = $true
    $result.sourceOutcome = 'fixture-verified'

    # Atomic job assignment at creation also covers parent cancellation before
    # CreateProcess returns. The handle allowlist excludes the job/CI handles.
    # Job objects: https://learn.microsoft.com/windows/win32/procthread/job-objects

    $stdout = Join-Path $rawDirectory 'stdout.txt'
    $stderr = Join-Path $rawDirectory 'stderr.txt'
    $failureTrace = Join-Path $rawDirectory 'failure.txt'
    $serviceTrace = Join-Path $rawDirectory 'services.txt'
    $windowsDirectory = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    $systemDirectory = [Environment]::SystemDirectory
    # Construct from an allowlist; do not copy the CI environment and then try
    # to guess token/secret variable names. No stdin or inherited CI handles.
    $childEnvironment = @(
        "SystemRoot=$windowsDirectory", "WINDIR=$windowsDirectory"
        "PATH=$runtimeDirectory;$systemDirectory;$windowsDirectory"
        "COMSPEC=$(Join-Path $systemDirectory 'cmd.exe')", "TEMP=$workingDirectory", "TMP=$workingDirectory"
        "USERPROFILE=$profileDirectory", "HOME=$profileDirectory"
        "APPDATA=$(Join-Path $profileDirectory 'AppData/Roaming')"
        "LOCALAPPDATA=$(Join-Path $profileDirectory 'AppData/Local')", 'RUST_BACKTRACE=1'
    )
    $arguments = @('--max-instructions', [string]$InstructionLimit, '--trace-file', $failureTrace,
        '--trace-win16-io-complete', $serviceTrace, (Join-Path $workingDirectory 'PFE.EXE'))
    $windowProbe = New-Object Compat16.PfeProbe.WindowReadiness
    $probeClock = [Diagnostics.Stopwatch]::StartNew()
    $sequence = [Func[long]]{ Get-PfeTraceSequence (Get-PfeLiveTrace $serviceTrace) }
    $readiness = [Func[IntPtr,int]]{
        param([IntPtr]$job)
        $traceSnapshot = Get-PfeLiveTrace $serviceTrace
        $windowProbe.Observe($job, $probeClock.ElapsedMilliseconds,
            (Get-PfeMessageLoopSeen $traceSnapshot), $sequence)
    }
    # Entering the launch attempt alone is not proof of guest execution.
    $result.executionAttempted = $true
    $run = [Compat16.PfeProbe.ContainedProcess]::Run((Join-Path $runtimeDirectory 'compat16.exe'),
        $arguments, $workingDirectory, $childEnvironment, @($stdout, $stderr, $failureTrace, $serviceTrace),
        $TimeoutSeconds, $readiness)
    $result.windowObservation = [ordered]@{ visibleFrames = $windowProbe.VisibleFrameCount
        visibleDialogs = $windowProbe.VisibleDialogCount; failure = $windowProbe.Failure
        nullProbes = @($windowProbe.Probes.ToArray()) }
    $result.exitCode = $run.ExitCode
    $result.elapsedMilliseconds = $run.ElapsedMilliseconds
    $result.processTreeCleaned = $run.ProcessTreeCleaned
    $result.status = $run.StopReason
    # The last polling sample precedes descendant cleanup. Recheck the stopped
    # tree's complete output before allocating any strings or warning receipts.
    $rawBytes = 0L
    foreach ($path in @($stdout, $stderr, $failureTrace, $serviceTrace)) {
        if (Test-Path -LiteralPath $path -PathType Leaf) { $rawBytes += (Get-Item -LiteralPath $path).Length }
    }
    if ($rawBytes -gt 8MB) { $result.status = 'output-limit' }
    else {
        $errorText = [IO.File]::ReadAllText($stderr)
        $services = if (Test-Path -LiteralPath $serviceTrace) { [IO.File]::ReadAllText($serviceTrace) } else { '' }
        $trace = if (Test-Path -LiteralPath $failureTrace) { [IO.File]::ReadAllText($failureTrace) } else { '' }
        $result.warnings = @($errorText -split '\r?\n' | Where-Object { $_ -match '\[warn/' })
        $evidence = Get-PfeStartupEvidence -SourceVerified $result.sourceVerified -Run $run -WindowProbe $windowProbe `
            -Services $services -Stderr $errorText -FailureTrace $trace -OutputBytes $rawBytes
        $result.initTaskCrossing = $evidence.initTaskCrossing
        $result.startupEvidence = $evidence
        if ($evidence.accepted) { $result.status = 'startup-message-loop-observed' }
        elseif (($errorText + $trace) -match '\[(?:error|critical)/compatibility_gap\]') {
            $result.status = 'compatibility-gap'
        } elseif (($errorText + $trace) -match '\[(?:error|critical)/guest_fault\]') {
            $result.status = 'guest-fault'
        } elseif ($run.StopReason -eq 'exited' -and $run.ExitCode -eq 0) {
            $result.status = 'early-exit-inconclusive'
        } elseif ($run.StopReason -eq 'window-responsive') {
            $result.status = 'window-response-without-guest-evidence'
        }
    }

} catch {
    if ($result.status -notin @('source-unavailable', 'source-rejected')) { $result.status = 'harness-failed' }
    $result.error = Protect-ResultText $_.Exception.Message
} finally {
    # Deliberate text-only allowlist. No ZIP, guest binary/help/license copy,
    # arbitrary generated file, or guest-memory dump enters the artifact folder.
    $artifactBytes = 0L
    foreach ($name in @('stdout.txt', 'stderr.txt', 'failure.txt', 'services.txt')) {
        $path = Join-Path $rawDirectory $name
        try {
            if (Test-Path -LiteralPath $path -PathType Leaf) {
                $length = (Get-Item -LiteralPath $path).Length
                if ($length -le 8MB -and $artifactBytes + $length -le 8MB) {
                    [IO.File]::WriteAllText((Join-Path $resultsDirectory $name),
                        (Protect-ResultText ([IO.File]::ReadAllText($path))), [Text.UTF8Encoding]::new($false))
                    $artifactBytes += $length
                } else {
                    $result.status = 'output-limit'
                    $result.error = 'Diagnostic text exceeded the 8 MiB aggregate artifact limit; oversized files were not copied.'
                }
            }
        } catch {
            $result.status = 'harness-failed'
            $result.error = Protect-ResultText ("Could not preserve $name`: " + $_.Exception.Message)
        }
    }
    $result.warnings = @($result.warnings | ForEach-Object { Protect-ResultText $_ })
    [IO.File]::WriteAllText((Join-Path $resultsDirectory 'result.json'),
        (($result | ConvertTo-Json -Depth 5) + "`n"), [Text.UTF8Encoding]::new($false))
    Write-Host ("PFE Win16 diagnostic: {0}; evidence: {1}" -f $result.status, $resultsDirectory)
    foreach ($warning in $result.warnings) { Write-Host $warning }
}
if ($result.status -ne 'startup-message-loop-observed') {
    throw "PFE Win16 diagnostic did not establish responsive startup: $($result.status). $($result.error)"
}
Write-Host 'Observed a visible owned frame, GetMessage and guest WM_NULL round trips; editing, saving and normal exit remain unvalidated.'
