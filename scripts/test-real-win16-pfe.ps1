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

$source = 'https://www.lancaster.ac.uk/~steveb/cpaap/pfe/pfe101.zip'
$archiveHash = '75156260f361e3dc88dbbf340edc36369d8f80bac658482b5c680e1da8985288'
$executableHash = '2affadbd7ad74f63311c72b099a73ca536c0980f07b064432e980cfea3a9388f'
$result = [ordered]@{
    fixture = 'PFE 1.01 Win16'; status = 'harness-failed'; scope = 'startup-prefix only'
    architecture = $Architecture; runner = $RunnerLabel; source = $source
    archiveSha256 = $archiveHash; executableSha256 = $executableHash
    instructionLimit = $InstructionLimit; timeoutSeconds = $TimeoutSeconds
    sourceCommit = $env:GITHUB_SHA; exitCode = $null; elapsedMilliseconds = $null
    processTreeCleaned = $false; initTaskCrossing = $false; warnings = @(); error = $null
    sourceOutcome = 'not-attempted'; sourceVerified = $false; sourceAttempts = @()
    sourceDnsObservation = $null; executionAttempted = $false
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
    $message = Protect-ResultText $Exception.Message
    if ($message.Length -gt 1500) { $message = $message.Substring(0, 1500) }
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

try {
    # No redirects, credentials, alternate mirrors, certificate bypass, or
    # unbounded response buffering. Only typed transport/DNS/timeouts retry.
    # Three <=16s observed attempts + 2/4s delays + one <=3s DNS observation
    # leave room for the default 30s guest run inside the 3-minute CI step.
    $archiveBytes = $null
    for ($number = 1; $number -le 3; $number++) {
        $attempt = [ordered]@{ number = $number; source = $source
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
            if ($attempt.retryable) { $result.sourceDnsObservation = Get-SourceDnsObservation }
            throw "PFE source retrieval stopped before execution: $($attempt.outcome). $($attempt.error)"
        }
        Start-Sleep -Seconds (2 * $number)
    }
    $archivePath = Join-Path $scratch 'pfe101.zip'
    [IO.File]::WriteAllBytes($archivePath, $archiveBytes)
    if ($archiveBytes.Length -ne 558157 -or (Get-FileHash -LiteralPath $archivePath).Hash -ine $archiveHash) {
        $result.status = 'source-rejected'; $result.sourceOutcome = 'integrity-rejected'
        throw 'Archive identity mismatch; refusing extraction and execution.'
    }
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
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;
namespace Compat16.PfeProbe {
    public sealed class Outcome {
        public uint ExitCode; public long ElapsedMilliseconds; public string StopReason;
        public bool ProcessTreeCleaned;
    }
    public static class ContainedProcess {
        [StructLayout(LayoutKind.Sequential)] struct Security {
            public int Length; public IntPtr Descriptor; public int Inherit;
        }
        [StructLayout(LayoutKind.Sequential, CharSet=CharSet.Unicode)] struct Startup {
            public int Size; public string Reserved, Desktop, Title;
            public uint X, Y, XSize, YSize, XCountChars, YCountChars, FillAttribute, Flags;
            public ushort ShowWindow, ReservedSize; public IntPtr ReservedBytes, Input, Output, Error;
        }
        [StructLayout(LayoutKind.Sequential)] struct StartupEx { public Startup Startup; public IntPtr Attributes; }
        [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr Process, Thread; public uint ProcessId, ThreadId; }
        [StructLayout(LayoutKind.Sequential)] struct BasicLimit {
            public long ProcessTime, JobTime; public uint Flags;
            public UIntPtr MinimumWorkingSet, MaximumWorkingSet; public uint ActiveProcessLimit;
            public UIntPtr Affinity; public uint PriorityClass, SchedulingClass;
        }
        [StructLayout(LayoutKind.Sequential)] struct IoCounters { public ulong A, B, C, D, E, F; }
        [StructLayout(LayoutKind.Sequential)] struct ExtendedLimit {
            public BasicLimit Basic; public IoCounters Io;
            public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
        }
        [StructLayout(LayoutKind.Sequential)] struct Accounting {
            public long UserTime, KernelTime, PeriodUserTime, PeriodKernelTime;
            public uint PageFaults, TotalProcesses, ActiveProcesses, TerminatedProcesses;
        }
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateJobObjectW(IntPtr attributes, string name);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref ExtendedLimit info, uint size);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool QueryInformationJobObject(IntPtr job, int infoClass, out Accounting info, uint size, IntPtr returned);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateJobObject(IntPtr job, uint code);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool TerminateProcess(IntPtr process, uint code);
        [DllImport("kernel32.dll", SetLastError=true)] static extern uint ResumeThread(IntPtr thread);
        [DllImport("kernel32.dll", SetLastError=true)] static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool GetExitCodeProcess(IntPtr process, out uint code);
        [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern IntPtr CreateFileW(string path, uint access, uint share, ref Security security, uint creation, uint flags, IntPtr template);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, uint flags, ref IntPtr size);
        [DllImport("kernel32.dll", SetLastError=true)] static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attribute, IntPtr value, IntPtr size, IntPtr previous, IntPtr returned);
        [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)] static extern bool CreateProcessW(string app, StringBuilder command, IntPtr processAttributes, IntPtr threadAttributes, bool inherit, uint flags, IntPtr environment, string directory, ref StartupEx startup, out ProcessInfo process);
        static void Check(bool ok, string operation) { if (!ok) throw new Win32Exception(Marshal.GetLastWin32Error(), operation); }
        static string Quote(string value) {
            var text = new StringBuilder("\""); int slashes = 0;
            foreach (char c in value) {
                if (c == '\\') { slashes++; continue; }
                text.Append('\\', c == '"' ? slashes * 2 + 1 : slashes); text.Append(c); slashes = 0;
            }
            return text.Append('\\', slashes * 2).Append('"').ToString();
        }
        public static Outcome Run(string executable, string[] args, string directory,
                string[] environment, string[] outputPaths, int timeoutSeconds) {
            var outcome = new Outcome(); var handles = new List<IntPtr>();
            IntPtr job = IntPtr.Zero, attributes = IntPtr.Zero, handleList = IntPtr.Zero, jobList = IntPtr.Zero, env = IntPtr.Zero;
            var pi = new ProcessInfo(); bool initialized = false, assigned = false;
            var timer = new Stopwatch();
            try {
                job = CreateJobObjectW(IntPtr.Zero, null); Check(job != IntPtr.Zero, "CreateJobObject");
                var limits = new ExtendedLimit();
                limits.Basic.Flags = 0x2000; // KILL_ON_JOB_CLOSE, with neither breakaway flag.
                Check(SetInformationJobObject(job, 9, ref limits, (uint)Marshal.SizeOf<ExtendedLimit>()), "SetInformationJobObject");
                var security = new Security { Length = Marshal.SizeOf<Security>(), Inherit = 1 };
                foreach (string path in new [] { "NUL", outputPaths[0], outputPaths[1] }) {
                    bool input = path == "NUL";
                    IntPtr handle = CreateFileW(path, input ? 0x80000000u : 0x40000000u, 3,
                        ref security, input ? 3u : 1u, 0x80, IntPtr.Zero);
                    Check(handle != new IntPtr(-1), "Create redirected standard handle"); handles.Add(handle);
                }
                IntPtr size = IntPtr.Zero;
                InitializeProcThreadAttributeList(IntPtr.Zero, 2, 0, ref size);
                if (size == IntPtr.Zero) throw new InvalidOperationException("No process attribute-list size.");
                attributes = Marshal.AllocHGlobal(size);
                Check(InitializeProcThreadAttributeList(attributes, 2, 0, ref size), "InitializeProcThreadAttributeList"); initialized = true;
                handleList = Marshal.AllocHGlobal(IntPtr.Size * handles.Count);
                for (int i = 0; i < handles.Count; i++) Marshal.WriteIntPtr(handleList, i * IntPtr.Size, handles[i]);
                Check(UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x20002), handleList,
                    new IntPtr(IntPtr.Size * handles.Count), IntPtr.Zero, IntPtr.Zero), "Set inherited handle allowlist");
                // PROC_THREAD_ATTRIBUTE_JOB_LIST (Windows 10+): assignment is
                // part of process creation, leaving no uncontained orphan gap.
                jobList = Marshal.AllocHGlobal(IntPtr.Size); Marshal.WriteIntPtr(jobList, job);
                Check(UpdateProcThreadAttribute(attributes, 0, new IntPtr(0x2000D), jobList,
                    new IntPtr(IntPtr.Size), IntPtr.Zero, IntPtr.Zero), "Set atomic process job membership");
                Array.Sort(environment, StringComparer.OrdinalIgnoreCase);
                env = Marshal.StringToHGlobalUni(string.Join("\0", environment) + "\0\0");
                var startup = new StartupEx { Attributes = attributes };
                startup.Startup.Size = Marshal.SizeOf<StartupEx>(); startup.Startup.Flags = 0x100;
                startup.Startup.Input = handles[0]; startup.Startup.Output = handles[1]; startup.Startup.Error = handles[2];
                var command = new StringBuilder(Quote(executable));
                foreach (string arg in args) command.Append(' ').Append(Quote(arg));
                // Suspended + Unicode environment + extended startup + no console.
                Check(CreateProcessW(executable, command, IntPtr.Zero, IntPtr.Zero, true,
                    0x08080404, env, directory, ref startup, out pi), "Create suspended launcher");
                assigned = true;
                timer.Start(); Check(ResumeThread(pi.Thread) != uint.MaxValue, "Resume launcher");
                while (true) {
                    uint wait = WaitForSingleObject(pi.Process, 100);
                    Check(wait != uint.MaxValue, "Wait for launcher");
                    long bytes = 0;
                    foreach (string path in outputPaths) if (File.Exists(path)) bytes += new FileInfo(path).Length;
                    if (bytes > 8 * 1024 * 1024) { outcome.StopReason = "output-limit"; break; }
                    if (wait == 0) { outcome.StopReason = "exited"; break; }
                    if (timer.Elapsed.TotalSeconds >= timeoutSeconds) { outcome.StopReason = "timeout"; break; }
                }
                outcome.ElapsedMilliseconds = timer.ElapsedMilliseconds;
                if (outcome.StopReason != "exited") Check(TerminateJobObject(job, 125), "Terminate bounded process tree");
                Check(WaitForSingleObject(pi.Process, 5000) == 0, "Wait for terminated launcher");
                Check(GetExitCodeProcess(pi.Process, out outcome.ExitCode), "Get launcher exit code");
            } finally {
                try {
                    if (assigned) {
                        // Also reap helpers left behind after normal launcher exit.
                        Check(TerminateJobObject(job, 125), "Clean up process tree");
                        var cleanup = Stopwatch.StartNew();
                        while (true) {
                            Accounting accounting;
                            Check(QueryInformationJobObject(job, 1, out accounting, (uint)Marshal.SizeOf<Accounting>(), IntPtr.Zero), "Verify process-tree cleanup");
                            if (accounting.ActiveProcesses == 0) { outcome.ProcessTreeCleaned = true; break; }
                            if (cleanup.Elapsed.TotalSeconds >= 5) throw new InvalidOperationException("Process-tree cleanup did not complete.");
                            Thread.Sleep(50);
                        }
                    } else if (pi.Process != IntPtr.Zero) {
                        Check(TerminateProcess(pi.Process, 125), "Terminate unassigned suspended launcher");
                        Check(WaitForSingleObject(pi.Process, 5000) == 0, "Wait for unassigned launcher cleanup");
                    }
                } finally {
                    if (job != IntPtr.Zero) CloseHandle(job); // kill-on-close fallback, including exceptional exits
                    if (pi.Thread != IntPtr.Zero) CloseHandle(pi.Thread);
                    if (pi.Process != IntPtr.Zero) CloseHandle(pi.Process);
                    foreach (IntPtr handle in handles) CloseHandle(handle);
                    if (initialized) DeleteProcThreadAttributeList(attributes);
                    if (attributes != IntPtr.Zero) Marshal.FreeHGlobal(attributes);
                    if (handleList != IntPtr.Zero) Marshal.FreeHGlobal(handleList);
                    if (jobList != IntPtr.Zero) Marshal.FreeHGlobal(jobList);
                    if (env != IntPtr.Zero) Marshal.FreeHGlobal(env);
                }
            }
            return outcome;
        }
    }
}
'@
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
        '--trace-win16-io', $serviceTrace, (Join-Path $workingDirectory 'PFE.EXE'))
    # True means entering the launch attempt, not proof guest instructions ran.
    $result.executionAttempted = $true
    $run = [Compat16.PfeProbe.ContainedProcess]::Run((Join-Path $runtimeDirectory 'compat16.exe'),
        $arguments, $workingDirectory, $childEnvironment, @($stdout, $stderr, $failureTrace, $serviceTrace), $TimeoutSeconds)
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
    if ($result.status -eq 'exited') {
        $errorText = [IO.File]::ReadAllText($stderr)
        $services = if (Test-Path -LiteralPath $serviceTrace) { [IO.File]::ReadAllText($serviceTrace) } else { '' }
        $trace = if (Test-Path -LiteralPath $failureTrace) { [IO.File]::ReadAllText($failureTrace) } else { '' }
        $result.warnings = @($errorText -split '\r?\n' | Where-Object { $_ -match '\[warn/' })
        # The InitTask register-context handler completes synchronously. Other
        # dispatch-return rows may merely transfer control into a guest callback.
        $entryPattern = '(?m)^[#@]\d+ service-boundary stage=dispatch-enter module=KERNEL name=InitTask ordinal=91 instruction=(\d+) guest=([0-9A-F]{4}:[0-9A-F]{4})\r?$'
        $entry = [regex]::Match($services, $entryPattern)
        if ($entry.Success) {
            $returnPattern = '(?m)^[#@]\d+ service-boundary stage=dispatch-return module=KERNEL name=InitTask ordinal=91 instruction=' +
                [regex]::Escape($entry.Groups[1].Value) + ' guest=' + [regex]::Escape($entry.Groups[2].Value) + '\r?$'
            $result.initTaskCrossing = [regex]::IsMatch($services.Substring($entry.Index + $entry.Length), $returnPattern)
        }
        $terminalPattern = '(?m)^runtime: \[warn/execution_limit\] after ' + $InstructionLimit +
            ' instructions, CS:IP=[0-9A-F]{4}:[0-9A-F]{4}: Win16 instruction budget exhausted\r?$'
        $savedPattern = '(?m)^\[warn/execution_limit\] after ' + $InstructionLimit +
            ' instructions, CS:IP=[0-9A-F]{4}:[0-9A-F]{4}: Win16 instruction budget exhausted\r?$'
        $badEvidence = ($errorText + "`n" + $trace) -match '\[(?:error|critical)/|\[warn/(?:host_failure|internal_invariant)\]' -or
            $services -match 'service-boundary stage=dispatch-error'
        if ($run.ExitCode -eq 125 -and $run.ProcessTreeCleaned -and $result.initTaskCrossing -and
            $errorText -match $terminalPattern -and $trace -match $savedPattern -and -not $badEvidence) {
            $result.status = 'startup-prefix-observed'
        } elseif (($errorText + $trace) -match '\[(?:error|critical)/compatibility_gap\]') {
            $result.status = 'compatibility-gap'
        } elseif (($errorText + $trace) -match '\[(?:error|critical)/guest_fault\]') {
            $result.status = 'guest-fault'
        } elseif ($run.ExitCode -eq 0) {
            $result.status = 'early-exit-inconclusive'
        } else { $result.status = 'runtime-failed-or-evidence-incomplete' }
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
if ($result.status -ne 'startup-prefix-observed') {
    throw "PFE Win16 diagnostic did not establish the startup prefix: $($result.status). $($result.error)"
}
Write-Host 'Observed the bounded startup prefix and InitTask crossing only; application compatibility is not established.'
