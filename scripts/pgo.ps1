[CmdletBinding()]
param(
    [ValidateSet('Collect', 'Merge')][string]$Action,
    [ValidateSet('arm64', 'amd64', 'x64')][string]$Architecture,
    [ValidateSet('console', 'windowed')][string]$Launcher = 'console',
    [string]$GuestPath,
    [string[]]$GuestArguments = @(),
    [string[]]$RuntimeArguments = @(),
    [ValidatePattern('^[A-Za-z0-9._-]{1,64}$')][string]$Workload = 'workload',
    [int]$ExpectedExitCode = 0,
    [switch]$Library
)

function Get-PgoHash {
    param([string]$Text)
    $algorithm = [Security.Cryptography.SHA256]::Create()
    try {
        return ([BitConverter]::ToString($algorithm.ComputeHash([Text.Encoding]::UTF8.GetBytes($Text)))).Replace('-', '').ToLowerInvariant()
    } finally { $algorithm.Dispose() }
}

function Write-PgoJson {
    param([string]$Path, $Value)
    $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.tmp'
    [IO.File]::WriteAllText($temporary, ((ConvertTo-Json -InputObject $Value -Depth 8) + "`n"), [Text.UTF8Encoding]::new($false))
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Get-PgoSourceHash {
    param([string]$Root)
    $files = @('Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'scripts/build.ps1', 'scripts/pgo.ps1') |
        ForEach-Object { Get-Item -LiteralPath (Join-Path $Root $_) }
    foreach ($directory in @('crates', 'build-support', 'assets', '.cargo')) {
        $path = Join-Path $Root $directory
        if (Test-Path -LiteralPath $path) { $files += @(Get-ChildItem -LiteralPath $path -File -Recurse) }
    }
    $entries = @($files | Sort-Object FullName | ForEach-Object {
        $_.FullName.Substring($Root.Length + 1).Replace('\', '/') + ':' + (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash
    })
    return Get-PgoHash ($entries -join "`n")
}

function Invoke-PgoTool {
    param([string]$Executable, [string[]]$Arguments)
    # Windows PowerShell 5.1 treats a native stderr line as an error record.
    $preference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $Executable @Arguments 2>&1)
        $code = $LASTEXITCODE
    } finally { $ErrorActionPreference = $preference }
    if ($code -ne 0) {
        $diagnostic = ($output | Select-Object -First 8 | ForEach-Object { [string]$_ }) -join "`n"
        foreach ($prefix in @([IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..')), [Environment]::GetFolderPath('UserProfile'))) {
            if ($prefix) { $diagnostic = $diagnostic.Replace($prefix, '<build>') }
        }
        throw "PGO tool failed (exit $code): $($Arguments[0]).`n$diagnostic"
    }
    return ($output | ForEach-Object { [string]$_ }) -join "`n"
}

function Get-PgoTools {
    param([string]$Rustc, [string]$Sysroot, [string]$Target)
    $version = Invoke-PgoTool $Rustc @('-vV')
    if ($version -notmatch '(?m)^release: 1\.99\.0\r?$') { throw 'PGO requires the pinned Rust 1.99.0 release.' }
    if ($version -notmatch '(?m)^host: (\S+)') { throw 'Could not determine the PGO compiler host.' }
    $profdata = Join-Path $Sysroot ('lib\rustlib\' + $Matches[1] + '\bin\llvm-profdata.exe')
    if (-not (Test-Path -LiteralPath $profdata -PathType Leaf)) {
        throw 'PGO requires llvm-tools-preview in the selected Rust 1.99.0 installation; see the README PGO instructions.'
    }
    $libraries = Join-Path $Sysroot ('lib\rustlib\' + $Target + '\lib')
    if (@(Get-ChildItem -LiteralPath $libraries -Filter 'libprofiler_builtins-*.rlib' -ErrorAction SilentlyContinue).Count -eq 0) {
        throw "The selected Rust distribution has no profiler runtime for $Target. A regular release build remains available."
    }
    $toolVersion = Invoke-PgoTool $profdata @('--version')
    return [pscustomobject]@{ rustc = $version; llvmProfdata = $profdata; toolSha256 = (Get-FileHash -LiteralPath $profdata -Algorithm SHA256).Hash; toolVersion = $toolVersion }
}

function Get-PgoBuildIdentity {
    param([string]$Root, [string]$Target, $Tools, [string]$Cargo, [string]$Flags, [object[]]$Remaps, [string]$VsDevCmd, [string]$CargoHome)
    if ($env:RUSTC_WRAPPER -or $env:RUSTC_WORKSPACE_WRAPPER) { throw 'PGO does not support external rustc wrappers.' }
    if ($Flags -match 'profile-(generate|use|sample-use)|instrument-coverage') { throw 'Remove external instrumentation or profile flags before using the PGO workflow.' }
    $canonicalFlags = $Flags
    foreach ($remap in $Remaps) { $canonicalFlags = $canonicalFlags.Replace($remap.source, $remap.target) }
    $settings = @(Get-ChildItem Env: | Where-Object { $_.Name -like 'CARGO_PROFILE_*' -or $_.Name -like 'CARGO_TARGET_*' } |
        Sort-Object Name | ForEach-Object { $_.Name + '=' + $_.Value })
    # Cargo also reads configuration outside the checkout. Hash it without
    # recording account paths or the contents in a portable receipt.
    $configuration = @()
    $directory = Get-Item -LiteralPath $Root
    while ($null -ne $directory) {
        $configuration += Join-Path $directory.FullName '.cargo\config'
        $configuration += Join-Path $directory.FullName '.cargo\config.toml'
        $directory = $directory.Parent
    }
    $configuration += Join-Path $CargoHome 'config'
    $configuration += Join-Path $CargoHome 'config.toml'
    $configHashes = @($configuration | ForEach-Object {
        if (Test-Path -LiteralPath $_ -PathType Leaf) { (Get-FileHash -LiteralPath $_ -Algorithm SHA256).Hash } else { '-' }
    })
    $buildSettings = @($canonicalFlags, ($settings -join "`n"), ($configHashes -join "`n"), (Get-FileHash -LiteralPath $VsDevCmd -Algorithm SHA256).Hash)
    return [pscustomobject][ordered]@{
        target = $Target
        sourceSha256 = Get-PgoSourceHash $Root
        rustcSha256 = Get-PgoHash $Tools.rustc
        cargoSha256 = Get-PgoHash (Invoke-PgoTool $Cargo @('--version'))
        llvmProfdataSha256 = $Tools.toolSha256
        buildSettingsSha256 = Get-PgoHash ($buildSettings -join "`n")
    }
}

function Assert-PgoIdentity {
    param($Recorded, $Current)
    foreach ($key in @('target', 'sourceSha256', 'rustcSha256', 'cargoSha256', 'llvmProfdataSha256', 'buildSettingsSha256')) {
        if (-not $Recorded.$key -or $Recorded.$key -cne $Current.$key) { throw "PGO profile is stale or incompatible ($key changed). Generate and collect a new session." }
    }
}

function Get-PgoSession {
    param([string]$Root, [string]$Architecture)
    $base = Join-Path $Root ('target\pgo\' + $Architecture)
    $pointer = Get-Content -LiteralPath (Join-Path $base 'current.json') -Raw | ConvertFrom-Json
    if ($pointer.session -notmatch '^[a-f0-9]{32}$') { throw 'Invalid PGO session identifier.' }
    $directory = Join-Path $base ('sessions\' + $pointer.session)
    $metadata = Get-Content -LiteralPath (Join-Path $directory 'session.json') -Raw | ConvertFrom-Json
    if ($metadata.schema -ne 1 -or $metadata.session -cne $pointer.session -or $metadata.architecture -cne $Architecture) { throw 'Invalid PGO session metadata.' }
    return [pscustomobject]@{ directory = $directory; metadata = $metadata }
}

function Get-PgoCollectionHash {
    param([string]$Directory)
    $entries = @(Get-ChildItem -Path (Join-Path $Directory 'raw\*\run.json') -File -ErrorAction SilentlyContinue |
        Sort-Object FullName | ForEach-Object { $_.Directory.Name + ':' + (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash })
    return Get-PgoHash ($entries -join "`n")
}

function Get-PgoBinaryReceipt {
    param([string]$Directory, [string]$Architecture)
    $machine = if ($Architecture -eq 'arm64') { 0xaa64 } else { 0x8664 }
    return @(@('compat16.exe', 'compat16w.exe', 'compat16.dll', 'compat16host.exe') | ForEach-Object {
        $path = Join-Path $Directory $_
        $stream = [IO.File]::OpenRead($path)
        $reader = [IO.BinaryReader]::new($stream)
        try {
            if ($reader.ReadUInt16() -ne 0x5a4d) { throw "Invalid PGO PE file: $_" }
            $stream.Position = 0x3c
            $offset = $reader.ReadUInt32()
            $stream.Position = $offset
            if ($reader.ReadUInt32() -ne 0x4550 -or $reader.ReadUInt16() -ne $machine) { throw "PGO PE architecture mismatch: $_" }
        } finally { $reader.Dispose() }
        [pscustomobject]@{ file = $_; sha256 = (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash }
    })
}

function Assert-PgoBinaries {
    param($Session)
    $current = Get-PgoBinaryReceipt (Join-Path $Session.directory 'runtime') $Session.metadata.architecture
    if ((ConvertTo-Json -InputObject $current -Compress) -cne (ConvertTo-Json -InputObject $Session.metadata.binaries -Compress)) { throw 'Instrumented PGO runtime files changed after generation.' }
}

function Get-PgoModules {
    param([string]$Profdata, [string]$Profile)
    # --covered excludes zero-count functions. Match the Rust crate component
    # in either mangling format, plus the DLL's explicit ABI entrypoint.
    $names = Invoke-PgoTool $Profdata @('show', '--all-functions', '--covered', $Profile)
    $patterns = [ordered]@{
        'compat16.exe' = '(8compat16(?:4main|::)|compat16::main)'
        'compat16w.exe' = '(9compat16w(?:4main|::)|compat16w::main)'
        'compat16.dll' = '(6engine|engine::|compat16_entry_v1)'
        'compat16host.exe' = '(12compat16host|compat16host::)'
    }
    return @($patterns.Keys | Where-Object { $names -match $patterns[$_] })
}

function ConvertTo-PgoWindowsArgument {
    param([string]$Value)
    # CommandLineToArgvW quoting, including trailing backslashes before quotes.
    $quoted = [Text.StringBuilder]::new('"')
    $slashes = 0
    foreach ($character in $Value.ToCharArray()) {
        if ($character -eq '\') { $slashes++; continue }
        if ($character -eq '"') {
            [void]$quoted.Append(('\' * (2 * $slashes + 1)) + '"')
        } else { [void]$quoted.Append(('\' * $slashes) + $character) }
        $slashes = 0
    }
    [void]$quoted.Append(('\' * (2 * $slashes)) + '"')
    return $quoted.ToString()
}

if ($Library) { return }
$ErrorActionPreference = 'Stop'
try {
    if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)) { throw 'PGO collection and merging require Windows ARM64 or AMD64.' }
    if (-not $Architecture -or -not $Action) { throw 'Specify -Action Collect or Merge and -Architecture arm64 or amd64.' }
    $pgoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    $pgoArch = if ($Architecture -eq 'arm64') { 'arm64' } else { 'x64' }
    $pgoTarget = if ($pgoArch -eq 'arm64') { 'aarch64-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }
    $pgoSession = Get-PgoSession $pgoRoot $pgoArch
    if ($pgoSession.metadata.identity.target -cne $pgoTarget -or $pgoSession.metadata.identity.sourceSha256 -cne (Get-PgoSourceHash $pgoRoot)) { throw 'PGO session architecture or source changed. Generate a new session.' }
    Assert-PgoBinaries $pgoSession
    # Generation records the exact tool binary; merging never searches PATH
    # for a possibly incompatible LLVM raw-profile reader.
    $pgoToolCandidates = @()
    $pgoLocalRustc = Join-Path $pgoRoot '.dev\cargo\bin\rustc.exe'
    if (Test-Path -LiteralPath $pgoLocalRustc -PathType Leaf) {
        $pgoToolCandidates += @(Get-ChildItem -Path (Join-Path $pgoRoot '.dev\rustup\toolchains\1.99.0-*\lib\rustlib\*\bin\llvm-profdata.exe') -ErrorAction SilentlyContinue)
    }
    $pgoTool = $pgoToolCandidates | Where-Object { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash -ceq $pgoSession.metadata.identity.llvmProfdataSha256 } | Select-Object -First 1
    $pgoRustc = Get-Command rustc.exe -CommandType Application -ErrorAction SilentlyContinue
    if (-not $pgoTool -and $pgoRustc) {
        $pgoOldToolchain = $env:RUSTUP_TOOLCHAIN
        try {
            $env:RUSTUP_TOOLCHAIN = '1.99.0'
            $pgoSysroot = Invoke-PgoTool $pgoRustc.Source @('--print', 'sysroot')
            $pgoToolCandidates += @(Get-ChildItem -Path (Join-Path $pgoSysroot 'lib\rustlib\*\bin\llvm-profdata.exe') -ErrorAction SilentlyContinue)
        } finally { $env:RUSTUP_TOOLCHAIN = $pgoOldToolchain }
    }
    $pgoTool = $pgoToolCandidates | Where-Object { (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash -ceq $pgoSession.metadata.identity.llvmProfdataSha256 } | Select-Object -First 1
    if (-not $pgoTool) { throw 'The exact llvm-profdata used for generation is unavailable. Restore the selected Rust llvm-tools-preview component or generate a new session.' }

    if ($Action -eq 'Collect') {
        if (-not $GuestPath -or -not (Test-Path -LiteralPath $GuestPath -PathType Leaf)) { throw 'Collect requires -GuestPath pointing to an existing legacy executable.' }
        $pgoRun = [Guid]::NewGuid().ToString('N')
        $pgoRunDirectory = Join-Path $pgoSession.directory ('raw\' + $pgoRun)
        # LLVM's Windows profile writer uses CreateFileA and narrow CRT paths.
        # Reject an unrepresentable output path before launching the guest.
        $pgoCodePage = [int](Get-ItemPropertyValue -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\Nls\CodePage' -Name ACP)
        $pgoEncoding = [Text.Encoding]::GetEncoding($pgoCodePage, [Text.EncoderExceptionFallback]::new(), [Text.DecoderExceptionFallback]::new())
        try { [void]$pgoEncoding.GetBytes($pgoRunDirectory) }
        catch { throw 'The PGO output path is not representable in the Windows ANSI code page. Use a compatible checkout path for collection.' }
        New-Item -ItemType Directory -Path $pgoRunDirectory -Force | Out-Null
        $pgoExecutable = if ($Launcher -eq 'console') { 'compat16.exe' } else { 'compat16w.exe' }
        $pgoStart = [Diagnostics.ProcessStartInfo]::new()
        $pgoStart.FileName = Join-Path $pgoSession.directory ('runtime\' + $pgoExecutable)
        $pgoStart.UseShellExecute = $false
        $pgoStart.WorkingDirectory = (Get-Location).Path
        $pgoStart.Arguments = (@($RuntimeArguments + @((Resolve-Path -LiteralPath $GuestPath).Path) + $GuestArguments) | ForEach-Object { ConvertTo-PgoWindowsArgument $_ }) -join ' '
        $pgoStart.EnvironmentVariables['LLVM_PROFILE_FILE'] = Join-Path $pgoRunDirectory '%m-%p.profraw'
        Write-Host ('[INFO] Collecting {0} with {1}; close the guest normally to finish.' -f $Workload, $pgoExecutable) -ForegroundColor Cyan
        $pgoProcess = [Diagnostics.Process]::Start($pgoStart)
        try { $pgoProcess.WaitForExit(); $pgoExit = $pgoProcess.ExitCode } finally { $pgoProcess.Dispose() }
        if ($pgoExit -ne $ExpectedExitCode) { throw "Training exited with $pgoExit, expected $ExpectedExitCode. This run will not be merged." }
        $pgoRawFiles = @(Get-ChildItem -LiteralPath $pgoRunDirectory -Filter '*.profraw' -File)
        $pgoModules = @()
        $pgoProfiles = @($pgoRawFiles | Sort-Object Name | ForEach-Object {
            $modules = @(Get-PgoModules $pgoTool.FullName $_.FullName)
            $pgoModules += $modules
            [pscustomobject]@{ file = $_.Name; sha256 = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash; modules = $modules }
        })
        if ($pgoModules -notcontains 'compat16.dll' -or $pgoModules -notcontains $pgoExecutable) { throw 'Training did not produce covered functions for both the selected launcher and the engine DLL. This run will not be merged.' }
        if ($pgoSession.metadata.identity.sourceSha256 -cne (Get-PgoSourceHash $pgoRoot)) { throw 'Source changed during training; generate a new session.' }
        Write-PgoJson (Join-Path $pgoRunDirectory 'run.json') ([pscustomobject]@{ schema = 1; session = $pgoSession.metadata.session; run = $pgoRun; workload = $Workload; launcher = $pgoExecutable; exitCode = $pgoExit; profiles = $pgoProfiles })
        Write-Host ('[ OK ] Collected {0} profiles; observed: {1}.' -f $pgoProfiles.Count, (($pgoModules | Sort-Object -Unique) -join ', ')) -ForegroundColor Green
    } else {
        $pgoInputs = @()
        $pgoInputHashes = @{}
        $pgoCoveredModules = @()
        $pgoCollectionHash = Get-PgoCollectionHash $pgoSession.directory
        $pgoReceipts = @(Get-ChildItem -Path (Join-Path $pgoSession.directory 'raw\*\run.json') -File -ErrorAction SilentlyContinue)
        foreach ($pgoReceipt in $pgoReceipts) {
            $pgoRunMetadata = Get-Content -LiteralPath $pgoReceipt.FullName -Raw | ConvertFrom-Json
            if ($pgoRunMetadata.schema -ne 1 -or $pgoRunMetadata.session -cne $pgoSession.metadata.session -or $pgoRunMetadata.run -cne $pgoReceipt.Directory.Name) { throw 'Invalid PGO collection receipt.' }
            foreach ($pgoProfile in $pgoRunMetadata.profiles) {
                if ($pgoProfile.file -notmatch '^[0-9_]+-[0-9]+\.profraw$') { throw 'Invalid raw profile filename in collection receipt.' }
                $pgoInput = Join-Path $pgoReceipt.Directory.FullName $pgoProfile.file
                if ((Get-FileHash -LiteralPath $pgoInput -Algorithm SHA256).Hash -cne $pgoProfile.sha256) { throw 'A collected PGO profile changed; recollect that workload.' }
                $pgoInputs += $pgoInput
                $pgoInputHashes[$pgoInput] = $pgoProfile.sha256
                $pgoCoveredModules += @(Get-PgoModules $pgoTool.FullName $pgoInput)
            }
        }
        if ($pgoInputs.Count -eq 0 -or $pgoCoveredModules -notcontains 'compat16.dll') { throw 'No successfully collected engine profiles are available.' }
        $pgoProfilePath = Join-Path $pgoSession.directory 'merged.profdata'
        # Keep zero-count records: sparse profiles can inhibit PGO optimization.
        # --failure-mode=any rejects partial merges containing invalid profiles.
        $pgoListPath = Join-Path $pgoSession.directory 'merge-inputs.txt'
        [IO.File]::WriteAllLines($pgoListPath, $pgoInputs, [Text.UTF8Encoding]::new($false))
        try { [void](Invoke-PgoTool $pgoTool.FullName @('merge', '--instr', '--failure-mode=any', ('--input-files=' + $pgoListPath), '-o', $pgoProfilePath)) }
        finally { Remove-Item -LiteralPath $pgoListPath -ErrorAction SilentlyContinue }
        if ($pgoCollectionHash -cne (Get-PgoCollectionHash $pgoSession.directory)) { throw 'Training receipts changed during merge; merge again after collection finishes.' }
        foreach ($pgoInput in $pgoInputs) {
            if ((Get-FileHash -LiteralPath $pgoInput -Algorithm SHA256).Hash -cne $pgoInputHashes[$pgoInput]) { throw 'Training profiles changed during merge; recollect the workload.' }
        }
        $pgoCoveredModules = @($pgoCoveredModules | Sort-Object -Unique)
        Write-PgoJson (Join-Path $pgoSession.directory 'merged.json') ([pscustomobject]@{ schema = 1; session = $pgoSession.metadata.session; identity = $pgoSession.metadata.identity; sha256 = (Get-FileHash -LiteralPath $pgoProfilePath -Algorithm SHA256).Hash; collectionSha256 = $pgoCollectionHash; runs = $pgoReceipts.Count; profiles = $pgoInputs.Count; modules = $pgoCoveredModules })
        Write-Host ('[ OK ] Merged {0} profiles from {1} workloads.' -f $pgoInputs.Count, $pgoReceipts.Count) -ForegroundColor Green
        foreach ($pgoModule in @('compat16.exe', 'compat16w.exe', 'compat16.dll', 'compat16host.exe')) {
            if ($pgoCoveredModules -notcontains $pgoModule) { Write-Warning ("No executed functions recorded for $pgoModule; exercise that workflow before assessing its performance.") }
        }
    }
} catch {
    $pgoMessage = $_.Exception.Message
    foreach ($pgoPrefix in @($pgoRoot, [Environment]::GetFolderPath('UserProfile'))) {
        if ($pgoPrefix) { $pgoMessage = $pgoMessage.Replace($pgoPrefix, '<build>') }
    }
    Write-Host ('[FAIL] ' + $pgoMessage) -ForegroundColor Red
    exit 1
}
