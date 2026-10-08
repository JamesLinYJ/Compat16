[CmdletBinding()]
param(
    [ValidateSet('arm64', 'amd64', 'x64', 'all')]
    [string]$Architecture,
    [switch]$Offline,
    [switch]$NonInteractive
)

$ErrorActionPreference = 'Stop'
$originalLocation = Get-Location
$originalEnvironment = @{}
Get-ChildItem Env: | ForEach-Object { $originalEnvironment[$_.Name] = $_.Value }

function Write-Status {
    param([ValidateSet('OK', 'INFO', 'WARN', 'FAIL')][string]$Kind, [string]$Message)
    switch ($Kind) {
        'OK' { $tag = '[ OK ]'; $color = 'Green' }
        'INFO' { $tag = '[INFO]'; $color = 'Cyan' }
        'WARN' { $tag = '[WARN]'; $color = 'Yellow' }
        'FAIL' { $tag = '[FAIL]'; $color = 'Red' }
    }
    Write-Host ("{0} {1}" -f $tag, $Message) -ForegroundColor $color
}

function Write-Stage {
    param([int]$Number, [string]$Title)
    Write-Host ''
    Write-Host ('[{0:D2}/03] {1}' -f $Number, $Title) -ForegroundColor Cyan
}

function Get-ArchitectureLabel {
    param([string]$Value)
    if ($Value -eq 'arm64') { return 'ARM64' }
    return 'AMD64'
}

function Get-ExecutablePath {
    param([string]$Name)
    $application = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue
    if ($null -eq $application) { return $null }
    return $application.Source
}

function Test-PinnedToolchain {
    param([string]$RustupExecutable, [string]$PinnedChannel, [string]$HostTriple)
    $installed = & $RustupExecutable toolchain list
    if ($LASTEXITCODE -ne 0) { return $false }
    $expected = @($PinnedChannel, ($PinnedChannel + '-' + $HostTriple))
    foreach ($line in $installed) {
        $name = ([string]$line -split '\s+')[0]
        if ($expected -contains $name) { return $true }
    }
    return $false
}

function Restore-EnvironmentVariable {
    param([string]$Name)
    if ($originalEnvironment.ContainsKey($Name)) {
        Set-Item -LiteralPath ('Env:' + $Name) -Value $originalEnvironment[$Name]
    } elseif (Test-Path -LiteralPath ('Env:' + $Name)) {
        Remove-Item -LiteralPath ('Env:' + $Name)
    }
}

try {
    Write-Host '--------------------------------' -ForegroundColor Cyan
    Write-Host 'COMPAT16 / BUILD' -ForegroundColor Cyan
    Write-Host '--------------------------------' -ForegroundColor Cyan
    Write-Host ''

    Write-Stage 1 'Preflight'
    if (-not [Runtime.InteropServices.RuntimeInformation]::IsOSPlatform([Runtime.InteropServices.OSPlatform]::Windows)) {
        throw 'This entry supports native Windows ARM64 and AMD64 builds only.'
    }
    $projectRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
    Set-Location -LiteralPath $projectRoot

    if ($PSBoundParameters.ContainsKey('Architecture')) {
        switch ($Architecture.ToLowerInvariant()) {
            'arm64' { $selectedArchitecture = 'arm64' }
            { $_ -in @('amd64', 'x64') } { $selectedArchitecture = 'x64' }
            'all' { $selectedArchitecture = 'all' }
        }
    } elseif ($NonInteractive) {
        $selectedArchitecture = 'all'
    } else {
        Write-Host '  1) ARM64'
        Write-Host '  2) AMD64'
        Write-Host '  3) All (default)' -ForegroundColor Green
        while (-not $selectedArchitecture) {
            $choice = Read-Host 'Choose 1-3'
            if ([string]::IsNullOrWhiteSpace($choice)) { $choice = '3' }
            switch ($choice.Trim().ToLowerInvariant()) {
                { $_ -in @('1', 'arm64') } { $selectedArchitecture = 'arm64' }
                { $_ -in @('2', 'amd64', 'x64') } { $selectedArchitecture = 'x64' }
                { $_ -in @('3', 'all') } { $selectedArchitecture = 'all' }
                default { Write-Status WARN 'Enter 1, 2, or 3.' }
            }
        }
    }

    if ($selectedArchitecture -eq 'all') {
        $architectures = @('arm64', 'x64')
    } else {
        $architectures = @($selectedArchitecture)
    }
    $targetByArchitecture = @{
        arm64 = 'aarch64-pc-windows-msvc'
        x64 = 'x86_64-pc-windows-msvc'
    }
    $requiredFiles = @('compat16.exe', 'compat16w.exe', 'compat16.dll', 'compat16host.exe')
    $requiredLegalFiles = @(
        'LICENSE',
        'LICENSES\NOTICE.txt',
        'LICENSES\DEPENDENCIES.txt',
        'LICENSES\Microsoft-MS-DOS-MIT.txt'
    )
    $architectureSummary = ($architectures | ForEach-Object { Get-ArchitectureLabel $_ }) -join ', '
    Write-Status INFO ("Targets: {0}" -f $architectureSummary)
    Write-Host ("  Release files: {0}" -f ($requiredFiles -join ', ')) -ForegroundColor DarkGray
    if ($Offline) { Write-Host '  Cargo dependency resolution: offline' -ForegroundColor DarkGray }
    foreach ($legalFile in $requiredLegalFiles) {
        if (-not (Test-Path -LiteralPath (Join-Path $projectRoot $legalFile) -PathType Leaf)) {
            throw "Required package license file is missing: $legalFile"
        }
    }

    $toolchainText = Get-Content -LiteralPath (Join-Path $projectRoot 'rust-toolchain.toml') -Raw
    if ($toolchainText -notmatch '(?m)^\s*channel\s*=\s*"([^"]+)"') {
        throw 'rust-toolchain.toml does not declare a channel.'
    }
    $pinnedChannel = $Matches[1]
    $machineArchitecture = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE', 'Machine')
    if ($machineArchitecture -match '^(AMD64|ARM64)$') {
        $hostArchitecture = $machineArchitecture.ToLowerInvariant()
    } else {
        # Older .NET can report X64 under x64-emulated PowerShell on an ARM64 host.
        $hostArchitecture = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString().ToLowerInvariant()
    }
    switch ($hostArchitecture) {
        { $_ -in @('x64', 'amd64') } { $hostTriple = 'x86_64-pc-windows-msvc'; $vsHostArchitecture = 'amd64' }
        'arm64' { $hostTriple = 'aarch64-pc-windows-msvc'; $vsHostArchitecture = 'arm64' }
        default { throw "Unsupported Windows host architecture: $hostArchitecture" }
    }

    $cargoHome = Join-Path $projectRoot '.dev\cargo'
    $rustupHome = Join-Path $projectRoot '.dev\rustup'
    $cargoBin = Join-Path $cargoHome 'bin'
    $localCargo = Join-Path $cargoBin 'cargo.exe'
    $localRustup = Join-Path $cargoBin 'rustup.exe'
    $localRustc = Join-Path $cargoBin 'rustc.exe'
    $usingProjectToolchain = $false
    if ((Test-Path -LiteralPath $localCargo -PathType Leaf) -and
        (Test-Path -LiteralPath $localRustup -PathType Leaf) -and
        (Test-Path -LiteralPath $localRustc -PathType Leaf)) {
        $env:CARGO_HOME = $cargoHome
        $env:RUSTUP_HOME = $rustupHome
        if ([string]::IsNullOrEmpty($env:PATH)) { $env:PATH = $cargoBin }
        else { $env:PATH = $cargoBin + ';' + $env:PATH }
        if (Test-PinnedToolchain $localRustup $pinnedChannel $hostTriple) {
            $cargoExe = $localCargo
            $rustupExe = $localRustup
            $rustcExe = $localRustc
            $usingProjectToolchain = $true
        } else {
            Restore-EnvironmentVariable 'PATH'
            Restore-EnvironmentVariable 'CARGO_HOME'
            Restore-EnvironmentVariable 'RUSTUP_HOME'
            Write-Status WARN 'The local .dev toolchain does not contain the pinned Rust version; checking PATH.'
        }
    }
    if (-not $usingProjectToolchain) {
        $cargoExe = Get-ExecutablePath 'cargo.exe'
        $rustupExe = Get-ExecutablePath 'rustup.exe'
        if (-not $cargoExe -or -not $rustupExe) {
            throw 'Rustup-managed Cargo was not found in .dev/cargo/bin or PATH.'
        }
        $cargoDirectory = Split-Path -Parent $cargoExe
        $adjacentRustup = Join-Path $cargoDirectory 'rustup.exe'
        $adjacentRustc = Join-Path $cargoDirectory 'rustc.exe'
        if (Test-Path -LiteralPath $adjacentRustup -PathType Leaf) {
            $rustupExe = $adjacentRustup
        } elseif ((Split-Path -Parent $rustupExe) -ne $cargoDirectory) {
            throw 'PATH Cargo and rustup do not come from the same Rust installation.'
        }
        if (-not (Test-Path -LiteralPath $adjacentRustc -PathType Leaf)) {
            throw 'PATH Cargo does not have its matching rustc proxy.'
        }
        $rustcExe = $adjacentRustc
        if (-not (Test-PinnedToolchain $rustupExe $pinnedChannel $hostTriple)) {
            throw "Pinned Rust toolchain '$pinnedChannel' is not installed in the selected rustup home."
        }
    }
    $env:RUSTUP_TOOLCHAIN = $pinnedChannel
    if ($usingProjectToolchain) { Write-Status OK "Using project-local Rust $pinnedChannel." }
    else { Write-Status OK "Using PATH Rust $pinnedChannel; no global configuration was changed." }

    $programFilesX86 = [Environment]::GetFolderPath('ProgramFilesX86')
    $vswhere = Join-Path $programFilesX86 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) {
        throw 'Visual Studio Installer vswhere.exe was not found.'
    }
    $vsInstallations = @(& $vswhere -latest -products '*' -prerelease -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath)
    if ($LASTEXITCODE -ne 0 -or $vsInstallations.Count -eq 0) {
        throw 'Visual Studio with the MSVC x86/x64 tools was not found by vswhere.'
    }
    $vsInstall = ([string]$vsInstallations[0]).Trim()
    $vsDevCmd = Join-Path $vsInstall 'Common7\Tools\VsDevCmd.bat'
    if (-not (Test-Path -LiteralPath $vsDevCmd -PathType Leaf)) {
        throw 'The selected Visual Studio installation has no VsDevCmd.bat.'
    }

    $userProfile = [Environment]::GetFolderPath('UserProfile')
    $effectiveCargoHome = if ([string]::IsNullOrEmpty($env:CARGO_HOME)) { Join-Path $userProfile '.cargo' } else { $env:CARGO_HOME }
    $effectiveRustupHome = if ([string]::IsNullOrEmpty($env:RUSTUP_HOME)) { Join-Path $userProfile '.rustup' } else { $env:RUSTUP_HOME }
    if (-not (Test-Path -LiteralPath $rustcExe -PathType Leaf)) {
        throw 'The selected Rust toolchain has no rustc.exe.'
    }
    $sysrootOutput = @(& $rustcExe --print sysroot)
    if ($LASTEXITCODE -ne 0 -or $sysrootOutput.Count -eq 0) {
        throw 'Could not determine the selected Rust sysroot for path remapping.'
    }
    $sysroot = ([string]$sysrootOutput[0]).Trim()

    $remapPairs = @(
        [pscustomobject]@{ source = $sysroot; target = '/_/rust/sysroot' },
        [pscustomobject]@{ source = $effectiveRustupHome; target = '/_/rust/rustup' },
        [pscustomobject]@{ source = $effectiveCargoHome; target = '/_/rust/cargo' },
        [pscustomobject]@{ source = $userProfile; target = '/_/user' },
        [pscustomobject]@{ source = $projectRoot; target = '/_/compat16' }
    )
    if (-not [string]::IsNullOrEmpty($env:HOME) -and $env:HOME -ne $userProfile) {
        $remapPairs += [pscustomobject]@{ source = $env:HOME; target = '/_/home' }
    }
    $remapFlags = @($remapPairs | ForEach-Object { '--remap-path-prefix=' + $_.source + '=' + $_.target })
    if ($originalEnvironment.ContainsKey('CARGO_ENCODED_RUSTFLAGS')) {
        $existingEncodedFlags = $originalEnvironment['CARGO_ENCODED_RUSTFLAGS']
        $flagsToAppend = @($remapFlags + '-Cdebuginfo=0') -join [char]0x1f
        if ([string]::IsNullOrEmpty($existingEncodedFlags)) {
            $env:CARGO_ENCODED_RUSTFLAGS = $flagsToAppend
        } else {
            $env:CARGO_ENCODED_RUSTFLAGS = $existingEncodedFlags + [char]0x1f + $flagsToAppend
        }
    } elseif ($originalEnvironment.ContainsKey('RUSTFLAGS') -and
        -not [string]::IsNullOrWhiteSpace($originalEnvironment['RUSTFLAGS'])) {
        $rustFlags = @($originalEnvironment['RUSTFLAGS'] -split '\s+' | Where-Object { $_.Length -gt 0 })
        $rustFlags += $remapFlags
        $rustFlags += '-Cdebuginfo=0'
        $env:CARGO_ENCODED_RUSTFLAGS = $rustFlags -join [char]0x1f
    } else {
        $env:CARGO_ENCODED_RUSTFLAGS = @($remapFlags + '-Cdebuginfo=0') -join [char]0x1f
    }
    Write-Status OK 'MSVC and path-remapping settings are ready.'

    $vsTargetByArchitecture = @{ arm64 = 'arm64'; x64 = 'amd64' }
    $cargoTargetDirectory = Join-Path $projectRoot 'target'
    $offlineArgument = ''
    if ($Offline) { $offlineArgument = ' --offline' }
    $releaseBuilds = @()

    Write-Stage 2 'Build targets'
    for ($index = 0; $index -lt $architectures.Count; $index++) {
        $architecture = $architectures[$index]
        $target = $targetByArchitecture[$architecture]
        $label = Get-ArchitectureLabel $architecture
        $percent = [int](($index * 70) / $architectures.Count)
        Write-Progress -Activity 'COMPAT16 / BUILD' -Status ("Building {0} ({1}/{2})" -f $label, ($index + 1), $architectures.Count) -PercentComplete $percent
        Write-Status INFO ("Building {0} -> {1}" -f $label, $target)
        $command = 'call "{0}" -arch={1} -host_arch={2} && "{3}" build --quiet --workspace --release --locked --target {4} --target-dir "{5}"{6}' -f `
            $vsDevCmd, $vsTargetByArchitecture[$architecture], $vsHostArchitecture, $cargoExe, $target, $cargoTargetDirectory, $offlineArgument
        # Native diagnostics may contain Cargo/SDK paths even after rustc source
        # remapping. Keep local account and checkout paths out of shared logs.
        # Merge native streams in cmd: PowerShell 5.1 otherwise promotes stderr
        # diagnostics to terminating NativeCommandError under Stop.
        & $env:ComSpec /d /c ('(' + $command + ') 2>&1') | ForEach-Object {
            $line = [string]$_
            foreach ($prefix in @($projectRoot, $userProfile, $effectiveCargoHome, $effectiveRustupHome)) {
                if ($prefix) { $line = $line.Replace($prefix, '<build>') }
            }
            [Console]::WriteLine($line)
        }
        $buildExitCode = $LASTEXITCODE
        if ($buildExitCode -ne 0) { throw "Cargo build failed for $target with exit code $buildExitCode." }
        $releaseBuilds += [pscustomobject]@{
            architecture = $architecture
            target = $target
            releaseDirectory = Join-Path $cargoTargetDirectory (Join-Path $target 'release')
        }
        Write-Status OK ("{0} build finished." -f $label)
    }

    Write-Stage 3 'Stage release files'
    for ($index = 0; $index -lt $releaseBuilds.Count; $index++) {
        $releaseBuild = $releaseBuilds[$index]
        $architecture = $releaseBuild.architecture
        $target = $releaseBuild.target
        $label = Get-ArchitectureLabel $architecture
        $percent = [int](70 + (($index * 30) / $releaseBuilds.Count))
        Write-Progress -Activity 'COMPAT16 / BUILD' -Status ("Staging {0} ({1}/{2})" -f $label, ($index + 1), $releaseBuilds.Count) -PercentComplete $percent

        $distributionRoot = Join-Path $projectRoot 'dist'
        $stagingDirectory = Join-Path $distributionRoot ('.' + $architecture + '.staging-' + [Guid]::NewGuid().ToString('N'))
        $destinationDirectory = Join-Path $distributionRoot $architecture
        $backupDirectory = Join-Path $distributionRoot ('.' + $architecture + '.previous-' + [Guid]::NewGuid().ToString('N'))
        New-Item -ItemType Directory -Path $distributionRoot -Force | Out-Null
        New-Item -ItemType Directory -Path $stagingDirectory | Out-Null
        try {
            foreach ($file in $requiredFiles) {
                # Cargo assigns PDB names from target names even without debug
                # info. Keep the library target distinct from the console bin;
                # the release package owns the public DLL filename.
                $compiledName = if ($file -eq 'compat16.dll') { 'engine.dll' } else { $file }
                $source = Join-Path $releaseBuild.releaseDirectory $compiledName
                if (-not (Test-Path -LiteralPath $source -PathType Leaf)) { throw "Expected release file was not produced: $file" }
                Copy-Item -LiteralPath $source -Destination (Join-Path $stagingDirectory $file)
            }
            foreach ($legalFile in $requiredLegalFiles) {
                $source = Join-Path $projectRoot $legalFile
                $destination = Join-Path $stagingDirectory $legalFile
                $licenseParentDirectory = Split-Path -Parent $destination
                New-Item -ItemType Directory -Path $licenseParentDirectory -Force | Out-Null
                Copy-Item -LiteralPath $source -Destination $destination
            }

            $manifestFiles = @(
                Get-ChildItem -LiteralPath $stagingDirectory -File -Recurse |
                    Sort-Object { $_.FullName.Substring($stagingDirectory.Length + 1) } |
                    ForEach-Object {
                        $relativePath = $_.FullName.Substring($stagingDirectory.Length + 1).Replace('\', '/')
                        $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
                        [pscustomobject][ordered]@{ path = $relativePath; bytes = $_.Length; sha256 = $hash }
                    }
            )
            $manifest = [pscustomobject][ordered]@{ target = $target; files = $manifestFiles }
            $manifestText = (ConvertTo-Json -InputObject $manifest -Depth 4) + "`n"
            [System.IO.File]::WriteAllText((Join-Path $stagingDirectory 'manifest.json'), $manifestText, [System.Text.UTF8Encoding]::new($false))

            if (Test-Path -LiteralPath $destinationDirectory) { Move-Item -LiteralPath $destinationDirectory -Destination $backupDirectory }
            try {
                Move-Item -LiteralPath $stagingDirectory -Destination $destinationDirectory
            } catch {
                if (Test-Path -LiteralPath $destinationDirectory) { Remove-Item -LiteralPath $destinationDirectory -Recurse -Force }
                if (Test-Path -LiteralPath $backupDirectory) { Move-Item -LiteralPath $backupDirectory -Destination $destinationDirectory }
                throw
            }
            if (Test-Path -LiteralPath $backupDirectory) { Remove-Item -LiteralPath $backupDirectory -Recurse -Force }
            Write-Status OK ("dist/{0} is ready." -f $architecture)
        } catch {
            if (Test-Path -LiteralPath $stagingDirectory) { Remove-Item -LiteralPath $stagingDirectory -Recurse -Force }
            throw
        }
    }

    Write-Progress -Activity 'COMPAT16 / BUILD' -Completed
    Write-Host ''
    Write-Status OK 'Build and staging completed.'
    foreach ($releaseBuild in $releaseBuilds) {
        $packageItems = @($requiredFiles + @(
            'LICENSE',
            'LICENSES/NOTICE.txt',
            'LICENSES/DEPENDENCIES.txt',
            'LICENSES/Microsoft-MS-DOS-MIT.txt',
            'manifest.json'
        ))
        Write-Host ("  dist/{0} ({1})" -f $releaseBuild.architecture, $releaseBuild.target) -ForegroundColor White
        Write-Host ("    {0}" -f ($packageItems -join ', ')) -ForegroundColor DarkGray
    }
} catch {
    Write-Progress -Activity 'COMPAT16 / BUILD' -Completed
    $message = $_.Exception.Message
    foreach ($prefix in @($projectRoot, [Environment]::GetFolderPath('UserProfile'))) {
        if ($prefix) { $message = $message.Replace($prefix, '<build>') }
    }
    Write-Status FAIL $message
    exit 1
} finally {
    Get-ChildItem Env: | ForEach-Object {
        if (-not $originalEnvironment.ContainsKey($_.Name)) { Remove-Item -LiteralPath ('Env:' + $_.Name) }
    }
    foreach ($name in $originalEnvironment.Keys) {
        Set-Item -LiteralPath ('Env:' + $name) -Value $originalEnvironment[$name]
    }
    Set-Location -LiteralPath $originalLocation.Path
}
