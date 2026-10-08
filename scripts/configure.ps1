[CmdletBinding()]
param(
    [switch]$InstallBuildTools,
    [switch]$NonInteractive
)

$ErrorActionPreference = 'Stop'
$repoRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$toolchainFile = Join-Path $repoRoot 'rust-toolchain.toml'
$devRoot = Join-Path $repoRoot '.dev'
$cargoHome = Join-Path $devRoot 'cargo'
$rustupHome = Join-Path $devRoot 'rustup'
$processVariables = @('CARGO_HOME', 'RUSTUP_HOME', 'RUSTUP_TOOLCHAIN', 'PATH')
$originalEnvironment = @{}
foreach ($name in $processVariables) {
    $originalEnvironment[$name] = [Environment]::GetEnvironmentVariable($name, 'Process')
}
$configured = $false
$nextAction = 'Fix the reported issue, then rerun .\scripts\configure.ps1.'

function Write-Header {
    Write-Host "`n========================================`n         COMPAT16 / CONFIGURE`n========================================`n" -ForegroundColor Cyan
}

function Write-Stage {
    param([int]$Number, [string]$Label)
    Write-Host ("`n[{0:D2}/04] {1}" -f $Number, $Label) -ForegroundColor Cyan
}

function Write-Status {
    param([string]$Name, [string]$Value, [bool]$Ready = $true)
    $tag = if ($Ready) { '[ OK ]' } else { '[MISSING]' }
    $color = if ($Ready) { 'Green' } else { 'Yellow' }
    Write-Host ('  {0,-12}{1} {2}' -f $Name, $tag, $Value) -ForegroundColor $color
}

function Invoke-NativeCommand {
    param([Parameter(Mandatory = $true)][string]$FilePath, [string[]]$Arguments)
    $savedPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $output = @(& $FilePath @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $savedPreference
    }
    return [pscustomobject]@{ Output = $output; ExitCode = $exitCode }
}

function Find-VsWhere {
    $candidates = @()
    $programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    $programFiles = [Environment]::GetEnvironmentVariable('ProgramFiles')
    foreach ($base in @($programFilesX86, $programFiles)) {
        if ($base) {
            $candidates += Join-Path $base 'Microsoft Visual Studio\Installer\vswhere.exe'
        }
    }
    foreach ($candidate in $candidates) {
        if (Test-Path -LiteralPath $candidate -PathType Leaf) { return $candidate }
    }
    $command = Get-Command 'vswhere.exe' -ErrorAction SilentlyContinue
    if ($command) { return $command.Source }
    return $null
}

function Get-VsInstallations {
    param([string]$VsWhere)
    if (-not $VsWhere) { return @() }
    $result = Invoke-NativeCommand -FilePath $VsWhere -Arguments @('-all', '-prerelease', '-products', '*', '-version', '[17.0,)', '-property', 'installationPath')
    if ($result.ExitCode -ne 0) { throw "vswhere failed (exit code $($result.ExitCode))." }
    return @($result.Output | Where-Object { $_ -is [string] -and $_.Trim() -and (Test-Path -LiteralPath $_.Trim() -PathType Container) } |
        ForEach-Object { $_.Trim() })
}

function Find-CompleteVsCppInstallation {
    param([string]$VsWhere)
    if (-not $VsWhere) { return $null }
    $arguments = @('-all', '-prerelease', '-products', '*', '-version', '[17.0,)', '-requires',
        'Microsoft.VisualStudio.Component.VC.Tools.x86.x64', 'Microsoft.VisualStudio.Component.VC.Tools.ARM64',
        '-property', 'installationPath')
    $result = Invoke-NativeCommand -FilePath $VsWhere -Arguments $arguments
    if ($result.ExitCode -ne 0) { throw "vswhere failed (exit code $($result.ExitCode))." }
    foreach ($instance in $result.Output) {
        if ($instance -is [string] -and $instance.Trim() -and (Test-Path -LiteralPath $instance.Trim() -PathType Container)) { return $instance.Trim() }
    }
    return $null
}

function Test-WindowsSdkForBothTargets {
    $roots = @()
    $programFilesX86 = [Environment]::GetEnvironmentVariable('ProgramFiles(x86)')
    $programFiles = [Environment]::GetEnvironmentVariable('ProgramFiles')
    if ($programFilesX86) { $roots += Join-Path $programFilesX86 'Windows Kits\10' }
    if ($programFiles) { $roots += Join-Path $programFiles 'Windows Kits\10' }
    try {
        $registry = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine,
            [Microsoft.Win32.RegistryView]::Registry64)
        $rootsKey = $registry.OpenSubKey('SOFTWARE\Microsoft\Windows Kits\Installed Roots')
        if ($rootsKey) {
            $registeredRoot = [string]$rootsKey.GetValue('KitsRoot10')
            if ($registeredRoot) { $roots += $registeredRoot.TrimEnd('\') }
            $rootsKey.Close()
        }
        $registry.Close()
    } catch {
        # Standard Windows Kits locations above remain available if registry lookup is restricted.
    }

    foreach ($root in ($roots | Select-Object -Unique)) {
        $includeRoot = Join-Path $root 'Include'
        $versions = @(Get-ChildItem -LiteralPath $includeRoot -Directory -ErrorAction SilentlyContinue |
            Sort-Object Name -Descending)
        foreach ($version in $versions) {
            $libRoot = Join-Path (Join-Path $root 'Lib') $version.Name
            $requiredFiles = @(
                (Join-Path $version.FullName 'um\Windows.h'),
                (Join-Path $version.FullName 'ucrt\stdio.h'),
                (Join-Path $libRoot 'um\x64\kernel32.lib'),
                (Join-Path $libRoot 'um\arm64\kernel32.lib'),
                (Join-Path $libRoot 'ucrt\x64\ucrt.lib'),
                (Join-Path $libRoot 'ucrt\arm64\ucrt.lib')
            )
            if (@($requiredFiles | Where-Object { -not (Test-Path -LiteralPath $_ -PathType Leaf) }).Count -eq 0) {
                return $true
            }
        }
    }
    return $false
}

function Install-BuildTools {
    param([string]$VsWhere)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object -TypeName Security.Principal.WindowsPrincipal -ArgumentList $identity
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Installing Visual Studio Build Tools changes machine-wide software and requires an elevated PowerShell. Re-run as Administrator with -InstallBuildTools.'
    }

    $installations = @(Get-VsInstallations -VsWhere $VsWhere)
    $installer = $null
    if ($VsWhere) {
        $installerCandidate = Join-Path (Split-Path -Parent $VsWhere) 'vs_installer.exe'
        if (Test-Path -LiteralPath $installerCandidate -PathType Leaf) { $installer = $installerCandidate }
    }

    $setupOptions = '--wait --quiet --norestart --add Microsoft.VisualStudio.Workload.VCTools --includeRecommended --add Microsoft.VisualStudio.Component.VC.Tools.ARM64'
    if ($installations.Count -gt 0 -and $installer) {
        $arguments = @('modify', '--installPath', $installations[0], '--quiet', '--wait', '--norestart',
            '--add', 'Microsoft.VisualStudio.Workload.VCTools', '--includeRecommended',
            '--add', 'Microsoft.VisualStudio.Component.VC.Tools.ARM64')
        $result = Invoke-NativeCommand -FilePath $installer -Arguments $arguments
        $exitCode = $result.ExitCode
    } else {
        $winget = Get-Command 'winget.exe' -ErrorAction SilentlyContinue
        if (-not $winget) {
            throw 'winget is unavailable. Install Visual Studio 2022 Build Tools from https://visualstudio.microsoft.com/downloads/ with the C++ build tools, ARM64 tools, and a Windows 10/11 SDK, then rerun this script.'
        }
        $arguments = @('install', '--id', 'Microsoft.VisualStudio.2022.BuildTools', '--exact', '--source', 'winget',
            '--accept-package-agreements', '--accept-source-agreements', '--override', $setupOptions)
        $result = Invoke-NativeCommand -FilePath $winget.Source -Arguments $arguments
        $exitCode = $result.ExitCode
    }
    if ($exitCode -notin @(0, 3010)) {
        throw "Visual Studio Build Tools setup failed (exit code $exitCode). Use Visual Studio Installer to add the C++ tools, ARM64 tools, and Windows SDK, then rerun this script."
    }
}

Write-Header
try {
    Write-Stage 1 'Inspect host and project settings'
    if ($env:OS -ne 'Windows_NT') { throw 'This setup script requires Windows PowerShell on Windows.' }
    if ($PSVersionTable.PSVersion -lt [Version]'5.1') { throw 'PowerShell 5.1 or newer is required.' }

    $nativeArchitecture = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE', 'Machine')
    if (-not $nativeArchitecture) { $nativeArchitecture = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITEW6432') }
    if (-not $nativeArchitecture) { $nativeArchitecture = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE') }
    if (-not $nativeArchitecture) { throw 'Could not determine the Windows host architecture.' }
    switch ($nativeArchitecture.ToUpperInvariant()) {
        'ARM64' { $rustupHost = 'aarch64-pc-windows-msvc'; $hostLabel = 'ARM64' }
        'AMD64' { $rustupHost = 'x86_64-pc-windows-msvc'; $hostLabel = 'AMD64' }
        default { throw "Unsupported Windows architecture '$nativeArchitecture'. Use native ARM64 or AMD64 Windows." }
    }

    if (-not (Test-Path -LiteralPath $toolchainFile -PathType Leaf)) { throw 'rust-toolchain.toml is missing from the repository root.' }
    $toolchainConfig = Get-Content -LiteralPath $toolchainFile -Raw
    $channelMatch = [regex]::Match($toolchainConfig, '(?m)^\s*channel\s*=\s*"([^"]+)"')
    if (-not $channelMatch.Success -or $channelMatch.Groups[1].Value -notmatch '^[A-Za-z0-9][A-Za-z0-9.-]*$') {
        throw 'Could not read a safe, pinned toolchain channel from rust-toolchain.toml.'
    }
    $channel = $channelMatch.Groups[1].Value
    $componentMatch = [regex]::Match($toolchainConfig, '(?m)^\s*components\s*=\s*\[([^\]]*)\]')
    $targetMatch = [regex]::Match($toolchainConfig, '(?m)^\s*targets\s*=\s*\[([^\]]*)\]')
    $components = @()
    $targets = @()
    if ($componentMatch.Success) { $components = @([regex]::Matches($componentMatch.Groups[1].Value, '"([^"]+)"') | ForEach-Object { $_.Groups[1].Value }) }
    if ($targetMatch.Success) { $targets = @([regex]::Matches($targetMatch.Groups[1].Value, '"([^"]+)"') | ForEach-Object { $_.Groups[1].Value }) }
    if ($targets -notcontains 'aarch64-pc-windows-msvc' -or $targets -notcontains 'x86_64-pc-windows-msvc') {
        throw 'rust-toolchain.toml must include both aarch64-pc-windows-msvc and x86_64-pc-windows-msvc targets.'
    }

    [Environment]::SetEnvironmentVariable('CARGO_HOME', $cargoHome, 'Process')
    [Environment]::SetEnvironmentVariable('RUSTUP_HOME', $rustupHome, 'Process')
    $rustupExe = Join-Path $cargoHome 'bin\rustup.exe'
    $cargoExe = Join-Path $cargoHome 'bin\cargo.exe'
    $toolchainPath = Join-Path (Join-Path $rustupHome 'toolchains') "$channel-$rustupHost"
    $rustReady = $false
    if ((Test-Path -LiteralPath $rustupExe -PathType Leaf) -and
        (Test-Path -LiteralPath $cargoExe -PathType Leaf) -and
        (Test-Path -LiteralPath $toolchainPath -PathType Container)) {
        $result = Invoke-NativeCommand -FilePath $rustupExe -Arguments @('target', 'list', '--installed', '--toolchain', $channel)
        $installedTargets = $result.Output
        $rustReady = $result.ExitCode -eq 0
        foreach ($target in $targets) { if ($installedTargets -notcontains $target) { $rustReady = $false } }
        $result = Invoke-NativeCommand -FilePath $rustupExe -Arguments @('component', 'list', '--installed', '--toolchain', $channel)
        $installedComponents = $result.Output
        if ($result.ExitCode -ne 0) { $rustReady = $false }
        foreach ($component in $components) {
            if (-not ($installedComponents | Where-Object { $_ -match ('^' + [regex]::Escape($component) + '-') })) { $rustReady = $false }
        }
    }
    Write-Status 'Host' $hostLabel
    Write-Status 'Pinned Rust' "$channel project-local" $rustReady
    Write-Status 'Rust targets' 'x64 + ARM64' $rustReady

    Write-Stage 2 'Check Visual Studio and Windows SDK'
    $vswhere = Find-VsWhere
    $vsInstallation = Find-CompleteVsCppInstallation -VsWhere $vswhere
    $hasSdk = Test-WindowsSdkForBothTargets
    $buildToolsReady = [bool]$vsInstallation -and $hasSdk
    Write-Status 'MSVC tools' 'Visual Studio 2022+ x86/x64 + ARM64' ([bool]$vsInstallation)
    Write-Status 'Windows SDK' 'x64 + ARM64 libraries' $hasSdk

    if (-not $buildToolsReady) {
        Write-Host '  Required: Visual Studio 2022+ C++ tools (x86/x64 and ARM64) plus a Windows SDK for both targets.' -ForegroundColor Yellow
        $shouldInstall = [bool]$InstallBuildTools
        if (-not $InstallBuildTools -and -not $NonInteractive) {
            $answer = Read-Host 'Allow the official Visual Studio Installer to add the missing tools machine-wide? [y/N]'
            $shouldInstall = ([string]$answer).Trim() -match '^(?i)y(es)?$'
        }
        if (-not $shouldInstall) {
            if ($NonInteractive) {
                $nextAction = 'Run elevated PowerShell with .\scripts\configure.ps1 -InstallBuildTools -NonInteractive, or install the C++/ARM64 tools and Windows SDK manually.'
            } else {
                $nextAction = 'Run .\scripts\configure.ps1 -InstallBuildTools from elevated PowerShell, or install the C++/ARM64 tools and Windows SDK manually.'
            }
            throw 'Required Visual Studio components or Windows SDK are missing; installer was not started.'
        }

        $nextAction = 'Rerun from elevated PowerShell with -InstallBuildTools, or use Visual Studio Installer to add C++ x86/x64, ARM64 tools, and a Windows SDK.'
        Write-Host '  [INFO] The official installer makes a machine-wide change shared with other projects.' -ForegroundColor Cyan
        Write-Host '  [INFO] Starting Visual Studio setup; this may take several minutes.' -ForegroundColor Cyan
        Install-BuildTools -VsWhere $vswhere
        $vswhere = Find-VsWhere
        $vsInstallation = Find-CompleteVsCppInstallation -VsWhere $vswhere
        $hasSdk = Test-WindowsSdkForBothTargets
        $buildToolsReady = [bool]$vsInstallation -and $hasSdk
        Write-Status 'MSVC tools' 'Visual Studio 2022+ x86/x64 + ARM64' ([bool]$vsInstallation)
        Write-Status 'Windows SDK' 'x64 + ARM64 libraries' $hasSdk
        if (-not $buildToolsReady) {
            throw 'The installer completed, but the required MSVC components or Windows SDK were not detected.'
        }
    }

    Write-Stage 3 'Prepare the pinned Rust toolchain'
    [void][IO.Directory]::CreateDirectory($cargoHome)
    [void][IO.Directory]::CreateDirectory($rustupHome)
    if (-not (Test-Path -LiteralPath $rustupExe -PathType Leaf) -or -not (Test-Path -LiteralPath $cargoExe -PathType Leaf)) {
        Write-Host '  [INFO] Downloading the official Rust bootstrapper over HTTPS.' -ForegroundColor Cyan
        $nextAction = 'Check HTTPS access to static.rust-lang.org, then rerun .\scripts\configure.ps1.'
        $previousSecurityProtocol = [Net.ServicePointManager]::SecurityProtocol
        $installerPath = Join-Path ([IO.Path]::GetTempPath()) ([Guid]::NewGuid().ToString('N') + '.exe')
        try {
            [Net.ServicePointManager]::SecurityProtocol = $previousSecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
            $uri = "https://static.rust-lang.org/rustup/dist/$rustupHost/rustup-init.exe"
            try {
                Invoke-WebRequest -Uri $uri -OutFile $installerPath -UseBasicParsing
            } catch {
                throw 'Could not download official rustup over HTTPS from static.rust-lang.org.'
            }
            $installerArguments = @('--default-host', $rustupHost, '--default-toolchain', 'none', '--no-modify-path', '-y')
            $result = Invoke-NativeCommand -FilePath $installerPath -Arguments $installerArguments
            if ($result.ExitCode -ne 0) { throw "Official rustup setup failed (exit code $($result.ExitCode))." }
        } finally {
            [Net.ServicePointManager]::SecurityProtocol = $previousSecurityProtocol
            Remove-Item -LiteralPath $installerPath -Force -ErrorAction SilentlyContinue
        }
    } else {
        Write-Host '  [ OK ] Reusing project-private rustup.' -ForegroundColor Green
    }
    if (-not (Test-Path -LiteralPath $rustupExe -PathType Leaf)) { throw 'The project-private rustup executable was not created.' }

    Write-Host "  [INFO] Ensuring Rust $channel and targets from rust-toolchain.toml." -ForegroundColor Cyan
    $nextAction = 'Check access to the official Rust distribution, then rerun .\scripts\configure.ps1.'
    $toolchainArguments = @('toolchain', 'install', $channel, '--profile', 'minimal')
    foreach ($component in $components) { $toolchainArguments += @('--component', $component) }
    foreach ($target in $targets) { $toolchainArguments += @('--target', $target) }
    $result = Invoke-NativeCommand -FilePath $rustupExe -Arguments $toolchainArguments
    if ($result.ExitCode -ne 0) { throw "Rust toolchain $channel setup failed (exit code $($result.ExitCode))." }

    Write-Stage 4 'Activate this PowerShell session'
    [Environment]::SetEnvironmentVariable('RUSTUP_TOOLCHAIN', $channel, 'Process')
    $cargoBin = Join-Path $cargoHome 'bin'
    $existingPathEntries = @(([Environment]::GetEnvironmentVariable('PATH', 'Process') -split ';') | Where-Object { $_ })
    if (-not ($existingPathEntries | Where-Object { [string]::Equals($_.TrimEnd('\'), $cargoBin.TrimEnd('\'), [StringComparison]::OrdinalIgnoreCase) })) {
        $processPath = [Environment]::GetEnvironmentVariable('PATH', 'Process')
        if ([string]::IsNullOrWhiteSpace($processPath)) { $processPath = $cargoBin }
        else { $processPath = "$cargoBin;$processPath" }
        [Environment]::SetEnvironmentVariable('PATH', $processPath, 'Process')
    }

    $rustcExe = Join-Path $cargoBin 'rustc.exe'
    $result = Invoke-NativeCommand -FilePath $rustcExe -Arguments @('--version')
    if ($result.ExitCode -ne 0) { throw 'The pinned project toolchain did not start successfully.' }
    $configured = $true
    Write-Status 'Environment' 'Private Rust active for this session'
    Write-Host '  [INFO] Next command: .\scripts\build.ps1' -ForegroundColor Cyan
    Write-Host '  [INFO] Rerun configure.ps1 in each new PowerShell session.' -ForegroundColor Cyan
} catch {
    if (-not $configured) {
        foreach ($name in $processVariables) {
            [Environment]::SetEnvironmentVariable($name, $originalEnvironment[$name], 'Process')
        }
    }
    $failureMessage = $_.Exception.Message
    foreach ($privatePath in @($repoRoot, [Environment]::GetEnvironmentVariable('USERPROFILE'))) {
        if ($privatePath) { $failureMessage = $failureMessage.Replace($privatePath, '<local>') }
    }
    Write-Host ''
    Write-Host "[FAIL] $failureMessage" -ForegroundColor Red
    Write-Host "[NEXT] $nextAction" -ForegroundColor Yellow
    Write-Host ''
    exit 1
}
