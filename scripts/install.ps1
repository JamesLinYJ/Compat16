[CmdletBinding()]
param([switch]$Yes)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'installation.ps1')
$parentPath = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\NtVdm64'
$keyPath = "$parentPath\Compat16"

function Get-ViewState([string]$View) {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::$View)
    try {
        $parent = $base.OpenSubKey($parentPath, $false)
        $key = $base.OpenSubKey($keyPath, $false)
        try { [pscustomobject]@{ view = $View; parentExisted = [bool]$parent; keyExists = [bool]$key } }
        finally { if ($key) { $key.Close() }; if ($parent) { $parent.Close() } }
    } finally { $base.Close() }
}
function Find-WildcardProviders([string[]]$Views) {
    $found = @()
    foreach ($view in $Views) {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
            [Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::$view)
        try {
            $parent = $base.OpenSubKey($parentPath, $false)
            if ($parent) {
                try {
                    foreach ($name in $parent.GetSubKeyNames()) {
                        $provider = $parent.OpenSubKey($name, $false)
                        if (-not $provider) { continue }
                        try {
                            $internal = [string]$provider.GetValue('InternalName', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                            if ($internal -ceq '*') {
                                $product = [string]$provider.GetValue('ProductName', '', [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
                                if (-not $product) { $product = $name }
                                $found += [pscustomobject]@{ view = $view; key = $name; product = $product }
                            }
                        } finally { $provider.Close() }
                    }
                } finally { $parent.Close() }
            }
        } finally { $base.Close() }
    }
    $found
}
function Add-Provider([object]$State, [string]$View) {
    $expected = @($State.registryViews | Where-Object { $_.view -eq $View })[0]
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey(
        [Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::$View)
    try {
        $parentNow = $base.OpenSubKey($parentPath, $false)
        $keyNow = $base.OpenSubKey($keyPath, $false)
        try {
            if ([bool]$parentNow -ne [bool]$expected.parentExisted -or $keyNow) {
                throw "$View NtVdm64 state changed after review; it was left untouched."
            }
        } finally { if ($keyNow) { $keyNow.Close() }; if ($parentNow) { $parentNow.Close() } }

        $parent = $base.CreateSubKey($parentPath, $true)
        if (-not $parent) { throw "$View NtVdm64 key could not be created." }
        try {
            $key = $parent.OpenSubKey('Compat16', $true)
            if ($key) { $key.Close(); throw "$View Compat16 key appeared during installation; it was left untouched." }
            $key = $parent.CreateSubKey('Compat16', $true)
            if (-not $key) { throw "$View Compat16 key could not be created." }
            try {
                if ($key.GetValueNames().Count -ne 0 -or $key.GetSubKeyNames().Count -ne 0) {
                    throw "$View Compat16 key is no longer empty; its contents were left untouched."
                }
                foreach ($entry in $State.registryValues) {
                    $key.SetValue([string]$entry.name, [string]$entry.value, [Microsoft.Win32.RegistryValueKind]::String)
                }
                $key.Flush()
            } finally { $key.Close() }
        } finally { $parent.Close() }
    } finally { $base.Close() }
}
function Copy-VerifiedFile([string]$Source, [string]$Relative, [string]$Hash, [string]$Root) {
    if (-not (Test-SafeRelativePath $Relative)) { throw "Unsafe package path '$Relative'." }
    $destination = [IO.Path]::GetFullPath((Join-Path $Root ($Relative.Replace('/', '\'))))
    $prefix = [IO.Path]::GetFullPath($Root).TrimEnd('\') + '\'
    if (-not $destination.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)) { throw "Package path escapes install root: $Relative" }
    Assert-NoInstallReparsePoint $Root $destination
    $directory = Split-Path -Parent $destination
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) { New-Item -ItemType Directory -Path $directory -Force | Out-Null }
    Assert-NoInstallReparsePoint $Root $destination
    # File.Copy rejects an existing destination when overwrite is false.
    [IO.File]::Copy($Source, $destination, $false)
    Assert-NoInstallReparsePoint $Root $destination
    if ((Get-FileHash -LiteralPath $destination -Algorithm SHA256).Hash -ine $Hash) { throw "Copied file hash mismatch: $Relative" }
}

Write-Host '========================================' -ForegroundColor DarkCyan
Write-Host 'Compat16 / Install' -ForegroundColor Green
Write-Host '========================================' -ForegroundColor DarkCyan
Write-Phase 1 'Check native Windows, elevation, package, and existing state'
Assert-Compat16Admin 'Installation' $PSCommandPath
$architecture = Get-NativeArchitecture
$target = if ($architecture -eq 'arm64') { 'aarch64-pc-windows-msvc' } else { 'x86_64-pc-windows-msvc' }
$project = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$programFiles = Get-ProgramFilesRoot
$installRoot = Join-Path $programFiles 'Compat16'
$receiptPath = Join-Path $programFiles 'Compat16.install-state.json'
if (Test-Path -LiteralPath $receiptPath) { throw 'A Compat16 receipt already exists. Run scripts/uninstall.ps1 first; nothing was overwritten.' }
if (Test-Path -LiteralPath $installRoot) { throw 'The Compat16 install directory already exists. Inspect or uninstall it first; nothing was overwritten.' }
$helper = Join-Path $PSScriptRoot 'installation.ps1'
$uninstaller = Join-Path $PSScriptRoot 'uninstall.ps1'
foreach ($path in @($helper, $uninstaller)) { if (-not (Test-Path -LiteralPath $path -PathType Leaf)) { throw "Required restore script is missing: $(Split-Path -Leaf $path)" } }

$dist = Join-Path $project (Join-Path 'dist' $architecture)
$manifestPath = Join-Path $dist 'manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath -PathType Leaf)) { throw "dist/$architecture/manifest.json is missing. Run scripts/build.ps1 first." }
try { $manifest = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($manifestPath, [Text.Encoding]::UTF8)) }
catch { throw "Package manifest is invalid: $($_.Exception.Message)" }
if ($manifest.target -cne $target -or $null -eq $manifest.files) { throw "Package target does not match native $architecture Windows." }
$packageFiles = @()
$seen = @{}
foreach ($entry in @($manifest.files)) {
    $relative = [string]$entry.path
    if (-not (Test-SafeRelativePath $relative) -or $relative.Contains('\') -or
        $relative -match '(^|/)manifest\.json$' -or
        $relative -match '^(installation|uninstall)\.ps1$') { throw "Unsafe or reserved package path '$relative'." }
    if ($seen.ContainsKey($relative.ToLowerInvariant())) { throw "Duplicate package path '$relative'." }
    $seen[$relative.ToLowerInvariant()] = $true
    if ([string]$entry.sha256 -notmatch '^[0-9a-fA-F]{64}$' -or [long]$entry.bytes -lt 0) { throw "Invalid manifest entry '$relative'." }
    $source = [IO.Path]::GetFullPath((Join-Path $dist $relative))
    $prefix = [IO.Path]::GetFullPath($dist).TrimEnd('\') + '\'
    if (-not $source.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase) -or -not (Test-Path -LiteralPath $source -PathType Leaf)) {
        throw "Manifest file is missing or outside dist/${architecture}: '$relative'."
    }
    $item = Get-Item -LiteralPath $source
    $hash = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($item.Length -ne [long]$entry.bytes -or $hash -ine [string]$entry.sha256) { throw "Manifest verification failed: '$relative'." }
    $packageFiles += [pscustomobject]@{ path = $relative; source = $source; hash = $hash }
}
$required = @('compat16.exe', 'compat16w.exe', 'compat16.dll', 'compat16host.exe')
foreach ($name in $required) { if (-not $seen.ContainsKey($name)) { throw "Manifest is missing release file '$name'." } }
$views = @('Registry64', 'Registry32')
$viewStates = @()
foreach ($view in $views) {
    $state = Get-ViewState $view
    if ($state.keyExists) { throw "$view already has NtVdm64\Compat16. It was left untouched; uninstall or review it first." }
    $viewStates += $state
}
$registryValues = @(
    [pscustomobject]@{ name = 'InternalName'; value = '*' },
    [pscustomobject]@{ name = 'ProductName'; value = '*' },
    [pscustomobject]@{ name = 'ProductVersion'; value = '*' },
    [pscustomobject]@{ name = 'MappedExeName'; value = (Join-Path $installRoot 'compat16w.exe') },
    [pscustomobject]@{ name = 'CommandLine'; value = ' --system-module "%m" --system-command %c' }
)
$wildcards = Find-WildcardProviders $views
$files = @($packageFiles | ForEach-Object { [pscustomobject]@{ path = $_.path; sha256 = $_.hash } })
$files += [pscustomobject]@{ path = 'manifest.json'; sha256 = (Get-FileHash $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant() }
$files += [pscustomobject]@{ path = 'installation.ps1'; sha256 = (Get-FileHash $helper -Algorithm SHA256).Hash.ToLowerInvariant() }
$files += [pscustomobject]@{ path = 'uninstall.ps1'; sha256 = (Get-FileHash $uninstaller -Algorithm SHA256).Hash.ToLowerInvariant() }
$receipt = [pscustomobject]@{
    product = 'Compat16'; schemaVersion = 1; installId = [Guid]::NewGuid().ToString('D')
    architecture = $architecture; installPath = $installRoot; files = @($files)
    registryValues = @($registryValues); registryViews = @($viewStates)
}

Write-Phase 2 'Review files and NtVdm64 registration'
Write-Host "  Target: $target"
Write-Host "  Files:  $($packageFiles.Count) SHA-256-verified payload files plus restore tools"
Write-Host '  Keys:   HKLM NtVdm64\Compat16 in Registry64 and Registry32'
Write-Host '  Global .exe associations: unchanged'
foreach ($provider in $wildcards) { Write-Host "  Existing wildcard provider: $($provider.product) [$($provider.key), $($provider.view)]" -ForegroundColor Yellow }
if ($wildcards.Count) { Write-Host '  Provider priority is host-defined and is not verified; existing providers will not be removed.' -ForegroundColor Yellow }
if ($architecture -eq 'arm64') {
    Write-Host '  Windows 10 ARM lacks NtVdm64; Windows 11 ARM64 support is unconfirmed. Registration alone does not guarantee double-click support.' -ForegroundColor Yellow
}
if (-not (Confirm-Compat16 -Yes:$Yes -Prompt 'Install this provider?')) { Write-Host 'Cancelled; no changes made.' -ForegroundColor Yellow; return }

Write-Phase 3 'Write durable recovery receipt, then copy verified files'
foreach ($view in $viewStates) {
    $current = Get-ViewState $view.view
    if ($current.keyExists -or $current.parentExisted -ne $view.parentExisted) { throw "$($view.view) registry state changed after review; no files were copied." }
}
if ((Test-Path -LiteralPath $installRoot) -or (Test-Path -LiteralPath $receiptPath)) { throw 'Install path or receipt appeared after review; nothing was overwritten.' }
Write-DurableState $receiptPath $receipt
try {
    New-Item -ItemType Directory -Path $installRoot | Out-Null
    Assert-NoInstallReparsePoint $installRoot $installRoot
    if (@(Get-ChildItem -LiteralPath $installRoot -Force).Count) { throw 'Install directory was populated after review; contents were preserved.' }
    foreach ($file in $packageFiles) { Copy-VerifiedFile $file.source $file.path $file.hash $installRoot }
    Copy-VerifiedFile $manifestPath 'manifest.json' $files[($files.Count - 3)].sha256 $installRoot
    Copy-VerifiedFile $helper 'installation.ps1' $files[($files.Count - 2)].sha256 $installRoot
    Copy-VerifiedFile $uninstaller 'uninstall.ps1' $files[($files.Count - 1)].sha256 $installRoot

    Write-Phase 4 'Create the new provider key in both registry views'
    foreach ($view in $views) { Add-Provider $receipt $view }
    foreach ($view in $views) {
        $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::$view)
        try {
            $key = $base.OpenSubKey($keyPath, $false)
            try {
                if (-not $key) { throw "$view Compat16 registration is missing after installation." }
                foreach ($expected in $registryValues) { if (-not (Test-InstalledValue $key $expected)) { throw "$view Compat16 value '$($expected.name)' failed verification." } }
            } finally { if ($key) { $key.Close() } }
        } finally { $base.Close() }
    }
} catch {
    Write-Host "Install stopped: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "Receipt retained: $receiptPath" -ForegroundColor Yellow
    Write-Host "Recovery: run scripts/uninstall.ps1 as Administrator (or $installRoot\uninstall.ps1 if present)." -ForegroundColor Yellow
    throw
}
Write-Host 'Compat16 files and provider values were installed.' -ForegroundColor Green
Write-Host "Uninstaller: $installRoot\uninstall.ps1"
Write-Host 'Windows provider selection was not tested; ARM64 support remains unconfirmed.' -ForegroundColor Yellow
