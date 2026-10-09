[CmdletBinding()]
param([switch]$Yes)

$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'installation.ps1')
$parentPath = 'SOFTWARE\Microsoft\Windows NT\CurrentVersion\NtVdm64'
$keyPath = "$parentPath\Compat16"

Write-Host '========================================' -ForegroundColor DarkCyan
Write-Host 'Compat16 / Uninstall' -ForegroundColor Green
Write-Host '========================================' -ForegroundColor DarkCyan
Write-Phase 1 'Locate and validate the installation receipt'
if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitOperatingSystem) { throw 'Compat16 integration requires native 64-bit Windows.' }
$architecture = Get-NativeArchitecture
$programFiles = Get-ProgramFilesRoot
$installRoot = Join-Path $programFiles 'Compat16'
$receiptPath = Join-Path $programFiles 'Compat16.install-state.json'
if (-not (Test-Path -LiteralPath $receiptPath -PathType Leaf)) {
    if (Test-Path -LiteralPath $receiptPath) { throw 'The receipt path exists but is not a file; nothing was changed.' }
    if ((Test-Path -LiteralPath $installRoot)) { throw 'Compat16 files exist without an ownership receipt; they were left untouched.' }
    Write-Host 'No Compat16 installation was found.' -ForegroundColor Yellow
    return
}
Assert-Compat16Admin 'Uninstall' $PSCommandPath
try { $receipt = ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($receiptPath, [Text.Encoding]::UTF8)) }
catch { throw "The installation receipt is invalid; no changes made: $($_.Exception.Message)" }
$id = [Guid]::Empty
if ($receipt.product -cne 'Compat16' -or [int]$receipt.schemaVersion -ne 1 -or -not [Guid]::TryParse([string]$receipt.installId, [ref]$id)) {
    throw 'The installation receipt is not a valid Compat16 owner record.'
}
if ([IO.Path]::GetFullPath([string]$receipt.installPath).TrimEnd('\') -ine [IO.Path]::GetFullPath($installRoot).TrimEnd('\') -or
    [string]$receipt.architecture -cne $architecture) { throw 'Receipt path or native architecture does not match this installation.' }
$stateHash = (Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash
$files = @($receipt.files)
$systemLauncher = $receipt.systemLauncher
if ($systemLauncher) {
    if ($architecture -cne 'arm64' -or $systemLauncher.name -cne 'ntvdm64.dll' -or
        [string]$systemLauncher.sha256 -notmatch '^[0-9a-fA-F]{64}$') { throw 'Invalid system launch adapter receipt; no changes made.' }
    $systemLauncherPath = Get-SystemLauncherPath
    Assert-NoInstallReparsePoint (Split-Path -Parent $systemLauncherPath) $systemLauncherPath
}
$seen = @{}
foreach ($file in $files) {
    $relative = [string]$file.path
    if (-not (Test-SafeRelativePath $relative) -or [string]$file.sha256 -notmatch '^[0-9a-fA-F]{64}$') { throw "Invalid receipt file entry '$relative'." }
    if ($seen.ContainsKey($relative.ToLowerInvariant())) { throw "Duplicate receipt path '$relative'." }
    $seen[$relative.ToLowerInvariant()] = $true
    $full = [IO.Path]::GetFullPath((Join-Path $installRoot ($relative.Replace('/', '\'))))
    if (-not $full.StartsWith(([IO.Path]::GetFullPath($installRoot).TrimEnd('\') + '\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw "Receipt file path escapes the installation: '$relative'."
    }
    Assert-NoInstallReparsePoint $installRoot $full
}
foreach ($required in @('compat16.exe', 'compat16w.exe', 'compat16.dll', 'compat16host.exe', 'manifest.json', 'installation.ps1', 'uninstall.ps1')) {
    if (-not $seen.ContainsKey($required)) { throw "Receipt is missing '$required'; no changes made." }
}
$views = @($receipt.registryViews)
if ($views.Count -ne 2 -or @($views | Where-Object { $_.view -eq 'Registry64' }).Count -ne 1 -or
    @($views | Where-Object { $_.view -eq 'Registry32' }).Count -ne 1) { throw 'Receipt does not cover both registry views.' }
$expected = @(
    [pscustomobject]@{ name = 'InternalName'; value = '*' },
    [pscustomobject]@{ name = 'ProductName'; value = '*' },
    [pscustomobject]@{ name = 'ProductVersion'; value = '*' },
    [pscustomobject]@{ name = 'MappedExeName'; value = (Join-Path $installRoot 'compat16w.exe') },
    [pscustomobject]@{ name = 'CommandLine'; value = ' --system-module "%m" --system-command %c' }
)
$plans = @()
foreach ($view in @('Registry64', 'Registry32')) {
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::$view)
    try {
        $key = $base.OpenSubKey($keyPath, $false)
        try {
            $changed = 0
            if ($key) {
                foreach ($entry in $expected) {
                    $value = Get-RegistryValue $key $entry.name
                    if (-not $value.exists) { continue }
                    if (-not (Test-InstalledValue $key $entry)) { $changed++ }
                }
                $extras = @($key.GetValueNames() | Where-Object { $_ -notin $expected.name })
                if ($extras.Count -or @($key.GetSubKeyNames()).Count) { $changed++ }
            }
            $viewReceipt = @($views | Where-Object { $_.view -eq $view })[0]
            $plans += [pscustomobject]@{ view = $view; parentExisted = [bool]$viewReceipt.parentExisted; changed = $changed }
        } finally { if ($key) { $key.Close() } }
    } finally { $base.Close() }
}
$registryConflicts = @($plans | Where-Object { $_.changed -gt 0 }).Count
$fileDelete = 0; $fileChanged = 0
foreach ($file in $files) {
    $path = Join-Path $installRoot ($file.path.Replace('/', '\'))
    Assert-NoInstallReparsePoint $installRoot $path
    if (-not (Test-Path -LiteralPath $path)) { continue }
    if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or
        (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine [string]$file.sha256) { $fileChanged++ }
    else { $fileDelete++ }
}
Write-Phase 2 'Review owned registry values and recorded file hashes'
Write-Host "  Registry views with conflicts: $registryConflicts"
Write-Host "  Unchanged recorded files: $fileDelete; modified/replaced files: $fileChanged"
Write-Host '  Unrecorded files are never deleted.'
if ($systemLauncher) { Write-Host "  Recorded native launch adapter: $systemLauncherPath" }
if ($registryConflicts) { Write-Host '  Registry conflicts keep all runtime files in place.' -ForegroundColor Yellow }
if (-not (Confirm-Compat16 -Yes:$Yes -Prompt 'Restore this Compat16 installation?')) { Write-Host 'Cancelled; no changes made.' -ForegroundColor Yellow; return }
if ((Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash -ine $stateHash) { throw 'Receipt changed after review; no changes made.' }

Write-Phase 3 'Remove only registry values that still match Compat16'
$conflicts = @(); $errors = @()
foreach ($plan in $plans) {
    $view = [string]$plan.view
    $viewConflict = $false
    $base = [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, [Microsoft.Win32.RegistryView]::$view)
    try {
        $key = $base.OpenSubKey($keyPath, $true)
        if ($key) {
            try {
                foreach ($entry in $expected) {
                    $value = Get-RegistryValue $key $entry.name
                    if (-not $value.exists) { continue }
                    if (Test-InstalledValue $key $entry) { $key.DeleteValue($entry.name, $false) }
                    else { $conflicts += "$view $($entry.name): value changed"; $viewConflict = $true }
                }
                $extras = @($key.GetValueNames() | Where-Object { $_ -notin $expected.name })
                if ($extras.Count -or @($key.GetSubKeyNames()).Count) { $conflicts += "$view Compat16 key contains unrelated data"; $viewConflict = $true }
                if (-not $viewConflict -and
                    @($key.GetValueNames()).Count -eq 0 -and @($key.GetSubKeyNames()).Count -eq 0) {
                    $key.Close(); $key = $null
                    $parent = $base.OpenSubKey($parentPath, $true)
                    if ($parent) { try { $parent.DeleteSubKey('Compat16', $false) } finally { $parent.Close() } }
                }
            } finally { if ($key) { $key.Close() } }
        }
        if (-not $plan.parentExisted) {
            $parent = $base.OpenSubKey($parentPath, $true)
            if ($parent) {
                try {
                    if (@($parent.GetValueNames()).Count -eq 0 -and @($parent.GetSubKeyNames()).Count -eq 0) {
                        $parent.Close(); $parent = $null; $base.DeleteSubKey($parentPath, $false)
                    }
                } finally { if ($parent) { $parent.Close() } }
            }
        }
    } catch { $errors += "$view registry cleanup: $($_.Exception.Message)" }
    finally { $base.Close() }
}
if ($conflicts.Count) { Write-Host 'Registry conflicts were preserved; runtime files and receipt remain for recovery.' -ForegroundColor Yellow }

Write-Phase 4 'Remove unchanged files only when registry cleanup is conflict-free'
if ($conflicts.Count -or $errors.Count) {
    foreach ($message in $conflicts) { Write-Host "  PRESERVED: $message" -ForegroundColor Yellow }
    foreach ($message in $errors) { Write-Host "  ERROR: $message" -ForegroundColor Red }
    Write-Host "Receipt retained: $receiptPath" -ForegroundColor Yellow
    return
}
if ($systemLauncher) {
    try {
        Assert-NoInstallReparsePoint (Split-Path -Parent $systemLauncherPath) $systemLauncherPath
        if (Test-Path -LiteralPath $systemLauncherPath) {
            if (-not (Test-Path -LiteralPath $systemLauncherPath -PathType Leaf) -or
                (Get-FileHash $systemLauncherPath).Hash -ine $systemLauncher.sha256) {
                throw 'The system launch module changed; runtime files and the receipt were preserved.'
            }
            Remove-Item -LiteralPath $systemLauncherPath -Force
        }
    } catch {
        Write-Host $_.Exception.Message -ForegroundColor Yellow
        Write-Host "Receipt retained: $receiptPath" -ForegroundColor Yellow
        return
    }
}
$bootstrapNames = @('uninstall.ps1', 'installation.ps1')
foreach ($file in $files) {
    if ($bootstrapNames -contains [string]$file.path) { continue }
    $path = Join-Path $installRoot ($file.path.Replace('/', '\'))
    try {
        Assert-NoInstallReparsePoint $installRoot $path
        if (-not (Test-Path -LiteralPath $path)) { continue }
        if (-not (Test-Path -LiteralPath $path -PathType Leaf) -or
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine [string]$file.sha256) {
            $conflicts += "$($file.path): changed file preserved"; continue
        }
        Assert-NoInstallReparsePoint $installRoot $path
        Remove-Item -LiteralPath $path -Force
    } catch { $errors += "$($file.path): $($_.Exception.Message)" }
}
$directories = @{}
foreach ($file in $files) {
    $directory = Split-Path -Parent ($file.path.Replace('/', '\'))
    while ($directory) { $directories[$directory] = $true; $directory = Split-Path -Parent $directory }
}
foreach ($directory in @($directories.Keys | Sort-Object { ($_ -split '[\\/]').Count } -Descending)) {
    $path = Join-Path $installRoot $directory
    try {
        Assert-NoInstallReparsePoint $installRoot $path
        if ((Test-Path -LiteralPath $path -PathType Container) -and @(Get-ChildItem -LiteralPath $path -Force).Count -eq 0) {
            Assert-NoInstallReparsePoint $installRoot $path
            Remove-Item -LiteralPath $path -Force
        }
    } catch { $errors += "${directory}: $($_.Exception.Message)" }
}
if (-not $conflicts.Count -and -not $errors.Count) {
    foreach ($name in $bootstrapNames) {
        $file = @($files | Where-Object { $_.path -eq $name })[0]; $path = Join-Path $installRoot $name
        Assert-NoInstallReparsePoint $installRoot $path
        if ((Test-Path -LiteralPath $path) -and
            (-not (Test-Path -LiteralPath $path -PathType Leaf) -or (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash -ine [string]$file.sha256)) {
            $conflicts += "${name}: changed file preserved"
        }
    }
    if (-not $conflicts.Count -and -not $errors.Count) {
        foreach ($name in $bootstrapNames) {
            $path = Join-Path $installRoot $name
            try {
                Assert-NoInstallReparsePoint $installRoot $path
                if (Test-Path -LiteralPath $path) { Remove-Item -LiteralPath $path -Force }
            }
            catch { $errors += "${name}: $($_.Exception.Message)"; break }
        }
        if (-not $conflicts.Count -and -not $errors.Count) {
            Assert-NoInstallReparsePoint $installRoot $installRoot
            if ((Test-Path -LiteralPath $installRoot -PathType Container) -and @(Get-ChildItem -LiteralPath $installRoot -Force).Count -eq 0) {
                Assert-NoInstallReparsePoint $installRoot $installRoot
                Remove-Item -LiteralPath $installRoot -Force
            }
        }
    }
}
if ($conflicts.Count -or $errors.Count -or (Get-FileHash -LiteralPath $receiptPath -Algorithm SHA256).Hash -ine $stateHash) {
    foreach ($message in $conflicts) { Write-Host "  PRESERVED: $message" -ForegroundColor Yellow }
    foreach ($message in $errors) { Write-Host "  ERROR: $message" -ForegroundColor Red }
    Write-Host "Receipt retained: $receiptPath" -ForegroundColor Yellow
    return
}
Assert-NoInstallReparsePoint $installRoot $installRoot
Remove-Item -LiteralPath $receiptPath -Force
Write-Host 'Compat16 registration was restored and unchanged recorded files were removed.' -ForegroundColor Green
if (Test-Path -LiteralPath $installRoot) { Write-Host "Unrecorded items remain in $installRoot and were preserved." -ForegroundColor Yellow }
