function Write-Phase([int]$Number, [string]$Text) {
    Write-Host ("[{0}/4] {1}" -f $Number, $Text) -ForegroundColor Cyan
}

function Get-NativeArchitecture {
    # RuntimeInformation can report the emulated PowerShell process on ARM64.
    $machine = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE', 'Machine')
    if ($machine -eq 'ARM64') { return 'arm64' }
    if ($machine -eq 'AMD64') { return 'x64' }
    try { $name = [Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() }
    catch {
        $name = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITEW6432')
        if (-not $name) { $name = [Environment]::GetEnvironmentVariable('PROCESSOR_ARCHITECTURE') }
    }
    $normalized = ($name -replace '[^A-Za-z0-9]', '').ToUpperInvariant()
    if ($normalized -eq 'ARM64') { return 'arm64' }
    if ($normalized -eq 'X64' -or $normalized -eq 'AMD64') { return 'x64' }
    throw "Unsupported native Windows architecture '$name'."
}
function Get-ProgramFilesRoot {
    $root = [Environment]::GetEnvironmentVariable('ProgramW6432')
    if (-not $root) { $root = [Environment]::GetEnvironmentVariable('ProgramFiles') }
    if (-not $root -or -not (Test-Path -LiteralPath $root -PathType Container)) {
        throw 'The native 64-bit Program Files directory was not found.'
    }
    [IO.Path]::GetFullPath($root)
}
function Assert-Compat16Admin([string]$Operation, [string]$ScriptPath) {
    if ($env:OS -ne 'Windows_NT' -or -not [Environment]::Is64BitOperatingSystem) {
        throw 'Compat16 integration requires native 64-bit Windows.'
    }
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "$Operation requires an elevated PowerShell. Open PowerShell as Administrator and run:" -ForegroundColor Yellow
        Write-Host ("  & '{0}' -Yes" -f $ScriptPath.Replace("'", "''")) -ForegroundColor White
        throw 'Administrator privileges are required; no changes were made.'
    }
}
function Confirm-Compat16([switch]$Yes, [string]$Prompt) {
    if ($Yes) { return $true }
    if ([Console]::IsInputRedirected) { throw 'Use -Yes only after reviewing the plan; no interactive confirmation is available.' }
    $answer = Read-Host "$Prompt [y/N]"
    return $answer -eq 'y' -or $answer -eq 'Y' -or $answer -eq 'yes' -or $answer -eq 'YES'
}

function Get-RegistryValue([Microsoft.Win32.RegistryKey]$Key, [string]$Name) {
    if (-not $Key -or $Key.GetValueNames() -notcontains $Name) {
        return [pscustomobject]@{ exists = $false; kind = ''; value = $null }
    }
    $kind = $Key.GetValueKind($Name).ToString()
    $value = if ($kind -eq 'String') {
        [string]$Key.GetValue($Name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)
    } else { $null }
    [pscustomobject]@{ exists = $true; kind = $kind; value = $value }
}

function Test-InstalledValue([Microsoft.Win32.RegistryKey]$Key, [object]$Expected) {
    $current = Get-RegistryValue -Key $Key -Name ([string]$Expected.name)
    return $current.exists -and $current.kind -eq 'String' -and $current.value -ceq [string]$Expected.value
}

function Test-SafeRelativePath([string]$Path) {
    return -not [string]::IsNullOrWhiteSpace($Path) -and
        -not [IO.Path]::IsPathRooted($Path) -and
        $Path -notmatch '(^|[\\/])\.\.?([\\/]|$)' -and
        $Path -notmatch '[:*?"<>|]'
}

function Assert-NoInstallReparsePoint([string]$Root, [string]$Path) {
    $rootPath = [IO.Path]::GetFullPath($Root).TrimEnd('\')
    $fullPath = [IO.Path]::GetFullPath($Path).TrimEnd('\')
    if ($fullPath -ine $rootPath -and
        -not $fullPath.StartsWith(($rootPath + '\'), [StringComparison]::OrdinalIgnoreCase)) {
        throw 'The requested path is outside the Compat16 installation root.'
    }
    # GetFullPath checks spelling, not junction destinations. Inspect only our
    # install root and its descendants; do not traverse arbitrary host parents.
    # GetAttributes inspects the reparse entry itself, including dangling links.
    $components = @($rootPath)
    if ($fullPath -ine $rootPath) {
        $current = $rootPath
        foreach ($part in $fullPath.Substring($rootPath.Length + 1).Split('\')) {
            $current = Join-Path $current $part
            $components += $current
        }
    }
    foreach ($component in $components) {
        try { $attributes = [IO.File]::GetAttributes($component) }
        catch [IO.FileNotFoundException] { break }
        catch [IO.DirectoryNotFoundException] { break }
        if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Reparse point conflict: '$component'. This path was left untouched; the ownership receipt is retained."
        }
    }
}

function Write-DurableState([string]$Path, [object]$State) {
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(((ConvertTo-Json -InputObject $State -Depth 8) + "`n"))
    $stream = [IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    $done = $false
    try { $stream.Write($bytes, 0, $bytes.Length); $stream.Flush($true); $done = $true }
    finally { $stream.Dispose(); if (-not $done) { Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue } }
}
