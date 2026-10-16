Set-StrictMode -Version Latest

function Get-PfeTransportEnvironmentNames {
    @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY', 'CURL_HOME', 'XDG_CONFIG_HOME',
        'CURL_CA_BUNDLE', 'CURL_SSL_BACKEND', 'SSL_CERT_FILE', 'SSL_CERT_DIR', 'SSLKEYLOGFILE',
        'DOTNET_SYSTEM_NET_DISABLEIPV6')
}

function Get-PfeAlternateTransportPolicy([object]$Observation, [string]$FailureOutcome) {
    if ($FailureOutcome -cne 'dns-failure') { return 'not-a-DNS-retry' }
    try {
        if ($null -eq $Observation -or $Observation.defaultProxyRoute -cne 'direct-observed') {
            return 'equivalent-direct-route-not-observed'
        }
        $presence = $Observation.environmentVariablePresence
        foreach ($name in (Get-PfeTransportEnvironmentNames)) {
            $entry = if ($presence -is [Collections.IDictionary]) { $presence[$name] } else { $presence.$name }
            if ($null -eq $entry -or $entry.nonempty -isnot [bool]) { return 'transport-environment-not-observed' }
            if ($entry.nonempty) { return 'custom-transport-environment' }
        }
    } catch {
        return 'transport-environment-not-observed'
    }
    return 'equivalent-direct-route'
}

function Get-PfePinnedArchiveBytes([byte[]]$Bytes, [long]$Length, [string]$Sha256) {
    if ($Bytes.LongLength -ne $Length) { throw 'Source response has a different byte count.' }
    $hash = [Security.Cryptography.SHA256]::Create()
    try { $actual = ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-','').ToLowerInvariant() }
    finally { $hash.Dispose() }
    if ($actual -cne $Sha256) { throw 'Source archive identity mismatch.' }
    return ,$Bytes
}

function Get-PfeCurlResponseBytes([object]$Outcome, [string]$Status, [byte[]]$Bytes) {
    if ($Outcome.StopReason -cne 'exited' -or -not $Outcome.ProcessTreeCleaned -or $Outcome.ExitCode -ne 0) {
        throw 'Controlled source transport did not complete successfully.'
    }
    if ($Status -cne '200' -or $Bytes.Length -ne 558157) { throw 'Source returned a rejected HTTP status or length.' }
    return ,$Bytes
}

function Invoke-PfeSystemCurl {
    param([string]$Source, [string]$RawDirectory, [string]$ProfileDirectory, [object]$Observation,
        [string]$FailureOutcome)
    $policy = Get-PfeAlternateTransportPolicy $Observation $FailureOutcome
    $result = [ordered]@{ attempted = $false; policy = $policy; outcome = 'alternate-unavailable'
        transport = 'system-curl-schannel'; addressFamily = 'IPv4'; exitCode = $null; elapsedMilliseconds = $null; bytes = $null }
    if ($policy -cne 'equivalent-direct-route') { return [pscustomobject]$result }
    if ($Source -cne 'https://www.lancaster.ac.uk/~steveb/cpaap/pfe/pfe101.zip') {
        throw 'Alternate source transport requires the fixed official origin.'
    }
    $system = [Environment]::SystemDirectory
    $windows = [Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
    $curl = Join-Path $system 'curl.exe'
    if (-not (Test-Path -LiteralPath $curl -PathType Leaf)) { return [pscustomobject]$result }
    # Run only the OS tool, with no CI environment/credentials or user config.
    # Both transports retain the original hostname, OS certificate trust, no
    # redirects, fixed size and the common pinned SHA-256 validation.
    $environment = @("SystemRoot=$windows", "WINDIR=$windows", "PATH=$system;$windows"
        "TEMP=$RawDirectory", "TMP=$RawDirectory", "USERPROFILE=$ProfileDirectory", "HOME=$ProfileDirectory"
        "APPDATA=$(Join-Path $ProfileDirectory 'AppData/Roaming')"
        "LOCALAPPDATA=$(Join-Path $ProfileDirectory 'AppData/Local')")
    $version = Join-Path $RawDirectory 'source-curl-version.txt'
    $versionErrors = Join-Path $RawDirectory 'source-curl-version-stderr.txt'
    try {
        $run = [Compat16.PfeProbe.ContainedProcess]::Run($curl, @('-q','--version'), $RawDirectory,
            $environment, @($version,$versionErrors), 3)
        if ($run.StopReason -cne 'exited' -or $run.ExitCode -ne 0 -or -not $run.ProcessTreeCleaned -or
            (Get-Item -LiteralPath $version).Length -gt 8192) {
            return [pscustomobject]$result
        }
        $identity = [regex]::Match([IO.File]::ReadAllText($version), '(?m)^curl (\d+\.\d+\.\d+)[^\r\n]*\bSchannel\b')
        # 8.4 also enforces max-filesize when response length is unknown.
        if (-not $identity.Success -or [version]$identity.Groups[1].Value -lt [version]'8.4.0') { return [pscustomobject]$result }
        $body = Join-Path $RawDirectory 'source-curl-body.tmp'
        $status = Join-Path $RawDirectory 'source-curl-status.txt'
        $errors = Join-Path $RawDirectory 'source-curl-stderr.txt'
        $arguments = @('-q','--silent','--stderr','NUL','--proto','=https','--proto-redir','=https'
            '--max-redirs','0','--max-time','15','--connect-timeout','5','--max-filesize','558157'
            '--no-ssl-auto-client-cert','--ipv4','--output',$body,'--write-out','%{http_code}','--url',$Source)
        # Try an A-only OS lookup after the first transport's DNS failure. No
        # IP, resolver, proxy route, certificate setting or host is replaced.
        $result.attempted = $true
        $run = [Compat16.PfeProbe.ContainedProcess]::Run($curl, $arguments, $RawDirectory,
            $environment, @($status,$errors,$body), 17)
        $result.exitCode = $run.ExitCode; $result.elapsedMilliseconds = $run.ElapsedMilliseconds
        if ($run.StopReason -cne 'exited') { $result.outcome = 'timeout'; return [pscustomobject]$result }
        if ($run.ExitCode -ne 0) {
            $result.outcome = switch ($run.ExitCode) {
                6 { 'dns-failure' }; 7 { 'connection-failure' }; 28 { 'timeout' }
                35 { 'tls-rejected' }; 60 { 'tls-rejected' }; default { 'alternate-source-failure' }
            }
            return [pscustomobject]$result
        }
        if (-not (Test-Path -LiteralPath $body -PathType Leaf) -or (Get-Item -LiteralPath $body).Length -ne 558157 -or
            (Get-Item -LiteralPath $status).Length -ne 3) { $result.outcome = 'size-rejected'; return [pscustomobject]$result }
        $result.bytes = Get-PfeCurlResponseBytes $run ([IO.File]::ReadAllText($status)) ([IO.File]::ReadAllBytes($body))
        $result.outcome = 'downloaded'
    } catch {
        $result.outcome = 'alternate-source-failure'
    }
    return [pscustomobject]$result
}

Export-ModuleMember -Function Get-PfeTransportEnvironmentNames, Get-PfeAlternateTransportPolicy, Get-PfePinnedArchiveBytes, Get-PfeCurlResponseBytes, Invoke-PfeSystemCurl
