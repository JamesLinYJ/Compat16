Set-StrictMode -Version Latest

function Get-PfeLiveTrace([string]$Path) {
    $stream = $null
    try {
        $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
            [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
        $length = $stream.Length
        if ($length -gt 8MB) { return '' }
        $bytes = New-Object byte[] ([int]$length)
        $offset = 0
        while ($offset -lt $bytes.Length) {
            $count = $stream.Read($bytes, $offset, $bytes.Length - $offset)
            if ($count -eq 0) { break }
            $offset += $count
        }
        return [Text.Encoding]::UTF8.GetString($bytes, 0, $offset)
    } catch [IO.IOException] { return '' }
    finally { if ($null -ne $stream) { $stream.Dispose() } }
}

function Get-PfeTraceSequence([string]$Services) {
    $rows = [regex]::Matches($Services, '(?m)^[@#](\d+) [^\r\n]*\r?\n')
    if ($rows.Count -eq 0) { return -1L }
    $sequence = 0L
    if (-not [long]::TryParse($rows[$rows.Count-1].Groups[1].Value, [ref]$sequence)) { return -1L }
    return $sequence
}

function Get-PfeMessageLoopSeen([string]$Services) {
    return [regex]::IsMatch($Services,
        '(?m)^[@#]\d+ service-boundary stage=dispatch-enter module=USER name=GetMessage ordinal=108 instruction=\d+ guest=[0-9A-F]{4}:[0-9A-F]{4}\r?\n')
}

function Get-PfeInitTaskCrossing([string]$Services) {
    $entry = [regex]::Match($Services,
        '(?m)^[@#]\d+ service-boundary stage=dispatch-enter module=KERNEL name=InitTask ordinal=91 instruction=(\d+) guest=([0-9A-F]{4}:[0-9A-F]{4})\r?\n')
    if (-not $entry.Success) { return $false }
    $returned = '(?m)^[@#]\d+ service-boundary stage=dispatch-return module=KERNEL name=InitTask ordinal=91 instruction=' +
        [regex]::Escape($entry.Groups[1].Value) + ' guest=' + [regex]::Escape($entry.Groups[2].Value) + '\r?\n'
    return [regex]::IsMatch($Services.Substring($entry.Index + $entry.Length), $returned)
}

function Get-PfeStartupEvidence {
    param([bool]$SourceVerified, [object]$Run, [object]$WindowProbe,
        [string]$Services, [string]$Stderr, [string]$FailureTrace, [long]$OutputBytes)
    $init = Get-PfeInitTaskCrossing $Services
    $messageLoop = Get-PfeMessageLoopSeen $Services
    $bad = ($Stderr + "`n" + $FailureTrace) -match '\[(?:error|critical)/|\[warn/(?:host_failure|internal_invariant)\]' -or
        $Services -match 'service-boundary stage=dispatch-error'
    $reasons = New-Object 'System.Collections.Generic.List[string]'
    if (-not $SourceVerified) { $reasons.Add('source-not-verified') }
    if ($OutputBytes -lt 0 -or $OutputBytes -gt 8MB) { $reasons.Add('output-limit') }
    if (-not $init) { $reasons.Add('InitTask-not-completed') }
    if (-not $messageLoop) { $reasons.Add('GetMessage-not-entered') }
    if ($bad) { $reasons.Add('runtime-error') }
    if ($null -eq $Run -or $Run.StopReason -cne 'window-responsive' -or
        -not $Run.WindowReadinessObserved -or $Run.ExitCode -ne 125 -or -not $Run.ProcessTreeCleaned) {
        $reasons.Add('responsive-owned-process-not-observed')
    }
    $roundTrips = 0
    $commonWindows = $null
    $usedCallbacks = New-Object 'System.Collections.Generic.HashSet[string]'
    if ($null -eq $WindowProbe -or $WindowProbe.Failure -or
        $WindowProbe.VisibleFrameCount -lt 1 -or $WindowProbe.VisibleDialogCount -ne 0 -or
        $WindowProbe.Probes.Count -ne 2) {
        $reasons.Add('owned-window-observation-incomplete')
    } else {
        $callbacks = [regex]::Matches($Services,
            '(?m)^[@#](?<sequence>\d+) window-callback phase=(?<phase>guest-entry|guest-return) procedure=wndproc callback=(?<callback>\d+) window=(?<window>[0-9A-F]{4}) message=0000 return=(?<value>pending|WNDPROC32:[0-9A-F]{8}) dialog-msgresult=not-applicable\r?\n')
        $priorEnd = -1L
        foreach ($probe in $WindowProbe.Probes) {
            if (-not $probe.Completed -or $probe.StartSequence -lt 0 -or
                $probe.EndSequence -le $probe.StartSequence -or $probe.StartSequence -lt $priorEnd -or
                $probe.ElapsedMilliseconds -lt 0 -or $probe.ElapsedMilliseconds -gt 1500) {
                $reasons.Add('native-null-probe-incomplete'); continue
            }
            $priorEnd = $probe.EndSequence
            $pending = @{}
            $windows = New-Object 'System.Collections.Generic.HashSet[string]'
            $invalid = $false
            foreach ($row in $callbacks) {
                $sequence = [long]$row.Groups['sequence'].Value
                if ($sequence -le $probe.StartSequence -or $sequence -gt $probe.EndSequence) { continue }
                $id = $row.Groups['callback'].Value
                $window = $row.Groups['window'].Value
                if ($row.Groups['phase'].Value -ceq 'guest-entry') {
                    if ($row.Groups['value'].Value -cne 'pending' -or $pending.ContainsKey($id) -or $usedCallbacks.Contains($id)) {
                        $invalid = $true
                    } else { $pending[$id] = $window }
                } else {
                    if (-not $pending.ContainsKey($id) -or $pending[$id] -cne $window -or
                        $row.Groups['value'].Value -notmatch '^WNDPROC32:[0-9A-F]{8}$') {
                        $invalid = $true
                    } else {
                        $pending.Remove($id); [void]$usedCallbacks.Add($id); [void]$windows.Add($window); $roundTrips++
                    }
                }
            }
            if ($invalid -or $pending.Count -ne 0 -or $windows.Count -eq 0) {
                $reasons.Add('guest-null-callback-not-completed')
            }
            if ($null -eq $commonWindows) { $commonWindows = $windows }
            else { $commonWindows.IntersectWith($windows) }
        }
        if ($null -eq $commonWindows -or $commonWindows.Count -eq 0) { $reasons.Add('null-probes-target-different-guest-windows') }
    }
    [pscustomobject]@{ accepted = $reasons.Count -eq 0; reasons = @($reasons.ToArray())
        initTaskCrossing = $init; getMessageSeen = $messageLoop; guestNullRoundTrips = $roundTrips }
}

Export-ModuleMember -Function Get-PfeLiveTrace, Get-PfeTraceSequence, Get-PfeMessageLoopSeen, Get-PfeInitTaskCrossing, Get-PfeStartupEvidence
