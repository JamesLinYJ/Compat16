#Requires -Version 5.1
# Pure protocol/ownership fixtures; native process checks do not launch a guest.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$helpers = Join-Path $PSScriptRoot 'win16-startup'
Add-Type -Path @((Join-Path $helpers 'WindowReadiness.cs'), (Join-Path $helpers 'tests/FakeWindowPlatform.cs'))
Add-Type -Path (Join-Path $helpers 'ContainedProcess.cs')
Import-Module (Join-Path $helpers 'pfe-evidence.psm1') -Force
Import-Module (Join-Path $helpers 'source-curl.psm1') -Force
$script:cases = 0
$script:assertions = 0
function Assert-That([bool]$Condition, [string]$Message) {
    $script:assertions++
    if (-not $Condition) { throw $Message }
}
function Assert-Throws([scriptblock]$Body, [string]$Message) {
    $failed = $false
    try { & $Body | Out-Null } catch { $failed = $true }
    Assert-That $failed $Message
}
function Test-Case([string]$Name, [scriptblock]$Body) {
    & $Body
    $script:cases++
    Write-Output ("STARTUP_CONTRACT_PASSED " + $Name)
}
function New-RunFacts {
    [pscustomobject]@{ StopReason='window-responsive'; WindowReadinessObserved=$true; ExitCode=125; ProcessTreeCleaned=$true }
}
function New-ProbeFacts {
    [pscustomobject]@{ Failure=$null; VisibleFrameCount=1; VisibleDialogCount=0; Probes=@(
        [pscustomobject]@{StartSequence=10L; EndSequence=12L; ElapsedMilliseconds=1L; Completed=$true},
        [pscustomobject]@{StartSequence=20L; EndSequence=22L; ElapsedMilliseconds=1L; Completed=$true}) }
}
$baseServices = @'
@1 service-boundary stage=dispatch-enter module=KERNEL name=InitTask ordinal=91 instruction=5 guest=0008:0004
@2 service-boundary stage=dispatch-return module=KERNEL name=InitTask ordinal=91 instruction=5 guest=0008:0004
@3 service-boundary stage=dispatch-enter module=USER name=GetMessage ordinal=108 instruction=60 guest=0008:0168
@11 window-callback phase=guest-entry procedure=wndproc callback=90 window=0050 message=0000 return=pending dialog-msgresult=not-applicable
@12 window-callback phase=guest-return procedure=wndproc callback=90 window=0050 message=0000 return=WNDPROC32:00000000 dialog-msgresult=not-applicable
@21 window-callback phase=guest-entry procedure=wndproc callback=91 window=0050 message=0000 return=pending dialog-msgresult=not-applicable
@22 window-callback phase=guest-return procedure=wndproc callback=91 window=0050 message=0000 return=WNDPROC32:00000000 dialog-msgresult=not-applicable
'@
$baseServices += "`n"
function Get-Evidence([string]$Services=$baseServices, [object]$Run=(New-RunFacts),
    [object]$Probe=(New-ProbeFacts), [string]$Errors='', [bool]$Verified=$true, [long]$Bytes=2048) {
    Get-PfeStartupEvidence -SourceVerified $Verified -Run $Run -WindowProbe $Probe -Services $Services `
        -Stderr $Errors -FailureTrace '' -OutputBytes $Bytes
}

Test-Case 'visible-frame-and-two-exact-guest-round-trips' {
    $e = Get-Evidence
    Assert-That $e.accepted 'Completed owned/native/guest evidence was rejected.'
    Assert-That ($e.guestNullRoundTrips -eq 2) 'Both guest callback returns are required.'
}
Test-Case 'optional-monotonic-timing-preserves-exact-complete-row-evidence' {
    $timed = [regex]::Replace($baseServices, '\r?\n', " elapsed-us=123`n")
    Assert-That (Get-Evidence $timed).accepted 'Timed complete events lost their identities.'
    Assert-That (-not (Get-Evidence $timed.TrimEnd()).accepted) 'An unterminated timed return was accepted.'
    foreach ($bad in @('-1','invalid','123 extra')) {
        Assert-That (-not (Get-Evidence ($timed.Replace('elapsed-us=123',"elapsed-us=$bad"))).accepted) 'Malformed timing made incomplete event evidence acceptable.'
    }
}
Test-Case 'native-only-response-is-not-guest-readiness' {
    $text = ($baseServices -split "`n" | Where-Object { $_ -notmatch 'window-callback' }) -join "`n"
    Assert-That (-not (Get-Evidence ($text+"`n")).accepted) 'Native-only replies must not pass.'
}
Test-Case 'entered-or-wrong-window-callback-does-not-complete' {
    foreach ($text in @(
        $baseServices.Replace('@12 window-callback phase=guest-return','@12 ignored phase=guest-return'),
        $baseServices.Replace('callback=90 window=0050 message=0000 return=WNDPROC32','callback=90 window=0051 message=0000 return=WNDPROC32'),
        $baseServices.Replace('callback=91 window=0050','callback=90 window=0050'),
        $baseServices.Replace('callback=91 window=0050','callback=91 window=0051'))) {
        Assert-That (-not (Get-Evidence $text).accepted) 'Unpaired/reused or different-window callback was accepted.'
    }
}
Test-Case 'partial-and-out-of-interval-rows-do-not-count' {
    Assert-That (-not (Get-Evidence $baseServices.TrimEnd()).accepted) 'An unterminated return row was accepted.'
    $probe = New-ProbeFacts; $probe.Probes[0].StartSequence = 11
    Assert-That (-not (Get-Evidence -Probe $probe).accepted) 'A callback entered before the probe interval was accepted.'
    $probe = New-ProbeFacts; $probe.Probes[1].StartSequence = 10
    Assert-That (-not (Get-Evidence -Probe $probe).accepted) 'Overlapping probe intervals were accepted.'
}
Test-Case 'InitTask-and-GetMessage-are-required' {
    Assert-That (-not (Get-Evidence ($baseServices.Replace('name=GetMessage','name=Other'))).accepted) 'Missing GetMessage was accepted.'
    Assert-That (-not (Get-Evidence ($baseServices.Replace('dispatch-return module=KERNEL','ignored module=KERNEL'))).accepted) 'Uncompleted InitTask was accepted.'
}
Test-Case 'timeouts-and-budget-only-exits-never-pass' {
    foreach ($reason in @('timeout','exited','window-probe-failed','output-limit')) {
        $run = New-RunFacts; $run.StopReason = $reason
        Assert-That (-not (Get-Evidence -Run $run).accepted) 'A timeout/budget-only/failed observation was accepted.'
    }
}
Test-Case 'source-cleanup-and-runtime-errors-remain-failures' {
    Assert-That (-not (Get-Evidence -Verified $false).accepted) 'Unverified original source was accepted.'
    $run = New-RunFacts; $run.ProcessTreeCleaned = $false
    Assert-That (-not (Get-Evidence -Run $run).accepted) 'Unreaped process tree was accepted.'
    foreach ($errorText in @('[critical/internal_invariant] failed','[error/guest_fault] failed','[warn/host_failure] failed')) {
        Assert-That (-not (Get-Evidence -Errors $errorText).accepted) 'Runtime failure was hidden by responsive windows.'
    }
    Assert-That (-not (Get-Evidence ($baseServices+'@23 service-boundary stage=dispatch-error')).accepted) 'A dispatch error was ignored.'
    Assert-That (-not (Get-Evidence -Bytes (8MB+1)).accepted) 'Oversized diagnostic output was accepted.'
}
Test-Case 'modal-and-incomplete-native-probes-never-pass' {
    $probe = New-ProbeFacts; $probe.VisibleDialogCount=1
    Assert-That (-not (Get-Evidence -Probe $probe).accepted) 'A modal startup dialog was accepted.'
    $probe = New-ProbeFacts; $probe.VisibleFrameCount=0
    Assert-That (-not (Get-Evidence -Probe $probe).accepted) 'No visible frame was accepted.'
    $probe = New-ProbeFacts; $probe.Probes[1].Completed=$false
    Assert-That (-not (Get-Evidence -Probe $probe).accepted) 'An uncompleted native probe was accepted.'
}

function New-Frame {
    $frame = New-Object Compat16.PfeProbe.WindowSnapshot
    $frame.Window=[IntPtr]1; $frame.ProcessId=11; $frame.ThreadId=12; $frame.Style=0x00cf0000
    $frame.Owned=$true; $frame.Visible=$true; $frame.Enabled=$true; $frame.HasCaption=$true; $frame.Nonempty=$true
    return $frame
}
function New-Observer {
    $api = New-Object Compat16.PfeProbe.FakeWindowPlatform
    $api.Windows = @((New-Frame))
    $state = New-Object Compat16.PfeProbe.WindowReadiness -ArgumentList $api
    [pscustomobject]@{ Api=$api; State=$state }
}
function New-Sequences {
    $script:sequences = New-Object 'System.Collections.Generic.Queue[long]'
    foreach ($value in @(10,12,20,22)) { $script:sequences.Enqueue($value) }
    return [Func[long]]{ $script:sequences.Dequeue() }
}
Test-Case 'window-observation-is-stable-bounded-and-idempotent' {
    $o=New-Observer; $read=New-Sequences
    Assert-That ($o.State.Observe([IntPtr]99,0,$true,$read) -eq 0) 'Unstable frame passed.'
    Assert-That ($o.State.Observe([IntPtr]99,499,$true,$read) -eq 0) 'Frame stability was not checked.'
    Assert-That ($o.State.Observe([IntPtr]99,500,$true,$read) -eq 0) 'One probe was sufficient.'
    Assert-That ($o.State.Observe([IntPtr]99,1000,$true,$read) -eq 1) 'Two stable probe responses did not complete.'
    Assert-That ($o.State.Observe([IntPtr]99,1500,$true,$read) -eq 1) 'Readiness retry changed its result.'
    Assert-That ($o.Api.Sent -eq 2) 'Completed readiness replayed a native message.'
}
Test-Case 'foreign-hidden-popup-disabled-and-dialog-windows-are-not-probed' {
    foreach ($invalid in @('foreign','hidden','popup','disabled','dialog','owner','empty','iconic')) {
        $o=New-Observer; $read=New-Sequences; $frame=New-Frame
        switch ($invalid) {
            foreign {$frame.Owned=$false}; hidden {$frame.Visible=$false}; popup {$frame.Style=[uint32]2147483648}
            disabled {$frame.Enabled=$false}; dialog {$frame.Dialog=$true}; owner {$frame.HasOwner=$true}
            empty {$frame.Nonempty=$false}; iconic {$frame.Iconic=$true}
        }
        $o.Api.Windows=@($frame)
        [void]$o.State.Observe([IntPtr]99,0,$true,$read)
        Assert-That ($o.State.Observe([IntPtr]99,500,$true,$read) -eq 0 -and $o.Api.Sent -eq 0) 'An invalid or foreign window received a probe.'
    }
    $o=New-Observer; $read=New-Sequences
    [void]$o.State.Observe([IntPtr]99,0,$false,$read)
    Assert-That ($o.State.Observe([IntPtr]99,500,$false,$read) -eq 0 -and $o.Api.Sent -eq 0) 'A window was probed before the guest message loop.'
}
Test-Case 'ownership-loss-and-native-timeout-do-not-publish-readiness' {
    foreach ($failure in @('before','after','reply','replacement')) {
        $o=New-Observer; $read=New-Sequences
        [void]$o.State.Observe([IntPtr]99,0,$true,$read)
        if ($failure -eq 'before') {$o.Api.OwnerBefore=$false}
        if ($failure -eq 'after') {$o.Api.OwnerAfter=$false}
        if ($failure -eq 'reply') {$o.Api.Reply=$false}
        $first=$o.State.Observe([IntPtr]99,500,$true,$read)
        if ($failure -eq 'replacement') {
            $frame=New-Frame; $frame.Window=[IntPtr]2; $o.Api.Windows=@($frame)
            Assert-That ($first -eq 0 -and $o.State.Observe([IntPtr]99,1000,$true,$read) -eq -1) 'Replacement window inherited another probe.'
        } else { Assert-That ($first -eq -1) 'A failed ownership/response check was accepted.' }
        Assert-That ($o.Api.Sent -le 1) 'A failed probe was resubmitted.'
    }
}

function New-TransportObservation {
    $presence=[ordered]@{}
    foreach ($name in (Get-PfeTransportEnvironmentNames)) { $presence[$name]=@{nonempty=$false} }
    [pscustomobject]@{defaultProxyRoute='direct-observed'; environmentVariablePresence=$presence}
}
Test-Case 'alternate-transport-requires-observed-direct-anonymous-policy' {
    $obs=New-TransportObservation
    Assert-That ((Get-PfeAlternateTransportPolicy $obs 'dns-failure') -ceq 'equivalent-direct-route') 'Direct DNS retry was rejected.'
    $copy=$obs | ConvertTo-Json -Depth 5 | ConvertFrom-Json
    Assert-That ((Get-PfeAlternateTransportPolicy $copy 'dns-failure') -ceq 'equivalent-direct-route') 'Deserialized policy evidence changed semantics.'
    foreach ($failure in @('tls-rejected','http-rejected','timeout')) {
        Assert-That ((Get-PfeAlternateTransportPolicy $obs $failure) -cne 'equivalent-direct-route') 'Alternate client bypassed a different failure.'
    }
    foreach ($route in @('timeout','proxy-observed','observation-failed')) {
        $obs=New-TransportObservation; $obs.defaultProxyRoute=$route
        Assert-That ((Get-PfeAlternateTransportPolicy $obs 'dns-failure') -cne 'equivalent-direct-route') 'Unknown/proxied route was bypassed.'
    }
    foreach ($name in @('HTTP_PROXY','HTTPS_PROXY','NO_PROXY','SSL_CERT_FILE','CURL_CA_BUNDLE')) {
        $obs=New-TransportObservation; $obs.environmentVariablePresence[$name].nonempty=$true
        Assert-That ((Get-PfeAlternateTransportPolicy $obs 'dns-failure') -cne 'equivalent-direct-route') 'Custom proxy/trust configuration was ignored.'
    }
    $obs=New-TransportObservation; $obs.environmentVariablePresence.Remove('HTTPS_PROXY')
    Assert-That ((Get-PfeAlternateTransportPolicy $obs 'dns-failure') -cne 'equivalent-direct-route') 'Missing environment observation was accepted.'
}
Test-Case 'source-integrity-and-HTTP-status-are-independent-requirements' {
    $bytes=[Text.Encoding]::ASCII.GetBytes('abc')
    $hash='ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'
    $copy=Get-PfePinnedArchiveBytes $bytes 3 $hash
    Assert-That ($copy -is [byte[]] -and $copy.Length -eq 3) 'Byte-array identity was not preserved.'
    Assert-Throws {Get-PfePinnedArchiveBytes $bytes 4 $hash} 'Wrong byte count passed.'
    Assert-Throws {Get-PfePinnedArchiveBytes ([byte[]]@(0,1,2)) 3 $hash} 'Wrong archive hash passed.'
    $body=New-Object byte[] 558157
    $run=[pscustomobject]@{StopReason='exited'; ExitCode=0; ProcessTreeCleaned=$true}
    Assert-That ((Get-PfeCurlResponseBytes $run '200' $body).Length -eq 558157) 'Bounded HTTP response shape was rejected.'
    Assert-Throws {Get-PfeCurlResponseBytes $run '302' $body} 'Redirect status passed.'
    Assert-Throws {Get-PfeCurlResponseBytes $run '404' $body} 'HTTP error passed.'
    $run.ExitCode=60
    Assert-Throws {Get-PfeCurlResponseBytes $run '200' $body} 'TLS failure passed.'
    $run.ExitCode=0; $run.StopReason='timeout'
    Assert-Throws {Get-PfeCurlResponseBytes $run '200' $body} 'Timed-out source process passed.'
}

$native = [Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT
if ($native) {
    Test-Case 'native-process-containment-and-readiness-callback' {
        $scratch=Join-Path ([IO.Path]::GetTempPath()) ('compat16-startup-contract-'+[Guid]::NewGuid().ToString('N'))
        [void][IO.Directory]::CreateDirectory($scratch)
        try {
            $system=[Environment]::SystemDirectory
            $windows=[Environment]::GetFolderPath([Environment+SpecialFolder]::Windows)
            $environment=@("SystemRoot=$windows","WINDIR=$windows","PATH=$system;$windows","TEMP=$scratch","TMP=$scratch")
            $powershell=Join-Path $system 'WindowsPowerShell/v1.0/powershell.exe'
            $output=@((Join-Path $scratch 'exit-out.txt'),(Join-Path $scratch 'exit-err.txt'))
            # A small OS executable isolates normal process exit from Windows
            # PowerShell's variable cold-start time on fresh hosted runners.
            $ordinaryProcess=Join-Path $system 'where.exe'
            $run=[Compat16.PfeProbe.ContainedProcess]::Run($ordinaryProcess,@('/q','cmd.exe'),$scratch,$environment,$output,5)
            Assert-That ($run.StopReason -ceq 'exited' -and $run.ExitCode -eq 0 -and $run.ProcessTreeCleaned -and -not $run.WindowReadinessObserved) ('Ordinary process exit was misclassified: '+($run|ConvertTo-Json -Compress))
            foreach ($answer in @(1,-1)) {
                $script:callbackAnswer=$answer
                $callback=[Func[IntPtr,int]]{param([IntPtr]$job) if ($job -eq [IntPtr]::Zero) {throw 'Callback has no exact job.'}; $script:callbackAnswer}
                $output=@((Join-Path $scratch ("probe-$answer-out.txt")),(Join-Path $scratch ("probe-$answer-err.txt")))
                $run=[Compat16.PfeProbe.ContainedProcess]::Run($powershell,@('-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 10'),$scratch,$environment,$output,8,$callback)
                $reason=if ($answer -eq 1) {'window-responsive'} else {'window-probe-failed'}
                Assert-That ($run.StopReason -ceq $reason -and $run.ExitCode -eq 125 -and $run.ProcessTreeCleaned) 'Readiness callback did not stop and reap its exact process tree.'
            }
        } finally { Remove-Item -LiteralPath $scratch -Recurse -Force }
    }
}
[pscustomobject]@{status='passed'; cases=$script:cases; assertions=$script:assertions; nativeProcessContainment=$native} | ConvertTo-Json -Compress
