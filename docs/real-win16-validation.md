# Real Win16 startup diagnostics

`scripts/test-real-win16-pfe.ps1` uses the original **Programmer's File Editor
1.01, 16-bit edition**, without generating or modifying a guest executable.
The Windows workflow runs this bounded diagnostic after successful native release
staging on push, pull request and manual workflow dispatch, on both disposable
GitHub-hosted architectures. It does not install Compat16 or PFE and does not
validate complete editor behavior.

## Fixture and terms

The [author's download page](https://www.lancaster.ac.uk/~steveb/cpaap/pfe/pfefiles.htm)
identifies `pfe101.zip` as the Windows 3.1x / Windows for Workgroups 3.1x release.
The script downloads only the author's HTTPS URL, rejects redirects, and pins:

| File | Bytes | SHA-256 |
| --- | ---: | --- |
| `pfe101.zip` | 558157 | `75156260f361e3dc88dbbf340edc36369d8f80bac658482b5c680e1da8985288` |
| `PFE.EXE` | 555520 | `2affadbd7ad74f63311c72b099a73ca536c0980f07b064432e980cfea3a9388f` |

These are independently observed hashes, not an author signature. Source outage,
changed bytes or unexpected archive entries stop the probe before execution.
PFE.EXE is MZ/NE, with its NE header at `0x400`, Windows target 2, expected Windows
version `0x030A`, 100 segments and startup entry segment 98, offset `0x001A`.
Its first imported startup call is KERNEL.91 InitTask. Its 289 distinct imports
span nine Win16 modules. `PFEDOS.EXE` is a DOS helper, not the Win16 application.

The archive's README permits free use for any purpose. Distribution must retain
the supplied files intact, with charges limited to reasonable distribution
costs; commercial-product bundling requires an agreement with the author. The
[author's home page](https://www.lancaster.ac.uk/~steveb/cpaap/pfe/) also describes
these terms. PFE is freeware, not a verified open-source dependency.

The script retains the original package locally and runs a separate complete
working copy. Do not commit, cache, mirror or include the archive or extracted
files in releases or CI artifacts. Reconsider permission before adding any such
distribution. The binary is supplied at test time by the author, not by this
repository.

## Running on CI

Build with `scripts/build.ps1` first. Keep all four staged runtime files together:
`compat16.exe`, `compat16w.exe`, `compat16.dll`, `compat16host.exe`.

```powershell
# GitHub-hosted windows-2022, native x64 PowerShell:
.\scripts\test-real-win16-pfe.ps1 -Architecture x64 -RunnerLabel windows-2022

# GitHub-hosted windows-11-arm, native ARM64 PowerShell:
.\scripts\test-real-win16-pfe.ps1 -Architecture arm64 -RunnerLabel windows-11-arm
```

The script checks GitHub-hosted Windows metadata and matching native OS/process
architecture. These checks do not make an arbitrary computer disposable. Do not
spoof them to run this probe on a personal or shared machine.

Default limits are 100000 guest instructions and a separate 30-second wall
timeout. The instruction count is a diagnostic prefix, not a calibrated editor
startup threshold. A blocked native call can outlive the instruction budget.
The native launcher starts suspended, atomically assigned at creation to a non-breakaway, kill-on-close
[Windows Job Object](https://learn.microsoft.com/windows/win32/procthread/job-objects)
using `PROC_THREAD_ATTRIBUTE_JOB_LIST`. The harness stops and verifies cleanup of its job
process tree on exit, timeout or exception. Only explicit stdout/stderr/NUL
handles are inherited. The child environment is constructed from a small
allowlist, excluding CI token variables. A monitored aggregate 8 MiB diagnostic
output ceiling bounds normal operation; it is not an atomic disk quota.

Neither the Job Object, environment sanitization nor temporary working directory
provides a filesystem, registry or network sandbox. Windows profile APIs can
still resolve the real runner profile independently of environment variables.
Use only disposable runners with no supplied secrets, minimal job permissions
and checkout credential persistence disabled. No UI input, printing, external
command, DDE client or installer operation is requested. Windows UI may still
appear as part of ordinary app startup.

## Interpreting results

Exit 125 is shared by runtime failures, so it is never sufficient by itself.
The script returns success only for `startup-prefix-observed`, requiring all of:

- Exact budget exhaustion at the requested instruction count in both stderr and
  the saved runtime trace, with launcher exit 125
- A KERNEL.91 InitTask dispatch-enter/dispatch-return pair with matching recorded
  instruction count and guest gate address
- No recorded dispatch error, runtime error/critical diagnostic, or host/invariant
  warning, and verified job-tree cleanup

The parser follows the existing CLI and trace formats in
`crates/engine/src/entry.rs`, `crates/runtime/src/diagnostics.rs` and
`crates/runtime/src/win16_io_trace.rs`. A format change causes missing-evidence
failure, not an inferred pass. Uncalled-import warnings remain in the result and
console. Their presence neither proves nor disproves the bounded prefix.

`compatibility-gap`, `guest-fault`, `timeout`, `output-limit`,
`early-exit-inconclusive`, missing evidence and harness failures all fail the
diagnostic step. Do not turn them into a compatibility pass with
`continue-on-error` or a baseline of arbitrary failure messages.

Even the successful prefix does not demonstrate a working main window, text
rendering, opening/saving a file, normal application exit, or compatibility of
the editor as a whole. Those require separate observable acceptance criteria
after inspecting a real run. No unattended PFE macro/quit syntax is assumed.

## Evidence artifacts

The step writes a `results-directory` value to `GITHUB_OUTPUT`, including on most
failures after preflight. The workflow uploads an exact text-file allowlist from
that directory on success or failure, provided the directory output exists,
and retains it for three days. The allowlist contains `result.json`, stdout/stderr,
the bounded failure trace and service trace. The result records architecture,
source commit, hashes, outcome, limits, exit status, warnings and cleanup status.
Artifacts are named by architecture and run attempt. Preflight failures before
the output exists remain visible in the step log; no empty upload path is used.
Never upload the parent directory, arbitrary app-created files, or guest-memory
dumps. Review traces before sharing them beyond the authorized repository.
