# Compatibility status

This note records guest-visible DOS and Win16 coverage in this branch. A
successful build shows that the code compiles. It does not show that a
particular application runs.

## Added in this branch

INT 21h AH=59h (`Get Extended Error`) now returns the error from the latest
failed INT 21h call:

- AX is the DOS error code.
- BH is the error class, BL the suggested action, and CH the locus, using the
  MS-DOS 4.0 `ERR_TABLE_21` / `ERR_TABLE_24` classification.
- BX must be 0. Any other value fails as invalid function and replaces the
  stored error.
- A later successful INT 21h clears the stored error. Repeating AH=59h does
  not.
- A table entry whose locus is call-specific is reported as unknown (`01h`).
  This kernel does not keep a separate per-call locus, and it does not return
  a media-id pointer in ES:DI.

INT 21h AH=68h and AH=6Ah (`Commit File`) share one implementation. AH=6Ah is
the DOS 4 alias. On failure the call returns AX=6 (`invalid handle`), which is
the only code MS-DOS allows for Commit. AH=59h still returns the original
cause, such as disk full or access denied.

Protected-mode AH=59h is a register-only DOS service. A Win16 HFILE that
collides with AH=68h or AH=6Ah is still rejected before DOS sees it, and that
rejection is visible to AH=59h.

INT 21h AH=0Dh commits every distinct owned file, including a host file left
open after a failed close, and ignores commit failures. AH=2Eh and AH=54h
store and query the verify flag. The flag does not re-read host writes.

## DOS INT 21h already covered

The DOS kernel dispatches these AH values: 00h, 01h, 02h, 06h–0Eh, 19h, 1Ah,
25h, 2Ah, 2Ch, 2Eh, 2Fh, 30h, 33h, 35h, 36h, 38h–4Fh, 50h–52h, 54h, 56h, 57h,
59h, 5Ah, 5Bh, 62h, 65h, 67h, 68h, 6Ah, and 6Ch. Character devices, SFT/JFT
handle tables, and extended country data for US CP437 are included in that set.

AH=0Dh commits each distinct owned file and ignores a commit failure, matching
MS-DOS 4 `$DISK_RESET`, which returns no status. AH=2Eh and AH=54h store and
return the verify-after-write flag. Host writes are not re-read; this kernel
has no sector buffer. A child process shares that flag with its parent.

## Still open

DOS services that still return invalid function include auxiliary and printer
I/O, the FCB family, set date/time, InDOS, memory strategy, file locks,
truename, and code-page switching.

Only Commit reduces a disallowed error code in AX while preserving the real
code for AH=59h. Other calls still return their direct DOS code in AX. The
MS-DOS allowed-error map would change those AX values and is not applied here.

Win16 still has large declaration-only areas. Examples that applications call
and this tree does not bind include `GetFreeSystemResources`, `ClipCursor`,
`FindWindowEx`, `GetScrollInfo` / `SetScrollInfo`, `FormatMessage`, and
`GetForegroundWindow` / `SetForegroundWindow`. Graphics, DDE, OLE, and
multimedia remain partial even where individual exports are bridged.
