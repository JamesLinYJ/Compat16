# Verified Microsoft SDK declarations

This record covers GDI.350 GetCharWidth, USER.196 TabbedTextOut,
USER.197 GetTabbedTextExtent, USER.44 OpenIcon, USER.233 SetParent, and the four GDI rectangle predicate exports
listed below. It independently establishes the stated import identities and
ABI evidence for these entries. It does not establish other entries'
provenance or verify runtime behavior. Existing third-party notices remain applicable.

Source: Microsoft Windows SDK 3.10 disk 03, archived by PCjs.

- https://www.pcjs.org/software/pcx86/sdk/windows/3.10/#directory-of-windows-sdk-310-disk-03
- https://diskettes.pcjs.org/pcx86/sdk/windows/3.10/WIN31SDK-DISK03.json
- SDK file timestamp: 1992-03-23 03:10:00; inspected 2026-10-10.
- JSON SHA-256: `898b908d9f3a9d13a8c37040ffd00b28e76fd977da452243c51b89a4d19b8e8b`.
- Reconstructed disk: 1474560 bytes;
  SHA-256 `f7014a3f993efb348ff0ab32a3948523b53b4218d8179fcf1a2286e7e0f85637`;
  MD5 `4325ad2967a6827d9700161647e0908e` (matches archive imageInfo).

## Artifacts

- `INC/WINDOWS.H_`: compressed MD5 `a7551a00e34379b718b311e68e68a4e4`.
  Expanded `WINDOWS.H`: 151579 bytes;
  SHA-256 `0e26530e07a6b6d6e6c6442d4a5092a186ca94520ddcf43f95387712c1330738`.
- `WLIB/LIBW.LI_`: compressed MD5 `17efe2d90be6580c3d2b200c0045812a`.
  Expanded `LIBW.LIB`: 80351 bytes;
  SHA-256 `234101bae0f50884a6e2f5f932ac2a53dd79c017ce174772b449a9d98e049c06`.

## Verified entries

- GDI.350 GetCharWidth: `WINDOWS.H` line 1698; `LIBW.LIB` IMPDEF byte offset
  `0x4cb1`; module GDI, import GETCHARWIDTH, ordinal `0x015e`.
- USER.196 TabbedTextOut: `WINDOWS.H` line 1655; `LIBW.LIB` IMPDEF byte offset
  `0x82f2`; module USER, import TABBEDTEXTOUT, ordinal `0x00c4`.
- USER.197 GetTabbedTextExtent: `WINDOWS.H` line 1663; `LIBW.LIB` IMPDEF byte
  offset `0x8338`; module USER, import GETTABBEDTEXTEXTENT, ordinal `0x00c5`.

Method: reconstruct CHS sectors as little-endian 32-bit words, repeating the
final word to fill shortened sector arrays; verify the disk hash; extract FAT12
files and verify their archived hashes; expand SZDD mode A and check declared
output lengths; read the unmodified headers and OMF COMENT records (record
`0x88`, class `0xa0`, subtype `0x01`, import-by-ordinal flag `0x01`). Offsets
refer to expanded `LIBW.LIB`. Header line numbers count original CRLF-delimited
lines. `WINDOWS.H` line 124 defines WINAPI as far Pascal.

## Rectangle predicate exports

The same disk 03 `LIBW.LIB` contains these import-by-ordinal IMPDEF records.
Names are shown with their original case; lookup in this project is ASCII
case-insensitive.

- GDI.104 RECTVISIBLE: OMF record offset `0x3b20`.
- GDI.181 RECTINREGION: OMF record offset `0x41d1`.
- GDI.465 RECTVISIBLE_EHH: OMF record offset `0x5414`.
- GDI.466 RECTINREGION_EHH: OMF record offset `0x5455`.

`WINDOWS.H` line 1590 declares RectVisible with HDC and `const RECT FAR*`
parameters; line 1517 declares RectInRegion with HRGN and `const RECT FAR*`
parameters. Both return BOOL, defined as int on line 129, and use WINAPI
(far Pascal). The header does not declare the `_EHH` names.

The original SDK debug GDI module independently confirms all four exported
names and ordinals, including `_EHH`, rather than merely import-library aliases:

- https://www.pcjs.org/software/pcx86/sdk/windows/3.10/#directory-of-windows-sdk-310-disk-02
- https://diskettes.pcjs.org/pcx86/sdk/windows/3.10/WIN31SDK-DISK02.json
- JSON SHA-256: `61021f4be09c98a3ec103678f81e04cfae046aaad0ef20c3445393955ac5ec96`.
- Reconstructed disk: 1474560 bytes;
  SHA-256 `370536e16d4ebeb02055c4c9f2cb08a74478fe6fff971c508705aafb1ba29103`;
  MD5 `b7a6a8f0af4c0f0f5de989b3d446ce26` (matches archive imageInfo).
- `DEBUG/GDI.EX_`: compressed MD5 `c3cf2ceffa7150dc9f7b130cf90e1497`.
  Expanded `GDI.EXE`: 275261 bytes;
  SHA-256 `81effc1e452ef9997cc07b5b56305cd2bb32456d22f967945c232b6b5cd99793`.
- SDK file timestamp: 1992-03-23 03:10:00; inspected 2026-10-10.

All following offsets refer to the expanded `GDI.EXE`. Its NE header is at
`0x400`; segment 1 starts at file offset `0x1e20`. The NE nonresident-name
record offsets and entry records are:

- 104 RECTVISIBLE: name `0x104e`; entry `0x7fc`, segment 1:`5578`, file `0x7398`.
- 181 RECTINREGION: name `0x1b6d`; entry `0x8e5`, segment 1:`5558`, file `0x7378`.
- 465 RECTVISIBLE_EHH: name `0x13a4`; entry `0xbe2`, segment 1:`2fd8`, file `0x4df8`.
- 466 RECTINREGION_EHH: name `0xe68`; entry `0xbe5`, segment 1:`30e0`, file `0x4f00`.

The standard debug entrypoints check the handle and eight-byte FAR RECT,
then tail-jump to their matching `_EHH` entry: 104 at file `0x73b2`
(`e9 43 da`) to 465, and 181 at `0x7392` (`e9 6b db`) to 466.
Their stack accesses establish a 16-bit handle and a 16:16 RECT pointer,
six argument bytes in physical Pascal order. The BOOL result is in AX.
Both shared exits, file `0x4e6f` and `0x4f74`, contain `ca 06 00` (RETF 6);
the standard wrappers' failure exits at `0x73b5` and `0x7395` do too.
This supplies the `_EHH` ABI evidence missing from the public header.

The project retains its former `RectVisibleOld` and `RectInRegionOld` names
as explicit GDI-scoped lookup aliases to 104 and 181. They are not additional
SDK export declarations. Correcting the canonical `RectVisible` name moves
its lookup from 465 to 104; both ordinals remain callable, but the former
name-to-address identity cannot also be preserved. `RectInRegion` moves from
the formerly unbound 466 declaration to 181, and 466 now has a typed request
binding of its own. Existing Rust descriptor IDs keep their ordinal identities;
their names need not match the canonical guest export names.

This bounded change restores name/ordinal reachability and checked ABI
decoding into the existing requests. It makes no historical geometry or
debug/retail error-behavior equivalence claim. The original shared code also
consults the calling module's expected Windows version before a rectangle-edge
adjustment. That behavior is separate from these entrypoint names and is not
implemented by this routing change.

## OpenIcon and its restore query

The same original SDK disk 03 artifacts independently establish USER.44:

- `WINDOWS.H` line 3286 declares `BOOL WINAPI OpenIcon(HWND)`.
- `LIBW.LIB` IMPDEF record at byte offset `0x615d` imports `OPENICON` from
  `USER` by ordinal `0x002c` (44).
- `WINAPI` is far Pascal (line 124), `BOOL` is 16-bit int (line 129), and
  `HWND` is declared on line 2622. The handle macros on lines 209–216 use
  a 16-bit near pointer under STRICT or UINT otherwise. The argument is
  therefore one WORD: two callee-popped bytes, with a WORD BOOL in AX.
  The far return adds four bytes, for six total bytes consumed on return.
- `WINDOWS.H` line 3266 defines `WM_QUERYOPEN` as `0x0013`.

Modern Microsoft documentation supplies the native forwarding contract:
[OpenIcon](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-openicon)
restores and activates an iconic window, returns a success BOOL, and sends
[WM_QUERYOPEN](https://learn.microsoft.com/en-us/windows/win32/winmsg/wm-queryopen).
That message has no pointer-bearing parameters, and a zero window-procedure
result vetoes restoration. It must reach the guest through the normal callback
continuation; ShowWindow's previous-visibility result is not interchangeable.

The runtime retains the target token and accepts only a Boolean completion.
The worker resolves the existing HWND identity before native OpenIcon and
holds no worker-state borrow across synchronous callbacks. Regression tests
cover the ABI and callback/result contracts; real restore/veto/reentry tests
are Windows-desktop opt-in tests, not evidence that GUI behavior was executed.

## USER.233 SetParent

`WINDOWS.H` line 3073 declares `HWND WINAPI SetParent(HWND, HWND)`.
The original `LIBW.LIB` IMPDEF at byte offset `0x8ace` imports `SETPARENT`
from USER ordinal `0x00e9`. The header's HWND type and far Pascal WINAPI
establish two WORD parameters, four callee-popped argument bytes, and an HWND16
return. The artifact hashes above cover this independent ABI evidence.

The host adapter delegates behavior to modern native SetParent, including its
preservation of WS_CHILD/WS_POPUP and NULL-to-desktop convention. Actual parent
observation uses GetAncestor(GA_PARENT), separately from the parent/owner field.
These native contracts and the opt-in differential fixtures do not establish
historical Win16 behavior for unusual window-style combinations.

- https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-setparent
- https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-getancestor
- https://learn.microsoft.com/windows/win32/api/winuser/nf-winuser-destroywindow
