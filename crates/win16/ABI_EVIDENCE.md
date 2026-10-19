# ABI declaration evidence and provenance

The sections below record bounded declaration, import-identity, and ABI evidence
for selected exports. Original SDK artifacts, historical implementation references,
and modern native contracts are identified separately. In particular, the WINNLS
section does not establish original SDK export identities. These records do not
verify runtime behavior. Existing third-party notices remain applicable.
Historical implementations supply evidence, not a limit on SDK functionality or
a requirement to reproduce their internal architecture. Declaration checks and
successful compilation do not establish application compatibility.

Original SDK source: Microsoft Windows SDK 3.10 disk 03, archived by PCjs.

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
- USER.181 SetSysColors: `WINDOWS.H` line 1338; `LIBW.LIB` IMPDEF byte offset
  `0x7fa1`; module USER, import SETSYSCOLORS, ordinal `0x00b5`.
- USER.186 SwapMouseButton: `WINDOWS.H` line 3665; `LIBW.LIB` IMPDEF byte
  offset `0x8084`; module USER, import SWAPMOUSEBUTTON, ordinal `0x00ba`.

Method: reconstruct CHS sectors as little-endian 32-bit words, repeating the
final word to fill shortened sector arrays; verify the disk hash; extract FAT12
files and verify their archived hashes; expand SZDD mode A and check declared
output lengths; read the unmodified headers and OMF COMENT records (record
`0x88`, class `0xa0`, subtype `0x01`, import-by-ordinal flag `0x01`). Offsets
refer to expanded `LIBW.LIB`. Header line numbers count original CRLF-delimited
lines. `WINDOWS.H` line 124 defines WINAPI as far Pascal.

## USER.196 TabbedTextOut and USER.197 GetTabbedTextExtent

The verified imports above correspond to `LONG WINAPI TabbedTextOut(HDC, int,
int, LPCSTR, int, int, int FAR*, int)` and `DWORD WINAPI
GetTabbedTextExtent(HDC, LPCSTR, int, int, int FAR*)`. Their Pascal argument
frames are 20 and 14 bytes respectively; both return the full packed value in
DX:AX. Coordinates, byte counts, tab counts and tab-array elements are signed
16-bit `int`, not unsigned WORD counts.

The bridge copies the requested guest bytes and 16-bit tab array before host
execution, converts ANSI/DBCS text to UTF-16, and widens tab positions separately.
The native W calls receive the converted UTF-16 count. Their result preserves
width in the low word and height in the high word, as documented by
[TabbedTextOutW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-tabbedtextoutw)
and [GetTabbedTextExtentW](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-gettabbedtextextentw).
This establishes the translation route, not historical rendering equivalence;
the modern TabbedTextOutW documentation itself notes changed text-alignment
behavior on Windows Vista and later.

## USER.181 SetSysColors

The Windows 3.1 SDK `WINDOWS.H:1338` declares
`void WINAPI SetSysColors(int, const int FAR*, const COLORREF FAR*)`.
`WINAPI` is far Pascal (`WINDOWS.H:124`), `int` is signed 16-bit, and
`COLORREF` is `DWORD` (`WINDOWS.H:1325`), a 32-bit color value. The `LIBW.LIB`
IMPDEF record at byte offset `0x7fa1` imports `SETSYSCOLORS` from USER by
ordinal `0x00b5` (181). This establishes the historical module, ordinal,
argument widths, and void return.

The bridge rejects negative counts, copies the signed 16-bit system-color
indices and 32-bit COLORREF array from checked guest memory, and treats count
zero as an empty call without dereferencing either pointer. The native Windows
adapter invokes `SetSysColors` on the owning USER worker, with no worker-state
borrow held across the native call. Its synchronous `WM_SYSCOLORCHANGE`
notifications enter the existing guest callback/continuation chain. The native
BOOL is checked as an internal completion type; the Win16 void return follows
the project's AX/DX-preservation policy, including a native false result.
This records the ABI and translation path, not historical system-color behavior
equivalence.

## USER.186 SwapMouseButton

The Windows 3.1 SDK `WINDOWS.H:3665` declares
`BOOL WINAPI SwapMouseButton(BOOL)`. `WINAPI` is far Pascal
(`WINDOWS.H:124`), and Win16 `BOOL` is a signed 16-bit `int`; the BOOL return
is the prior primary-button mapping. The `LIBW.LIB` IMPDEF record at byte
offset `0x8084` imports `SWAPMOUSEBUTTON` from USER by ordinal `0x00ba` (186).
This establishes the historical module, ordinal, argument width, return width,
and calling convention.

The decoder maps any nonzero guest BOOL to `true`, then the host adapter calls
the native `SwapMouseButton` and returns its previous mapping state as a Win16
word. See [SwapMouseButton] for the native function's contract.

[SwapMouseButton]: https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-swapmousebutton

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

## USER.43 CloseWindow

`WINDOWS.H` line 3287 declares `void WINAPI CloseWindow(HWND)`.
`LIBW.LIB` IMPDEF at byte offset `0x6130` imports `CLOSEWINDOW` from USER
ordinal `0x002b`. The original artifact hashes above apply. The one WORD
argument is callee-popped (two bytes); the typed Void descriptor deliberately
overrides the spec's `-ret16`, preserving guest AX and DX.

The original Microsoft Windows 3.0 SDK reference's
[CloseWindow section](https://www.pcjs.org/documents/books/mspl13/win/w3sdkr1/)
specifies minimization of overlapped windows and no effect on popup or child
windows. The worker explicitly rejects WS_POPUP/WS_CHILD before forwarding
to native CloseWindow. It resolves exact HWND token/cookie identity and keeps
no worker borrow across synchronous native callbacks. Native BOOL is accepted
only as an internal Boolean completion, never as the guest return. Completion
retry cannot repeat minimization, allocate HWNDs, or retire window handles.
Native desktop fixtures are opt-in and ignored in unattended CI; mock and ABI
tests do not establish executed GUI behavior or full historical equivalence.

## USER.221 ScrollDC

`WINDOWS.H` line 3440 declares
`BOOL WINAPI ScrollDC(HDC, int, int, const RECT FAR*, const RECT FAR*, HRGN, RECT FAR*)`.
`LIBW.LIB` IMPDEF at byte offset `0x87ed` imports `SCROLLDC` from USER
ordinal `0x00dd` (221). The original artifact hashes above apply. The four
16-bit scalar/handle arguments and three 32-bit FAR arguments occupy 20
callee-popped Pascal argument bytes; BOOL returns in AX. This establishes
the declaration and ABI, not complete historical scrolling behavior.

The [original SDK reference](https://www.pcjs.org/documents/books/mspl13/win/w3sdkr1/)
documents optional update-region/rectangle outputs. The
[modern ScrollDC contract](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-scrolldc)
additionally documents nullable scroll/clip rectangles; the older reference is
silent on those two nullable inputs.
The adapter copies input RECT16 values before output, checks the complete
output range before native mutation, leases the HDC, and uses an independent
HRGN snapshot with exact-token commit. A nonzero invalid handle never becomes
NULL. Native ScrollDC uses the DC's existing mapping: deltas are device units,
input rectangles are logical coordinates, and update outputs are client
coordinates. The bridge adds no coordinate transform or window-scrolling substitute.

Returned RECT16 coordinates retain the existing update-region saturation
policy. Original Win16 out-of-range overflow semantics are unverified. Neither
reference specifies failure output contents: native FALSE suppresses scratch
RECT copy-back and HRGN snapshot commit, matching the existing ScrollWindowEx
failure path. ABI, mock, and owned-memory native fixtures cover this bounded
bridge; they do not establish historical equivalence or desktop application behavior.

## USER.170 ArrangeIconicWindows

The original SDK disk 03 artifacts establish `UINT WINAPI
ArrangeIconicWindows(HWND)` (`WINDOWS.H` line 4230) and the USER ordinal 170
import (`LIBW.LIB` IMPDEF at `0x7d69`). This is one WORD HWND argument,
two bytes of far Pascal callee cleanup, and an unsigned WORD result in AX;
DX is preserved. The existing spec declaration now reaches a typed request.

The worker forwards to native
[ArrangeIconicWindows](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-arrangeiconicwindows)
on its HWND-owning thread. The native row-height result is narrowed to the
Win16 unsigned WORD, never Booleanized. NULL, invalid tokens, retired mappings, and mismatched worker-owned identity
cookies return zero without entering the native API or substituting a desktop
HWND. Foreign-thread windows retain the existing USER resolver's weaker native
liveness check; this change does not establish foreign HWND incarnation safety. An
explicit live mapped desktop token retains its usual native meaning, but tests
never arrange the desktop. Identity resolution releases all worker-state
borrows before callbacks, and completion uses the existing replay-free path.
Only integer completions are accepted; malformed handle-bearing results cannot
create guest handles or retire unrelated objects.

Windows 3.0's no-icons wording differs from the later 3.1/native contract.
Historical version-specific behavior is not established here: no special
no-icons result is synthesized. The original 3.1 reference is
[Programmer's Reference volume 2, printed page 26](https://www.bitsavers.org/pdf/microsoft/windows_3.1/Microsoft_Windows_3.1_SDK_1992/PC28916-0492_Programmers_Reference_Volume_2_199204.pdf).
The SDK header/import artifacts establish the ABI independently of that prose.
Host-independent tests cover lookup, frame bounds, unsigned results including
37 and high-bit values, callbacks, invalid target encoding and completion retry.
Opt-in native tests use owned hidden parents and minimized children only;
they cover native row-height forwarding, stale identity rejection before a
native call, and callback reentry. These are bounded contract tests, not a
claim of historical layout equivalence or full application compatibility.

## Catalog migration provenance

The production declaration source is now the repository-root `abi/catalog.toml`
and its indexed groups and shared types. Historical specification and Rust
parameter-table paths in manifest evidence identify the pre-migration source
at commit `f8ab8e0393c8df86ab5a54ef462d73cc89fa596d`; they are provenance, not
additional production ABI inputs. This migration does not change the scope of
the independent SDK evidence above or establish additional runtime compatibility.

In particular, USER.399 ChildWindowFromPointEx used the Wine-derived USER
specification, not a claimed historical Microsoft Win16 prototype:
https://github.com/wine-mirror/wine/blob/master/dlls/user.exe16/user.exe16.spec .
The original parameter tables also cite Open Watcom declarations where noted
in their retained revision history. The project license and third-party
notices remain applicable; conversion to TOML does not remove those obligations.

## USER.115 ReplyMessage and USER.192 InSendMessage

The Windows 3.1 SDK `WINDOWS.H:2836` declares
`void WINAPI ReplyMessage(LRESULT)`, with LRESULT defined as LONG. NT 3.5's
`MVDM/WOW16/USER/USER.DEF:130` assigns ordinal 115, and
`MVDM/WOW32/WUMSG.C:1404-1454` forwards the LONG to native ReplyMessage.
The Win16 contract therefore consumes four Pascal argument bytes and has no
guest return value; the native BOOL is an internal completion receipt. The
signed LONG is widened to native LRESULT without truncating to a WORD.

ReplyMessage runs through nested commands on the suspended native USER stack,
so Windows retains the actual synchronous sender even inside a same-thread
nested SendMessage. Guest message payloads remain owned until their normal
callback return. ReplyMessage does not synthesize an early output-buffer
copyback. The opt-in native tests compare ordinary WM_GETTEXT completion with
early ReplyMessage and verify that later callback output cannot overwrite the
sender's already reused text buffer. Runtime tests cover the void ABI and
retained-completion retries without repeating the native reply.

The Windows 3.1 SDK `WINDOWS.H:2837` declares `BOOL WINAPI InSendMessage(void)`;
the SDK `LIBW.LIB` IMPDEF at `0x81d2` imports `INSENDMESSAGE` from USER ordinal
192 (`0x00c0`). The header's far Pascal WINAPI and 16-bit BOOL establish zero
argument bytes and a WORD result in AX. NT 3.5's `MVDM/WOW16/USER/USER.DEF:207`
confirms the ordinal, and `MVDM/WOW32/WUMSG.C:852-860` calls native InSendMessage
and narrows with `GETBOOL16`; its internal ULONG return does not make this a
DWORD guest result. The runtime queries the native USER worker while the active
guest window callback retains its native call stack. This is static routing
evidence; the opt-in ReplyMessage tests additionally exercise InSendMessage
outside a send, in a cross-thread send, and in a nested same-thread send.

## USER window management: 184, 188, 189, 198, 199, 281, and 284

`QuerySendMessage` is `BOOL WINAPI QuerySendMessage(HANDLE, HANDLE, HANDLE, LPMSG)`.
The three handles are reserved and ignored. Its BOOL is the same native
`InSendMessage` result as USER.192, including a nested same-thread send. When
that result is nonzero and a guest window callback is active, the runtime
writes an 18-byte `MSG16` from that callback's guest HWND, message, wParam,
and lParam, plus `GetMessageTime` and `GetMessagePos`. A null `LPMSG` is not
written. Posted dispatch and timers are not treated as the sent message.
Windows 3.1 text describes an intertask send only; this tree follows the
native predicate already chosen for `InSendMessage`.

`SetSysModalWindow` and `GetSysModalWindow` store one guest HWND. Zero clears
it and returns the previous value. An unknown nonzero handle does not replace
the current window and returns zero. Retiring that guest HWND clears the
flag. No host pointer is stored; the modern host has no equivalent API.

`CascadeChildWindows` and `TileChildWindows` submit only `mdi_children` whose
recorded parent is the argument. Iconic and hidden children are omitted.
`MDITILE_SKIPDISABLED` also omits a disabled child. Tile honors
`MDITILE_HORIZONTAL`; other flag bits are masked off. The count is the number
of windows passed to native `CascadeWindows` or `TileWindows`. Those calls
also set `MDITILE_ZORDER` so stacking order is native. This tree does not
reimplement the Windows 3.1 geometry.

`GetSysColorBrush` returns the existing `COLOR_* + 1` pseudo-brush for indices
0 through 20 (`COLOR_SCROLLBAR` through `COLOR_BTNHIGHLIGHT`) and zero
otherwise. No GDI object is allocated. `GetFreeSystemResources` returns 90
for the SDK selectors 0, 1, and 2, the NT WOW compatibility percentage used
because this runtime has no 16-bit USER or GDI heap, and zero for any other
selector.

## USER.288 GetMessageExtraInfo and USER.14 GetTimerResolution

`WINDOWS.H:2801` declares `LPARAM WINAPI GetMessageExtraInfo(void)`, with LPARAM
defined as LONG at line 164. The original LIBW.LIB IMPDEF at `0x9668` imports
`GETMESSAGEEXTRAINFO` from USER ordinal 288 (`0x0120`). It takes no argument
bytes and returns 32 bits in DX:AX. NT 3.5 `MVDM/WOW32/WUSER31.C:133-142`
forwards native GetMessageExtraInfo through GETLONG16. Native pointer-sized
message metadata is narrowed to the guest's 32-bit payload, not dereferenced.
The query must run on the USER thread whose message state is being observed.

`WINDOWS.H:294` declares `DWORD WINAPI GetTimerResolution(void)`: no argument
bytes and an unsigned DX:AX result. This name is absent from the inspected
LIBW.LIB. USER ordinal 14 is independently established by NT 3.5
`MVDM/WOW16/USER/USER.DEF:29`, where it is marked internal, and
`MVDM/WOW32/WUTBL2.H:32`. `MVDM/WOW32/WUSER.C:1291-1311` states that Windows
3.0/3.1 return 1000 and implements that constant. The bridge follows that
historical contract; it does not infer the result from a modern host timer.

USER.115 ReplyMessage is implemented through the suspended native USER stack;
its ABI, nested-send context and buffer lifecycle evidence are documented in
the ReplyMessage/InSendMessage section above.

## USER.70 SetCursorPos and USER.16 ClipCursor

The original SDK declarations are `void WINAPI SetCursorPos(int, int)`
(`WINDOWS.H:4033`) and `void WINAPI ClipCursor(const RECT FAR*)` (line 4042).
LIBW.LIB IMPDEF records at `0x66e1` and `0x5b2f` establish USER ordinals 70
and 16 respectively. Both use four bytes of far Pascal callee cleanup:
two signed WORD coordinates for SetCursorPos, or one 16:16 pointer for ClipCursor.
RECT contains four signed WORDs (eight bytes). These Win16 calls return void;
native BOOL results are not guest return values. The typed Void projection
preserves guest AX/DX as an emulator convention, not an SDK register guarantee.

NT 3.5 `MVDM/WOW32/WUCURSOR.C:43-56,273-285` likewise discards native results;
its ClipCursor contract at lines 25-36 permits NULL to remove clipping.
A non-null guest rectangle must be completely decoded before native use.
ABI and source inspection do not establish observed cursor movement, clipping,
or restoration on a native desktop.

## GDI.71 EnumObjects

The original SDK `LIBW.LIB` IMPDEF at `0x34c0` imports `ENUMOBJECTS` from GDI
ordinal 71 (`0x0047`). `WINDOWS.H:1388` declares
`int WINAPI EnumObjects(HDC, int, GOBJENUMPROC, LPARAM)` under STRICT; the
non-STRICT declaration at line 1390 uses LPSTR for the same four-byte final
argument. That payload remains opaque guest data. HDC and int occupy two bytes
each; the callback and final argument occupy four each: 12 far Pascal
callee-popped bytes and a signed WORD result in AX.

`WINDOWS.H:1382` declares the callback as `(void FAR*, LPARAM)` with CALLBACK
(far Pascal, line 125) and an implicit int return. It consumes eight argument
bytes and returns signed AX. NT 3.5 `MVDM/INC/WOWGDI.H:730-735` corroborates
the API's reversed stack fields; `MVDM/INC/WOW.H:185-190` does the same for the
callback. `MVDM/WOW32/WGDI.C:871-936` marshals each object into guest storage,
passes the original payload, narrows the callback result to SHORT, and narrows
the enclosing EnumObjects result with GETINT16.

The SDK's byte packing (line 74), POINT (lines 1081-1085), LOGPEN
(lines 1400-1405), and LOGBRUSH (lines 1447-1452) establish these guest layouts:

| Object | Bytes | Field offsets |
| --- | --- | --- |
| LOGPEN16 | 10 | style: WORD at 0; width x/y: signed WORDs at 2/4; color: DWORD at 6 |
| LOGBRUSH16 | 8 | style: WORD at 0; color: DWORD at 2; hatch: signed WORD at 6 |

OBJ_PEN is 1 and OBJ_BRUSH is 2 (lines 1394-1395). Native pointer-sized brush
hatch values require semantic conversion; they cannot be truncated into guest
handles. The [native EnumObjects contract](https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-enumobjects)
returns the last callback value and stops when the callback returns zero.
These declarations do not establish historical device-specific enumeration order
or prove guest callback execution in a desktop application.

## GDI Windows-format metafile handles

The original SDK declares HMETAFILE as a WORD handle at `WINDOWS.H:2342`.
The following far Pascal declarations and original LIBW.LIB IMPDEF records
establish the entrypoints. WORD results are in AX; PlayMetaFileRecord is void.
No native handle is returned directly to guest code.

| GDI ordinal | SDK declaration | Header line | IMPDEF | Argument bytes |
| --- | --- | --- | --- | --- |
| 124 | `HMETAFILE GetMetaFile(LPCSTR)` | 2347 | `0x3c10` | 4 |
| 123 | `BOOL PlayMetaFile(HDC, HMETAFILE)` | 2351 | `0x3bd1` | 4 |
| 151 | `HMETAFILE CopyMetaFile(HMETAFILE, LPCSTR)` | 2349 | `0x3ec1` | 6 |
| 127 | `BOOL DeleteMetaFile(HMETAFILE)` | 2348 | `0x3cc3` | 2 |
| 159 | `HGLOBAL GetMetaFileBits(HMETAFILE)` | 2353 | `0x3ff4` | 2 |
| 160 | `HMETAFILE SetMetaFileBits(HGLOBAL)` | 2354 | `0x4034` | 2 |
| 196 | `HMETAFILE SetMetaFileBitsBetter(HGLOBAL)` | 2356 | `0x429a` | 2 |

The SDK additionally declares `void WINAPI PlayMetaFileRecord(HDC,
HANDLETABLE FAR*, METARECORD FAR*, UINT)` at `WINDOWS.H:2482` (GDI.176,
12 argument bytes), and `BOOL WINAPI EnumMetaFile(HDC, HMETAFILE, MFENUMPROC,
LPARAM)` at line 2490 (GDI.175, 12 argument bytes). The `MFENUMPROC` declaration
at line 2485 is FAR PASCAL `(WORD, FAR pointer, FAR pointer, INT16, DWORD)`:
16 argument bytes, a four-byte FAR return, and an INT16 result in AX.
PlayMetaFileRecord must preserve the void ABI even though its Win32 counterpart
returns BOOL.

Enumeration copies records into checked, process-owned guest buffers and
translates each HANDLETABLE WORD through the GDI identity table. Native
EnumMetaFile owns clipping/selection restoration and table-object cleanup;
whole-DC SaveDC/RestoreDC would also restore attributes that enumeration leaves
changed. NT 3.5 `MFPLAY16.C:91-358` documents this native lifecycle and
`GetEvent` excludes META_EOF from callbacks. `WGMETA.C:218-325,373-410` copies
the Win16 table in both directions and builds a temporary native table for
standalone record playback. These references establish contracts; they do not
establish complete WMF drawing compatibility. Complex bitmap/region records
and Escape payloads still require nested codecs before pointer-only playback.

LPCSTR is a guest 16:16 pointer to ANSI bytes; HDC, HMETAFILE, and HGLOBAL
each occupy one WORD. The Win16 METAHEADER at lines 2369-2378 is 18 bytes:
type/header-size/version at offsets 0/2/4, DWORD size at 6, object count at 10,
DWORD maximum record size at 12, and parameter count at 16. Sizes are measured
in WORDs. NT 3.5 `WINDOWS/GDI/CLIENT/MF16.H:202-208` and
`MFPLAY16.C:1840-1857` accept type 1 or 2, a nine-WORD header, and versions
0x0100 or 0x0300. These fields are not a sufficient validity check without
bounds on the complete record stream.

The [WMF META_HEADER specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wmf/d169108a-e3fe-436a-bb44-bea61a46ce56)
describes the standard header. The distinct
[placeable extension](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-wmf/828e1864-7fe7-42d8-ab0a-1de161b32f27)
has a 22-byte prefix with key `0x9ac6cdd7`, preceding that header. Neither this
prefix nor an enhanced-metafile header is the standard Win16 WMF header.

NT 3.5 `MVDM/WOW32/WGMETA.C:21-94` explicitly models guest HMETAFILE as a
GlobalAlloc block accessible through GlobalLock and GlobalSize. Conversion from
a native metafile allocates the WMF bytes plus one extra METAHEADER (18 bytes),
with GMEM_MOVEABLE and GMEM_DDESHARE. Temporary native handles are reconstructed
from those bytes and freed after use. Its CopyMetaFile NULL-path branch
(lines 130-171) copies the entire global allocation, including extra bytes;
copying only the declared WMF length changes this observable contract. Its
DeleteMetaFile (lines 192-216) releases the guest global block.

Shared ownership follows the actual caller: WGMETA.C lines 49 and 152 call
GlobalAllocLock16 (`WOW32/WCALL16.H:48`, `WCALL16.C:275-295`), which callbacks
into `WOW16/KERNEL31/WOW16CAL.ASM:679-692` and calls GlobalAlloc from KERNEL's
CODE segment (opened at line 131). `KERNEL31/3GINTERF.ASM:270-286` derives a
shared allocation's owner from the calling code segment. Get/Copy therefore use
the builtin KERNEL owner. In contrast, GDI.196 calls GlobalReAlloc directly from
GDI (`WOW16/GDI/GDI.ASM:195-204`), so its shared conversion uses builtin GDI.

The file-path branches (lines 124-129 and 330-349) also materialize WMF bytes
into guest global memory. Native `MFREC16.C:2108-2111` writes a complete type-1
stream to disk while retaining type 2 in its internal object; GetMetaFileBitsEx
(lines 2332-2364) copies the stored stream. This documents the selected NT WOW
bridge model, not an independently verified original Win3.1 file-backed handle
layout. Guest global memory must not contain native pointers or guessed filename
structures. The [current GetMetaFileW documentation](https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-getmetafilew)
reports that entry as unimplemented. A checked file-read path followed by
[SetMetaFileBitsEx](https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-setmetafilebitsex)
supports conversion to temporary native playback handles. Memory copies retain guest allocation contents;
file output and native playback require a valid, bounded WMF stream.

The three Bits entrypoints use the actual WOW16 implementation in
`MVDM/WOW16/GDI/GDI.ASM:173-204`: GetMetaFileBits returns the original input
when GlobalHandle's low WORD is nonzero; SetMetaFileBits simply returns its
input; SetMetaFileBitsBetter calls GlobalReAlloc with size zero and flags
0x2080 (GMEM_MODIFY | GMEM_SHAREALL). The apparent WOW32 alternatives in
`WGMETA.C:410-442` are disabled with `#if 0`. These handle operations do not
parse WMF records, replace the global allocation with a native object, or
implicitly lock/unlock it. Format validation belongs at the byte-consumption
boundary. Native playback, disk round trips, and historical malformed-input
equivalence have not been established by this ABI audit.

Current playback delegates drawing records to native GDI without translating
guest ANSI/DBCS text record by record. Records whose function low byte is 0x26
(META_ESCAPE) are explicitly unsupported because their payloads need separate
ABI translation. The framing codec rejects inconsistent mtSize, truncated or
undersized records, and missing or malformed EOF instead of applying NT's
historical repairs. These limits prevent a claim of complete WMF behavior
compatibility from the verified data layouts and handle contracts.

## USER.259-261 Deferred window positioning

The original SDK `WINDOWS.H:3204-3208` declares opaque HDWP and the following
far Pascal entrypoints. The listed IMPDEF offsets are in the verified LIBW.LIB.

| USER ordinal | Declaration | IMPDEF | Argument bytes | AX result |
| --- | --- | --- | --- | --- |
| 259 | `HDWP BeginDeferWindowPos(int)` | `0x9138` | 2 | HDWP16 |
| 260 | `HDWP DeferWindowPos(HDWP, HWND, HWND, int, int, int, int, UINT)` | `0x9173` | 16 | HDWP16 |
| 261 | `BOOL EndDeferWindowPos(HDWP)` | `0x91b6` | 2 | BOOL16 |

Every argument is one WORD; the int count and coordinates are signed, while
UINT flags are unsigned. NT 3.5 `MVDM/INC/WOWUSR.H:547-550,863-873,1134-1137`
corroborates the physical Pascal layouts. Its WOW16 USER.DEF lines 274-276
also establish the three ordinals. The SDK defines insert-after sentinels
0, 1, -1, and -2 at lines 3197-3200; they must retain their special meanings.

There is a return-value discrepancy in the NT reference:
`MVDM/WOW32/WUWIND.C:1083-1095` discards the native EndDeferWindowPos result
and returns zero. The guest descriptor follows the original SDK BOOL declaration,
consistent with the [modern native contract](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-enddeferwindowpos);
the NT thunk is not evidence for that return behavior. Native
[DeferWindowPos](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-deferwindowpos)
can replace the batch handle, ignores insert-after under SWP_NOZORDER, and
requires abandoning a failed batch. Native End may synchronously send window
messages. Static ABI evidence does not establish observed batch or callback
behavior on either supported host architecture.

## WINNLS.16 EnableIME and WINNLS.18 GetEnableStatus

These entries have a narrower provenance claim. NT 3.5's internal compatibility
header `MVDM/WOW16/INC/WINNLS.H:51,54` declares
`BOOL FAR PASCAL WINNLSEnableIME(HWND, BOOL)` and
`BOOL FAR PASCAL WINNLSGetEnableStatus(HWND)`. This establishes two and one WORD
arguments respectively, four and two bytes of callee cleanup, and BOOL16 in AX.
No guest structure or pointer argument is involved.

The inspected original disk 03 WINDOWS.H and LIBW.LIB contain neither name nor
a WINNLS import. The internal header supplies no ordinals. Ordinals 16 and 18
are retained from this project's pre-existing catalog; no original WINNLS
export table or import library independently establishing them was verified in
this audit. They must not be described as verified public Windows 3.1 SDK exports.

The modern [WINNLSEnableIME contract](https://learn.microsoft.com/en-us/windows/win32/api/winnls32/nf-winnls32-winnlsenableime)
returns the previous enable state; FALSE is a valid result. The bridge preserves
that Boolean through the resumable USER call path. This supports the native
forwarding choice, not historical Far East IME behavior or observed reentrancy.

## USER.105 FlashWindow

Windows 3.1 SDK Programmer's Reference Volume 2, printed page 310, declares
`BOOL FlashWindow(HWND, BOOL)`: two WORD slots, far Pascal cleanup of four bytes,
and a WORD return. The [original Microsoft reference](https://bitsavers.trailing-edge.com/pdf/microsoft/windows_3.1/Microsoft_Windows_3.1_SDK_1992/PC28916-0492_Programmers_Reference_Volume_2_199204.pdf)
states that this flashes once and returns the previous active state. Zero is a
valid result. For minimized windows the icon flashes regardless of the invert
argument, and the result is always nonzero.

The worker resolves the opaque token before querying iconic state and calling
native FlashWindow, retaining no worker borrow over callbacks. Same-worker
windows retain exact cookie checks; foreign aliases retain the existing ordinary
USER lifetime limitations. Iconic targets force the native invert flag, and the
iconic return override requires successful resolution to the same native target
after the call. A callback-retired target retains the native prior-state result.
The runtime uses the existing WindowCall continuation and Boolean result checking;
completion retries cannot repeat the native flash. No timer, activation, or focus
operation is added. The native API has no distinct failure return or documented
last-error contract; host operation errors remain errors in the continuation.

Focused ABI tests cover both WORD slots, noncanonical BOOL16 values, truncated
frames and four-byte cleanup. Runtime tests cover zero/one results, exact opaque
targets, completion retry, callback return and malformed result rejection. Native
caption/icon and identity tests are ignored by default and require an explicitly
selected disposable Windows desktop; compilation alone does not verify those
visual effects.

## GDI.38 Escape query subset

The original SDK artifacts above establish `int WINAPI Escape(HDC, int, int,
LPCSTR, void FAR*)` (`WINDOWS.H` line 2543) and GDI ordinal 38 (`LIBW.LIB`
IMPDEF at `0x2d8b`). This is 14 bytes of far Pascal callee cleanup and a signed
16-bit AX result; DX is preserved. The original declaration metadata remains
unchanged, and the typed Word return follows the SDK prototype independently.

The inspected Windows 3.1 SDK Programmer's Reference volume 3,
printed pages 478–479 and 491–492 (PDF SHA-256
`a53b45602c256720cc00589c3bda88a1ea4ce43e02c6f467ae4f4fe75c898cd8`),
defines QUERYESCSUPPORT (8) with a two-byte
Win16 int input and GETPHYSPAGESIZE (12), GETPRINTINGOFFSET (13), and
GETSCALINGFACTOR (14) with four-byte POINT16 outputs. Scaling components are
exponents of two, not multipliers. The query-only bridge rejects other escapes
with zero, including print-job commands, callbacks, and private driver escapes.

Microsoft's [GetDeviceCaps contract](https://learn.microsoft.com/windows/win32/api/wingdi/nf-wingdi-getdevicecaps)
replaces the three point escapes with six native cap indices. The adapter
conservatively requires printer/plotter technology and positive physical page
extent, and rejects results outside signed POINT16 range. Zero offsets and
scaling exponents remain valid. Support reports and point retrieval share this
conversion policy. QUERYESCSUPPORT's own support is probed with one fixed,
owned native int; no arbitrary escape or guest pointer reaches native Escape.

This policy is a bounded host conversion, not proof of historical driver
support equivalence. Tests cover ABI, guest memory/identity boundaries, mock
cap conversions, and nonprinting native DCs. They do not establish real printer
behavior or successful execution of this import by a desktop application.

STARTDOC (10), NEWFRAME (1), ENDDOC (11), and ABORTDOC (2) use the same
`Escape` prototype. STARTDOC's `nCount` is the document-name byte count. A NUL
only in the last counted byte is a terminator and is not part of the name; an
earlier NUL is rejected. Its output pointer is unused. The other three ignore
both pointers. Success is a positive signed int. `SP_ERROR` (-1) is the
failure value. Zero remains reserved for an unimplemented escape.

Win32 supersedes these with `StartDoc`, `StartPage`, `EndPage`, `EndDoc`, and
`AbortDoc`. The 3.1 header does not describe that page split. This bridge
pairs STARTDOC with `StartDoc` plus the first `StartPage`, NEWFRAME with
`EndPage` plus the next `StartPage`, and ENDDOC with `EndPage` plus `EndDoc`.
A NEWFRAME that already advanced the page, followed by ENDDOC, can therefore
close one extra page. A non-positive result stops the pair. A failed first
`StartPage` aborts the job started by STARTDOC. `QUERYESCSUPPORT` for these
four codes is true only for printer or plotter technology. `SETABORTPROC`,
`PASSTHROUGH`, `NEXTBAND`, `SETCOPYCOUNT`, and private codes still return zero
and do not call the host. No guest pointer is passed to native `Escape`.

## USER.131/132 class default-menu LONG

The Windows 3.1 SDK `WINDOWS.H:2951-2964` declares GetClassLong/SetClassLong
with signed int indices and LONG results, and defines GCL_MENUNAME as -8.
The original [Microsoft SDK GetClassLong and SetClassLong
entries](https://www.pcjs.org/documents/books/mspl13/win/w3sdkr1/)
define that field as the class menu-name FAR pointer. NT 3.5
`MVDM/WOW32/WUCLASS.C` independently retains the guest value in `vpszMenu`
when mapping the native class menu string.

The runtime keeps the exact original/replacement FAR bits in guest metadata,
and separately owns the ANSI resource-name bytes or zero-selector resource
number. Null clears the default. Reading metadata never dereferences an old
FAR or exposes a native pointer; replacing a string validates and copies it
before publishing either value. An invalid string returns zero without
changing the old default. That malformed-input refusal is a checked runtime
policy, not an assertion about every historical Win16 fault outcome.

Subsequent CreateWindow and custom-dialog preparation resolve the new menu
through the registering module's existing RT_MENU resource path. Explicit
menus and WS_CHILD creation keep their existing rules. Already prepared
creation payloads and existing HWND menus own independent menu instances;
changing the default does not replace them. This does not add the other
class WORD metadata setters or change predefined native classes.

Focused runtime checks exercise the Pascal API frames, resource selection,
creation callbacks, dialog preparation and nested menu snapshots. An opt-in
native USER check reads actual HWND menus to verify independent instances and
that clearing the next default leaves existing menus intact. These are
component checks, separate from original-application acceptance.

## USER.129-132 class field access at its declared width

`WINDOWS.H:2949-2952` declares `GetClassWord`/`SetClassWord` with WORD results
and `GetClassLong`/`SetClassLong` with LONG results, and `WINDOWS.H:2954-2966`
publishes one offset list "for GetClassLong() and GetClassWord()". Only
`GCL_WNDPROC` and `GCL_MENUNAME` are 32-bit class-structure fields; the class
style, the two allocation sizes, the module handle, the icon, the cursor, the
background and the atom are WORD fields. NT 3.5 `MVDM/WOW16/USER/USER.INC`
places them in that order, and `WINMISC1.ASM` serves both accessors from one
`GetWC2`/`SetWC2` pair over the shared index.

The original [SDK GetClassWord/GetClassLong and SetClassWord/SetClassLong
entries](https://www.pcjs.org/documents/books/mspl13/win/w3sdkr1/) describe
the WORD and LONG predefined fields separately. A shared constants table
does not establish a zero-extension or truncation rule for cross-width access.
`GetWC2` reads `[bx]` and `[bx+2]` unconditionally; for example,
`GetClassLong(GCW_HICON)` can include the cursor field in its high word.
Cross-width support needs a checked representation of that adjacency and
translation of every affected resource. Until that is implemented, both
cross-width directions remain explicit gaps rather than dropping those bits.

`SetClassWord(GCW_HMODULE)` keeps USER's own refusal: `WINMISC1.ASM` returns
the current module handle and never replaces it (Bug #5138, Designer 2.0), so
the runtime reports the class owner and leaves it alone. The LONG form has no
such guard in USER, and class ownership is a runtime invariant, so it stays a
reported gap. The allocation-size, style and atom fields report a gap as well:
the registration already committed them, and reporting a successful replacement
would be an invented result.

The reported `GCW_HMODULE` is the owning module header handle, resolved through
the loaded-module registry from the class's normalized owning instance; it is
not the instance/data-selector value. `USER.INC` names the field `uclshModule`,
and `WINMISC1.ASM` explicitly distinguishes module from instance handles in
the refusal's compatibility rationale.

`SetClassWord` does replace the class icon, cursor and background,
because ordinary `DefWindowProc` defaulting reads those class fields for every
window of the class. The runtime resolves the guest handle to an owned resource
and has the native USER worker apply it to the registered class before
publishing the guest WORD. Native refusal preserves the old guest field and
reports zero. A worker transport error stops dispatch without publishing a
guest result; it is not a claim that an unobserved native mutation rolled back.
Clearing a field is a replacement with a zero handle. The worker verifies the
exact property-bound HWND incarnation and its owned registration before use.
It also checks that incarnation and reads the native field back after the
setter. A native USER probe confirmed that replacing a null class icon can
return zero and leave `ERROR_INVALID_HANDLE` even though the icon was installed;
the final class value establishes publication or unchanged-field refusal.
An unobservable or unexpected outcome is a host error, not a fabricated rollback.

Focused runtime checks cover the Pascal API frames, the width boundary, the
module-handle refusal, the guest encodings and the atomic refusal path. An
opt-in native USER check applies a replacement through the worker and reads the
actual `GCLP_*` class fields back, including a mismatched incarnation-cookie
refusal. A native resolver check rejects icon/cursor token type confusion,
non-brush GDI objects and retired tokens; registration and replacement share
those resolvers. These are component checks, separate from original-application
acceptance.

Native class backgrounds share an incarnation retirement flag with the GDI
identity table. [WNDCLASSEXW's background-brush contract](https://learn.microsoft.com/en-us/windows/win32/api/winuser/ns-winuser-wndclassexw)
specifies deletion by USER when the class is unregistered. After a successful
unregister, the worker acknowledges an actual brush deletion before replying;
host lookup and cleanup then reject that retired token. Replacing or clearing
the background does not retire the displaced brush, and surviving stock/system
brushes keep their aliases. Both initial registration and replacement carry
this ownership identity. The native check covers failed unregister, displaced
brushes, current custom-brush deletion and stock-brush survival.

## KERNEL.16 GlobalReAlloc guest locks

`WINDOWS.H:602` declares `HGLOBAL WINAPI GlobalReAlloc(HGLOBAL, DWORD, UINT)`;
the original LIBW.LIB IMPDEF at `0x02e2` names KERNEL ordinal 16. The argument
frame is eight bytes and the returned HGLOBAL occupies AX.

The original [Microsoft Windows SDK 3.0 reference, GlobalReAlloc and GlobalLock
entries](https://www.pcjs.org/documents/books/mspl13/win/w3sdkr1/)
expressly permits relocating a guest-locked movable block when GMEM_MOVEABLE
is supplied. Locking alone is therefore not a universal refusal condition.
The allocator distinguishes guest lock counts from retained runtime backing,
page locks and selector aliases: an unchanged size returns the existing handle,
guest locks permit an in-place resize, and relocation checks GMEM_MOVEABLE.
Retained backing leases continue to prevent size or base changes. These are
memory/ownership contracts; copying a historical allocator's internal layout is
not required.

## USER.22 SetFocus NULL target

`WINDOWS.H:3538` declares `HWND WINAPI SetFocus(HWND)`; LIBW.LIB IMPDEF
`0x5c8d` imports USER ordinal 22. It consumes two argument bytes and returns a
16-bit HWND in AX. The original [Microsoft SDK SetFocus
entry](https://www.pcjs.org/documents/books/mspl13/win/w3sdkr1/) defines NULL as
removing keyboard focus and describes WM_KILLFOCUS delivery and the previous
focus HWND result. NT 3.5 `MVDM/WOW32/WUSER.C:2401-2439` independently preserves
that contract. The typed worker request distinguishes NULL from an invalid
nonzero guest handle and uses the existing resumable message path for callbacks.

## USER notifications and HWND_BROADCAST

The original SDK defines WM_SYSCOLORCHANGE (`0x0015`, `WINDOWS.H:1366`),
WM_FONTCHANGE (`0x001d`, line 1844), WM_TIMECHANGE (`0x001e`, line 2693), and
HWND_BROADCAST (`0xffff`, lines 2839-2840). The last is explicitly a target for
both PostMessage and SendMessage, not an ordinary guest window handle.
Their prototypes at lines 2829-2830 use a ten-byte Pascal argument frame;
PostMessage returns BOOL16 in AX and SendMessage returns LRESULT in DX:AX.
LIBW.LIB IMPDEF records `0x6f40` and `0x6f70` confirm USER ordinals 110 and 111.

The three notifications carry no pointer or handle parameters, as documented
by [WM_SYSCOLORCHANGE](https://learn.microsoft.com/en-us/windows/win32/gdi/wm-syscolorchange),
[WM_FONTCHANGE](https://learn.microsoft.com/en-us/windows/win32/gdi/wm-fontchange)
and [WM_TIMECHANGE](https://learn.microsoft.com/en-us/windows/win32/sysinfo/wm-timechange).
Broadcast delivery has a separate target and parameter classification at both
the runtime and native boundary. Pointer-, handle- and character-bearing forms
require their own conversion; a numeric message ID alone does not authorize
forwarding guest bits to unrelated native windows. These declarations and source
routes do not establish desktop application or cross-process runtime acceptance.

## Native control subclassing and character conversion

`SetWindowLong(GWL_WNDPROC)` can install a guest FAR procedure on a native
dialog control through a per-window worker bridge. The old native procedure
is returned as a retained guest call gate. HWND incarnation, mutation revision
and provider-module ownership remain explicit through installation, restoration
and WM_NCDESTROY. Ordinary query/gate/replacement failures return zero. Native
dialog template controls capture their creator's Win16 instance before entering
WM_INITDIALOG; later parent changes do not select a different callback instance.

Synchronous WM_USER control messages first reach the guest subclass with the
original Win16 words via a private numeric carrier. `CallWindowProc(old)` uses
the existing control-family translation before invoking native USER. Unadapted
native-only control messages fall back to the saved native procedure.

The WM_CHAR, WM_DEADCHAR, WM_SYSCHAR and WM_SYSDEADCHAR paths use the fixed guest
code page at sends, broadcasts, queued dispatch, callbacks and default calls.
Packed DBCS words use low-byte lead/high-byte trail, consistent with the byte
order consumed by the historical USER character thunk. A partial lead byte has
no cross-message state in this adapter; encodings needing more than two guest
bytes have no Win16 character-word representation. These source contracts do
not establish original application acceptance.

## Classic file paths, private profiles and DOS extended open

`OpenFile`, `_lopen` and `_lcreat` resolve ANSI names against the calling
task's retained DOS drive/directory and virtual aliases. `OF_REOPEN` resolves
the saved OFSTRUCT filename, while `OF_VERIFY` compares the opened object's
DOS date/time. Native opens remain capability-rooted. NUL and CON use fixed
endpoint names through a separate adapter; arbitrary device paths are excluded.

Private INI names retain the Windows-directory rule for bare filenames;
explicit relative paths use the task directory. The host holds the target
object, asks the native Unicode profile parser to process a uniquely named
private snapshot, and copies successful writes back through the same target
handle. Read queries need no target write access. ANSI/UTF-16 BOM encodings and
guest output byte capacities remain explicit. Native cache flush, encoding or
copyback failure cannot become a successful write; copyback is not an atomic
file replacement. The documented profile search and modern IniFileMapping
behavior are described in [GetPrivateProfileStringW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-getprivateprofilestringw).

DOS INT 21h/AH=6Ch accepts replacement actions DX=0002h and 0012h and reports
CX=3 only after replacing an existing object. Created/opened results remain
CX=2/1. Creation and replacement can return read-only DOS handles: mutation
rights are temporary, and DuplicateHandle reduces the same native object to
read access before publication. Existing-only truncation cannot accidentally
create a missing file. These contracts follow the extended-open dispatch in
the public [MS-DOS FILE.ASM](https://github.com/microsoft/MS-DOS/blob/main/v4.0/src/DOS/FILE.ASM)
and the native [CreateFileW](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
disposition contract; they are separate from application-level acceptance.

## GDI printer-driver spool jobs

The Windows 3.1 SDK `INC/PRINT.H` declares `OpenJob(LPSTR, LPSTR, HPJOB)`,
`WriteSpool(HPJOB, LPSTR, int)`, `CloseJob(HPJOB)`, `DeleteJob(HPJOB, int)`,
`StartSpoolPage(HPJOB)` and `EndSpoolPage(HPJOB)`. `HPJOB` is a Win16 handle,
and each entry uses the SDK's `WINAPI` convention. The NT 3.5 WOW16 `GDI.DEF`
lists these names at GDI ordinals 240, 241, 243, 244, 246 and 247; `GDI.ASM`
contains the matching `OPENJOB,10` and `CLOSEJOB` thunks. These are documented
Windows 3.1 printer-driver interfaces and count as core Win16 exports.

The runtime copies the `WriteSpool` bytes from checked guest memory before
calling the host. GDI HPJOB words map to opaque spool tokens within the current
Win16 task, separately tagged from WNet job IDs; task teardown releases native
printer jobs, and ordinary GDI jobs are excluded from the WNet queue index.
The Windows host adapter reuses its existing `StartDocPrinterW`, `WritePrinter`,
page, close and cancel operations. `WriteDialog`, `GetSpoolJob` and
`DeleteSpoolPage` remain unbound because their behavior is not supplied by this
spool-job adapter.

The original Microsoft [DDK Adaptation Guide, sections 5.4.1–5.4.4](https://www.pcjs.org/documents/books/mspl13/win/w3ddkadp/)
describes positive Print Manager statuses as success and negative `SP_*` values
as failures. GDI HPJOB aliases therefore stay in `1..=0x7fff`, independently of
WNet's WORD ID space. Native disk-full and memory errors map to `SP_OUTOFDISK`
and `SP_OUTOFMEMORY`; other native failures map to `SP_ERROR`, not BOOL zero.
`WriteSpool` returns the actual completed byte count and rejects oversized host
results. Every export has explicit call parameters and Pascal stack cleanup.
Failed close/cancel operations retain the guest alias and exact native lease;
successful document phases are retained across a failed handle close so a retry
does not submit or cancel the document twice.

The DDK identifies OpenJob's third WORD as the application's abort DC. The
runtime checks nonzero guest DCs before creating a document. `SetAbortProc`
still reports an explicit compatibility gap, so this bridge does not install
guest abort procedures. `QueryAbort` (GDI ordinal 155) therefore returns TRUE
for a live guest DC, including while a spool job that names that DC is open
and when its code word is `SP_OUTOFDISK`. The code word is not a pointer and
is not sent to the host. An HDC that is not a live guest device context
returns FALSE, and `QueryAbort` does not cancel the open job. GDI driver data
uses the native RAW datatype, keeping device-dependent bytes intact rather
than selecting a queue's text processor; see the native
[WritePrinter contract](https://learn.microsoft.com/en-us/windows/win32/printdocs/writeprinter).

## GDI printer environment

Windows 3.1 SDK `WINDOWS.H` declares `SetEnvironment` and `GetEnvironment`
(GDI ordinals 132 and 133) as far Pascal `int` functions of
`(LPCSTR, const void FAR* / void FAR*, UINT)`. The DDK Adaptation Guide
describes the block as GDI-owned binary data for the port, not a process
environment string. `SetEnvironment` returns the number of bytes stored. A
zero count deletes that port's block and returns 1. `GetEnvironment` with a
null buffer returns the stored size and writes nothing; a non-null buffer
receives at most the caller's count and the return is the copied count. Bytes
beyond that prefix are left unchanged. A null or empty port on
`SetEnvironment` is stored under the leading device-name bytes (at most 32,
stopping at NUL). `GetEnvironment` does not read its output buffer to invent
that key, so a null port on get returns 0.

## Callback and session contracts

### Instance registers at USER callbacks

The Windows prolog adaptation in `formats::ne_prologs` preserves the instance
data selector supplied in AX for multi-instance entries. An NE movable data
segment's HINSTANCE is selector minus one; that handle is not the selector
consumed by `MOV DS,AX`. USER window, dialog, timer and guest-dispatch callback
entries resolve owned NE segment handles before loading AX, while leaving
guest-visible instance handles unchanged. MakeProcInstance already resolves
the instance data selector in its generated guest thunk. Selector permissions,
limits and callback-owner validation remain enforced.

KERNEL.155 `GetTaskDS` also returns a selector. The NT 3.5
[`KERNEL31/3GINTERF.ASM`](https://github.com/Hengle/windows_nt_3_5_source_code/blob/d2894c9125ff1c14028435ed1b21164f6b2b871a/windows_nt_3_5_source_code/NT-782/PRIVATE/MVDM/WOW16/KERNEL31/3GINTERF.ASM#L1460)
documents and implements the same task data selector in both AX and DX.
The runtime call result is now DWORD-width and repeats the selector in both
words, preserving the caller's DS. The historical `ret16` declaration hint
is retained independently of this corrected physical return contract.

### ExitWindows follows the NT WOW thunk

USER.7 retains its DWORD/WORD Pascal frame. NT 3.5
[`WU32ExitWindows`](https://github.com/Hengle/windows_nt_3_5_source_code/blob/d2894c9125ff1c14028435ed1b21164f6b2b871a/windows_nt_3_5_source_code/NT-782/PRIVATE/MVDM/WOW32/WUMAN.C#L34)
and the XP
[`WU32ExitWindows`](https://github.com/killvxk/winxpscodes/blob/a2f6d7c93aa4f11efc51147566d5961c59a8ef89/Source/XPSP1/NT/base/mvdm/wow32/wuman.c#L30)
both forward the original arguments positionally to Win32 `ExitWindows` and
return its BOOL. The NT 3.5 `MVDM/INC/WOWUSR.H` packed `EXITWINDOWS16` structure
contains the stack-top WORD followed by the DWORD, matching this Pascal frame.
The DWORD and WORD remain intact through the runtime-to-host request; there
is no truncation, code-specific restart dispatch, or replacement Shell dialog.

The NT 3.5 SDK
[`WINUSER.H`](https://github.com/Hengle/windows_nt_3_5_source_code/blob/d2894c9125ff1c14028435ed1b21164f6b2b871a/windows_nt_3_5_source_code/NT-782/PUBLIC/SDK/INC/WINUSER.H#L1506)
and the current SDK define `ExitWindows` as a macro invoking
`ExitWindowsEx(EWX_LOGOFF, 0xFFFFFFFF)`. This macro ignores both old arguments;
they are not `ExitWindowsEx` flags and a reason. The native adapter follows
that macro and reports the actual native BOOL and last-error result. Thus
this WOW route requests host logoff, including for the normal `(0, 0)` call.
No shutdown privilege is needed or acquired; the unused token-cleanup state
and diagnostics are removed. Tests inject the native callee
and do not perform a real session change.

USER.2 `OldExitWindows` has a separate, local contract. The NT 3.5
[`USER.ASM`](https://github.com/Hengle/windows_nt_3_5_source_code/blob/d2894c9125ff1c14028435ed1b21164f6b2b871a/windows_nt_3_5_source_code/NT-782/PRIVATE/MVDM/WOW16/USER/USER.ASM#L425)
identifies the entry as the Windows 3.1 final implementation and terminates
the application through DOS INT 21h/AX=4C00h. Runtime routes it to the existing
guest task-exit continuation, preserving ToolHelp notification and native
source-drain ordering; it never submits a native session operation.
The `ExitWindowsExec` launcher protocol remains an implementation gap.

### Windows 3.1 EDIT scrolling

The Windows 3.1 `WINDOWS.H` EDIT family uses `WM_USER+5` for `EM_SCROLL`
and `WM_USER+14` for `EM_GETTHUMB`. NT WOW's `WCTLM32.C` treats both as
scalar control messages. They now have typed runtime requests and use the
native EDIT message IDs, with unused LPARAM set to zero. `EM_SCROLL` keeps
the original command WORD and packed result (success in the high WORD,
scrolled line count in the low WORD); invalid commands remain native failures.
`EM_GETTHUMB` returns the native scroll position. These operations reuse the
existing checked control-family and procedure identity routing. Their ignored
guest fields are never interpreted as host or guest pointers. See Microsoft's
[`EM_SCROLL`](https://learn.microsoft.com/en-us/windows/win32/controls/em-scroll)
and [`EM_GETTHUMB`](https://learn.microsoft.com/en-us/windows/win32/controls/em-getthumb)
contracts. EDIT HLOCAL and word-break callback messages remain unsupported.

### Native system-timer queue messages

XP's [`DispatchMessageWorker`](https://github.com/killvxk/winxpscodes/blob/a2f6d7c93aa4f11efc51147566d5961c59a8ef89/Source/XPSP1/NT/windows/core/ntuser/client/clmsg.c#L2358)
distinguishes `WM_SYSTIMER` with nonzero LPARAM from a guest TIMERPROC:
Windows dispatches it in its server context. On a 64-bit host, truncating that
native value to MSG16 and treating it as a guest FARPROC loses its provenance.
Only callback-free, WORD-sized native timer parameters take the scalar queue
route. Other native system-timer messages retain their complete native MSG and
use the existing private native dispatch path, including checked removal when
encountered by a non-removing peek. No selector validation is relaxed.

Guest `SetSystemTimer` retains its existing registration/generation route.
Guest `WM_TIMER` and `WM_SYSTIMER` posts with a callback value both use owned
sidecars and the worker's native thunk; retrieval restores the guest message
identifier, WORD WPARAM and DWORD LPARAM. Non-removing guest peeks retain that
sidecar until removal. These guest addresses never become native TIMERPROC
values. Native queue filters still need a separate projection for a filter
containing only `WM_SYSTIMER`, because registered/carrier timers use native
`WM_TIMER`; this change does not claim complete timer-filter equivalence.

### KERNEL module names and complete filenames

KERNEL31 [`IGetModuleHandle`](https://github.com/killvxk/winxpscodes/blob/a2f6d7c93aa4f11efc51147566d5961c59a8ef89/Source/XPSP1/NT/base/mvdm/wow16/kernel31/ldaux.asm#L413)
searches the resident module namespace before its filename fallback.
[`FindExeInfo` and `ResidentFindExeFile`](https://github.com/killvxk/winxpscodes/blob/a2f6d7c93aa4f11efc51147566d5961c59a8ef89/Source/XPSP1/NT/base/mvdm/wow16/kernel31/ldutil.asm#L850)
compare resident names and complete basenames respectively; a filename's EXE,
DLL or DRV extension remains part of its identity. An executable whose resident
name differs from its file stem must not satisfy a bare import of a separate
DLL merely because both files share that stem.

The loader's [`ALFindModule`](https://github.com/killvxk/winxpscodes/blob/a2f6d7c93aa4f11efc51147566d5961c59a8ef89/Source/XPSP1/NT/base/mvdm/wow16/kernel31/ld.asm#L1296)
first checks the complete filename, then the resident name without a supplied
extension. The runtime keeps this loader fallback separate from the public
module-handle lookup, retains builtin source-module/suffix aliases, and continues
to exclude retired and external-application identities. Resolving a missing
import still fails the load and now identifies the exact symbol in diagnostics.

### KERNEL global-discard notifications

XP's Win16 [`WINDOWS.H`](https://github.com/killvxk/winxpscodes/blob/a2f6d7c93aa4f11efc51147566d5961c59a8ef89/Source/XPSP1/NT/base/mvdm/wow16/inc/windows.h#L717)
declares `GlobalNotify` as void and its callback as a Pascal BOOL taking one
HGLOBAL word. [`IGlobalNotify` and `gnotify`](https://github.com/killvxk/winxpscodes/blob/a2f6d7c93aa4f11efc51147566d5961c59a8ef89/Source/XPSP1/NT/base/mvdm/wow16/kernel31/3gmoreme.asm#L480)
retain the task's registration and ask its callback before discarding a
task-owned allocation marked GMEM_NOTIFY. A zero callback result vetoes that
discard. Module-owned objects and unmarked allocations do not use this task
callback. The runtime keeps the input NOTIFY policy separate from the output
DISCARDED state: both use bit 0x4000 in their different Win16 API contexts.

The callback enters the checked FAR-call path with AX, DS and ES set to SS,
as in gnotify; MakeProcInstance retains its own subsequent instance projection.
Guest execution may free, resize or pin the candidate. A discard after its
return rechecks the complete allocation generation and current pin state,
so a reused WORD handle cannot authorize discarding a replacement object.
Compaction retains vetoed identities, continues in LRU order, and returns the
allocator's actual largest free range. Public GlobalAlloc/GlobalReAlloc can
retry after memory-pressure compaction; an ordinary successful resize remains
on the immediate path without adding CPU-root pins to the caller's data block.
Active decisions use the shared callback LIFO, retain their caller/parked CPU
owners, and cancel without committing an unreturned vote after task execution
ends. Registered code participates in module roots until task retirement.

KERNEL.126 `MemoryFreed` regains its original binding ID 1000024 with a verified
two-byte argument frame. [`MemoryFreed`](https://github.com/killvxk/winxpscodes/blob/a2f6d7c93aa4f11efc51147566d5961c59a8ef89/Source/XPSP1/NT/base/mvdm/wow16/kernel31/2gmoreme.asm#L753)
takes a WORD count of freed paragraphs, supports a zero-count budget query,
and returns zero outside an active notification. Its low-word subtraction
wraps, its high return word is zero, and reaching the reported budget stops
the current discard pass. This is not a host-memory counter or an assertion
that the reported free space physically exists; GlobalCompact still measures
its actual result. Heap-backed internal service helpers retain their existing
synchronous allocation contracts; this does not claim general cross-task
execution or complete parity of every historical allocator policy. Huge
reallocation can still fail when an adjacent stable HGLOBAL prevents expanding
the original contiguous selector run; it must preserve the original data and
report failure even if a notification has released another block.

## USER named dialog icon resources

For a dialog STATIC with `SS_ICON`, its title identifies an icon resource,
including a resource name encoded in the original guest ANSI bytes. The
[static-control contract](https://learn.microsoft.com/en-us/windows/win32/controls/static-control-styles)
and XP
[`xxxStaticLoadImage`](https://github.com/killvxk/winxpscodes/blob/a2f6d7c93aa4f11efc51147566d5961c59a8ef89/Source/XPSP1/NT/windows/core/ntuser/client/statctl.c#L243)
resolve that name through the control's owning module. The title is neither
an RT_STRING ID nor a host executable resource name. The 3.x path loads an
icon; XP's cursor fallback is explicitly limited to 4.0-compatible windows.

Dialog preparation now passes both named and numeric titles through the
existing guest LoadIcon resource/group decoder and module cache. Named titles
keep their ANSI/DBCS bytes through resource selection. After obtaining the
typed icon token, preparation clears the native template title and uses the
same retained icon sidecar, installation ordering, and teardown as numeric
icons. Resource, HGLOBAL, and FAR-address templates share this preparation for
modal and modeless dialogs. Missing resources still return the existing
preflight failure without substituting a string, ordinal, system image, or
host resource. This does not add custom-class/creation-data icon routes or
change their existing preflight restrictions. The installation route still
requires resolved stock control class atoms throughout the template;
guest-registered classes remain outside that image-installation route.

Class lookup precedes control-title interpretation. The
[class search order](https://learn.microsoft.com/en-us/windows/win32/winmsg/about-window-classes)
uses application-local registrations, application-global registrations, then
predefined controls, including controls created by the dialog manager. XP
[dialog child creation](https://github.com/killvxk/winxpscodes/blob/a2f6d7c93aa4f11efc51147566d5961c59a8ef89/Source/XPSP1/NT/windows/core/ntuser/client/dlgbegin.c#L1244)
passes a control's class and title into native window creation. It does not
interpret a custom class's style bits as predefined STATIC behavior.

The runtime resolves string-encoded standard control names through its
existing class namespace before preparing typed images. An unshadowed
STATIC becomes a stock class atom and can use numeric or named icon titles.
A registered class named STATIC keeps its exact guest class token, callback
route and ordinary title; no icon is loaded merely because its style has the
same low bits as SS_ICON. A missing class reports GuestClassUnavailable before
image preparation or native creation. This also preserves the six standard
control names encoded as strings alongside an icon control, without treating
unregistered names or custom-class callbacks as stock controls.

The NE integration fixture creates a hidden modeless stock dialog using a
DBCS-named RT_GROUP_ICON, reads a nonzero guest HICON through Win16
SendDlgItemMessage/STM_GETICON, and destroys the dialog. It requires real
native USER creation and executes in both guest engines; it supplies no
keyboard, mouse, menu, or visible-window interaction.
An additional fixture uses mixed-case STATIC and BUTTON class strings for
the same hidden icon readback and destruction protocol.

## Unimplemented call contracts

### Unknown parameter frames

An unknown historical stub signature is not a zero-argument Pascal call.
Driver frames verified from the Windows 3.1 DDK are bound in ids
`7000000`–`7000102`. A documented zero-argument entry, such as
`CreateDIBitmap` or `MouseGetIntVect`, keeps that empty frame.
`StretchDIB` (MSVIDEO.115) is bound as id `9000000`. Its parameter list and
void return are the Windows SDK `vfw.h` contract published by
[StretchDIB](https://learn.microsoft.com/en-us/windows/win32/api/vfw/nf-vfw-stretchdib).
Each `int` is a signed word and each pointer is a far pointer, matching the
16-bit widths Wine's `dlls/msvideo.dll16/msvideo.dll16.spec` uses for those
types on `DrawDibDraw`. The destination buffer is not written. The other
rows whose parameter list is still unpublished stay declaration-only,
including `ReadCommString`, `InquireEx`, `NewTableEx`, `DoBeep`,
`MyOpenSound`, `InquireLongInts`, `QueryDeviceNames`, and the unnamed
display ordinals. `DoBeep` is an empty `pascal -ret16` frame in
`dlls/sound.drv16/sound.drv16.spec` and is not bound. Existing binding IDs
are not renumbered.

The same rule applies to KERNEL, USER and GDI. Their declaration groups retain
71, 63 and 100 additional stub rows respectively without runtime call bindings.
These rows supply neither a parameter list nor independent zero-argument ABI
evidence. Treating an omitted signature as an empty Pascal frame would return
with an unverified stack cleanup and return shape. Import names and ordinals
remain available to diagnostics; execution reports a compatibility gap through
the existing declaration-only path. Known frames and surviving binding IDs are
unchanged. This does not implement those deferred interfaces.

KERNEL.99 `GetLPErrMode` is retained separately. The
[Wine implementation proposal](https://www.winehq.org/pipermail/wine-devel/2021-December/202312.html)
describes a Windows 3.1 experiment and a no-argument pointer-to-16-bit-value
prototype. This supplies limited independent frame and return-width evidence,
not evidence for this runtime's task-error-mode storage semantics. Its original
stub declaration metadata is preserved; the existing call contract and behavior
are unchanged by the removal of unknown frames.

The Win16 Video for Windows `AVIFILE.H` declarations give
`AVIMakeCompressedStream` four far pointers (16 argument bytes),
`AVIMakeFileFromStreams` a far pointer, signed 16-bit count, and far pointer
(10 bytes), and `AVIMakeStreamFromClipboard` two 16-bit values followed by a far
pointer (8 bytes). These HRESULT constructors return `AVIERR_UNSUPPORTED`
(`MAKE_AVIERR(101)`, `0x80044065`) without publishing an output object.
`DllGetClassObject` has three far pointers and 12 bytes of Pascal cleanup.

OLE 2.01 Win16 `DISPATCH.H` declares both Variant/DOS date conversion results
as `int`, a 16-bit value. Unimplemented conversions therefore return zero,
not an HRESULT that a caller would interpret as true. Allocation and other
pointer results likewise return null; only HRESULT contracts use `E_NOTIMPL`.
These failure paths establish neither AVI compression nor OLE functionality.

## GDI CreateScalableFontResource

Windows 3.1 GDI ordinal 310 is the public `CreateScalableFontResource`. It is a far-Pascal `BOOL` with a hidden flag and three `LPCSTR` paths. It creates a TrueType font resource file and does not install the font; the caller still uses `AddFontResource`. The `Engine*` driver ordinals stay unbound.

The public remarks preserved by [CreateScalableFontResourceA](https://learn.microsoft.com/en-us/windows/win32/api/wingdi/nf-wingdi-createscalablefontresourcea) distinguish the two path forms. A bare font filename must be paired with a current path: that filename is what the resource file records, and the current path is only the directory read while the resource is created. A font path that already contains a directory separator or a drive prefix requires the current path to be omitted, and that path is what the resource file records. NULL and an empty string are that omission. A nonempty current path together with a directory-bearing font path returns false. Documented hidden values are 0 and 1; the guest word is forwarded unchanged, and a nonzero native `BOOL` becomes guest 1.

Guest path bytes are copied and resolved through the same DOS filesystem mapping as `AddFontResource`, including native-volume mounts, then passed to `CreateScalableFontResourceW`. The resource file may be absent. The TrueType file must resolve. For a bare filename the native font argument stays the filename, while the native current path is the resolved host directory. For a directory-bearing font path the native current path is null after that path has been resolved. Path failure and a zero native `BOOL` become guest false. The XP WoW module-filename rule used by `AddFontResource` does not apply; these parameters are paths. This does not implement a custom font-resource codec.
