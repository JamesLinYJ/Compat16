# Bounded Windows 3.1 SDK ABI facts

`win31-sdk-abi.tsv` records 23 independently checked contracts for implemented
exports. Expected values were transcribed from Microsoft's original Windows
3.1 SDK `WINDOWS.H` declarations and `LIBW.LIB` import records, not generated
from this repository's catalog or Wine specifications. This is a regression
sample, not a complete API inventory or proof of runtime compatibility.

## Source and reproducibility

Archive: <https://diskettes.pcjs.org/pcx86/sdk/windows/3.10/WIN31SDK-DISK03.json>

- Archive JSON SHA-256: `898b908d9f3a9d13a8c37040ffd00b28e76fd977da452243c51b89a4d19b8e8b`
- `INC/WINDOWS.H_`, expanded as `WINDOWS.H`, 151579 bytes; SHA-256
  `0e26530e07a6b6d6e6c6442d4a5092a186ca94520ddcf43f95387712c1330738`
- `WLIB/LIBW.LI_`, expanded as `LIBW.LIB`, 80351 bytes; SHA-256
  `234101bae0f50884a6e2f5f932ac2a53dd79c017ce174772b449a9d98e049c06`

Reconstruct the FAT12 disk image from the archive sector words (little-endian),
extract the two files, and expand their SZDD compression. Hash the expanded
original bytes before newline conversion. Header references are one-based
physical lines; import offsets are zero-based bytes into the expanded library,
at the start of an OMF COMENT record. These records use class `A0`, subtype
`01` (IMPDEF), and an ordinal import flag. Read the external name, module, and
little-endian ordinal there. SDK import names are uppercase; comparison is
ASCII case-insensitive. No SDK files or source excerpts are bundled here.

## Interpretation

`WINDOWS.H` line 124 defines WINAPI as far Pascal. Lines 129–143 establish
BOOL/int, UINT, and DWORD/LONG; lines 164, 181, 209–224, and 244 establish
LPARAM, LPCSTR, and the 16-bit handles. For the 16-bit Windows ABI, int/UINT
and handles occupy 2 bytes; long/DWORD and 16:16 far pointers occupy 4 bytes.
The source-order slot list uses those sizes, independently of the catalog.
The comparator requires Word for each 2-byte argument and Dword for each
4-byte argument, rather than treating a Byte argument as an equivalent Word.
It does not claim to verify higher-level pointer ownership or buffer semantics.

Pascal arguments are stack-passed in declaration order and callee-cleaned;
cleanup is the sum of argument slots, excluding the far return address. The
fixture explicitly records both callee and caller cleanup. Return classes come
from the header types: void → Void, int/BOOL/UINT/handles → Word, DWORD → Dword,
and far pointer → FarPointer. This is a public calling contract, not a promise
about incidental register values left by the original binaries.

- `Escape` line 2543 returns int in AX, despite the historical declaration
  metadata lacking `ret16`; its 14-byte Pascal frame includes two FAR pointers.
- `LineDDA` takes a 4-byte callback (lines 1607–1609) and 4-byte LPARAM.
- `GlobalLock` line 609 is the STRICT void-far-pointer declaration; the
  non-STRICT char-far-pointer declaration at line 611 has the same ABI.
- `PtInRect` takes a POINT by value: its two 16-bit fields at lines 1081–1085
  occupy one 4-byte aggregate slot, in addition to the 4-byte RECT pointer.
- `CreateWindow` exercises eleven mixed-width arguments and 30-byte cleanup.
- `CloseWindow` is void; `OpenIcon`, `GetCharWidth`, `ArrangeIconicWindows`,
  and `SetParent` retain value-returning contracts. There are 13 Void rows.

Every row must resolve uniquely by name and ordinal to the same descriptor;
missing, duplicate, or unsupported rows fail rather than being skipped. There
are no contract exceptions. `TabbedTextOut` and `GetTabbedTextExtent` are not
included because this sample asserts implemented descriptors only. The
`audit-win16` command separately checks the validated canonical manifest against
compiled descriptors, including semantic return classes and stack cleanup.
That same-source consistency check does not replace these independent SDK facts;
historical declaration return flags remain provenance only.

## Provenance and limits

The SDK archive is historical Microsoft material, not a new license grant.
This fixture retains compact ABI facts and source references only. Existing
repository provenance, Wine-derived material, licenses, and notices remain
applicable and unchanged; this work makes no clean-room claim. The test runs
offline against the checked-in facts and does not download, compile, or execute
SDK content. It detects catalog drift within this sample; source revalidation
and guest/host behavioral acceptance remain separate work.
