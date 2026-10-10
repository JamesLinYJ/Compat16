# Verified Microsoft SDK declarations

This record covers only GDI.350 GetCharWidth, USER.196 TabbedTextOut, and
USER.197 GetTabbedTextExtent. It independently establishes the import ordinals
and header declarations for these entries. It does not establish other entries'
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
