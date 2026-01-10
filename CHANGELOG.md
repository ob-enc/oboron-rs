CHANGELOG
=========

All notable changes to Oboron will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
but note that pre-1.0 releases may not adhere strictly to all guidelines.


[Unreleased]
------------

### Added

- Batch and iter versions of all `enc*()`/`dec*()` methods and functions.

### Changed


[1.0.0-rc.1] - 2026-01-09
-------------------------

This is a major revision with a completely revised API and with breaking changes in the data format.

### Changed (summary)

- API
  - Renamed schemes:
    - ob01  -> zrbcx
    - ob21p -> upbc
    - ob31  -> aags
    - ob31p -> apgs
    - ob32  -> aasv
    - ob32p -> apsv
    - ob70  -> mock1
    - ob71  -> mock2
    - ob00  -> legacy
  - new names reflect algorithm properties better in the prefix
    - first letter:
      - "a": authenticated (ob3x tier)
      - "u": unauthenticated (ob2x tier)
      - "z": insecure (ob0x, ob1x tiers)
      - "t": testing (ob7x tier)
    - second letter: mode
      - "d": deterministic / no avalanche effect
      - "a": avalanche (deterministic + hash-like - change in any one byte changes obtext completely)
      - "r": referenceable (avalanche effect restricted to the prefix: like "a" but effect localized in the prefix only)
      - "p": probabilistic
  - "a"-scheme names use last 2 letters for algorithms (instead of numbers):
    - "gs": AES-GCM-SIV
    - "sv": AES-SIV

  - Renamed formats:
    - ob01:c32  -> zrbcx.c32
    - ob01:b32  -> zrbcx.b32
    - ob21p:b64 -> upbc.b64
    - ob31:hex  -> aags.hex
    - ob32p:c32 -> aasv.c32
    - etc.
    - new format uses "." as separator instead of colon

  - Renamed structs:
    - Ob01, Ob01Base32Crockford  -> ZrbcxC32
    - Ob01Base32Rfc              -> ZrbcxB32
    - Ob01Base64                 -> ZrbcxB64
    - Ob01Hex                    -> ZrbcxHex
    - Ob31, Ob31Base32Crockford  -> AagsC32
    - Ob31Base32Rfc              -> AagsB32
    - Ob31Base64                 -> AagsB64
    - Ob31Hex                    -> AagsHex
    - Ob31p, Ob31pBase32Crockford-> ApgsC32
    - Ob31pBase32Rfc             -> ApgsB32
    - Ob31pBase64                -> ApgsB64
    - Ob31pHex                   -> ApgsHex
    - etc.

  - ObMulti renamed -> Omnib
    - enc()
    - dec()
    - autodec() -> autodec(obtext) - full autodecode

  - ObtextCodec API change:
    - renamed dec_strict() -> dec()
    - removed former scheme-autodetecting dec() method
    - no more autodetection on static types

  - Removed ObFlex; Ob inherited full ObFlex functionality

  - Ob API change
    - former scheme-autodetecting dec() now strict (like in fixed format types)
    - autodec() works like in Omnib but optimized (tries current encoding first)

  - Insecure schemes separated in ztier module - no shared code with secure schemes
    - Equivalent generic structs/classes: Obz for Ob, Omnibz for Ominb
    - No more key sharing between ztier and others: ztier uses "secret" concept instead of "key"
    - ztier secret: 256 bits (43-char base64)

  - Format constans from str to &Format:
    - AASV_C32: &str "aasv.c32" -> &Format{Scheme::Aasv, Encoding::C32}
    - new AASV_C32_STR constants

  - Feature-gated convenience functions ("convenience" feature)

- Data format
  - 2-byte scheme marker instead of single scheme byte

- Algorithm changes:
  - zrbcx (former ob01): instead of reversing ciphertext, XORs first block with last
  - upbc (former ob21p): no longer reverses ciphertext; uses 256-bit AES-CBC


[0.3.0] - 2025-12-18
--------------------

### Changed

- Post-decryption UTF-8 validation now default

### Added

- "unchecked-utf8" feature for previous unsafe behavior (non-validated post-decryption return value)


[0.2.0] - 2025-12-18
--------------------

### Changed

- BREAKING CHANGES:
  - Changed payload: scheme byte mixed-in with ciphertext
  - Changed hardcoded key ("keyless"-feature-gated): now starts with "OBKEYz..."

- Regenerated tests/test-vectors.jsonl


[0.1.1] - 2025-12-19
--------------------

### Fixed

- Fixed wrong feature gate ("hex-keys"/"bytes-keys" mix-up)

### Added

- Test to ensure the keys feature gates mix-up doesn't happen again.

### Changed

- Harmonize parameter names - consitently use `key`: base64; `key_hex`: hex; `key_bytes`: bytes


[0.1.0] - 2025-12-17
--------------------

First release
