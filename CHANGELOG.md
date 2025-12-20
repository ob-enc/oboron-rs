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


[0.4.0] - 2025-12-19
--------------------

### Changed

- API BREAKING CHANGE
  - schemes/formats and format-specific structs renamed
  - new names reflect algorithm properties better in the prefix
    - first letter:
      - "a": authenticated (ob3x tier)
      - "u": unauthenticated (ob2x tier)
      - "z": insecure (ob0x, ob1x tiers)
      - "t": testing (ob7x tier)
    - second letter: determinisim
      - "d": deterministic
      - "p": probabilistic
  - "a"-scheme names use last 2 letters for algorithms (instead of numbers):
    - "gs": AES-GCM-SIV
    - "sv": AES-SIV
  - other tiers use a single letter for a 3 letters total
  - renamed schemes:
    - ob01  -> zdc
    - ob21p -> upc
    - ob31  -> adgs
    - ob31p -> apgs
    - ob32  -> adsv
    - ob32p -> apsv
    - ob70  -> mock1
    - ob71  -> mock2
    - ob00  -> legacy
  - new format uses "." as separator instead of colon
  - renamed formats:
    - ob01:c32  -> zdc.c32
    - ob01:b32  -> zdc.b32
    - ob21p:b64 -> upc.b64
    - ob31:hex  -> adgs.hex
    - ob32p:c32 -> adsv.c32
    - etc.
  - renamed structs:
    - Ob01, Ob01Base32Crockford  -> ZdcC32
    - Ob01Base32Rfc              -> ZdcB32
    - Ob01Base64                 -> ZdcB64
    - Ob01Hex                    -> ZdcHex
    - Ob31, Ob31Base32Crockford  -> AdgsC32
    - Ob31Base32Rfc              -> AdgsB32
    - Ob31Base64                 -> AdgsB64
    - Ob31Hex                    -> AdgsHex
    - Ob31p, Ob31pBase32Crockford-> ApgsC32
    - Ob31pBase32Rfc             -> ApgsB32
    - Ob31pBase64                -> ApgsB64
    - Ob31pHex                   -> ApgsHex
    - etc.

- DATA FORMAT BREAKING CHANGE
  - switched from 1B scheme byte to 2B scheme marker
  - structure: `[tier][det][algorithm]`
    - `[tier]`:       4 bits
    - `[det]`:        1 bit
    - `[algorithm]`: 11 bits

- Feature-gated convenience functions ("convenience" feature)

- Python crate README.md - rewrite parallel to oboron crate, adapted

- Moved `generate_key()` from obcrypt module to top level lib level


### Fixed

- Fixed Python API in oboron-py crate:
  - ObMulti no longer inherits from OboronBase (different interface)
  - Static classes (e.g., `Ob01`) properties fixed: `scheme`, `encoding`,
    `format` now consistent
  - `Ob.format` was a function, now property

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
