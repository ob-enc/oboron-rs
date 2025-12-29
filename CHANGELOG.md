CHANGELOG
=========

All notable changes to Oboron will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/),
but note that pre-1.0 releases may not adhere strictly to all guidelines.


[Unreleased]
------------

### Added

- Batch and iter versions of all `enc*()`/`dec*()` methods and functions.

- `ZrbcxXXX::new_with_secret(&secret)` - takes a 256-bit secret that is used as key + IV for CBC
    - "secret" does not have the implication of cryptographic key, does not suggest cryptographic safe
    - is not extracted from master key => no related key safety issues with unsafe schemes

### Changed

- DATA FORMAT BREAKING CHANGE
  - switched from 1B scheme byte to 2B scheme marker
  - structure: `[ext][version][tier][properties][algorithm]`
    - `[ext]` (1 bit): flip on when more bytes are needed (scheme marker extension)
    - `[version]` (4 bits): version (used for data format changes, logic changes, key extraction changes etc.)
    - `[tier]` (3 bits): `a`, `u`, `z`, `mock`
    - `[properties]` (4 bits): `a`, `r`, `p`
    - `[algorithm]` (4 bits): representing `cb`, `sv`, `gs`


[1.0.0-rc.1] - 2025-12-19
-------------------------

### Changed

- API BREAKING CHANGE
  - schemes/formats and format-specific structs renamed
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
  - other tiers use a single letter for a 3 letters total
  - renamed schemes:
    - ob01  -> zrbcx // use xor first/last instead of reversing
    - ob21p -> upbc // remove reversing; switch to 256-bit key
    - ob31  -> aags
    - ob31p -> apgs
    - ob32  -> aasv
    - ob32p -> apsv
    - ob70  -> mock1
    - ob71  -> mock2
    - ob00  -> legacy
  - new format uses "." as separator instead of colon
  - renamed formats:
    - ob01:c32  -> zrbcx.c32
    - ob01:b32  -> zrbcx.b32
    - ob21p:b64 -> upbc.b64
    - ob31:hex  -> aags.hex
    - ob32p:c32 -> aasv.c32
    - etc.
  - renamed structs:
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

- API BREAKING CHANGE: New ObMulti API
  - dec() -> dec_with_format(obtext, format) - format given
  - NEW: dec_with_encoding(obtext, encoding) - encoding given
  - autodec() -> autodec(obtext) - full autodecode

- API BREAKING CHANGE: ObtextCodec API change:
  - renamed dec_strict() -> dec()
  - removed former scheme-autodetecting dec() method
  - no more autodetection on static types

- API BREAKING CHANGE: Ob/ObFlex API change
  - former scheme-autodetecting dec() renamed to dec_auto_scheme()
  - only Ob/ObFlex have such a method now.

- API BREAKING CHANGE: Format constans from str to &Format:
  - AASV_C32: &str "aasv.c32" -> &Format{Scheme::Aasv, Encoding::C32}
  - new AASV_C32_STR constants

- API BREAKING CHANGE, DATA FORMAT BREAKING CHANGE:
  - `zrbcx` to not use Oboron master key any more
  - no more `ZrbcxXXX::new()` constructor, only `::new_keyless()`
  - keyless feature always enabled with zrbcx

- DATA FORMAT BREAKING CHANGE: `upbc` to use 256-bit encryption (was 128-bit)

- Feature-gated convenience functions ("convenience" feature)

- Moved Keychain from obcrypt up to root lib level

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
