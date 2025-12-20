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
