# Oboron CLI Test Suite

Language-agnostic CLI integration test suite for the Oboron CLI.  Each test file
exercises a binary (`ob` or `obz`) end-to-end — spawn the real binary, feed it inputs, and
assert on stdout — making the tests valid for **any** conforming Oboron CLI implementation, not
just the Rust one.

## Contents

- [Test Files](#test-files)
- [Test Vectors](#test-vectors)
- [Running the Tests](#running-the-tests)
  - [Run all test suites](#run-all-test-suites)
  - [Run a single suite](#run-a-single-suite)
  - [Run with a specific feature set](#run-with-a-specific-feature-set)
- [Feature Flags](#feature-flags)
- [Known Issues](#known-issues)

## Test Files

| File | Binary | Vector file | Description |
|------|--------|-------------|-------------|
| `ob_tests.rs` | `ob` | *(inline)* | Smoke/interface tests: profile flags, scheme flags, encoding flags, roundtrips, error handling |
| `obz_tests.rs` | `obz` | *(inline)* | Smoke/interface tests for `obz`: scheme flags, encoding flags, roundtrips, error handling |
| `vector_tests.rs` | `ob` | `test-vectors.jsonl` | Vector-driven enc/dec tests for all secure schemes (`aags`, `aasv`, `apgs`, `apsv`, `upbc`) |
| `ztier_vector_tests.rs` | `obz` | `ztier-test-vectors.jsonl` | Vector-driven enc/dec tests for z-tier schemes (`zrbcx`) |
| `legacy_vector_tests.rs` | `obz` | `legacy-test-vectors.jsonl` | Vector-driven enc/dec tests for the `legacy` scheme; secret is read from the file's meta line |

### Test strategy per scheme type

| Scheme type | Enc test | Dec test | Roundtrip |
|-------------|----------|----------|-----------|
| Deterministic (`aags`, `aasv`, `zrbcx`, `legacy`) | Exact match against vector obtext | Exact match against vector plaintext | — (exact enc match already proves roundtrip) |
| Probabilistic (`apgs`, `apsv`, `upbc`) | — (output differs each run) | Exact match against vector plaintext | Enc fresh obtext → dec → assert equals plaintext |

## Test Vectors

All vector files live under `tests/vectors/`.

### `test-vectors.jsonl`

Secure-scheme vectors for `ob` (`aags`, `aasv`, `apgs`, `apsv`, `upbc`).  Plain JSONL — every
line is a JSON object:

```json
{"format": "aags.c32", "plaintext": "hello", "obtext": "..."}
```

No meta line.  Used by `vector_tests.rs` with `-K` (keyless / hardcoded key).

### `ztier-test-vectors.jsonl`

Z-tier vectors for `obz` (`zrbcx`).  Same plain JSONL format.  Used by `ztier_vector_tests.rs`
with `-K`.

### `legacy-test-vectors.jsonl`

Legacy-scheme vectors for `obz`.  The **first line** is a meta object carrying the secret:

```json
{"type": "meta", "secret": "<43-char base64url secret>"}
```

Subsequent lines are standard vector objects.  Used by `legacy_vector_tests.rs`; the secret is
extracted from the meta line and passed to `obz` via `-s <secret>`.

## Running the Tests

The `ob` and `obz` binaries must be installed and available on `PATH` before running the tests.
Install any conforming Oboron CLI implementation (e.g. `cargo install oboron-cli`) and ensure `ob` and `obz` are on your `PATH`.

### Run all test suites

```shell
cargo test -p cli-tests
```

### Run a single suite

```shell
# Secure-scheme vector tests only
cargo test -p cli-tests --test vector_tests

# Legacy vector tests only
cargo test -p cli-tests --test legacy_vector_tests

# Z-tier vector tests only
cargo test -p cli-tests --test ztier_vector_tests

# Smoke tests (atier)
cargo test -p cli-tests --test ob_tests

# Smoke tests (obz)
cargo test -p cli-tests --test obz_tests
```

### Run with a specific feature set

By default every scheme is enabled.  You can restrict to a subset:

```shell
# Only aasv + apsv
cargo test -p cli-tests --no-default-features --features aasv,apsv
```

## Feature Flags

Tests gated with `#[cfg(feature = "...")]` are skipped automatically when the feature is not enabled.

| Feature | Enabled schemes |
|---------|-----------------|
| `aags`  | `aags` |
| `aasv`  | `aasv` |
| `apgs`  | `apgs` |
| `apsv`  | `apsv` |
| `upbc`  | `upbc` |
| `ztier` | `zrbcx`, `zmock`, `legacy` (enables `obz` binary) |

The default feature set enables all of the above.

## Known Issues

### Legacy scheme: trailing `=` stripped on decode

The `legacy` scheme has a known bug: `obz dec` strips trailing `=` characters from the
decoded plaintext.  The `legacy_vector_tests.rs` file accounts for this by trimming trailing `=`
from the expected value before asserting, and annotates the assertion message with the original
plaintext so failures are easy to diagnose.

Avoid round-trip tests with the `legacy` scheme on inputs that end with `=` — the decoded
output will not match the original plaintext.

### Empty-string plaintext is rejected

Both `ob enc` and `obz enc` reject empty-string plaintext with a non-zero exit code
(`Error: enc failed: empty plaintext`).  The `test_ob_enc_empty_plaintext_aasv` and
`test_obz_enc_empty_plaintext` tests assert **failure** for this input rather than success.
