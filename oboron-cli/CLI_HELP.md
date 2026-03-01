# Oboron CLI — Quick Reference

Reversible hash-like references (secure schemes)

## Usage

```
ob <COMMAND>
```

---

## `enc` (alias: `e`)

Encrypt+encode a plaintext string.

```
ob enc [OPTIONS] [TEXT]
```

| Flag / Option | Short | Description |
|---|---|---|
| `--key <KEY>` | `-k` | Encryption key (86 base64 chars); conflicts with `--profile`/`--keyless` |
| `--profile <NAME>` | `-p` | Use named key profile; conflicts with `--key`/`--keyless` |
| `--keyless` | `-K` | Use hardcoded key (INSECURE — testing only); conflicts with `--key`/`--profile` |
| `--format <FORMAT>` | `-f` | Format string, e.g. `aasv.b64`; cannot combine with scheme/encoding flags |
| `--aasv` | | Use aasv scheme (deterministic AES-SIV) |
| `--apsv` | | Use apsv scheme (probabilistic AES-SIV) |
| `--aags` | `-g` | Use aags scheme (deterministic AES-GCM-SIV) |
| `--apgs` | `-G` | Use apgs scheme (probabilistic AES-GCM-SIV) |
| `--upbc` | `-B` | Use upbc scheme (probabilistic AES-CBC, unauthenticated) |
| `--c32` | | Use Crockford base32 encoding |
| `--b32` | | Use RFC base32 encoding |
| `--b64` | | Use base64 encoding |
| `--hex` | `-x` | Use hex encoding |
| `--help` | `-h` | Print help |

If `[TEXT]` is omitted, input is read from stdin.

---

## `dec` (alias: `d`)

Decode+decrypt an obtext string.

```
ob dec [OPTIONS] [TEXT]
```

| Flag / Option | Short | Description |
|---|---|---|
| `--key <KEY>` | `-k` | Encryption key (86 base64 chars); conflicts with `--profile`/`--keyless` |
| `--profile <NAME>` | `-p` | Use named key profile; conflicts with `--key`/`--keyless` |
| `--keyless` | `-K` | Use hardcoded key (INSECURE — testing only); conflicts with `--key`/`--profile` |
| `--format <FORMAT>` | `-f` | Format string, e.g. `aasv.b64`; cannot combine with scheme/encoding flags |
| `--aasv` | | Use aasv scheme |
| `--apsv` | | Use apsv scheme |
| `--aags` | `-g` | Use aags scheme |
| `--apgs` | `-G` | Use apgs scheme |
| `--upbc` | `-B` | Use upbc scheme |
| `--c32` | | Use Crockford base32 encoding |
| `--b32` | | Use RFC base32 encoding |
| `--b64` | | Use base64 encoding |
| `--hex` | `-x` | Use hex encoding |
| `--help` | `-h` | Print help |

If `[TEXT]` is omitted, input is read from stdin.  When no scheme flag is given, the scheme is
auto-detected from the obtext payload.

---

## `init` (alias: `i`)

Initialize configuration with a randomly-generated key profile.

```
ob init [NAME]
```

| Argument | Description |
|---|---|
| `[NAME]` | Profile name (default: `default`) |

Creates `~/.ob/config.json` and `~/.ob/profiles/<NAME>.json`.  Backs up any existing profile
to `~/.ob/bkp/` before overwriting.

---

## `config` (alias: `c`)

Manage configuration.

```
ob config [OPTIONS] [SUBCOMMAND]
```

| Option | Short | Description |
|---|---|---|
| `--keyless` | `-K` | Use hardcoded key (INSECURE — testing only) |
| `--help` | `-h` | Print help |

Subcommands:

| Subcommand | Description |
|---|---|
| `show` | Print current configuration (default when no subcommand given) |
| `set` | Set configuration values |

### `config set`

```
ob config set [OPTIONS]
```

| Flag / Option | Short | Description |
|---|---|---|
| `--aasv` | | Set default scheme to aasv |
| `--apsv` | | Set default scheme to apsv |
| `--aags` | `-g` | Set default scheme to aags |
| `--apgs` | `-G` | Set default scheme to apgs |
| `--upbc` | `-B` | Set default scheme to upbc |
| `--c32` | | Set default encoding to c32 |
| `--b32` | | Set default encoding to b32 |
| `--b64` | | Set default encoding to b64 |
| `--hex` | `-x` | Set default encoding to hex |
| `--profile <NAME>` | `-p` | Set default key profile |
| `--help` | `-h` | Print help |

---

## `profile` (alias: `p`)

Manage key profiles.

```
ob profile <SUBCOMMAND>
```

### `profile list` (alias: `l`)

List all key profiles.

```
ob profile list
```

### `profile show [NAME]` (aliases: `g`, `get`)

Show a specific key profile.  Defaults to the active profile if `[NAME]` is omitted.

```
ob profile show [NAME]
ob profile g [NAME]
ob profile get [NAME]
```

### `profile activate <NAME>` (aliases: `a`, `use`)

Set a profile as the active (default) profile.

```
ob profile activate <NAME>
ob profile a <NAME>
ob profile use <NAME>
```

### `profile create <NAME>` (alias: `c`)

Create a new key profile.

```
ob profile create [OPTIONS] <NAME>
ob profile c [OPTIONS] <NAME>
```

| Option | Short | Description |
|---|---|---|
| `--key <KEY>` | `-k` | Encryption key (86 base64 chars); generated if omitted |
| `--help` | `-h` | Print help |

### `profile delete <NAME>` (alias: `d`)

Delete a key profile.

```
ob profile delete <NAME>
ob profile d <NAME>
```

### `profile rename <OLD> <NEW>` (aliases: `r`, `mv`)

Rename a key profile.

```
ob profile rename <OLD_NAME> <NEW_NAME>
ob profile r <OLD_NAME> <NEW_NAME>
ob profile mv <OLD_NAME> <NEW_NAME>
```

### `profile set <NAME>`

Set (replace) the key for an existing profile.

```
ob profile set [OPTIONS] <NAME>
```

| Option | Short | Description |
|---|---|---|
| `--key <KEY>` | `-k` | Encryption key (86 base64 chars); generated if omitted |
| `--help` | `-h` | Print help |

---

## `key` (alias: `k`)

Output the encryption key for the active or specified profile.

```
ob key [OPTIONS]
```

| Option | Short | Description |
|---|---|---|
| `--profile <NAME>` | `-p` | Use named key profile |
| `--keyless` | `-K` | Output the hardcoded key (INSECURE — testing only) |
| `--hex` | `-x` | Output key as hex instead of base64 |
| `--help` | `-h` | Print help |

---

## `completion`

Generate shell completion script.

```
ob completion <SHELL>
```

| Subcommand | Description |
|---|---|
| `bash` | Generate bash completion script |
| `zsh` | Generate zsh completion script |
| `fish` | Generate fish completion script |
| `powershell` | Generate PowerShell completion script |

---

## `obz` — Z-tier obfuscation tool

> ⚠️ **NOT SECURE** — for obfuscation only, never for sensitive data.

`obz` mirrors `ob` with these differences:

- Uses "secret" (`--secret`/`-s`, 43 base64 chars) instead of "key" (`--key`/`-k`)
- Config stored in `~/.obz/` instead of `~/.ob/`
- Default scheme is `zrbcx` instead of `aasv`
- Scheme flags: `--zrbcx`/`-b`, `--legacy`/`-l`
- `secret` command (alias: `s`) instead of `key`/`k`

All subcommands (`enc`/`e`, `dec`/`d`, `init`/`i`, `config`/`c`, `profile`/`p`,
`completion`) accept the same flags as their `ob` counterparts.

