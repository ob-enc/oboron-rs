# Oboron CLI

Reversible hash-like references

## Usage

```bash
ob <COMMAND>
```

## Commands

### `enc` (aliases: e)

Encrypt+encode a plaintext string

### `dec` (aliases: d)

Decode+decrypt an obtext string

### `init` (aliases: i)

Initialize configuration with random profile

### `config` (aliases: c)

Manage configuration

**Subcommands:**

- `show` - Show current configuration
- `set` - Set configuration values

### `profile` (aliases: p)

Manage key profiles

**Subcommands:**

- `list` - List all key profiles
- `show` - Show a specific key profile
- `activate` - Set a profile as the default
- `create` - Create a new key profile
- `delete` - Delete a key profile
- `rename` - Rename a key profile
- `set` - Set key for a profile

### `key` (aliases: k)

Output the encryption key

### `completion`

Generate shell completion script

**Subcommands:**

- `bash` - Generate bash completion script
- `zsh` - Generate zsh completion script
- `fish` - Generate fish completion script
- `powershell` - Generate PowerShell completion script

