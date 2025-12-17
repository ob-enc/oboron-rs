//! CLI application for oboron

mod completions;
mod config;

use anyhow::{Context, Result};
use clap::{Args, Parser, Subcommand};
use config::{load_profile, Config};
use oboron::{Encoding, Format, Oboron, Scheme};
use std::io::{self, Read};

#[derive(Parser)]
#[command(name = "ob")]
#[command(version, about = "Reversible hash-like references", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

/// Scheme selection flags (mutually exclusive)
#[derive(Args, Debug)]
struct SchemeFlags {
    /// Use ob00 scheme (legacy AES-CBC)
    #[cfg(feature = "ob00")]
    #[arg(short = '0', long, alias = "00")]
    ob00: bool,

    /// Use ob01 scheme (optimized AES-CBC, recommended)
    #[cfg(feature = "ob01")]
    #[arg(short = '1', long, alias = "01")]
    ob01: bool,

    /// Use ob21p scheme (probabilistic AES-CBC with PKCS#7)
    #[cfg(feature = "ob21p")]
    #[arg(short = '2', long, alias = "21p")]
    ob21p: bool,

    /// Use ob31 scheme (deterministic AES-GCM-SIV)
    #[cfg(feature = "ob31")]
    #[arg(short = 'g', long, alias = "31")]
    ob31: bool,

    /// Use ob31p scheme (probabilistic AES-GCM-SIV)
    #[cfg(feature = "ob31p")]
    #[arg(short = 'G', long, alias = "31p")]
    ob31p: bool,

    /// Use ob32 scheme (deterministic AES-SIV)
    #[cfg(feature = "ob32")]
    #[arg(short = 's', long, alias = "32")]
    ob32: bool,

    /// Use ob32p scheme (probabilistic AES-SIV)
    #[cfg(feature = "ob32p")]
    #[arg(short = 'S', long, alias = "32p")]
    ob32p: bool,

    /// Use ob70 scheme (testing, identity)
    #[cfg(feature = "ob70")]
    #[arg(long, alias = "70", hide = true)]
    ob70: bool,

    /// Use ob71 scheme (testing, string reversal)
    #[cfg(feature = "ob71")]
    #[arg(long, alias = "71", hide = true)]
    ob71: bool,
}

impl SchemeFlags {
    /// Convert flags to Option<Scheme>, returning error if multiple are set
    #[cfg(any(
        feature = "ob01",
        feature = "ob21p",
        feature = "ob31",
        feature = "ob31p",
        feature = "ob32",
        feature = "ob32p",
        feature = "ob70",
        feature = "ob71",
        feature = "ob00"
    ))]
    fn to_scheme(&self) -> Result<Option<Scheme>> {
        let mut count = 0;
        let mut scheme = None;

        #[cfg(feature = "ob00")]
        if self.ob00 {
            count += 1;
            scheme = Some(Scheme::Ob00);
        }
        #[cfg(feature = "ob01")]
        if self.ob01 {
            count += 1;
            scheme = Some(Scheme::Ob01);
        }
        #[cfg(feature = "ob21p")]
        if self.ob21p {
            count += 1;
            scheme = Some(Scheme::Ob21p);
        }
        #[cfg(feature = "ob31")]
        if self.ob31 {
            count += 1;
            scheme = Some(Scheme::Ob31);
        }
        #[cfg(feature = "ob31p")]
        if self.ob31p {
            count += 1;
            scheme = Some(Scheme::Ob31p);
        }
        #[cfg(feature = "ob32")]
        if self.ob32 {
            count += 1;
            scheme = Some(Scheme::Ob32);
        }
        #[cfg(feature = "ob32p")]
        if self.ob32p {
            count += 1;
            scheme = Some(Scheme::Ob32p);
        }
        #[cfg(feature = "ob70")]
        if self.ob70 {
            count += 1;
            scheme = Some(Scheme::Ob70);
        }
        #[cfg(feature = "ob71")]
        if self.ob71 {
            count += 1;
            scheme = Some(Scheme::Ob71);
        }

        if count > 1 {
            anyhow::bail!("Only one scheme flag can be specified at a time");
        }

        Ok(scheme)
    }

    /// Check if any scheme flag is set
    #[cfg(any(
        feature = "ob01",
        feature = "ob21p",
        feature = "ob31",
        feature = "ob31p",
        feature = "ob32",
        feature = "ob32p",
        feature = "ob70",
        feature = "ob71",
        feature = "ob00"
    ))]
    fn is_set(&self) -> bool {
        #[cfg(feature = "ob00")]
        if self.ob00 {
            return true;
        }
        #[cfg(feature = "ob01")]
        if self.ob01 {
            return true;
        }
        #[cfg(feature = "ob31")]
        if self.ob31 {
            return true;
        }
        #[cfg(feature = "ob32")]
        if self.ob32 {
            return true;
        }
        #[cfg(feature = "ob21p")]
        if self.ob21p {
            return true;
        }
        #[cfg(feature = "ob31p")]
        if self.ob31p {
            return true;
        }
        #[cfg(feature = "ob32p")]
        if self.ob32p {
            return true;
        }
        #[cfg(feature = "ob70")]
        if self.ob70 {
            return true;
        }
        #[cfg(feature = "ob71")]
        if self.ob71 {
            return true;
        }
        return false;
    }
}

/// Encoding selection flags (mutually exclusive)
#[derive(Args, Debug)]
struct EncodingFlags {
    /// Use base32crockford encoding
    #[arg(long, alias = "base32crockford")]
    c32: bool,

    /// Use base32rfc encoding
    #[arg(long, alias = "base32rfc")]
    b32: bool,

    /// Use base64 encoding
    #[arg(long, alias = "base64")]
    b64: bool,

    /// Use hex encoding
    #[arg(short = 'x', long)]
    hex: bool,
}

impl EncodingFlags {
    /// Convert flags to Option<Encoding>, returning error if multiple are set
    fn to_encoding(&self) -> Result<Option<Encoding>> {
        let mut count = 0;
        let mut encoding = None;

        if self.c32 {
            count += 1;
            encoding = Some(Encoding::Base32Crockford);
        }
        if self.b32 {
            count += 1;
            encoding = Some(Encoding::Base32Rfc);
        }
        if self.b64 {
            count += 1;
            encoding = Some(Encoding::Base64);
        }
        if self.hex {
            count += 1;
            encoding = Some(Encoding::Hex);
        }

        if count > 1 {
            anyhow::bail!("Only one encoding flag can be specified at a time");
        }

        Ok(encoding)
    }

    /// Check if any encoding flag is set
    fn is_set(&self) -> bool {
        self.c32 || self.b32 || self.b64 || self.hex
    }
}

/// Combined format specification (scheme + encoding)
#[derive(Debug)]
struct FormatSpec {
    scheme: Scheme,
    encoding: Encoding,
}

impl FormatSpec {
    /// Parse format from --format string, scheme flags, encoding flags, and config
    /// Validates that --format doesn't conflict with individual flags
    fn parse(
        format_str: Option<String>,
        scheme_flags: &SchemeFlags,
        encoding_flags: &EncodingFlags,
        config: Option<&Config>,
    ) -> Result<Self> {
        // Check for conflicts between --format and individual flags
        if format_str.is_some() && scheme_flags.is_set() {
            anyhow::bail!("Cannot use --format together with scheme flags (--ob00, --ob01, etc.)");
        }
        if format_str.is_some() && encoding_flags.is_set() {
            anyhow::bail!(
                "Cannot use --format together with encoding flags (--c32, --b32, --b64, --hex)"
            );
        }

        // Parse --format if provided
        if let Some(fmt_str) = format_str {
            let format = Format::from_str(&fmt_str).map_err(|e| anyhow::anyhow!("{}", e))?;
            return Ok(Self {
                scheme: format.scheme(),
                encoding: format.encoding(),
            });
        }

        // Otherwise get scheme and encoding from flags or config
        let scheme = get_scheme(scheme_flags.to_scheme()?, config)?;
        let encoding = get_encoding(encoding_flags.to_encoding()?, config)?;

        Ok(Self { scheme, encoding })
    }

    /// Convert to format string (e.g., "ob01:b64")
    fn to_string(&self) -> String {
        format!("{}:{}", self.scheme.as_str(), self.encoding.as_short_str())
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt+encode a plaintext string
    #[command(visible_alias = "e")]
    Enc {
        /// Plaintext string (reads from stdin if not provided)
        text: Option<String>,

        /// Encryption key (86 base64 chars)
        #[arg(short, long)]
        key: Option<String>,

        /// Use named key profile
        #[arg(short, long)]
        profile: Option<String>,

        /// Use hardcoded key (INSECURE - testing only)
        #[arg(short = 'z', long)]
        keyless: bool,

        /// Format specification (e.g., "ob01:b64", "ob31:b32")
        /// Cannot be combined with scheme or encoding flags
        #[arg(short, long)]
        format: Option<String>,

        /// Scheme selection
        #[command(flatten)]
        scheme: SchemeFlags,

        /// Encoding selection
        #[command(flatten)]
        encoding: EncodingFlags,
    },

    /// Decode+decrypt an obtext string
    #[command(visible_alias = "d")]
    Dec {
        /// Obtext string (reads from stdin if not provided)
        text: Option<String>,

        /// Encryption key (86 base64 chars)
        #[arg(short, long)]
        key: Option<String>,

        /// Use named key profile
        #[arg(short, long)]
        profile: Option<String>,

        /// Use hardcoded key (INSECURE - testing only)
        #[arg(short = 'z', long)]
        keyless: bool,

        /// Format specification (e.g., "ob01:b64", "ob31:b32")
        /// Cannot be combined with scheme or encoding flags
        #[arg(short, long)]
        format: Option<String>,

        /// Scheme selection
        #[command(flatten)]
        scheme: SchemeFlags,

        /// Encoding selection
        #[command(flatten)]
        encoding: EncodingFlags,
    },

    /// Initialize configuration with random profile
    #[command(visible_alias = "i")]
    Init {
        /// Name for the key profile (default: "default")
        #[arg(default_value = "default")]
        name: String,
    },

    /// Manage configuration
    #[command(visible_alias = "c")]
    Config {
        #[command(subcommand)]
        command: Option<ConfigCommands>,

        /// Use hardcoded key (INSECURE - testing only)
        #[arg(short = 'z', long)]
        keyless: bool,
    },

    /// Manage key profiles
    #[command(visible_alias = "p")]
    Profile {
        #[command(subcommand)]
        command: ProfileCommands,
    },

    /// Output the encryption key
    #[command(visible_alias = "k")]
    Key {
        /// Encryption key (86 base64 chars)
        #[arg(short, long)]
        key: Option<String>,

        /// Use named key profile
        #[arg(short, long)]
        profile: Option<String>,

        /// Use hardcoded key (INSECURE - testing only)
        #[arg(short = 'z', long)]
        keyless: bool,

        /// Output key as hex instead of base64
        #[arg(short = 'x', long)]
        hex: bool,
    },

    /// Generate shell completion script
    Completion {
        #[command(subcommand)]
        shell: completions::Shell,
    },
}

#[derive(Subcommand)]
enum ConfigCommands {
    /// Show current configuration
    Show {
        /// Use hardcoded key
        #[arg(short = 'z', long)]
        keyless: bool,
    },
    /// Set configuration values
    Set {
        /// Scheme selection
        #[command(flatten)]
        scheme: SchemeFlags,

        /// Encoding selection
        #[command(flatten)]
        encoding: EncodingFlags,

        /// Set default key profile
        #[arg(short, long)]
        profile: Option<String>,
    },
}

#[derive(Subcommand)]
enum ProfileCommands {
    /// List all key profiles
    #[command(visible_alias = "l")]
    List,
    /// Show a specific key profile
    #[command(visible_alias = "get")]
    #[command(visible_alias = "g")]
    Show {
        /// Profile name (shows default if not provided)
        name: Option<String>,
    },
    /// Set a profile as the default
    #[command(visible_alias = "a")]
    #[command(visible_alias = "use")]
    Activate {
        /// Profile name
        name: String,
    },
    /// Create a new key profile
    #[command(visible_alias = "c")]
    Create {
        /// Profile name
        name: String,

        /// Encryption key (86 base64 chars)
        #[arg(short, long, required = true)]
        key: String,
    },
    /// Delete a key profile
    #[command(visible_alias = "d")]
    Delete {
        /// Profile name
        name: String,
    },
    /// Rename a key profile
    #[command(visible_alias = "r")]
    #[command(visible_alias = "mv")]
    Rename {
        /// Current profile name
        old_name: String,

        /// New profile name
        new_name: String,
    },
    /// Set key for a profile
    Set {
        /// Profile name
        name: String,

        /// Encryption key (86 base64 chars)
        #[arg(long, required = true)]
        key: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Enc {
            text,
            key,
            profile,
            keyless,
            format,
            scheme,
            encoding,
        } => {
            let cfg = config::load_config().ok();
            let format_spec = FormatSpec::parse(format, &scheme, &encoding, cfg.as_ref())?;
            enc_command(text, key, profile, keyless, format_spec)
        }

        Commands::Dec {
            text,
            key,
            profile,
            keyless,
            format,
            scheme,
            encoding,
        } => {
            let cfg = config::load_config().ok();
            let scheme_is_explicit = scheme.is_set() || format.is_some();
            let format_spec = FormatSpec::parse(format, &scheme, &encoding, cfg.as_ref())?;
            dec_command(text, key, profile, keyless, format_spec, scheme_is_explicit)
        }

        Commands::Init { name } => config::init_command(&name),

        Commands::Config { command, keyless } => match command {
            Some(ConfigCommands::Show { keyless: _ }) | None => {
                config::config_show_command(keyless)
            }
            Some(ConfigCommands::Set {
                scheme,
                encoding,
                profile,
            }) => {
                let scheme_override = scheme.to_scheme()?;
                let encoding_override = encoding.to_encoding()?;
                config_set_command(scheme_override, encoding_override, profile)
            }
        },

        Commands::Profile { command } => match command {
            ProfileCommands::List => config::profile_list_command(),
            ProfileCommands::Show { name } => config::profile_show_command(name.as_deref()),
            ProfileCommands::Activate { name } => config::profile_activate_command(&name),
            ProfileCommands::Create { name, key } => config::profile_create_command(&name, &key),
            ProfileCommands::Delete { name } => config::profile_delete_command(&name),
            ProfileCommands::Rename { old_name, new_name } => {
                config::profile_rename_command(&old_name, &new_name)
            }
            ProfileCommands::Set { name, key } => config::profile_set_command(&name, &key),
        },

        Commands::Key {
            key,
            profile,
            keyless,
            hex,
        } => key_command(key, profile, keyless, hex),

        Commands::Completion { shell } => {
            completions::generate_completion(shell);
            Ok(())
        }
    }
}

fn enc_command(
    text: Option<String>,
    key: Option<String>,
    profile: Option<String>,
    keyless: bool,
    format_spec: FormatSpec,
) -> Result<()> {
    // Get text from argument or stdin
    let text = get_text_input(text)?;

    // Get config for key resolution
    let cfg = config::load_config().ok();

    // Create format
    let format = format_spec.to_string();

    // Get ob instance
    let ob = if keyless {
        oboron::new_keyless(&format)?
    } else {
        let b64_key = get_key(key.as_ref(), profile.as_deref(), cfg.as_ref())?;
        oboron::new(&format, &b64_key)?
    };

    // Encode
    let encd = ob.enc(&text)?;

    println!("{}", encd);
    Ok(())
}

fn dec_command(
    text: Option<String>,
    key: Option<String>,
    profile: Option<String>,
    keyless: bool,
    format_spec: FormatSpec,
    scheme_is_explicit: bool,
) -> Result<()> {
    // Get text from argument or stdin
    let text = get_text_input(text)?;

    // Get config for key resolution
    let cfg = config::load_config().ok();

    // Create format
    let format = format_spec.to_string();

    // Get ob instance
    let ob = if keyless {
        oboron::new_keyless(&format)?
    } else {
        let b64_key = get_key(key.as_ref(), profile.as_deref(), cfg.as_ref())?;
        oboron::new(&format, &b64_key)?
    };

    // Decode (strict if scheme was explicitly specified)
    let decd = if scheme_is_explicit {
        ob.dec_strict(&text)?
    } else {
        ob.dec(&text)?
    };

    println!("{}", decd);
    Ok(())
}

fn config_set_command(
    scheme_override: Option<Scheme>,
    encoding_override: Option<Encoding>,
    profile: Option<String>,
) -> Result<()> {
    let mut config = config::load_config().unwrap_or(Config {
        profile: "default".to_string(),
        scheme: "ob70".to_string(),
        encoding: "c32".to_string(),
    });

    // Update scheme if provided
    if let Some(scheme) = scheme_override {
        config.scheme = scheme.to_string();
    }

    // Update encoding if provided
    if let Some(encoding) = encoding_override {
        config.encoding = encoding.to_string();
    }

    // Update profile if provided
    if let Some(p) = profile {
        config.profile = p;
    }

    config::save_config(&config)?;

    println!("✓ Configuration updated");
    println!("  Profile: {}", config.profile);
    println!("  Scheme:  {}", config.scheme);
    println!("  Encoding: {}", config.encoding);

    Ok(())
}

fn key_command(
    key: Option<String>,
    profile: Option<String>,
    keyless: bool,
    hex: bool,
) -> Result<()> {
    use data_encoding::{BASE64URL_NOPAD, HEXLOWER};

    let b64_key = if keyless {
        oboron::HARDCODED_KEY_BASE64.to_string()
    } else {
        // Get config for key resolution
        let cfg = config::load_config().ok();
        get_key(key.as_ref(), profile.as_deref(), cfg.as_ref())?
    };

    if hex {
        // Decode base64 to bytes, then encode as hex
        let key_bytes = BASE64URL_NOPAD
            .decode(b64_key.as_bytes())
            .context("Failed to decode base64 key")?;
        let hex_key = HEXLOWER.encode(&key_bytes);
        println!("{}", hex_key);
    } else {
        // Output base64 key as-is
        println!("{}", b64_key);
    }

    Ok(())
}

fn get_text_input(text: Option<String>) -> Result<String> {
    match text {
        Some(t) => Ok(t),
        None => {
            let mut buffer = String::new();
            io::stdin()
                .read_to_string(&mut buffer)
                .context("failed to read from stdin")?;
            let trimmed = buffer.trim();
            if trimmed.is_empty() {
                anyhow::bail!("no input provided");
            }
            Ok(trimmed.to_string())
        }
    }
}

fn get_scheme(scheme_override: Option<Scheme>, config: Option<&Config>) -> Result<Scheme> {
    // Explicit flag takes precedence
    if let Some(scheme) = scheme_override {
        return Ok(scheme);
    }

    // Fall back to config
    if let Some(cfg) = config {
        return Scheme::from_str(&cfg.scheme).map_err(|e| anyhow::anyhow!("{}", e));
    }

    // No override and no config - error
    Err(anyhow::anyhow!(
        "scheme not specified: run 'ob init' or use a scheme flag (e.g., --ob32) or --format"
    ))
}

fn get_encoding(encoding_override: Option<Encoding>, config: Option<&Config>) -> Result<Encoding> {
    // Explicit flag takes precedence
    if let Some(encoding) = encoding_override {
        return Ok(encoding);
    }

    // Fall back to config
    if let Some(cfg) = config {
        return Encoding::from_str(&cfg.encoding).map_err(|e| anyhow::anyhow!("{}", e));
    }

    // No override and no config - error
    Err(anyhow::anyhow!(
        "encoding not specified: run 'ob init' or use an encoding flag (e.g., --b32) or --format"
    ))
}

fn get_key(key: Option<&String>, profile: Option<&str>, config: Option<&Config>) -> Result<String> {
    // Check for explicit key flag (highest priority)
    if let Some(key_str) = key {
        // Validate key format
        validate_base64_key(key_str)?;
        return Ok(key_str.clone());
    }

    // Check for explicit profile flag
    let profile_name = if let Some(name) = profile {
        Some(name)
    } else if let Some(cfg) = config {
        Some(cfg.profile.as_str())
    } else {
        None
    };

    if let Some(name) = profile_name {
        let profile = load_profile(name)?;
        // Validate key format
        validate_base64_key(&profile.key)?;
        return Ok(profile.key);
    }

    Err(anyhow::anyhow!(
        "No key specified: provide --key, --profile <profile>, or run 'ob init' to create config"
    ))
}

fn validate_base64_key(key_str: &str) -> Result<()> {
    // Check length
    if key_str.len() != 86 {
        return Err(anyhow::anyhow!(
            "Key must be {} base64 chars, got {} chars",
            86,
            key_str.len()
        ));
    }

    // Validate base64 encoding and length
    use data_encoding::BASE64URL_NOPAD;
    let key_bytes = BASE64URL_NOPAD
        .decode(key_str.as_bytes())
        .context("Invalid key base64 encoding")?;

    if key_bytes.len() != 64 {
        return Err(anyhow::anyhow!(
            "Key must decode to 64 bytes, got {} bytes",
            key_bytes.len()
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "ob70")]
    fn test_scheme_flags_to_scheme_single() {
        #[cfg(not(any(
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31",
            feature = "ob31p",
            feature = "ob32",
            feature = "ob32p",
            feature = "ob70",
            feature = "ob71",
            feature = "ob00"
        )))]
        compile_error!("At least one oboron scheme must be enabled");
        let flags = SchemeFlags {
            #[cfg(feature = "ob00")]
            ob00: false,
            #[cfg(feature = "ob01")]
            ob01: false,
            #[cfg(feature = "ob21p")]
            ob21p: false,
            #[cfg(feature = "ob31")]
            ob31: false,
            #[cfg(feature = "ob31p")]
            ob31p: false,
            #[cfg(feature = "ob32")]
            ob32: false,
            #[cfg(feature = "ob32p")]
            ob32p: false,
            #[cfg(feature = "ob70")]
            ob70: true,
            #[cfg(feature = "ob71")]
            ob71: false,
        };
        assert_eq!(flags.to_scheme().unwrap(), Some(Scheme::Ob70));
    }

    #[test]
    #[cfg(feature = "ob32")]
    #[cfg(feature = "ob32p")]
    fn test_scheme_flags_to_scheme_multiple_errors() {
        #[cfg(not(any(
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31",
            feature = "ob31p",
            feature = "ob32",
            feature = "ob32p",
            feature = "ob70",
            feature = "ob71",
            feature = "ob00"
        )))]
        compile_error!("At least one oboron scheme must be enabled");
        let flags = SchemeFlags {
            #[cfg(feature = "ob00")]
            ob00: false,
            #[cfg(feature = "ob01")]
            ob01: false,
            #[cfg(feature = "ob21p")]
            ob21p: false,
            #[cfg(feature = "ob31")]
            ob31: false,
            #[cfg(feature = "ob31p")]
            ob31p: false,
            #[cfg(feature = "ob32")]
            ob32: true,
            #[cfg(feature = "ob32p")]
            ob32p: true,
            #[cfg(feature = "ob70")]
            ob70: false,
            #[cfg(feature = "ob71")]
            ob71: false,
        };
        assert!(flags.to_scheme().is_err());
    }

    #[test]
    fn test_scheme_flags_to_scheme_none() {
        #[cfg(not(any(
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31",
            feature = "ob31p",
            feature = "ob32",
            feature = "ob32p",
            feature = "ob70",
            feature = "ob71",
            feature = "ob00"
        )))]
        compile_error!("At least one oboron scheme must be enabled");
        let flags = SchemeFlags {
            #[cfg(feature = "ob00")]
            ob00: false,
            #[cfg(feature = "ob01")]
            ob01: false,
            #[cfg(feature = "ob21p")]
            ob21p: false,
            #[cfg(feature = "ob31")]
            ob31: false,
            #[cfg(feature = "ob31p")]
            ob31p: false,
            #[cfg(feature = "ob32")]
            ob32: false,
            #[cfg(feature = "ob32p")]
            ob32p: false,
            #[cfg(feature = "ob70")]
            ob70: false,
            #[cfg(feature = "ob71")]
            ob71: false,
        };
        assert_eq!(flags.to_scheme().unwrap(), None);
    }

    #[test]
    fn test_encoding_flags_to_encoding_single() {
        let flags = EncodingFlags {
            c32: false,
            b32: false,
            b64: true,
            hex: false,
        };
        assert_eq!(flags.to_encoding().unwrap(), Some(Encoding::Base64));
    }

    #[test]
    fn test_encoding_flags_to_encoding_multiple_errors() {
        let flags = EncodingFlags {
            c32: false,
            b32: true,
            b64: true,
            hex: false,
        };
        assert!(flags.to_encoding().is_err());
    }

    #[test]
    #[cfg(feature = "ob70")]
    fn test_format_spec_from_format_string() {
        let config = Config {
            profile: "test".to_string(),
            scheme: "ob70".to_string(),
            encoding: "b32".to_string(),
        };

        #[cfg(not(any(
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31",
            feature = "ob31p",
            feature = "ob32",
            feature = "ob32p",
            feature = "ob70",
            feature = "ob71",
            feature = "ob00"
        )))]
        compile_error!("At least one oboron scheme must be enabled");
        let scheme_flags = SchemeFlags {
            #[cfg(feature = "ob00")]
            ob00: false,
            #[cfg(feature = "ob01")]
            ob01: false,
            #[cfg(feature = "ob21p")]
            ob21p: false,
            #[cfg(feature = "ob31")]
            ob31: false,
            #[cfg(feature = "ob31p")]
            ob31p: false,
            #[cfg(feature = "ob32")]
            ob32: false,
            #[cfg(feature = "ob32p")]
            ob32p: false,
            #[cfg(feature = "ob70")]
            ob70: false,
            #[cfg(feature = "ob71")]
            ob71: false,
        };
        let encoding_flags = EncodingFlags {
            c32: false,
            b32: false,
            b64: false,
            hex: false,
        };

        let result = FormatSpec::parse(
            Some("ob70:b64".to_string()),
            &scheme_flags,
            &encoding_flags,
            Some(&config),
        )
        .unwrap();

        assert_eq!(result.scheme, Scheme::Ob70);
        assert_eq!(result.encoding, Encoding::Base64);
    }

    #[test]
    #[cfg(feature = "ob70")]
    fn test_format_spec_conflicts_with_scheme_flag() {
        #[cfg(not(any(
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31",
            feature = "ob31p",
            feature = "ob32",
            feature = "ob32p",
            feature = "ob70",
            feature = "ob71",
            feature = "ob00"
        )))]
        compile_error!("At least one oboron scheme must be enabled");
        let scheme_flags = SchemeFlags {
            #[cfg(feature = "ob00")]
            ob00: false,
            #[cfg(feature = "ob01")]
            ob01: false,
            #[cfg(feature = "ob21p")]
            ob21p: false,
            #[cfg(feature = "ob31")]
            ob31: false,
            #[cfg(feature = "ob31p")]
            ob31p: false,
            #[cfg(feature = "ob32")]
            ob32: false,
            #[cfg(feature = "ob32p")]
            ob32p: false,
            #[cfg(feature = "ob70")]
            ob70: true,
            #[cfg(feature = "ob71")]
            ob71: false,
        };
        let encoding_flags = EncodingFlags {
            c32: false,
            b32: false,
            b64: false,
            hex: false,
        };

        let result = FormatSpec::parse(
            Some("ob70:b64".to_string()),
            &scheme_flags,
            &encoding_flags,
            None,
        );

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Cannot use --format together with scheme"));
    }

    #[test]
    fn test_format_spec_conflicts_with_encoding_flag() {
        #[cfg(not(any(
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31",
            feature = "ob31p",
            feature = "ob32",
            feature = "ob32p",
            feature = "ob70",
            feature = "ob71",
            feature = "ob00"
        )))]
        compile_error!("At least one oboron scheme must be enabled");
        let scheme_flags = SchemeFlags {
            #[cfg(feature = "ob00")]
            ob00: false,
            #[cfg(feature = "ob01")]
            ob01: false,
            #[cfg(feature = "ob21p")]
            ob21p: false,
            #[cfg(feature = "ob31")]
            ob31: false,
            #[cfg(feature = "ob31p")]
            ob31p: false,
            #[cfg(feature = "ob32")]
            ob32: false,
            #[cfg(feature = "ob32p")]
            ob32p: false,
            #[cfg(feature = "ob70")]
            ob70: false,
            #[cfg(feature = "ob71")]
            ob71: false,
        };
        let encoding_flags = EncodingFlags {
            c32: false,
            b32: false,
            b64: true,
            hex: false,
        };

        let result = FormatSpec::parse(
            Some("ob70:b64".to_string()),
            &scheme_flags,
            &encoding_flags,
            None,
        );

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Cannot use --format together with encoding"));
    }

    #[test]
    #[cfg(feature = "ob70")]
    fn test_format_spec_from_flags() {
        let config = Config {
            profile: "test".to_string(),
            scheme: "ob71".to_string(),
            encoding: "b32".to_string(),
        };

        #[cfg(not(any(
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31",
            feature = "ob31p",
            feature = "ob32",
            feature = "ob32p",
            feature = "ob70",
            feature = "ob71",
            feature = "ob00"
        )))]
        compile_error!("At least one oboron scheme must be enabled");
        let scheme_flags = SchemeFlags {
            #[cfg(feature = "ob00")]
            ob00: false,
            #[cfg(feature = "ob01")]
            ob01: false,
            #[cfg(feature = "ob21p")]
            ob21p: false,
            #[cfg(feature = "ob31")]
            ob31: false,
            #[cfg(feature = "ob31p")]
            ob31p: false,
            #[cfg(feature = "ob32")]
            ob32: false,
            #[cfg(feature = "ob32p")]
            ob32p: false,
            #[cfg(feature = "ob70")]
            ob70: true,
            #[cfg(feature = "ob71")]
            ob71: false,
        };
        let encoding_flags = EncodingFlags {
            c32: false,
            b32: false,
            b64: true,
            hex: false,
        };

        let result =
            FormatSpec::parse(None, &scheme_flags, &encoding_flags, Some(&config)).unwrap();

        assert_eq!(result.scheme, Scheme::Ob70);
        assert_eq!(result.encoding, Encoding::Base64);
    }

    #[test]
    #[cfg(feature = "ob70")]
    fn test_format_spec_from_config() {
        let config = Config {
            profile: "test".to_string(),
            scheme: "ob70".to_string(),
            encoding: "hex".to_string(),
        };

        #[cfg(not(any(
            feature = "ob01",
            feature = "ob21p",
            feature = "ob31",
            feature = "ob31p",
            feature = "ob32",
            feature = "ob32p",
            feature = "ob70",
            feature = "ob71",
            feature = "ob00"
        )))]
        compile_error!("At least one oboron scheme must be enabled");
        let scheme_flags = SchemeFlags {
            #[cfg(feature = "ob00")]
            ob00: false,
            #[cfg(feature = "ob01")]
            ob01: false,
            #[cfg(feature = "ob21p")]
            ob21p: false,
            #[cfg(feature = "ob31")]
            ob31: false,
            #[cfg(feature = "ob31p")]
            ob31p: false,
            #[cfg(feature = "ob32")]
            ob32: false,
            #[cfg(feature = "ob32p")]
            ob32p: false,
            #[cfg(feature = "ob70")]
            ob70: false,
            #[cfg(feature = "ob71")]
            ob71: false,
        };
        let encoding_flags = EncodingFlags {
            c32: false,
            b32: false,
            b64: false,
            hex: false,
        };

        let result =
            FormatSpec::parse(None, &scheme_flags, &encoding_flags, Some(&config)).unwrap();

        assert_eq!(result.scheme, Scheme::Ob70);
        assert_eq!(result.encoding, Encoding::Hex);
    }

    #[test]
    #[cfg(feature = "ob70")]
    fn test_get_scheme_from_override() {
        let result = get_scheme(Some(Scheme::Ob70), None);
        assert_eq!(result.unwrap(), Scheme::Ob70);
    }

    #[test]
    #[cfg(feature = "ob70")]
    fn test_get_scheme_from_config() {
        let config = Config {
            profile: "test".to_string(),
            scheme: "ob70".to_string(),
            encoding: "b32".to_string(),
        };
        let result = get_scheme(None, Some(&config));
        assert_eq!(result.unwrap(), Scheme::Ob70);
    }

    #[test]
    fn test_get_key_from_base64_string() {
        let key_str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
        let result = get_key(Some(&key_str), None, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), key_str);
    }

    #[test]
    fn test_validate_base64_key_valid() {
        let key_str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(validate_base64_key(&key_str).is_ok());
    }

    #[test]
    fn test_validate_base64_key_wrong_length() {
        let key_str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(validate_base64_key(&key_str).is_err());
    }

    #[test]
    fn test_validate_base64_key_invalid_encoding() {
        let mut key_str = "A".repeat(85);
        key_str.push('!'); // Invalid base64 character
        assert!(validate_base64_key(&key_str).is_err());
    }
}
