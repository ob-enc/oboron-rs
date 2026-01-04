use anyhow::{Context, Result};
use data_encoding::BASE64URL_NOPAD;
use oboron::generate_key;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

const CONFIG_DIR: &str = ".ob";
const PROFILES_SUBDIR: &str = "profiles";
const BACKUP_SUBDIR: &str = "bkp";
const CONFIG_FILENAME: &str = "config.json";

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(rename = "profile")]
    pub profile: String,
    pub scheme: String,
    pub encoding: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyProfile {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
}

pub fn config_path() -> PathBuf {
    dirs::home_dir()
        .expect("Failed to get home directory")
        .join(CONFIG_DIR)
        .join(CONFIG_FILENAME)
}

pub fn profile_dir() -> PathBuf {
    dirs::home_dir()
        .expect("Failed to get home directory")
        .join(CONFIG_DIR)
        .join(PROFILES_SUBDIR)
}

pub fn profile_path(name: &str) -> PathBuf {
    profile_dir().join(format!("{}.json", name))
}

pub fn backup_dir() -> PathBuf {
    dirs::home_dir()
        .expect("Failed to get home directory")
        .join(CONFIG_DIR)
        .join(BACKUP_SUBDIR)
}

fn backup_profile(name: &str) -> Result<PathBuf> {
    let path = profile_path(name);

    if !path.exists() {
        anyhow::bail!("Profile '{}' does not exist", name);
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let backup_path = backup_dir().join(format!("{}-{}.json", name, timestamp));

    // Create backup directory if it doesn't exist
    if let Some(parent) = backup_path.parent() {
        fs::create_dir_all(parent).context("Failed to create backup directory")?;
    }

    // Copy to backup location
    fs::copy(&path, &backup_path).context(format!("Failed to backup profile '{}'", name))?;

    Ok(backup_path)
}

pub fn load_config() -> Result<Config> {
    let path = config_path();
    let content = fs::read_to_string(&path).context(format!(
        "Failed to read config file {}\nHint: Run 'ob init' to create a config file",
        path.display()
    ))?;

    let mut config: Config =
        serde_json::from_str(&content).context("Failed to parse config file")?;

    // Default to aasv if not set
    if config.scheme.is_empty() {
        config.scheme = "aasv".to_string();
    }

    // Default to Crockford base32 if not set
    if config.encoding.is_empty() {
        config.encoding = "c32".to_string();
    }

    // Default to "default" profile if not set
    if config.profile.is_empty() {
        config.profile = "default".to_string();
    }

    Ok(config)
}

pub fn save_config(config: &Config) -> Result<()> {
    let path = config_path();

    // Create directory if it doesn't exist
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("Failed to create config directory")?;
    }

    let content = serde_json::to_string_pretty(config).context("Failed to serialize config")?;

    fs::write(&path, content).context("Failed to write config file")?;

    // Set permissions to 0600 on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms)?;
    }

    Ok(())
}

pub fn load_profile(name: &str) -> Result<KeyProfile> {
    let path = profile_path(name);
    let content = fs::read_to_string(&path).context(format!(
        "Failed to read key profile '{}'\nHint: Run 'ob init' or 'ob profile create {}' to create this key profile",
        name, name
    ))?;

    let profile: KeyProfile = serde_json::from_str(&content)
        .context(format!("Failed to parse key profile '{}'", name))?;

    Ok(profile)
}

pub fn save_key_profile(name: &str, profile: &KeyProfile) -> Result<()> {
    let path = profile_path(name);

    // Create profile directory if it doesn't exist
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("Failed to create profile directory")?;
    }

    // Backup existing profile if it exists
    if path.exists() {
        let backup_path = backup_profile(name)?;
        println!("Backed up existing profile to: {}", backup_path.display());
    }

    let content = serde_json::to_string_pretty(profile).context("Failed to serialize profile")?;

    fs::write(&path, content).context("Failed to write profile file")?;

    // Set permissions to 0600 on Unix
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(&path)?.permissions();
        perms.set_mode(0o600);
        fs::set_permissions(&path, perms)?;
    }

    Ok(())
}

/// Generate a z-tier secret (32 bytes = 43 base64 chars)
fn generate_secret() -> String {
    loop {
        let mut secret_bytes = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut secret_bytes);
        let secret_base64 = BASE64URL_NOPAD.encode(&secret_bytes);
        if !secret_base64.contains('-') && !secret_base64.contains('_') {
            return secret_base64;
        }
    }
}

pub fn init_command(name: &str) -> Result<()> {
    // Check if profile already exists
    let path = profile_path(name);
    if path.exists() {
        eprintln!("❌ Error: Profile '{}' already exists", name);
        eprintln!();
        eprintln!("To avoid accidental data loss, 'ob init' cannot overwrite an existing profile.");
        eprintln!();
        eprintln!("Options:");
        eprintln!("  1. Create a new profile with a different name:");
        eprintln!("     ob init --name <new-profile-name>");
        eprintln!();
        eprintln!("  2. Delete the existing profile first:");
        eprintln!("     ob profile delete {}", name);
        eprintln!();
        eprintln!("  3. Use 'ob profile create' to add additional profiles:");
        eprintln!("     ob profile create <profile-name>");
        eprintln!();
        eprintln!("  4. Manually delete the profile file:");
        eprintln!("     rm {}", path.display());

        anyhow::bail!("Profile '{}' already exists", name);
    }

    // Generate both key and secret
    let key = generate_key();
    let secret = generate_secret();

    let profile = KeyProfile {
        key: Some(key.clone()),
        secret: Some(secret.clone()),
    };

    save_key_profile(name, &profile)?;

    let config = Config {
        profile: name.to_string(),
        scheme: "aasv".to_string(),  // Default to aasv
        encoding: "c32".to_string(), // Default to Crockford base32
    };

    save_config(&config)?;

    println!("✓ Configuration saved to {}", config_path().display());
    println!("\nYour profile '{}':", name);
    println!("  Default scheme:  aasv");
    println!("  Default encoding: c32");
    println!("  Key:    {}", key);
    println!("  Secret: {}", secret);
    println!("\n⚠️  Keep these keys/secrets secure! Anyone with these can decode your data.");

    Ok(())
}

pub fn config_show_command(public_profile: bool) -> Result<()> {
    if public_profile {
        println!("Using public profile (INSECURE - testing only):");
        println!("Key: {}", oboron::HARDCODED_KEY_BASE64);
        return Ok(());
    }

    let config = load_config()?;
    let profile = load_profile(&config.profile)?;

    println!("Current configuration:");
    println!("  Profile:  {}", config.profile);
    println!("  Scheme:   {}", config.scheme);
    println!("  Encoding: {}", config.encoding);
    if let Some(key) = &profile.key {
        println!("  Key:    {}", key);
    }
    if let Some(secret) = &profile.secret {
        println!("  Secret: {}", secret);
    }

    Ok(())
}

pub fn profile_list_command() -> Result<()> {
    let profile_dir = profile_dir();

    if !profile_dir.exists() {
        println!("No profiles found.  Run 'ob init' to create one.");
        return Ok(());
    }

    let entries = fs::read_dir(&profile_dir)?;
    let mut profiles = Vec::new();

    for entry in entries {
        let entry = entry?;
        let path = entry.path();

        if path.extension().and_then(|s| s.to_str()) == Some("json") {
            if let Some(name) = path.file_stem().and_then(|s| s.to_str()) {
                profiles.push(name.to_string());
            }
        }
    }

    if profiles.is_empty() {
        println!("No profiles found.");
        return Ok(());
    }

    profiles.sort();

    let config = load_config().ok();
    let active_profile = config.as_ref().map(|c| c.profile.as_str());

    println!("Available profiles:");
    for profile in profiles {
        let marker = if Some(profile.as_str()) == active_profile {
            " (active)"
        } else {
            ""
        };
        println!("  {}{}", profile, marker);
    }

    Ok(())
}

pub fn profile_show_command(name: Option<&str>) -> Result<()> {
    let profile_name = if let Some(n) = name {
        n.to_string()
    } else {
        let config = load_config()?;
        config.profile
    };

    let profile = load_profile(&profile_name)?;

    println!("Profile '{}':", profile_name);
    if let Some(key) = &profile.key {
        println!("  Key:    {}", key);
    }
    if let Some(secret) = &profile.secret {
        println!("  Secret: {}", secret);
    }

    Ok(())
}

pub fn profile_activate_command(name: &str) -> Result<()> {
    // Verify profile exists
    load_profile(name)?;

    let mut config = load_config().unwrap_or(Config {
        profile: "default".to_string(),
        scheme: "aasv".to_string(),
        encoding: "c32".to_string(),
    });

    config.profile = name.to_string();
    save_config(&config)?;

    println!("✓ Activated profile '{}'", name);

    Ok(())
}

pub fn profile_create_command(name: &str, key: Option<&str>, secret: Option<&str>) -> Result<()> {
    let mut profile = KeyProfile {
        key: None,
        secret: None,
    };

    // Validate and set key if provided
    if let Some(k) = key {
        validate_base64_key(k)?;
        profile.key = Some(k.to_string());
    }

    // Validate and set secret if provided
    if let Some(s) = secret {
        validate_base64_secret(s)?;
        profile.secret = Some(s.to_string());
    }

    // At least one must be provided
    if profile.key.is_none() && profile.secret.is_none() {
        anyhow::bail!("At least one of --key or --secret must be provided");
    }

    save_key_profile(name, &profile)?;

    println!("✓ Created profile '{}'", name);
    if profile.key.is_some() {
        println!("  With key");
    }
    if profile.secret.is_some() {
        println!("  With secret");
    }
    println!("\n⚠️  Keep this profile secure!");

    Ok(())
}

pub fn profile_delete_command(name: &str) -> Result<()> {
    let path = profile_path(name);

    if !path.exists() {
        anyhow::bail!("Profile '{}' does not exist", name);
    }

    // Check if this is the active profile
    if let Ok(config) = load_config() {
        if config.profile == name {
            eprintln!("❌ Error: Cannot delete active profile '{}'", name);
            eprintln!();
            eprintln!(
                "The profile '{}' is currently set as the active profile.",
                name
            );
            eprintln!();
            eprintln!("To delete this profile:");
            eprintln!("  1. First activate a different profile:");
            eprintln!("     ob profile activate <other-profile-name>");
            eprintln!();
            eprintln!("  2. Or create a new profile:");
            eprintln!("     ob profile create <new-profile-name>");
            eprintln!("     ob profile activate <new-profile-name>");
            eprintln!();
            eprintln!("  3. Then delete this profile:");
            eprintln!("     ob profile delete {}", name);

            anyhow::bail!("Cannot delete active profile '{}'", name);
        }
    }

    // Backup the profile before deleting
    let backup_path = backup_profile(name)?;

    // Now delete the profile
    fs::remove_file(&path)?;

    println!("✓ Deleted profile '{}'", name);
    println!("  Backup saved to: {}", backup_path.display());

    Ok(())
}

pub fn profile_rename_command(old_name: &str, new_name: &str) -> Result<()> {
    let old_path = profile_path(old_name);
    let new_path = profile_path(new_name);

    // Check if old profile exists
    if !old_path.exists() {
        anyhow::bail!("Profile '{}' does not exist", old_name);
    }

    // Check if new profile name is already taken
    if new_path.exists() {
        anyhow::bail!(
            "Profile '{}' already exists. Cannot rename to an existing profile name.",
            new_name
        );
    }

    // Backup before renaming (safety measure)
    let backup_path = backup_profile(old_name)?;

    // Rename the profile file
    fs::rename(&old_path, &new_path).context(format!(
        "Failed to rename profile '{}' to '{}'",
        old_name, new_name
    ))?;

    // Check if the renamed profile is the active profile, and update config if so
    if let Ok(mut config) = load_config() {
        if config.profile == old_name {
            config.profile = new_name.to_string();
            save_config(&config)?;
            println!(
                "✓ Renamed profile '{}' to '{}' (active profile updated)",
                old_name, new_name
            );
        } else {
            println!("✓ Renamed profile '{}' to '{}'", old_name, new_name);
        }
    } else {
        println!("✓ Renamed profile '{}' to '{}'", old_name, new_name);
    }

    println!("  Backup saved to:   {}", backup_path.display());

    Ok(())
}

pub fn profile_set_command(name: &str, key: Option<&str>, secret: Option<&str>) -> Result<()> {
    // Load existing profile
    let mut profile = load_profile(name)?;

    // Update key if provided
    if let Some(k) = key {
        validate_base64_key(k)?;
        profile.key = Some(k.to_string());
    }

    // Update secret if provided
    if let Some(s) = secret {
        validate_base64_secret(s)?;
        profile.secret = Some(s.to_string());
    }

    // At least one must be set in the profile
    if profile.key.is_none() && profile.secret.is_none() {
        anyhow::bail!("Profile must have at least a key or secret");
    }

    save_key_profile(name, &profile)?;

    println!("✓ Updated profile '{}'", name);

    Ok(())
}

fn validate_base64_key(key_str: &str) -> Result<()> {
    // Check length
    if key_str.len() != 86 {
        anyhow::bail!("Key must be 86 base64 chars, got {} chars", key_str.len());
    }

    // Validate base64 encoding
    let key_bytes = BASE64URL_NOPAD
        .decode(key_str.as_bytes())
        .context("Invalid key base64 encoding")?;

    if key_bytes.len() != 64 {
        anyhow::bail!("Key must decode to 64 bytes, got {} bytes", key_bytes.len());
    }

    Ok(())
}

fn validate_base64_secret(secret_str: &str) -> Result<()> {
    // Check length
    if secret_str.len() != 43 {
        anyhow::bail!(
            "Secret must be 43 base64 chars, got {} chars",
            secret_str.len()
        );
    }

    // Validate base64 encoding
    let secret_bytes = BASE64URL_NOPAD
        .decode(secret_str.as_bytes())
        .context("Invalid secret base64 encoding")?;

    if secret_bytes.len() != 32 {
        anyhow::bail!(
            "Secret must decode to 32 bytes, got {} bytes",
            secret_bytes.len()
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_serialization() {
        let config = Config {
            profile: "test".to_string(),
            scheme: "aags".to_string(),
            encoding: "base64".to_string(),
        };

        let json = serde_json::to_string(&config).unwrap();
        let deserialized: Config = serde_json::from_str(&json).unwrap();

        assert_eq!(config.profile, deserialized.profile);
        assert_eq!(config.scheme, deserialized.scheme);
        assert_eq!(config.encoding, deserialized.encoding);
    }

    #[test]
    fn test_key_profile_serialization() {
        let profile = KeyProfile {
            key:  Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()),
            secret: Some("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()),
        };

        let json = serde_json::to_string(&profile).unwrap();
        let deserialized: KeyProfile = serde_json::from_str(&json).unwrap();

        assert_eq!(profile.key, deserialized.key);
        assert_eq!(profile.secret, deserialized.secret);
    }

    #[test]
    fn test_validate_base64_key_valid() {
        let key_str = oboron::generate_key();
        assert!(validate_base64_key(&key_str).is_ok());
    }

    #[test]
    fn test_validate_base64_secret_valid() {
        let secret_str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(validate_base64_secret(secret_str).is_ok());
    }

    #[test]
    fn test_validate_base64_key_wrong_length() {
        let key_str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(validate_base64_key(key_str).is_err());
    }

    #[test]
    fn test_validate_base64_secret_wrong_length() {
        let secret_str = "AAAAAAAAAAAAAAAAAAAAAAAA";
        assert!(validate_base64_secret(secret_str).is_err());
    }
}
