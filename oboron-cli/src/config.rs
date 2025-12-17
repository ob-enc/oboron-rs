use anyhow::{Context, Result};
use data_encoding::BASE64URL_NOPAD;
use oboron::generate_key_base64;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    #[serde(rename = "profile")]
    pub profile: String,
    pub scheme: String,
    pub encoding: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyProfile {
    pub key: String,
}

pub fn config_path() -> PathBuf {
    dirs::home_dir()
        .expect("Failed to get home directory")
        .join(".ob")
        .join("config.json")
}

pub fn profile_dir() -> PathBuf {
    dirs::home_dir()
        .expect("Failed to get home directory")
        .join(".ob")
        .join("profiles")
}

pub fn profile_path(name: &str) -> PathBuf {
    profile_dir().join(format!("{}.json", name))
}

pub fn backup_dir() -> PathBuf {
    dirs::home_dir()
        .expect("Failed to get home directory")
        .join(".ob")
        .join("bkp")
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

    // Default to ob32 if not set
    if config.scheme.is_empty() {
        config.scheme = "ob32".to_string();
    }

    // Default to base32crockford if not set
    if config.encoding.is_empty() {
        config.encoding = "base32crockford".to_string();
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

    // Generate random base64 key
    let key = generate_key_base64();

    let profile = KeyProfile { key: key.clone() };

    save_key_profile(name, &profile)?;

    let config = Config {
        profile: name.to_string(),
        scheme: "ob32".to_string(), // Default to ob32
        encoding: "base32crockford".to_string(),
    };

    save_config(&config)?;

    println!("✓ Configuration saved to {}", config_path().display());
    println!("\nYour profile '{}':", name);
    println!("  Default scheme: ob32");
    println!("  Default encoding: base32crockford");
    println!("  Key: {}", key);
    println!("\n⚠️  Keep these keys secure! Anyone with these keys can decode your data.");

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
    println!("  Profile: {}", config.profile);
    println!("  Scheme:  {}", config.scheme);
    println!("  Encoding: {}", config.encoding);
    println!("  Key: {}", profile.key);

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
    println!("  Key: {}", profile.key);

    Ok(())
}

pub fn profile_activate_command(name: &str) -> Result<()> {
    // Verify profile exists
    load_profile(name)?;

    let mut config = load_config().unwrap_or(Config {
        profile: "default".to_string(),
        scheme: "ob32".to_string(),
        encoding: "base32crockford".to_string(),
    });

    config.profile = name.to_string();
    save_config(&config)?;

    println!("✓ Activated profile '{}'", name);

    Ok(())
}

pub fn profile_create_command(name: &str, key: &str) -> Result<()> {
    // Validate key
    if key.len() != 86 {
        anyhow::bail!("Key must be {} base64 chars", 86);
    }

    // Validate base64 encoding
    let key_bytes = BASE64URL_NOPAD
        .decode(key.as_bytes())
        .context("Invalid key base64 encoding")?;

    if key_bytes.len() != 64 {
        anyhow::bail!("Key must decode to 64 bytes");
    }

    let profile = KeyProfile {
        key: key.to_string(),
    };

    save_key_profile(name, &profile)?;

    println!("✓ Created profile '{}'", name);
    println!("\n⚠️  Keep this key secure!");

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

    println!("  Backup saved to:  {}", backup_path.display());

    Ok(())
}

pub fn profile_set_command(name: &str, key: &str) -> Result<()> {
    // Validate key
    if key.len() != 86 {
        anyhow::bail!("Key must be {} base64 chars", 86);
    }

    // Validate base64 encoding
    let key_bytes = BASE64URL_NOPAD
        .decode(key.as_bytes())
        .context("Invalid key base64 encoding")?;

    if key_bytes.len() != 64 {
        anyhow::bail!("Key must decode to 64 bytes");
    }

    let profile = KeyProfile {
        key: key.to_string(),
    };

    save_key_profile(name, &profile)?;

    println!("✓ Updated profile '{}'", name);

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_serialization() {
        let config = Config {
            profile: "test".to_string(),
            scheme: "ob31".to_string(),
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
            key:  "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
        };

        let json = serde_json::to_string(&profile).unwrap();
        let deserialized: KeyProfile = serde_json::from_str(&json).unwrap();

        assert_eq!(profile.key, deserialized.key);
    }

    #[test]
    fn test_config_defaults() {
        let json = r#"{"profile":"","scheme":"","encoding":""}"#;
        let mut config: Config = serde_json::from_str(json).unwrap();

        // Simulate load_config logic
        if config.scheme.is_empty() {
            config.scheme = "ob32".to_string();
        }
        if config.encoding.is_empty() {
            config.encoding = "base32crockford".to_string();
        }
        if config.profile.is_empty() {
            config.profile = "default".to_string();
        }

        assert_eq!(config.profile, "default");
        assert_eq!(config.scheme, "ob32");
        assert_eq!(config.encoding, "base32crockford");
    }

    #[test]
    fn test_profile_path_construction() {
        let path = profile_path("myprofile");
        assert!(path.to_string_lossy().contains("myprofile.json"));
        assert!(path.to_string_lossy().contains(".ob"));
        assert!(path.to_string_lossy().contains("profiles"));
    }

    #[test]
    fn test_config_path_construction() {
        let path = config_path();
        assert!(path.to_string_lossy().contains("config.json"));
        assert!(path.to_string_lossy().contains(".ob"));
    }

    #[test]
    fn test_backup_dir_construction() {
        let path = backup_dir();
        assert!(path.to_string_lossy().contains("bkp"));
        assert!(path.to_string_lossy().contains(".ob"));
    }

    #[test]
    fn test_config_with_partial_fields() {
        let json = r#"{"profile":"custom","scheme":"ob01","encoding":""}"#;
        let mut config: Config = serde_json::from_str(json).unwrap();

        if config.encoding.is_empty() {
            config.encoding = "base32crockford".to_string();
        }

        assert_eq!(config.profile, "custom");
        assert_eq!(config.scheme, "ob01");
        assert_eq!(config.encoding, "base32crockford");
    }
}
