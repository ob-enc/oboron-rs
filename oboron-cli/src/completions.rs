use clap::{Command, Subcommand};
use clap_complete::{generate, Shell as ClapShell};
use std::io;

#[derive(Subcommand, Clone)]
pub enum Shell {
    /// Generate bash completion script
    Bash,
    /// Generate zsh completion script
    Zsh,
    /// Generate fish completion script
    Fish,
    /// Generate PowerShell completion script
    Powershell,
}

pub fn generate_completion(shell: Shell) {
    let mut cmd = build_cli();
    let bin_name = "ob";

    match shell {
        Shell::Bash => generate(ClapShell::Bash, &mut cmd, bin_name, &mut io::stdout()),
        Shell::Zsh => generate(ClapShell::Zsh, &mut cmd, bin_name, &mut io::stdout()),
        Shell::Fish => generate(ClapShell::Fish, &mut cmd, bin_name, &mut io::stdout()),
        Shell::Powershell => generate(ClapShell::PowerShell, &mut cmd, bin_name, &mut io::stdout()),
    }
}

fn build_cli() -> Command {
    // This should match your main CLI structure
    Command::new("ob")
        .about("Reversible hash-like references")
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommands(vec![
            Command::new("enc").alias("e").about("Encode a string"),
            Command::new("dec")
                .alias("d")
                .about("Decode an encoded string"),
            Command::new("init")
                .alias("i")
                .about("Initialize configuration with random profile"),
            Command::new("config")
                .alias("c")
                .about("Manage configuration")
                .subcommands(vec![
                    Command::new("show").about("Show current configuration"),
                    Command::new("set").about("Set configuration values"),
                ]),
            Command::new("profile")
                .alias("k")
                .about("Manage key profiles")
                .subcommands(vec![
                    Command::new("list").about("List all key profiles"),
                    Command::new("show").about("Show a specific key profile"),
                    Command::new("activate").about("Set a profile as the default"),
                    Command::new("create").about("Create a new key profile"),
                    Command::new("delete").about("Delete a key profile"),
                    Command::new("set").about("Set key and IV for a profile"),
                ]),
            Command::new("completion")
                .about("Generate shell completion script")
                .subcommands(vec![
                    Command::new("bash").about("Generate bash completion script"),
                    Command::new("zsh").about("Generate zsh completion script"),
                    Command::new("fish").about("Generate fish completion script"),
                    Command::new("powershell").about("Generate PowerShell completion script"),
                ]),
        ])
}
