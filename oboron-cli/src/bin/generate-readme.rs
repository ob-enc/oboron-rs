use clap::Command;
use std::fs;
use std::io;

fn main() -> io::Result<()> {
    let cmd = build_cli();

    // Generate markdown from the command
    let markdown = generate_markdown(&cmd);

    // Write to CLI_HELP.md in the project root
    fs::write("CLI_HELP.md", markdown)?;

    println!("✓ Generated CLI_HELP.md");
    Ok(())
}

fn build_cli() -> Command {
    Command::new("ob")
        .about("Reversible hash-like references")
        .version(env!("CARGO_PKG_VERSION"))
        .subcommand_required(true)
        .arg_required_else_help(true)
        .subcommands(vec![
            Command::new("enc")
                .alias("e")
                .about("Encrypt+encode a plaintext string"),
            Command::new("dec")
                .alias("d")
                .about("Decode+decrypt an obtext string"),
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
                .alias("p")
                .about("Manage key profiles")
                .subcommands(vec![
                    Command::new("list").about("List all key profiles"),
                    Command::new("show").about("Show a specific key profile"),
                    Command::new("activate").about("Set a profile as the default"),
                    Command::new("create").about("Create a new key profile"),
                    Command::new("delete").about("Delete a key profile"),
                    Command::new("rename").about("Rename a key profile"),
                    Command::new("set").about("Set key for a profile"),
                ]),
            Command::new("key")
                .alias("k")
                .about("Output the encryption key"),
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

fn generate_markdown(cmd: &Command) -> String {
    let mut output = String::new();

    // Header
    output.push_str("# Oboron CLI\n\n");

    if let Some(about) = cmd.get_about() {
        output.push_str(&format!("{}\n\n", about));
    }

    // Usage
    output.push_str("## Usage\n\n");
    output.push_str("```bash\n");
    output.push_str(&format!("{} <COMMAND>\n", cmd.get_name()));
    output.push_str("```\n\n");

    // Commands
    output.push_str("## Commands\n\n");

    for subcmd in cmd.get_subcommands() {
        if subcmd.is_hide_set() {
            continue;
        }

        let name = subcmd.get_name();
        let aliases: Vec<_> = subcmd.get_all_aliases().collect();

        output.push_str(&format!("### `{}`", name));
        if !aliases.is_empty() {
            output.push_str(&format!(" (aliases: {})", aliases.join(", ")));
        }
        output.push_str("\n\n");

        if let Some(about) = subcmd.get_about() {
            output.push_str(&format!("{}\n\n", about));
        }

        // Subcommands of this command
        let has_subcommands = subcmd.get_subcommands().any(|_| true);
        if has_subcommands {
            output.push_str("**Subcommands:**\n\n");
            for sub_subcmd in subcmd.get_subcommands() {
                if sub_subcmd.is_hide_set() {
                    continue;
                }
                let sub_name = sub_subcmd.get_name();
                let sub_aliases: Vec<_> = sub_subcmd.get_all_aliases().collect();

                output.push_str(&format!("- `{}`", sub_name));
                if !sub_aliases.is_empty() {
                    output.push_str(&format!(" (aliases:  {})", sub_aliases.join(", ")));
                }
                if let Some(about) = sub_subcmd.get_about() {
                    output.push_str(&format!(" - {}", about));
                }
                output.push_str("\n");
            }
            output.push_str("\n");
        }
    }

    output
}
