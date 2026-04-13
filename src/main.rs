mod commands;

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(name = "aegit")]
#[command(about = "Aegis operator CLI")]
struct Cli {
    #[command(subcommand)]
    command: TopLevel,
}

#[derive(Debug, Subcommand)]
enum TopLevel {
    #[command(subcommand)]
    Id(commands::identity::IdentityCommand),
    #[command(subcommand)]
    Msg(commands::message::MessageCommand),
    #[command(subcommand)]
    Relay(commands::relay::RelayCommand),
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        TopLevel::Id(cmd) => commands::identity::run(cmd)?,
        TopLevel::Msg(cmd) => commands::message::run(cmd)?,
        TopLevel::Relay(cmd) => commands::relay::run(cmd)?,
    }

    Ok(())
}
