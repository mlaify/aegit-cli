mod commands;

use clap::{Parser, Subcommand};
use commands::{id, msg};

#[derive(Debug, Parser)]
#[command(name = "aegit")]
#[command(about = "git-flavored CLI for the Aegis ecosystem")]
struct Cli {
    #[command(subcommand)]
    command: TopLevel,
}

#[derive(Debug, Subcommand)]
enum TopLevel {
    Id(id::IdCommand),
    Msg(msg::MsgCommand),
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        TopLevel::Id(command) => id::run(command)?,
        TopLevel::Msg(command) => msg::run(command)?,
    }

    Ok(())
}
