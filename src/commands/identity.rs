use clap::{Args, Subcommand};

#[derive(Debug, Subcommand)]
pub enum IdentityCommand {
    Init(InitArgs),
    Show(ShowArgs),
}

#[derive(Debug, Args)]
pub struct InitArgs {
    #[arg(long)]
    pub alias: Option<String>,
}

#[derive(Debug, Args)]
pub struct ShowArgs {
    #[arg(long)]
    pub identity: String,
}

pub fn run(cmd: IdentityCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        IdentityCommand::Init(args) => {
            println!("initialized local identity scaffold");
            if let Some(alias) = args.alias {
                println!("alias: {}", alias);
            }
        }
        IdentityCommand::Show(args) => {
            println!("identity: {}", args.identity);
        }
    }
    Ok(())
}
