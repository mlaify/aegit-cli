use std::fs;

use aegis_crypto::{CryptoSuite, DemoSuite};
use aegis_proto::{Envelope, IdentityId, MessageBody, PrivateHeaders, PrivatePayload};
use clap::{Args, Subcommand};

#[derive(Debug, Subcommand)]
pub enum MessageCommand {
    Seal(SealArgs),
    Open(OpenArgs),
}

#[derive(Debug, Args)]
pub struct SealArgs {
    #[arg(long)]
    pub to: String,
    #[arg(long)]
    pub from: Option<String>,
    #[arg(long)]
    pub subject: Option<String>,
    #[arg(long)]
    pub body: String,
    #[arg(long)]
    pub passphrase: String,
    #[arg(long)]
    pub out: String,
}

#[derive(Debug, Args)]
pub struct OpenArgs {
    #[arg(long)]
    pub input: String,
    #[arg(long)]
    pub passphrase: String,
}

pub fn run(cmd: MessageCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        MessageCommand::Seal(args) => {
            let suite = DemoSuite::from_passphrase(&args.passphrase);

            let payload = PrivatePayload {
                private_headers: PrivateHeaders {
                    subject: args.subject,
                    thread_id: None,
                    in_reply_to: None,
                },
                body: MessageBody {
                    mime: "text/plain".to_string(),
                    content: args.body,
                },
                attachments: vec![],
                extensions: serde_json::json!({}),
            };

            let encrypted = suite.encrypt_payload(&payload)?;
            let envelope = Envelope::new(
                IdentityId(args.to),
                args.from.map(IdentityId),
                suite.suite_id(),
                encrypted,
            );

            fs::write(&args.out, envelope.to_json_pretty()?)?;
            println!("sealed -> {}", args.out);
        }
        MessageCommand::Open(args) => {
            let suite = DemoSuite::from_passphrase(&args.passphrase);
            let raw = fs::read_to_string(&args.input)?;
            let envelope = Envelope::from_json(&raw)?;
            let payload = suite.decrypt_payload(&envelope.payload)?;

            println!("envelope: {:?}", envelope.envelope_id.0);
            println!("to: {}", envelope.recipient_id.0);
            println!(
                "from: {}",
                envelope.sender_hint.as_ref().map(|i| i.0.as_str()).unwrap_or("<anonymous>")
            );
            println!(
                "subject: {}",
                payload.private_headers.subject.as_deref().unwrap_or("<none>")
            );
            println!("{}", payload.body.content);
        }
    }

    Ok(())
}
