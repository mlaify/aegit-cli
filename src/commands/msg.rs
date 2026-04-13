use std::fs;

use aegis_crypto::{CryptoSuite, DemoSuite};
use aegis_proto::{Envelope, IdentityId, MessageBody, PrivateHeaders, PrivatePayload};
use clap::{Args, Subcommand};

#[derive(Debug, Args)]
pub struct MsgCommand {
    #[command(subcommand)]
    pub action: MsgAction,
}

#[derive(Debug, Subcommand)]
pub enum MsgAction {
    Seal {
        #[arg(long)] to: String,
        #[arg(long)] from: Option<String>,
        #[arg(long)] subject: Option<String>,
        #[arg(long)] body: String,
        #[arg(long)] passphrase: String,
        #[arg(long)] out: String,
    },
    Open {
        #[arg(long)] input: String,
        #[arg(long)] passphrase: String,
    },
}

pub fn run(command: MsgCommand) -> Result<(), Box<dyn std::error::Error>> {
    match command.action {
        MsgAction::Seal {
            to,
            from,
            subject,
            body,
            passphrase,
            out,
        } => {
            let suite = DemoSuite::from_passphrase(&passphrase);
            let payload = PrivatePayload {
                private_headers: PrivateHeaders {
                    subject,
                    thread_id: None,
                    in_reply_to: None,
                },
                body: MessageBody {
                    mime: "text/plain".to_string(),
                    content: body,
                },
                attachments: vec![],
                extensions: serde_json::json!({}),
            };

            let encrypted = suite.encrypt_payload(&payload)?;
            let envelope = Envelope::new(
                IdentityId(to),
                from.map(IdentityId),
                suite.suite_id(),
                encrypted,
            );

            fs::write(&out, envelope.to_json_pretty()?)?;
            println!("sealed -> {out}");
        }
        MsgAction::Open { input, passphrase } => {
            let suite = DemoSuite::from_passphrase(&passphrase);
            let raw = fs::read_to_string(&input)?;
            let envelope = Envelope::from_json(&raw)?;
            let payload = suite.decrypt_payload(&envelope.payload)?;

            println!("envelope: {}", envelope.envelope_id.0);
            println!("to: {}", envelope.recipient_id.0);
            println!(
                "from: {}",
                envelope
                    .sender_hint
                    .as_ref()
                    .map(|v| v.0.as_str())
                    .unwrap_or("<anonymous>")
            );
            println!(
                "subject: {}",
                payload
                    .private_headers
                    .subject
                    .as_deref()
                    .unwrap_or("<none>")
            );
            println!("\n{}", payload.body.content);
        }
    }

    Ok(())
}
