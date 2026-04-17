use std::{
    fs,
    path::{Path, PathBuf},
};

use aegis_crypto::{CryptoSuite, DemoSuite};
use aegis_proto::{Envelope, IdentityId, MessageBody, PrivateHeaders, PrivatePayload};
use clap::{Args, Subcommand};

use crate::state;

#[derive(Debug, Subcommand)]
pub enum MessageCommand {
    Seal(SealArgs),
    Open(OpenArgs),
    List(ListArgs),
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
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct OpenArgs {
    #[arg(long)]
    pub input: PathBuf,
    #[arg(long)]
    pub passphrase: String,
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    #[arg(long)]
    pub recipient: String,
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

            let out = args.out.unwrap_or_else(|| {
                state::sealed_envelope_path(&envelope.recipient_id.0, &envelope.envelope_id.0.to_string())
            });
            state::ensure_parent_dir(&out)?;
            fs::write(&out, envelope.to_json_pretty()?)?;
            println!("sealed {}", out.display());
            println!("id {}", envelope.envelope_id.0);
            println!("to {}", envelope.recipient_id.0);
        }
        MessageCommand::Open(args) => {
            let suite = DemoSuite::from_passphrase(&args.passphrase);
            let raw = fs::read_to_string(&args.input)?;
            let envelope = Envelope::from_json(&raw)?;
            let payload = suite.decrypt_payload(&envelope.payload)?;
            let out = args.out.unwrap_or_else(|| {
                state::opened_payload_path(
                    &envelope.recipient_id.0,
                    &envelope.envelope_id.0.to_string(),
                )
            });
            state::ensure_parent_dir(&out)?;
            fs::write(&out, serde_json::to_string_pretty(&payload)?)?;

            println!("opened {}", args.input.display());
            println!("payload {}", out.display());
            println!("id {}", envelope.envelope_id.0);
            println!("to {}", envelope.recipient_id.0);
            println!(
                "from {}",
                envelope.sender_hint.as_ref().map(|i| i.0.as_str()).unwrap_or("<anonymous>")
            );
            println!(
                "subject {}",
                payload.private_headers.subject.as_deref().unwrap_or("<none>")
            );
            println!("{}", payload.body.content);
        }
        MessageCommand::List(args) => {
            let dir = state::fetched_envelope_dir(&args.recipient);
            let entries = read_fetched_envelopes(&dir)?;

            println!("recipient {}", args.recipient);
            println!("count {}", entries.len());
            for envelope in entries {
                println!(
                    "{} {} {}",
                    envelope.created_at.to_rfc3339(),
                    envelope.envelope_id.0,
                    envelope_path(&dir, &envelope.envelope_id.0.to_string()).display()
                );
            }
        }
    }

    Ok(())
}

fn read_fetched_envelopes(dir: &Path) -> Result<Vec<Envelope>, Box<dyn std::error::Error>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if path.extension().and_then(|v| v.to_str()) != Some("json") {
            continue;
        }
        let raw = fs::read_to_string(path)?;
        out.push(Envelope::from_json(&raw)?);
    }

    out.sort_by(|a, b| b.created_at.cmp(&a.created_at));
    Ok(out)
}

fn envelope_path(dir: &Path, envelope_id: &str) -> PathBuf {
    dir.join(format!("{envelope_id}.json"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_proto::{EncryptedBlob, SuiteId};

    fn sample_envelope(recipient: &str, id_suffix: &str) -> Envelope {
        let mut envelope = Envelope::new(
            IdentityId(recipient.to_string()),
            None,
            SuiteId::DemoXChaCha20Poly1305,
            EncryptedBlob {
                nonce_b64: "bm9uY2U=".to_string(),
                ciphertext_b64: "Y2lwaGVydGV4dA==".to_string(),
            },
        );
        envelope.content_type = format!("message/private-{id_suffix}");
        envelope
    }

    #[test]
    fn read_fetched_envelopes_reads_json_only() {
        let dir = std::env::temp_dir().join(format!("aegit-msg-list-{}", std::process::id()));
        if dir.exists() {
            fs::remove_dir_all(&dir).expect("remove old temp dir");
        }
        fs::create_dir_all(&dir).expect("create dir");

        let envelope = sample_envelope("amp:did:key:z6MkRecipient", "a");
        fs::write(
            dir.join(format!("{}.json", envelope.envelope_id.0)),
            envelope.to_json_pretty().expect("encode envelope"),
        )
        .expect("write envelope");
        fs::write(dir.join("ignore.txt"), "noop").expect("write ignored file");

        let envelopes = read_fetched_envelopes(&dir).expect("read envelopes");
        assert_eq!(envelopes.len(), 1);
        assert_eq!(envelopes[0].recipient_id.0, "amp:did:key:z6MkRecipient");

        fs::remove_dir_all(&dir).expect("cleanup");
    }
}
