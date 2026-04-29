use std::{
    fs,
    path::{Path, PathBuf},
};

use aegis_crypto::{DemoSuite, EnvelopeSigner, EnvelopeVerifier, PayloadCipher};
use aegis_identity::decode_local_dev_signing_key;
use aegis_identity::parse_identity_id;
use aegis_proto::{Envelope, MessageBody, PrivateHeaders, PrivatePayload};
use clap::{Args, Subcommand};

use crate::{commands::identity, state};

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
            let recipient_id = parse_identity_id(&args.to)
                .map_err(|_| format!("invalid recipient identity id: {}", args.to))?;
            let sender_hint = match args.from {
                Some(from) => Some(
                    parse_identity_id(&from)
                        .map_err(|_| format!("invalid sender identity id: {}", from))?,
                ),
                None => match identity::read_default_identity_id()? {
                    Some(id) => Some(
                        parse_identity_id(&id)
                            .map_err(|_| format!("invalid default identity id: {}", id))?,
                    ),
                    None => {
                        return Err(
                            "no sender identity provided and no default identity configured; run `aegit id init` or pass `--from`"
                                .into(),
                        )
                    }
                },
            };

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
            let mut envelope =
                Envelope::new(recipient_id, sender_hint, suite.suite_id(), encrypted);
            if envelope.sender_hint.is_some() {
                let sender_identity = envelope.sender_hint.as_ref().expect("checked above");
                let signing_material = identity::read_signing_key_material(&sender_identity.0)?;
                let signing_key = decode_local_dev_signing_key(&signing_material)?;
                let signing_suite = DemoSuite::from_signing_key_bytes(&signing_key)?;
                let signature = signing_suite.sign_envelope(&envelope)?;
                envelope.outer_signature_b64 = Some(signature);
            }

            let out = args.out.unwrap_or_else(|| {
                state::sealed_envelope_path(
                    &envelope.recipient_id.0,
                    &envelope.envelope_id.0.to_string(),
                )
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
            let signature_status = signature_status(&envelope);
            println!("signature_status {}", signature_status.label());
            if let Some(reason) = signature_status.reason() {
                println!("signature_detail {}", reason);
            }
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
                envelope
                    .sender_hint
                    .as_ref()
                    .map(|i| i.0.as_str())
                    .unwrap_or("<anonymous>")
            );
            println!(
                "subject {}",
                payload
                    .private_headers
                    .subject
                    .as_deref()
                    .unwrap_or("<none>")
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

enum SignatureStatus {
    Unsigned,
    Verified,
    Failed(String),
    Unavailable(String),
}

impl SignatureStatus {
    fn label(&self) -> &'static str {
        match self {
            SignatureStatus::Unsigned => "unsigned",
            SignatureStatus::Verified => "present_verified",
            SignatureStatus::Failed(_) => "present_failed",
            SignatureStatus::Unavailable(_) => "verification_unavailable",
        }
    }

    fn reason(&self) -> Option<&str> {
        match self {
            SignatureStatus::Failed(reason) | SignatureStatus::Unavailable(reason) => {
                Some(reason.as_str())
            }
            SignatureStatus::Unsigned | SignatureStatus::Verified => None,
        }
    }
}

fn signature_status(envelope: &Envelope) -> SignatureStatus {
    let Some(signature) = envelope.outer_signature_b64.as_deref() else {
        return SignatureStatus::Unsigned;
    };

    let sender = match envelope.sender_hint.as_ref() {
        Some(sender) => sender,
        None => {
            return SignatureStatus::Unavailable(
                "signature present but sender_hint missing".to_string(),
            )
        }
    };

    let sender_doc = match identity::read_identity_document(&sender.0) {
        Ok(doc) => doc,
        Err(err) => {
            return SignatureStatus::Unavailable(format!(
                "sender identity document unavailable: {}",
                err
            ))
        }
    };

    let signing_key = match sender_doc.signing_keys.first() {
        Some(signing_key) => signing_key,
        None => {
            return SignatureStatus::Unavailable(
                "sender identity has no signing key records".to_string(),
            )
        }
    };

    let verify_suite = match DemoSuite::from_signing_key_b64(&signing_key.public_key_b64) {
        Ok(suite) => suite,
        Err(err) => {
            return SignatureStatus::Unavailable(format!("invalid signing key metadata: {}", err))
        }
    };

    match verify_suite.verify_envelope(envelope, signature) {
        Ok(()) => SignatureStatus::Verified,
        Err(err) => SignatureStatus::Failed(err.to_string()),
    }
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
    use aegis_proto::{EncryptedBlob, IdentityId, SuiteId};

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

    #[test]
    fn signature_status_reports_unsigned() {
        let envelope = sample_envelope("amp:did:key:z6MkRecipient", "unsigned");
        let status = signature_status(&envelope);
        assert_eq!(status.label(), "unsigned");
    }

    #[test]
    fn signature_status_reports_unavailable_without_sender_hint() {
        let mut envelope = sample_envelope("amp:did:key:z6MkRecipient", "signed");
        envelope.outer_signature_b64 = Some("c2ln".to_string());
        let status = signature_status(&envelope);
        assert_eq!(status.label(), "verification_unavailable");
    }
}
