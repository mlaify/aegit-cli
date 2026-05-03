use std::{
    cmp::Reverse,
    fs,
    path::{Path, PathBuf},
};

use aegis_crypto::{DemoSuite, EnvelopeSigner, EnvelopeVerifier, HybridPqSuite, PayloadCipher};
use aegis_identity::{
    decode_local_dev_signing_key, parse_identity_id, ALG_ED25519, ALG_MLDSA65, ALG_MLKEM768,
    ALG_X25519, SUITE_HYBRID_PQ,
};
use aegis_proto::{Envelope, IdentityId, MessageBody, PrivateHeaders, PrivatePayload, SuiteId};
use base64::{engine::general_purpose::STANDARD, Engine as _};
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
    /// Passphrase for demo (v0.1) suite. Required when recipient does not support hybrid PQ.
    #[arg(long)]
    pub passphrase: Option<String>,
    #[arg(long)]
    pub out: Option<PathBuf>,
}

#[derive(Debug, Args)]
pub struct OpenArgs {
    #[arg(long)]
    pub input: PathBuf,
    /// Passphrase for demo (v0.1) suite envelopes.
    #[arg(long)]
    pub passphrase: Option<String>,
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
        MessageCommand::Seal(args) => seal(args),
        MessageCommand::Open(args) => open(args),
        MessageCommand::List(args) => list(args),
    }
}

fn seal(args: SealArgs) -> Result<(), Box<dyn std::error::Error>> {
    let recipient_id = parse_identity_id(&args.to)
        .map_err(|_| format!("invalid recipient identity id: {}", args.to))?;

    let sender_hint = resolve_sender(args.from)?;

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

    let recipient_doc = identity::read_identity_document(&recipient_id.0).ok();
    let supports_pq = recipient_doc
        .as_ref()
        .map(|doc| doc.supported_suites.iter().any(|s| s == SUITE_HYBRID_PQ))
        .unwrap_or(false);

    if supports_pq {
        let doc = recipient_doc.as_ref().unwrap();

        let x25519_pk_b64 = doc
            .encryption_keys
            .iter()
            .find(|k| k.algorithm == ALG_X25519)
            .map(|k| k.public_key_b64.as_str())
            .ok_or("recipient identity missing X25519 encryption key")?;
        let kyber_pk_b64 = doc
            .encryption_keys
            .iter()
            .find(|k| k.algorithm == ALG_MLKEM768)
            .map(|k| k.public_key_b64.as_str())
            .ok_or("recipient identity missing ML-KEM-768 encryption key")?;

        let recipient_x25519_pk: [u8; 32] = STANDARD
            .decode(x25519_pk_b64)?
            .try_into()
            .map_err(|_| "invalid X25519 public key length")?;
        let recipient_kyber_pk = STANDARD.decode(kyber_pk_b64)?;

        let sender_id = sender_hint.as_ref().ok_or(
            "sender identity required for hybrid PQ seal; run `aegit id init` or pass --from",
        )?;
        let pq_material = identity::read_pq_key_material(&sender_id.0)?;

        let ed25519_seed: [u8; 32] = STANDARD
            .decode(&pq_material.ed25519_signing_seed_b64)?
            .try_into()
            .map_err(|_| "invalid Ed25519 seed length")?;
        let dilithium3_sk = STANDARD.decode(&pq_material.dilithium3_secret_key_b64)?;

        let suite = HybridPqSuite::for_sender_with_recipient_keys(
            ed25519_seed,
            dilithium3_sk,
            recipient_x25519_pk,
            recipient_kyber_pk,
        );

        let encrypted = suite.encrypt_payload(&payload)?;
        let mut envelope = Envelope::new(
            recipient_id.clone(),
            sender_hint.clone(),
            suite.suite_id(),
            encrypted,
        );
        let classical_sig = suite.sign_envelope(&envelope)?;
        let pq_sig = suite.sign_envelope_pq(&envelope)?;
        envelope.outer_signature_b64 = Some(classical_sig);
        envelope.outer_pq_signature_b64 = Some(pq_sig);
        write_envelope(envelope, args.out)?;
    } else {
        let passphrase = args
            .passphrase
            .ok_or("--passphrase required when recipient does not support hybrid PQ suite")?;
        let suite = DemoSuite::from_passphrase(&passphrase);
        let encrypted = suite.encrypt_payload(&payload)?;
        let mut envelope = Envelope::new(
            recipient_id,
            sender_hint.clone(),
            suite.suite_id(),
            encrypted,
        );
        if let Some(sender) = sender_hint.as_ref() {
            if let Ok(signing_material) = identity::read_signing_key_material(&sender.0) {
                let signing_key = decode_local_dev_signing_key(&signing_material)?;
                let signing_suite = DemoSuite::from_signing_key_bytes(&signing_key)?;
                let signature = signing_suite.sign_envelope(&envelope)?;
                envelope.outer_signature_b64 = Some(signature);
            }
        }
        write_envelope(envelope, args.out)?;
    }

    Ok(())
}

fn write_envelope(
    envelope: Envelope,
    out_path: Option<PathBuf>,
) -> Result<(), Box<dyn std::error::Error>> {
    let out = out_path.unwrap_or_else(|| {
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
    println!(
        "suite {}",
        match &envelope.suite_id {
            SuiteId::HybridX25519MlKem768Ed25519MlDsa65 => SUITE_HYBRID_PQ,
            SuiteId::DemoXChaCha20Poly1305 => "AMP-DEMO-XCHACHA20POLY1305",
            SuiteId::HybridPqPlaceholder => "AMP-HYBRID-PQ-PLACEHOLDER",
        }
    );
    Ok(())
}

fn open(args: OpenArgs) -> Result<(), Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(&args.input)?;
    let envelope = Envelope::from_json(&raw)?;

    let payload = match &envelope.suite_id {
        SuiteId::HybridX25519MlKem768Ed25519MlDsa65 => open_hybrid_pq(&envelope)?,
        _ => {
            let passphrase = args
                .passphrase
                .ok_or("--passphrase required for demo suite envelopes")?;
            let suite = DemoSuite::from_passphrase(&passphrase);
            let sig_status = demo_signature_status(&envelope);
            println!("signature_status {}", sig_status.label());
            if let Some(reason) = sig_status.reason() {
                println!("signature_detail {}", reason);
            }
            suite.decrypt_payload(&envelope.payload)?
        }
    };

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
    Ok(())
}

fn open_hybrid_pq(envelope: &Envelope) -> Result<PrivatePayload, Box<dyn std::error::Error>> {
    let recipient_id = &envelope.recipient_id.0;

    let pq_material = identity::read_pq_key_material(recipient_id).map_err(|_| {
        format!(
            "no PQ key material for {}; cannot open hybrid PQ envelope",
            recipient_id
        )
    })?;

    let x25519_sk: [u8; 32] = STANDARD
        .decode(&pq_material.x25519_private_key_b64)?
        .try_into()
        .map_err(|_| "invalid X25519 private key length")?;
    let kyber768_sk = STANDARD.decode(&pq_material.kyber768_secret_key_b64)?;

    let (sender_ed_vk, sender_dil_pk) = if let Some(sender) = envelope.sender_hint.as_ref() {
        match identity::read_identity_document(&sender.0) {
            Ok(doc) => {
                let ed_vk = doc
                    .signing_keys
                    .iter()
                    .find(|k| k.algorithm == ALG_ED25519)
                    .and_then(|k| STANDARD.decode(&k.public_key_b64).ok())
                    .and_then(|b| <[u8; 32]>::try_from(b).ok());
                let dil_pk = doc
                    .signing_keys
                    .iter()
                    .find(|k| k.algorithm == ALG_MLDSA65)
                    .and_then(|k| STANDARD.decode(&k.public_key_b64).ok());
                (ed_vk, dil_pk)
            }
            Err(_) => (None, None),
        }
    } else {
        (None, None)
    };

    let suite = HybridPqSuite::for_recipient(x25519_sk, kyber768_sk, sender_ed_vk, sender_dil_pk);

    if let Some(sig) = envelope.outer_signature_b64.as_deref() {
        match suite.verify_envelope(envelope, sig) {
            Ok(()) => println!("classical_signature verified"),
            Err(e) => println!("classical_signature FAILED: {}", e),
        }
    } else {
        println!("classical_signature absent");
    }

    if let Some(pq_sig) = envelope.outer_pq_signature_b64.as_deref() {
        match suite.verify_envelope_pq(envelope, pq_sig) {
            Ok(()) => println!("pq_signature verified"),
            Err(e) => println!("pq_signature FAILED: {}", e),
        }
    } else {
        println!("pq_signature absent");
    }

    Ok(suite.decrypt_payload(&envelope.payload)?)
}

fn list(args: ListArgs) -> Result<(), Box<dyn std::error::Error>> {
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
    Ok(())
}

fn resolve_sender(from: Option<String>) -> Result<Option<IdentityId>, Box<dyn std::error::Error>> {
    match from {
        Some(id_str) => {
            let id = parse_identity_id(&id_str)
                .map_err(|_| format!("invalid sender identity id: {}", id_str))?;
            Ok(Some(id))
        }
        None => match identity::read_default_identity_id()? {
            Some(id_str) => {
                let id = parse_identity_id(&id_str)
                    .map_err(|_| format!("invalid default identity id: {}", id_str))?;
                Ok(Some(id))
            }
            None => Ok(None),
        },
    }
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
            SignatureStatus::Failed(r) | SignatureStatus::Unavailable(r) => Some(r.as_str()),
            SignatureStatus::Unsigned | SignatureStatus::Verified => None,
        }
    }
}

fn demo_signature_status(envelope: &Envelope) -> SignatureStatus {
    let Some(signature) = envelope.outer_signature_b64.as_deref() else {
        return SignatureStatus::Unsigned;
    };

    let sender = match envelope.sender_hint.as_ref() {
        Some(s) => s,
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
        Some(k) => k,
        None => {
            return SignatureStatus::Unavailable(
                "sender identity has no signing key records".to_string(),
            )
        }
    };

    let verify_suite = match DemoSuite::from_signing_key_b64(&signing_key.public_key_b64) {
        Ok(s) => s,
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
    out.sort_by_key(|e| Reverse(e.created_at));
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
                eph_x25519_public_key_b64: None,
                mlkem_ciphertext_b64: None,
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
    fn demo_signature_status_reports_unsigned() {
        let envelope = sample_envelope("amp:did:key:z6MkRecipient", "unsigned");
        let status = demo_signature_status(&envelope);
        assert_eq!(status.label(), "unsigned");
    }

    #[test]
    fn demo_signature_status_reports_unavailable_without_sender_hint() {
        let mut envelope = sample_envelope("amp:did:key:z6MkRecipient", "signed");
        envelope.outer_signature_b64 = Some("c2ln".to_string());
        let status = demo_signature_status(&envelope);
        assert_eq!(status.label(), "verification_unavailable");
    }
}
