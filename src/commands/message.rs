use std::{
    cmp::Reverse,
    fs,
    path::{Path, PathBuf},
};

use aegis_crypto::{DemoSuite, EnvelopeSigner, EnvelopeVerifier, HybridPqSuite, PayloadCipher};
use aegis_identity::{
    decode_local_dev_signing_key, parse_identity_id, PrekeyBundlePrivateMaterial, ALG_ED25519,
    ALG_MLDSA65, ALG_MLKEM768, ALG_X25519, SUITE_HYBRID_PQ,
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
    /// Relay URL for resolving recipient identity when not found locally.
    /// Also used to claim a one-time prekey from the recipient's published
    /// pool (v0.3 phase 3); pass `--no-prekey` to skip and use the recipient's
    /// long-term Kyber768 from their IdentityDocument instead.
    #[arg(long, env = "AEGIS_RELAY_URL")]
    pub relay: Option<String>,
    /// Skip the prekey claim and seal against the recipient's long-term
    /// Kyber768 key. Useful for offline use, diagnostics, or when the
    /// recipient's prekey pool is exhausted and you want a deterministic
    /// fall-back.
    #[arg(long, default_value_t = false)]
    pub no_prekey: bool,
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

fn read_identity_document_opt(identity_id: &str) -> Option<aegis_proto::IdentityDocument> {
    identity::read_identity_document(identity_id).ok()
}

fn seal(args: SealArgs) -> Result<(), Box<dyn std::error::Error>> {
    let (recipient_id, resolved_recipient_doc) =
        resolve_recipient_target(&args.to, args.relay.as_deref())?;

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

    // Try local store first; fall back to relay if a URL is configured.
    let recipient_doc_opt =
        match resolved_recipient_doc.or_else(|| read_identity_document_opt(&recipient_id.0)) {
            Some(doc) => Some(doc),
            None => {
                let relay_url = args.relay.clone();
                match relay_url {
                    Some(url) => {
                        let rt = tokio::runtime::Builder::new_current_thread()
                            .enable_all()
                            .build()?;
                        Some(
                            rt.block_on(aegis_identity::resolver::resolve_identity(
                                &url,
                                &recipient_id.0,
                            ))
                            .map_err(|e| format!("could not resolve recipient identity: {}", e))?,
                        )
                    }
                    None => None,
                }
            }
        };

    let recipient_doc = recipient_doc_opt;
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
        let recipient_x25519_pk: [u8; 32] = STANDARD
            .decode(x25519_pk_b64)?
            .try_into()
            .map_err(|_| "invalid X25519 public key length")?;

        // (v0.3 phase 3) Try to claim a one-time prekey for the recipient
        // when a relay is configured and --no-prekey wasn't passed. On
        // success we use the prekey's Kyber public key for the KEM combine
        // and stamp `envelope.used_prekey_ids` with the claimed key_id so
        // the relay's atomic enforcement (phase 1) gates against replay.
        // On `PrekeyPoolExhausted` we fall back to the recipient's
        // long-term Kyber from the IdentityDocument and warn the user that
        // forward secrecy is degraded for this message.
        let (recipient_kyber_pk, claimed_prekey_key_id) = match (&args.relay, args.no_prekey) {
            (Some(relay_url), false) => {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()?;
                match rt.block_on(aegis_identity::resolver::claim_one_time_prekey(
                    relay_url,
                    &recipient_id.0,
                )) {
                    Ok(claimed) => {
                        if claimed.algorithm != ALG_MLKEM768 {
                            return Err(format!(
                                "claimed prekey has unexpected algorithm {} (expected {})",
                                claimed.algorithm, ALG_MLKEM768
                            )
                            .into());
                        }
                        let pk = STANDARD.decode(&claimed.public_key_b64)?;
                        println!("prekey_claimed {}", claimed.key_id);
                        (pk, Some(claimed.key_id))
                    }
                    Err(aegis_identity::resolver::ResolverError::PrekeyPoolExhausted(_)) => {
                        eprintln!(
                            "warning: prekey pool empty for {}; falling back to long-term \
                             Kyber768 (forward secrecy degraded for this message)",
                            recipient_id.0
                        );
                        let kyber_pk_b64 = doc
                            .encryption_keys
                            .iter()
                            .find(|k| k.algorithm == ALG_MLKEM768)
                            .map(|k| k.public_key_b64.as_str())
                            .ok_or("recipient identity missing ML-KEM-768 encryption key")?;
                        (STANDARD.decode(kyber_pk_b64)?, None)
                    }
                    Err(e) => {
                        return Err(format!("could not claim prekey from relay: {}", e).into());
                    }
                }
            }
            _ => {
                let kyber_pk_b64 = doc
                    .encryption_keys
                    .iter()
                    .find(|k| k.algorithm == ALG_MLKEM768)
                    .map(|k| k.public_key_b64.as_str())
                    .ok_or("recipient identity missing ML-KEM-768 encryption key")?;
                (STANDARD.decode(kyber_pk_b64)?, None)
            }
        };

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
        // Stamp the claimed prekey BEFORE signing so the signature covers it.
        if let Some(ref key_id) = claimed_prekey_key_id {
            envelope.used_prekey_ids = vec![key_id.clone()];
        }
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

fn resolve_recipient_target(
    to: &str,
    relay: Option<&str>,
) -> Result<(IdentityId, Option<aegis_proto::IdentityDocument>), Box<dyn std::error::Error>> {
    if let Ok(id) = parse_identity_id(to) {
        return Ok((id, None));
    }

    let relay_url = relay.ok_or_else(|| {
        format!(
            "recipient '{}' is not a valid identity id; pass --relay to resolve aliases",
            to
        )
    })?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let doc = rt
        .block_on(aegis_identity::resolver::resolve_alias(relay_url, to))
        .map_err(|e| format!("could not resolve recipient alias '{}': {}", to, e))?;
    Ok((doc.identity_id.clone(), Some(doc)))
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

    // (v0.3 phase 3) If the sender claimed a one-time prekey, decapsulate
    // with that prekey's Kyber secret instead of our long-term Kyber.
    // Phase 3 supports exactly one prekey per envelope; later phases may
    // generalize to multi-key contexts. After successful decrypt we splice
    // the consumed secret out of the local pool so it cannot be reused.
    let prekey_key_id = envelope.used_prekey_ids.first().cloned();
    let kyber768_sk = match prekey_key_id.as_deref() {
        Some(key_id) => load_one_time_prekey_secret(recipient_id, key_id)?,
        None => STANDARD.decode(&pq_material.kyber768_secret_key_b64)?,
    };

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

    let payload = suite.decrypt_payload(&envelope.payload)?;

    // Forward secrecy: only after a successful AEAD-verified decrypt do we
    // discard the consumed prekey secret. If the persistence step itself
    // fails we still return the plaintext (the user has it in memory and
    // the relay's atomic enforcement prevents replay) but we surface the
    // warning so the operator can investigate.
    if let Some(key_id) = prekey_key_id {
        if let Err(err) = consume_one_time_prekey_secret(recipient_id, &key_id) {
            eprintln!(
                "warning: failed to remove consumed prekey secret {} for {}: {}",
                key_id, recipient_id, err
            );
        } else {
            println!("prekey_consumed {}", key_id);
        }
    }

    Ok(payload)
}

/// Load the Kyber768 secret bytes for a one-time prekey `key_id` from the
/// recipient's locally-stored prekey-secrets file. Returns a clear error
/// when the file is missing or the `key_id` was already consumed (or never
/// generated).
fn load_one_time_prekey_secret(
    identity_id: &str,
    key_id: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let secrets = read_prekey_secrets(identity_id).ok_or_else(|| {
        format!(
            "envelope references prekey {} but no prekey-secrets file exists for {}",
            key_id, identity_id
        )
    })?;
    let entry = secrets
        .one_time_prekey_secrets
        .iter()
        .find(|s| s.key_id == key_id)
        .ok_or_else(|| {
            format!(
                "no local prekey secret matches key_id {} for {} \
                 (already consumed, or sender used a stale claim)",
                key_id, identity_id
            )
        })?;
    Ok(STANDARD.decode(&entry.kyber768_secret_key_b64)?)
}

/// Splice the consumed prekey secret out of the local pool and rewrite the
/// file atomically (tmpfile + rename). If no entry matches the call is a
/// no-op (already consumed); in that case we still return Ok.
fn consume_one_time_prekey_secret(
    identity_id: &str,
    key_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut secrets = match read_prekey_secrets(identity_id) {
        Some(s) => s,
        None => return Ok(()),
    };
    let before = secrets.one_time_prekey_secrets.len();
    secrets
        .one_time_prekey_secrets
        .retain(|s| s.key_id != key_id);
    if secrets.one_time_prekey_secrets.len() == before {
        return Ok(());
    }
    write_prekey_secrets_atomic(identity_id, &secrets)
}

fn read_prekey_secrets(identity_id: &str) -> Option<PrekeyBundlePrivateMaterial> {
    let path = state::prekey_secrets_path(identity_id);
    if !path.exists() {
        return None;
    }
    let raw = fs::read_to_string(&path).ok()?;
    serde_json::from_str(&raw).ok()
}

fn write_prekey_secrets_atomic(
    identity_id: &str,
    secrets: &PrekeyBundlePrivateMaterial,
) -> Result<(), Box<dyn std::error::Error>> {
    let path = state::prekey_secrets_path(identity_id);
    state::ensure_parent_dir(&path)?;
    let tmp_path = path.with_extension("json.tmp");
    let body = serde_json::to_string_pretty(secrets)?;
    fs::write(&tmp_path, body)?;
    fs::rename(&tmp_path, &path)?;
    Ok(())
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

    // ----- Phase 3: prekey-secrets persistence helpers -----

    use aegis_identity::OneTimePrekeySecret;

    fn isolated_state_dir(tag: &str) -> PathBuf {
        let path = std::env::temp_dir().join(format!(
            "aegit-prekey-test-{}-{}-{}",
            tag,
            std::process::id(),
            uuid_simple()
        ));
        std::env::set_var("AEGIT_STATE_DIR", &path);
        path
    }

    fn uuid_simple() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        format!("{:016x}{:016x}", now, n)
    }

    fn seed_secrets(identity_id: &str, key_ids: &[&str]) {
        let secrets = PrekeyBundlePrivateMaterial {
            identity_id: identity_id.to_string(),
            one_time_prekey_secrets: key_ids
                .iter()
                .map(|k| OneTimePrekeySecret {
                    key_id: k.to_string(),
                    algorithm: ALG_MLKEM768.to_string(),
                    // Real Kyber768 secret bytes are ~2400 bytes; for these
                    // helpers we only need a valid-base64 placeholder since
                    // we never actually decapsulate.
                    kyber768_secret_key_b64: STANDARD.encode(vec![0u8; 4]),
                })
                .collect(),
        };
        write_prekey_secrets_atomic(identity_id, &secrets).expect("seed write");
    }

    #[test]
    fn load_one_time_prekey_secret_returns_bytes_when_key_id_matches() {
        let _dir = isolated_state_dir("load-match");
        let id = "amp:did:key:z6MkLoadMatch";
        seed_secrets(id, &["ot-1", "ot-2"]);

        let bytes = load_one_time_prekey_secret(id, "ot-2").expect("load");
        assert_eq!(bytes, vec![0u8; 4]);
    }

    #[test]
    fn load_one_time_prekey_secret_errors_when_key_id_missing() {
        let _dir = isolated_state_dir("load-miss");
        let id = "amp:did:key:z6MkLoadMiss";
        seed_secrets(id, &["ot-1"]);

        let err = load_one_time_prekey_secret(id, "ot-not-here").expect_err("must error");
        let msg = err.to_string();
        assert!(
            msg.contains("ot-not-here") && msg.contains("already consumed"),
            "error must explain mismatch: {}",
            msg
        );
    }

    #[test]
    fn load_one_time_prekey_secret_errors_when_secrets_file_absent() {
        let _dir = isolated_state_dir("load-no-file");
        let id = "amp:did:key:z6MkLoadNoFile";

        let err = load_one_time_prekey_secret(id, "ot-1").expect_err("must error");
        assert!(
            err.to_string().contains("no prekey-secrets file"),
            "error must explain missing file: {}",
            err
        );
    }

    #[test]
    fn consume_one_time_prekey_secret_removes_only_matching_entry() {
        let _dir = isolated_state_dir("consume");
        let id = "amp:did:key:z6MkConsume";
        seed_secrets(id, &["ot-a", "ot-b", "ot-c"]);

        consume_one_time_prekey_secret(id, "ot-b").expect("consume");

        let after = read_prekey_secrets(id).expect("read after consume");
        let remaining: Vec<&str> = after
            .one_time_prekey_secrets
            .iter()
            .map(|s| s.key_id.as_str())
            .collect();
        assert_eq!(remaining, vec!["ot-a", "ot-c"]);
    }

    #[test]
    fn consume_one_time_prekey_secret_is_idempotent_on_missing_key() {
        let _dir = isolated_state_dir("consume-idempotent");
        let id = "amp:did:key:z6MkConsumeIdem";
        seed_secrets(id, &["ot-a"]);

        // First consume removes ot-a; second consume of the same key is a no-op.
        consume_one_time_prekey_secret(id, "ot-a").expect("first consume");
        consume_one_time_prekey_secret(id, "ot-a").expect("second consume should be ok");

        let after = read_prekey_secrets(id).expect("read after consume");
        assert!(after.one_time_prekey_secrets.is_empty());
    }

    #[test]
    fn consume_one_time_prekey_secret_no_op_when_file_absent() {
        let _dir = isolated_state_dir("consume-no-file");
        let id = "amp:did:key:z6MkConsumeNoFile";
        consume_one_time_prekey_secret(id, "ot-anything")
            .expect("consume should be ok when file absent");
    }
}
