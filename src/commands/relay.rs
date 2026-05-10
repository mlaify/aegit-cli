use std::{
    fs,
    path::{Path, PathBuf},
};

use aegis_api_types::{
    EnvelopeLifecycleResponse, FetchEnvelopeResponse, RelayCleanupResponse, RelayErrorResponse,
    StoreEnvelopeRequest, StoreEnvelopeResponse,
};
use aegis_proto::Envelope;
use clap::{Args, Subcommand};
use reqwest::StatusCode;

use crate::{config, state};

#[derive(Debug, Subcommand)]
pub enum RelayCommand {
    Push(PushArgs),
    Fetch(FetchArgs),
    Ack(AckArgs),
    Delete(DeleteArgs),
    Cleanup(CleanupArgs),
}

#[derive(Debug, Args)]
pub struct PushArgs {
    /// Relay base URL (e.g. `https://relay.example.com`). Falls back to
    /// `AEGIS_RELAY_URL` env, then `relay = ...` in the config file.
    #[arg(long)]
    pub relay: Option<String>,
    #[arg(long)]
    pub input: String,
    /// Bearer token for authenticated relays. Falls back to
    /// `AEGIS_RELAY_TOKEN` env, then `token = ...` in the config file.
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(Debug, Args)]
pub struct FetchArgs {
    #[arg(long)]
    pub relay: Option<String>,
    #[arg(long)]
    pub recipient: String,
    #[arg(long)]
    pub out: Option<PathBuf>,
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(Debug, Args)]
pub struct AckArgs {
    #[arg(long)]
    pub relay: Option<String>,
    #[arg(long)]
    pub recipient: String,
    #[arg(long)]
    pub envelope_id: String,
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(Debug, Args)]
pub struct DeleteArgs {
    #[arg(long)]
    pub relay: Option<String>,
    #[arg(long)]
    pub recipient: String,
    #[arg(long)]
    pub envelope_id: String,
    #[arg(long)]
    pub token: Option<String>,
}

#[derive(Debug, Args)]
pub struct CleanupArgs {
    #[arg(long)]
    pub relay: Option<String>,
    #[arg(long)]
    pub token: Option<String>,
}

pub fn run(cmd: RelayCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        RelayCommand::Push(args) => {
            let relay_url = config::resolve_relay_required(args.relay.as_deref())?;
            let token = config::resolve_token(args.token.as_deref());
            let raw = fs::read_to_string(&args.input)?;
            let envelope = Envelope::from_json(&raw)?;
            let envelope_id = envelope.envelope_id.0.to_string();
            let recipient_id = envelope.recipient_id.0.clone();
            let client = reqwest::blocking::Client::new();
            let url = format!("{}/v1/envelopes", relay_url.trim_end_matches('/'));
            let req = client.post(url).json(&StoreEnvelopeRequest { envelope });
            let req = with_token(req, token.as_deref());
            let resp = check_response(req.send()?, "push")?;
            let parsed: StoreEnvelopeResponse = resp.json()?;
            println!("status pushed");
            println!("accepted {}", parsed.accepted);
            println!("id {}", envelope_id);
            println!("to {}", recipient_id);
            println!("input {}", args.input);
            println!("relay {}", parsed.relay_id);
        }
        RelayCommand::Fetch(args) => {
            let relay_url = config::resolve_relay_required(args.relay.as_deref())?;
            let token = config::resolve_token(args.token.as_deref());
            let client = reqwest::blocking::Client::new();
            let url = format!(
                "{}/v1/envelopes/{}",
                relay_url.trim_end_matches('/'),
                args.recipient
            );
            let req = with_token(client.get(url), token.as_deref());
            let resp = check_response(req.send()?, "fetch")?;
            let data: FetchEnvelopeResponse = resp.json()?;
            let out = args
                .out
                .unwrap_or_else(|| state::fetched_envelope_dir(&args.recipient));
            let written = write_envelopes(&out, &data.envelopes)?;
            println!("status fetched");
            println!("count {}", written.len());
            println!("recipient {}", args.recipient);
            println!("dir {}", out.display());
            for path in written {
                println!("{}", path.display());
            }
        }
        RelayCommand::Ack(args) => {
            let relay_url = config::resolve_relay_required(args.relay.as_deref())?;
            let token = config::resolve_token(args.token.as_deref());
            let client = reqwest::blocking::Client::new();
            let url = format!(
                "{}/v1/envelopes/{}/{}/ack",
                relay_url.trim_end_matches('/'),
                args.recipient,
                args.envelope_id
            );
            let req = with_token(client.post(url), token.as_deref());
            let resp = check_response(req.send()?, "ack")?;
            let parsed: EnvelopeLifecycleResponse = resp.json()?;
            println!("status {}", parsed.status);
            println!("recipient {}", parsed.recipient_id);
            println!("id {}", parsed.envelope_id);
        }
        RelayCommand::Delete(args) => {
            let relay_url = config::resolve_relay_required(args.relay.as_deref())?;
            let token = config::resolve_token(args.token.as_deref());
            let client = reqwest::blocking::Client::new();
            let url = format!(
                "{}/v1/envelopes/{}/{}",
                relay_url.trim_end_matches('/'),
                args.recipient,
                args.envelope_id
            );
            let req = with_token(client.delete(url), token.as_deref());
            let resp = check_response(req.send()?, "delete")?;
            let parsed: EnvelopeLifecycleResponse = resp.json()?;
            println!("status {}", parsed.status);
            println!("recipient {}", parsed.recipient_id);
            println!("id {}", parsed.envelope_id);
        }
        RelayCommand::Cleanup(args) => {
            let relay_url = config::resolve_relay_required(args.relay.as_deref())?;
            let token = config::resolve_token(args.token.as_deref());
            let client = reqwest::blocking::Client::new();
            let url = format!("{}/v1/cleanup", relay_url.trim_end_matches('/'));
            let req = with_token(client.post(url), token.as_deref());
            let resp = check_response(req.send()?, "cleanup")?;
            let parsed: RelayCleanupResponse = resp.json()?;
            println!("status cleaned");
            println!("expired_removed {}", parsed.expired_removed);
            println!("orphan_ack_removed {}", parsed.orphan_ack_removed);
            println!("old_removed {}", parsed.old_removed);
        }
    }
    Ok(())
}

/// Check an HTTP response for success. On 2xx, return the response for
/// normal parsing. On 4xx/5xx, emit:
///
/// 1. A line-prefixed structured `relay_error_code` / `relay_error_message`
///    when the body decodes as the relay's standard `RelayErrorResponse`
///    (so operators see the relay's own error code, not just the HTTP one).
/// 2. A `hint:` line on stderr suggesting the operator action that's
///    likely to fix the failure (auth missing, prekey already used, ...).
/// 3. A `Box<dyn Error>` carrying the HTTP status so the command exits
///    non-zero.
fn check_response(
    resp: reqwest::blocking::Response,
    op: &str,
) -> Result<reqwest::blocking::Response, Box<dyn std::error::Error>> {
    let status = resp.status();
    if status.is_success() {
        return Ok(resp);
    }
    let body = resp.text().unwrap_or_default();
    if let Ok(parsed) = serde_json::from_str::<RelayErrorResponse>(&body) {
        eprintln!("relay_error_code {}", parsed.error.code);
        eprintln!("relay_error_message {}", parsed.error.message);
    } else if !body.is_empty() {
        eprintln!("relay_error_body {}", body);
    }
    if let Some(hint) = relay_error_hint(status, op) {
        eprintln!("hint: {}", hint);
    }
    Err(format!("relay returned status {}", status).into())
}

/// Map an HTTP status (and the operation that triggered it) to an
/// operator-friendly hint. Pure function — used by `check_response` and
/// directly by tests.
fn relay_error_hint(status: StatusCode, op: &str) -> Option<String> {
    match (status, op) {
        (StatusCode::UNAUTHORIZED, _) => Some(
            "relay requires authentication. Pass --token, set AEGIS_RELAY_TOKEN, \
             or add `token = \"...\"` to ~/.aegis/aegit/config.toml"
                .to_string(),
        ),
        (StatusCode::FORBIDDEN, _) => Some(
            "token lacks the required scope for this operation \
             (push needs PushEnvelope; ack/delete/cleanup need LifecycleChange; \
             identity puts need IdentityWrite)"
                .to_string(),
        ),
        (StatusCode::NOT_FOUND, "ack") => Some(
            "envelope not found (it may already have been acknowledged or deleted, \
             or the recipient ID is wrong)"
                .to_string(),
        ),
        (StatusCode::NOT_FOUND, "delete") => Some(
            "envelope not found (it may already have been deleted, \
             or the recipient ID is wrong)"
                .to_string(),
        ),
        (StatusCode::NOT_FOUND, "fetch") => Some(
            "no envelopes for recipient (or recipient ID is unknown to this relay)".to_string(),
        ),
        (StatusCode::NOT_FOUND, _) => Some("relay endpoint or resource not found".to_string()),
        (StatusCode::CONFLICT, "push") => Some(
            "envelope rejected by relay (commonly: prekey already used or unknown). \
             Re-claim a fresh prekey with `aegit msg seal --relay ...` and retry."
                .to_string(),
        ),
        (StatusCode::PAYLOAD_TOO_LARGE, "push") => {
            Some("envelope exceeds the relay's configured size limit".to_string())
        }
        (s, _) if s.is_client_error() => Some(format!(
            "relay rejected the request ({}); check arguments and retry",
            s
        )),
        (s, _) if s.is_server_error() => Some(format!("relay-side error ({}); try again later", s)),
        _ => None,
    }
}

fn with_token(
    req: reqwest::blocking::RequestBuilder,
    token: Option<&str>,
) -> reqwest::blocking::RequestBuilder {
    match token {
        Some(token) if !token.is_empty() => req.header("authorization", format!("Bearer {token}")),
        _ => req,
    }
}

fn write_envelopes(
    out_dir: &Path,
    envelopes: &[Envelope],
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    fs::create_dir_all(out_dir)?;

    let mut written = Vec::with_capacity(envelopes.len());
    for envelope in envelopes {
        let path = out_dir.join(format!("{}.json", envelope.envelope_id.0));
        fs::write(&path, envelope.to_json_pretty()?)?;
        written.push(path);
    }

    Ok(written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegis_proto::{EncryptedBlob, IdentityId, SuiteId};

    fn sample_envelope() -> Envelope {
        Envelope::new(
            IdentityId("amp:did:key:z6MkRecipient".to_string()),
            Some(IdentityId("amp:did:key:z6MkSender".to_string())),
            SuiteId::DemoXChaCha20Poly1305,
            EncryptedBlob {
                nonce_b64: "bm9uY2U=".to_string(),
                ciphertext_b64: "Y2lwaGVydGV4dA==".to_string(),
                eph_x25519_public_key_b64: None,
                mlkem_ciphertext_b64: None,
            },
        )
    }

    #[test]
    fn write_envelopes_persists_one_file_per_envelope() {
        let out_dir =
            std::env::temp_dir().join(format!("aegit-cli-fetch-test-{}", std::process::id()));
        if out_dir.exists() {
            fs::remove_dir_all(&out_dir).expect("clear temp dir");
        }

        let envelope = sample_envelope();
        let written =
            write_envelopes(&out_dir, std::slice::from_ref(&envelope)).expect("write envelopes");

        assert_eq!(written.len(), 1);
        let raw = fs::read_to_string(&written[0]).expect("read written envelope");
        let decoded = Envelope::from_json(&raw).expect("decode written envelope");
        assert_eq!(decoded, envelope);

        fs::remove_dir_all(&out_dir).expect("remove temp dir");
    }

    #[test]
    fn with_token_sets_bearer_header_when_provided() {
        let client = reqwest::blocking::Client::new();
        let req = with_token(client.get("http://localhost"), Some("dev-token"))
            .build()
            .expect("build request");
        let auth = req
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        assert_eq!(auth, "Bearer dev-token");
    }

    // ---- Issue #6: lifecycle output polish + error hints ----

    #[test]
    fn relay_error_hint_401_mentions_token_sources() {
        let hint =
            relay_error_hint(StatusCode::UNAUTHORIZED, "push").expect("401 should have a hint");
        assert!(hint.contains("--token"));
        assert!(hint.contains("AEGIS_RELAY_TOKEN"));
        assert!(hint.contains("config.toml"));
    }

    #[test]
    fn relay_error_hint_403_mentions_scopes() {
        let hint = relay_error_hint(StatusCode::FORBIDDEN, "ack").expect("403 should have a hint");
        assert!(hint.contains("scope"));
        assert!(hint.contains("LifecycleChange"));
    }

    #[test]
    fn relay_error_hint_404_distinguishes_ack_vs_delete_vs_fetch() {
        let ack = relay_error_hint(StatusCode::NOT_FOUND, "ack").expect("ack hint");
        let delete = relay_error_hint(StatusCode::NOT_FOUND, "delete").expect("delete hint");
        let fetch = relay_error_hint(StatusCode::NOT_FOUND, "fetch").expect("fetch hint");
        let other = relay_error_hint(StatusCode::NOT_FOUND, "cleanup").expect("default hint");

        assert!(ack.contains("acknowledged"));
        assert!(delete.contains("deleted"));
        assert!(fetch.contains("recipient"));
        assert!(other.contains("not found"));
        // Verify ack/delete give different guidance — operator confusion
        // between the two is the most common reported friction.
        assert_ne!(ack, delete);
    }

    #[test]
    fn relay_error_hint_409_on_push_mentions_prekey() {
        let hint = relay_error_hint(StatusCode::CONFLICT, "push").expect("409 push hint");
        assert!(hint.contains("prekey"));
    }

    #[test]
    fn relay_error_hint_413_on_push_mentions_size() {
        let hint = relay_error_hint(StatusCode::PAYLOAD_TOO_LARGE, "push").expect("413 hint");
        assert!(hint.contains("size limit"));
    }

    #[test]
    fn relay_error_hint_generic_5xx_says_try_later() {
        let hint =
            relay_error_hint(StatusCode::INTERNAL_SERVER_ERROR, "push").expect("5xx generic hint");
        assert!(hint.contains("try again later"));
    }

    #[test]
    fn relay_error_hint_generic_4xx_falls_through() {
        // A 4xx with no specific case should still produce SOME hint
        // (to avoid the "no hint at all" outcome being a regression
        // signal), and it should mention the status.
        let hint = relay_error_hint(StatusCode::BAD_REQUEST, "push").expect("4xx generic hint");
        assert!(hint.contains("400"));
    }

    #[test]
    fn relay_error_hint_2xx_returns_none() {
        // 2xx never reaches the hint mapper in production; the helper
        // should still return None for safety.
        assert!(relay_error_hint(StatusCode::OK, "push").is_none());
        assert!(relay_error_hint(StatusCode::CREATED, "push").is_none());
    }
}
