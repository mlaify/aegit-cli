use std::{
    fs,
    path::{Path, PathBuf},
};

use aegis_api_types::{FetchEnvelopeResponse, StoreEnvelopeRequest, StoreEnvelopeResponse};
use aegis_proto::Envelope;
use clap::{Args, Subcommand};

use crate::state;

#[derive(Debug, Subcommand)]
pub enum RelayCommand {
    Push(PushArgs),
    Fetch(FetchArgs),
}

#[derive(Debug, Args)]
pub struct PushArgs {
    #[arg(long)]
    pub relay: String,
    #[arg(long)]
    pub input: String,
}

#[derive(Debug, Args)]
pub struct FetchArgs {
    #[arg(long)]
    pub relay: String,
    #[arg(long)]
    pub recipient: String,
    #[arg(long)]
    pub out: Option<PathBuf>,
}

pub fn run(cmd: RelayCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        RelayCommand::Push(args) => {
            let raw = fs::read_to_string(&args.input)?;
            let envelope = Envelope::from_json(&raw)?;
            let envelope_id = envelope.envelope_id.0.to_string();
            let recipient_id = envelope.recipient_id.0.clone();
            let client = reqwest::blocking::Client::new();
            let url = format!("{}/v1/envelopes", args.relay.trim_end_matches('/'));
            let resp: StoreEnvelopeResponse = client
                .post(url)
                .json(&StoreEnvelopeRequest { envelope })
                .send()?
                .error_for_status()?
                .json()?;
            println!("pushed {}", args.input);
            println!("id {}", envelope_id);
            println!("to {}", recipient_id);
            println!("relay {}", resp.relay_id);
            println!("accepted {}", resp.accepted);
        }
        RelayCommand::Fetch(args) => {
            let client = reqwest::blocking::Client::new();
            let url = format!(
                "{}/v1/envelopes/{}",
                args.relay.trim_end_matches('/'),
                args.recipient
            );
            let resp = client.get(url).send()?.error_for_status()?;
            let data: FetchEnvelopeResponse = resp.json()?;
            let out = args
                .out
                .unwrap_or_else(|| state::fetched_envelope_dir(&args.recipient));
            let written = write_envelopes(&out, &data.envelopes)?;
            println!("fetched {}", written.len());
            println!("recipient {}", args.recipient);
            println!("dir {}", out.display());
            for path in written {
                println!("{}", path.display());
            }
        }
    }
    Ok(())
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
            },
        )
    }

    #[test]
    fn write_envelopes_persists_one_file_per_envelope() {
        let out_dir = std::env::temp_dir().join(format!(
            "aegit-cli-fetch-test-{}",
            std::process::id()
        ));
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
}
