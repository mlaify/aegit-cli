use aegis_proto::{IdentityDocument, IdentityId, PublicKeyRecord};
use clap::{Args, Subcommand};

#[derive(Debug, Args)]
pub struct IdCommand {
    #[command(subcommand)]
    pub action: IdAction,
}

#[derive(Debug, Subcommand)]
pub enum IdAction {
    Init { #[arg(long)] alias: Option<String> },
    Show { #[arg(long)] id: String },
}

pub fn run(command: IdCommand) -> Result<(), Box<dyn std::error::Error>> {
    match command.action {
        IdAction::Init { alias } => {
            let alias_text = alias.unwrap_or_else(|| "operator@mesh".to_string());
            let doc = IdentityDocument {
                version: 1,
                identity_id: IdentityId("amp:did:key:zExampleLocal".to_string()),
                aliases: vec![alias_text],
                signing_keys: vec![PublicKeyRecord {
                    key_id: "sig-demo-01".to_string(),
                    algorithm: "ed25519".to_string(),
                    public_key_b64: "BASE64_PLACEHOLDER".to_string(),
                }],
                encryption_keys: vec![PublicKeyRecord {
                    key_id: "enc-demo-01".to_string(),
                    algorithm: "x25519".to_string(),
                    public_key_b64: "BASE64_PLACEHOLDER".to_string(),
                }],
                supported_suites: vec!["AMP-DEMO-XCHACHA20POLY1305".to_string()],
                relay_endpoints: vec!["http://localhost:8080".to_string()],
                signature: None,
            };

            println!("{}", serde_json::to_string_pretty(&doc)?);
        }
        IdAction::Show { id } => {
            println!("identity: {id}");
        }
    }

    Ok(())
}
