use std::fs;

use aegis_identity::parse_identity_id;
use aegis_proto::{IdentityDocument, IdentityId};
use clap::{Args, Subcommand};
use uuid::Uuid;

use crate::state;

#[derive(Debug, Subcommand)]
pub enum IdentityCommand {
    Init(InitArgs),
    Show(ShowArgs),
    List,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    #[arg(long)]
    pub alias: Option<String>,
}

#[derive(Debug, Args)]
pub struct ShowArgs {
    #[arg(long)]
    pub identity: Option<String>,
}

pub fn run(cmd: IdentityCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        IdentityCommand::Init(args) => {
            let id = IdentityId(format!("amp:did:key:local-{}", Uuid::new_v4().simple()));
            let alias_list = args.alias.into_iter().collect::<Vec<_>>();
            let identity_doc = IdentityDocument {
                version: 1,
                identity_id: id.clone(),
                aliases: alias_list,
                signing_keys: vec![],
                encryption_keys: vec![],
                supported_suites: vec!["AMP-DEMO-XCHACHA20POLY1305".to_string()],
                relay_endpoints: vec![],
                signature: None,
            };

            let identity_path = state::identity_doc_path(&id.0);
            state::ensure_parent_dir(&identity_path)?;
            fs::write(&identity_path, serde_json::to_string_pretty(&identity_doc)?)?;

            let default_path = state::default_identity_path();
            state::ensure_parent_dir(&default_path)?;
            fs::write(&default_path, format!("{}\n", id.0))?;

            println!("initialized local identity");
            println!("identity {}", id.0);
            println!("stored {}", identity_path.display());
            println!("default {}", default_path.display());
            if !identity_doc.aliases.is_empty() {
                println!("aliases {}", identity_doc.aliases.join(","));
            }
        }
        IdentityCommand::Show(args) => {
            let requested = match args.identity {
                Some(id) => id,
                None => read_default_identity_id()?.ok_or_else(|| {
                    "no default identity configured; run `aegit id init`".to_string()
                })?,
            };

            let parsed = parse_identity_id(&requested)
                .map_err(|_| format!("invalid identity id: {}", requested))?;
            let doc = read_identity_document(&parsed.0)?;

            println!("identity {}", doc.identity_id.0);
            println!("aliases {}", join_or_none(&doc.aliases));
            println!("supported_suites {}", join_or_none(&doc.supported_suites));
            println!("relay_endpoints {}", join_or_none(&doc.relay_endpoints));
            println!("signing_keys {}", doc.signing_keys.len());
            println!("encryption_keys {}", doc.encryption_keys.len());
            println!("signature {}", doc.signature.as_deref().unwrap_or("<none>"));
        }
        IdentityCommand::List => {
            let docs = list_identity_documents()?;
            let default_identity = read_default_identity_id()?;
            println!("count {}", docs.len());
            for doc in docs {
                let marker = if default_identity.as_deref() == Some(doc.identity_id.0.as_str()) {
                    "*"
                } else {
                    " "
                };
                println!(
                    "{} {} {}",
                    marker,
                    doc.identity_id.0,
                    join_or_none(&doc.aliases)
                );
            }
            if default_identity.is_none() {
                println!("default <none>");
            }
        }
    }
    Ok(())
}

pub fn read_default_identity_id() -> Result<Option<String>, Box<dyn std::error::Error>> {
    let path = state::default_identity_path();
    if !path.exists() {
        return Ok(None);
    }
    let raw = fs::read_to_string(path)?;
    let value = raw.trim();
    if value.is_empty() {
        Ok(None)
    } else {
        Ok(Some(value.to_string()))
    }
}

pub fn read_identity_document(
    identity_id: &str,
) -> Result<IdentityDocument, Box<dyn std::error::Error>> {
    let path = state::identity_doc_path(identity_id);
    let raw = fs::read_to_string(&path)
        .map_err(|e| format!("failed to read identity document {}: {}", path.display(), e))?;
    let doc: IdentityDocument = serde_json::from_str(&raw)
        .map_err(|e| format!("invalid identity document {}: {}", path.display(), e))?;
    Ok(doc)
}

fn list_identity_documents() -> Result<Vec<IdentityDocument>, Box<dyn std::error::Error>> {
    let dir = state::identities_dir();
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut docs = Vec::new();
    for entry in fs::read_dir(&dir)? {
        let path = entry?.path();
        if path.extension().and_then(|v| v.to_str()) != Some("json") {
            continue;
        }
        let raw = fs::read_to_string(path)?;
        let doc: IdentityDocument = serde_json::from_str(&raw)?;
        docs.push(doc);
    }
    docs.sort_by(|a, b| a.identity_id.0.cmp(&b.identity_id.0));
    Ok(docs)
}

fn join_or_none(items: &[String]) -> String {
    if items.is_empty() {
        "<none>".to_string()
    } else {
        items.join(",")
    }
}
