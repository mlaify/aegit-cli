use std::fs;

use aegis_crypto::HybridPqKeyBundle;
use aegis_identity::{
    decode_local_dev_signing_key, generate_local_dev_signing_key_material, generate_prekey_bundle,
    parse_identity_id, sign_prekey_bundle, HybridPqPrivateKeyMaterial, LocalDevSigningKeyMaterial,
    PrekeyBundlePrivateMaterial, ALG_ED25519, ALG_MLDSA65, ALG_MLKEM768, ALG_X25519,
    SUITE_HYBRID_PQ,
};
use aegis_proto::{IdentityDocument, IdentityId, PublicKeyRecord};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use clap::{Args, Subcommand};
use uuid::Uuid;

use crate::state;

#[derive(Debug, Subcommand)]
pub enum IdentityCommand {
    Init(InitArgs),
    Show(ShowArgs),
    List,
    Publish(PublishArgs),
    PublishPrekeys(PublishPrekeysArgs),
}

#[derive(Debug, Args)]
pub struct PublishPrekeysArgs {
    /// Relay base URL to POST the bundle to.
    #[arg(long, env = "AEGIS_RELAY_URL")]
    pub relay: String,
    /// Identity to publish prekeys for; defaults to the current default identity.
    #[arg(long)]
    pub identity: Option<String>,
    /// Number of one-time prekeys to generate in this batch.
    #[arg(long, default_value_t = 10)]
    pub count: usize,
}

#[derive(Debug, Args)]
pub struct PublishArgs {
    #[arg(long, env = "AEGIS_RELAY_URL")]
    pub relay: String,
    #[arg(long)]
    pub identity: Option<String>,
}

#[derive(Debug, Args)]
pub struct InitArgs {
    #[arg(long)]
    pub alias: Option<String>,
    /// Generate legacy demo signing key material in addition to hybrid PQ keys.
    /// Only needed when interoperating with v0.1 local development tooling.
    #[arg(long, default_value_t = false)]
    pub include_demo_key: bool,
}

#[derive(Debug, Args)]
pub struct ShowArgs {
    #[arg(long)]
    pub identity: Option<String>,
}

pub fn run(cmd: IdentityCommand) -> Result<(), Box<dyn std::error::Error>> {
    match cmd {
        IdentityCommand::Publish(args) => publish(args)?,
        IdentityCommand::PublishPrekeys(args) => publish_prekeys(args)?,
        IdentityCommand::Init(args) => {
            let id = IdentityId(format!("amp:did:key:local-{}", Uuid::new_v4().simple()));
            let alias_list = args.alias.into_iter().collect::<Vec<_>>();

            // --- Generate hybrid PQ key bundle ---
            let bundle = HybridPqKeyBundle::generate();

            let pq_material = HybridPqPrivateKeyMaterial {
                identity_id: id.0.clone(),
                algorithm: HybridPqPrivateKeyMaterial::algorithm_marker().to_string(),
                x25519_private_key_b64: STANDARD.encode(bundle.x25519_private_key_bytes),
                kyber768_secret_key_b64: STANDARD.encode(&bundle.kyber768_secret_key_bytes),
                ed25519_signing_seed_b64: STANDARD.encode(bundle.ed25519_signing_seed_bytes),
                dilithium3_secret_key_b64: STANDARD.encode(&bundle.dilithium3_secret_key_bytes),
            };

            let identity_doc = IdentityDocument {
                version: 1,
                identity_id: id.clone(),
                aliases: alias_list,
                signing_keys: vec![
                    PublicKeyRecord {
                        key_id: "sig-ed25519-1".to_string(),
                        algorithm: ALG_ED25519.to_string(),
                        public_key_b64: bundle.ed25519_verifying_key_b64(),
                    },
                    PublicKeyRecord {
                        key_id: "sig-mldsa65-1".to_string(),
                        algorithm: ALG_MLDSA65.to_string(),
                        public_key_b64: bundle.dilithium3_public_key_b64(),
                    },
                ],
                encryption_keys: vec![
                    PublicKeyRecord {
                        key_id: "enc-x25519-1".to_string(),
                        algorithm: ALG_X25519.to_string(),
                        public_key_b64: bundle.x25519_public_key_b64(),
                    },
                    PublicKeyRecord {
                        key_id: "enc-mlkem768-1".to_string(),
                        algorithm: ALG_MLKEM768.to_string(),
                        public_key_b64: bundle.kyber768_public_key_b64(),
                    },
                ],
                supported_suites: vec![SUITE_HYBRID_PQ.to_string()],
                relay_endpoints: vec![],
                signature: None,
            };

            // Persist identity document
            let identity_path = state::identity_doc_path(&id.0);
            state::ensure_parent_dir(&identity_path)?;
            fs::write(&identity_path, serde_json::to_string_pretty(&identity_doc)?)?;

            // Persist hybrid PQ private key material
            let pq_key_path = state::pq_key_material_path(&id.0);
            state::ensure_parent_dir(&pq_key_path)?;
            fs::write(&pq_key_path, serde_json::to_string_pretty(&pq_material)?)?;

            // Set as default identity
            let default_path = state::default_identity_path();
            state::ensure_parent_dir(&default_path)?;
            fs::write(&default_path, format!("{}\n", id.0))?;

            // Optionally write legacy demo signing key for v0.1 compat
            if args.include_demo_key {
                let signing_key = generate_local_dev_signing_key_material("sig-local-dev-1");
                let signing_key_path = state::signing_key_material_path(&id.0);
                state::ensure_parent_dir(&signing_key_path)?;
                fs::write(
                    &signing_key_path,
                    serde_json::to_string_pretty(&signing_key)?,
                )?;
                println!("demo_signing_key {}", signing_key_path.display());
            }

            println!("initialized hybrid PQ identity");
            println!("identity {}", id.0);
            println!("suite {}", SUITE_HYBRID_PQ);
            println!("stored {}", identity_path.display());
            println!("pq_key {}", pq_key_path.display());
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
            println!(
                "pq_key_material {}",
                if read_pq_key_material(&doc.identity_id.0).is_ok() {
                    "present"
                } else {
                    "<none>"
                }
            );
            println!(
                "demo_signing_key {}",
                if read_signing_key_material(&doc.identity_id.0).is_ok() {
                    "present"
                } else {
                    "<none>"
                }
            );
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

fn publish(args: PublishArgs) -> Result<(), Box<dyn std::error::Error>> {
    use aegis_identity::sign_identity_document;
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let identity_id = match args.identity {
        Some(id) => id,
        None => {
            let path = state::default_identity_path();
            fs::read_to_string(path)?.trim().to_string()
        }
    };

    let doc_path = state::identity_doc_path(&identity_id);
    let raw = fs::read_to_string(&doc_path).map_err(|e| {
        format!(
            "failed to read identity document {}: {}",
            doc_path.display(),
            e
        )
    })?;
    let mut doc: aegis_proto::IdentityDocument = serde_json::from_str(&raw)
        .map_err(|e| format!("invalid identity document {}: {}", doc_path.display(), e))?;

    let pq_material = read_pq_key_material(&identity_id)?;

    let ed25519_seed: [u8; 32] = STANDARD
        .decode(&pq_material.ed25519_signing_seed_b64)?
        .try_into()
        .map_err(|_| "invalid ed25519 seed length")?;
    let dilithium3_sk = STANDARD.decode(&pq_material.dilithium3_secret_key_b64)?;

    sign_identity_document(&mut doc, &ed25519_seed, &dilithium3_sk)?;

    // Persist the signed document locally so future operations see the signature.
    fs::write(&doc_path, serde_json::to_string_pretty(&doc)?).map_err(|e| {
        format!(
            "failed to write signed identity document {}: {}",
            doc_path.display(),
            e
        )
    })?;

    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(aegis_identity::resolver::publish_identity(
        &args.relay,
        &doc,
    ))?;

    println!("published {}", doc.identity_id.0);
    println!("relay     {}", args.relay);
    println!("signed    {}", doc_path.display());
    Ok(())
}

fn publish_prekeys(args: PublishPrekeysArgs) -> Result<(), Box<dyn std::error::Error>> {
    if args.count == 0 {
        return Err("--count must be at least 1".into());
    }

    let identity_id = match args.identity {
        Some(id) => id,
        None => read_default_identity_id()?
            .ok_or_else(|| "no default identity configured; run `aegit id init`".to_string())?,
    };

    let parsed = parse_identity_id(&identity_id)
        .map_err(|_| format!("invalid identity id: {}", identity_id))?;

    // Generate fresh batch of one-time prekeys.
    let (mut bundle, private) = generate_prekey_bundle(&parsed, args.count, "ot");

    // Sign with the identity's existing hybrid signing keys.
    let pq_material = read_pq_key_material(&identity_id)?;
    let ed25519_seed: [u8; 32] = STANDARD
        .decode(&pq_material.ed25519_signing_seed_b64)?
        .try_into()
        .map_err(|_| "invalid ed25519 seed length")?;
    let dilithium3_sk = STANDARD.decode(&pq_material.dilithium3_secret_key_b64)?;
    sign_prekey_bundle(&mut bundle, &ed25519_seed, &dilithium3_sk)?;

    // Persist private halves locally BEFORE publishing — if the network fails,
    // we don't want to lose the secrets that match keys already on the relay.
    // Merge with any existing prekey-secrets file so re-running this command
    // appends to the local pool rather than overwriting it.
    let secrets_path = state::prekey_secrets_path(&identity_id);
    state::ensure_parent_dir(&secrets_path)?;
    let mut combined: PrekeyBundlePrivateMaterial = if secrets_path.exists() {
        let raw = fs::read_to_string(&secrets_path)?;
        serde_json::from_str(&raw)?
    } else {
        PrekeyBundlePrivateMaterial {
            identity_id: identity_id.clone(),
            one_time_prekey_secrets: vec![],
        }
    };
    combined
        .one_time_prekey_secrets
        .extend(private.one_time_prekey_secrets);
    fs::write(&secrets_path, serde_json::to_string_pretty(&combined)?)?;

    // POST to the relay.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    rt.block_on(aegis_identity::resolver::publish_prekey_bundle(
        &args.relay,
        &bundle,
    ))?;

    println!("published_prekeys {}", bundle.identity_id.0);
    println!("relay             {}", args.relay);
    println!("count             {}", bundle.one_time_prekeys.len());
    println!("secrets           {}", secrets_path.display());
    println!(
        "secrets_total     {}",
        combined.one_time_prekey_secrets.len()
    );
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

pub fn read_pq_key_material(
    identity_id: &str,
) -> Result<HybridPqPrivateKeyMaterial, Box<dyn std::error::Error>> {
    let path = state::pq_key_material_path(identity_id);
    let raw = fs::read_to_string(&path)
        .map_err(|e| format!("failed to read PQ key material {}: {}", path.display(), e))?;
    let material: HybridPqPrivateKeyMaterial = serde_json::from_str(&raw)
        .map_err(|e| format!("invalid PQ key material {}: {}", path.display(), e))?;
    Ok(material)
}

pub fn read_signing_key_material(
    identity_id: &str,
) -> Result<LocalDevSigningKeyMaterial, Box<dyn std::error::Error>> {
    let path = state::signing_key_material_path(identity_id);
    let raw = fs::read_to_string(&path).map_err(|e| {
        format!(
            "failed to read signing key material {}: {}",
            path.display(),
            e
        )
    })?;
    let material: LocalDevSigningKeyMaterial = serde_json::from_str(&raw)
        .map_err(|e| format!("invalid signing key material {}: {}", path.display(), e))?;
    decode_local_dev_signing_key(&material)
        .map_err(|e| format!("invalid signing key material {}: {}", path.display(), e))?;
    Ok(material)
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
        // Skip key material files — only read identity documents
        let filename = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default();
        if filename.contains(".signing-key") || filename.contains(".pq-key") {
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
