use std::{
    env,
    path::{Path, PathBuf},
};

pub fn state_root() -> PathBuf {
    if let Ok(path) = env::var("AEGIT_STATE_DIR") {
        return PathBuf::from(path);
    }

    if let Ok(home) = env::var("HOME") {
        return PathBuf::from(home).join(".aegis").join("aegit");
    }

    PathBuf::from(".aegit")
}

pub fn sanitize_segment(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_') {
            out.push(c);
        } else {
            out.push('_');
        }
    }

    while out.ends_with('_') {
        out.pop();
    }

    if out.is_empty() {
        "unknown".to_string()
    } else {
        out
    }
}

pub fn sealed_envelope_path(recipient: &str, envelope_id: &str) -> PathBuf {
    state_root()
        .join("sealed")
        .join(sanitize_segment(recipient))
        .join(format!("{envelope_id}.json"))
}

pub fn fetched_envelope_dir(recipient: &str) -> PathBuf {
    state_root()
        .join("fetched")
        .join(sanitize_segment(recipient))
}

pub fn opened_payload_path(recipient: &str, envelope_id: &str) -> PathBuf {
    state_root()
        .join("opened")
        .join(sanitize_segment(recipient))
        .join(format!("{envelope_id}.json"))
}

pub fn identities_dir() -> PathBuf {
    state_root().join("identities")
}

pub fn identity_doc_path(identity_id: &str) -> PathBuf {
    identities_dir().join(format!("{}.json", sanitize_segment(identity_id)))
}

pub fn default_identity_path() -> PathBuf {
    state_root().join("default_identity")
}

pub fn signing_key_material_path(identity_id: &str) -> PathBuf {
    identities_dir().join(format!(
        "{}.signing-key.json",
        sanitize_segment(identity_id)
    ))
}

pub fn pq_key_material_path(identity_id: &str) -> PathBuf {
    identities_dir().join(format!("{}.pq-key.json", sanitize_segment(identity_id)))
}

/// Path of the locally-persisted private halves for the identity's
/// currently-outstanding one-time prekey bundle. Each entry corresponds
/// to a `key_id` that was POSTed to the relay's prekey publish endpoint.
pub fn prekey_secrets_path(identity_id: &str) -> PathBuf {
    identities_dir().join(format!(
        "{}.prekey-secrets.json",
        sanitize_segment(identity_id)
    ))
}

pub fn ensure_parent_dir(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_segment_replaces_unsafe_chars() {
        let input = "amp:did/key:z6MkRecipient??";
        assert_eq!(sanitize_segment(input), "amp_did_key_z6MkRecipient");
    }

    #[test]
    fn sanitize_segment_falls_back_for_empty_result() {
        assert_eq!(sanitize_segment("::::"), "unknown");
    }

    #[test]
    fn identity_doc_path_is_in_identities_directory() {
        let path = identity_doc_path("amp:did:key:z6MkRecipient");
        let path_str = path.to_string_lossy();
        assert!(path_str.contains("/identities/"));
        assert!(path_str.ends_with(".json"));
    }

    #[test]
    fn default_identity_path_ends_with_default_identity() {
        let path = default_identity_path();
        assert!(path.to_string_lossy().ends_with("default_identity"));
    }

    #[test]
    fn signing_key_material_path_is_in_identities_directory() {
        let path = signing_key_material_path("amp:did:key:z6MkRecipient");
        let path_str = path.to_string_lossy();
        assert!(path_str.contains("/identities/"));
        assert!(path_str.ends_with(".signing-key.json"));
    }
}
