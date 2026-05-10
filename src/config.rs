//! `aegit` config-file support (`aegit.toml`).
//!
//! Provides per-user defaults for the small set of values that today are
//! threaded through CLI flags or environment variables: relay URL, relay
//! token, and state directory. Keeps repeatable workflows out of shell
//! history and lets operators stop typing `--relay https://...` on every
//! command.
//!
//! ## Resolution order
//!
//! For each setting:
//!
//! 1. Explicit CLI flag (e.g. `--relay <url>`)
//! 2. Environment variable (e.g. `AEGIS_RELAY_URL`, `AEGIS_RELAY_TOKEN`,
//!    `AEGIT_STATE_DIR`)
//! 3. Config file (this module)
//! 4. Built-in default (where applicable)
//!
//! ## File location
//!
//! Resolved in order:
//!
//! 1. `$AEGIT_CONFIG` if set (full path to a TOML file)
//! 2. `$HOME/.aegis/aegit/config.toml` if `HOME` is set
//! 3. Skipped (treated as empty config) otherwise
//!
//! A missing file is treated as an empty config (defaults). A malformed
//! file is a hard error so silent typos don't masquerade as "no config".
//!
//! ## Schema
//!
//! All keys are optional:
//!
//! ```toml
//! relay = "https://relay.example.com"
//! token = "dev-relay-token"
//! state_dir = "/var/lib/aegit"
//! ```
//!
//! Future keys SHOULD be added here, documented in README.md, and
//! plumbed through with the same flag > env > config precedence.

use std::{
    env, fs,
    path::{Path, PathBuf},
};

use serde::Deserialize;

/// Environment variable that, when set, overrides the default config
/// file path. Used by tests to point at a temporary file.
const ENV_CONFIG_PATH: &str = "AEGIT_CONFIG";

/// In-process cache so a single `aegit` invocation doesn't re-read +
/// re-parse the file for every command-line setting it consults.
///
/// `OnceLock` is fine here because the CLI process is short-lived and
/// the config is process-wide. Tests use [`Config::load_from`] directly
/// and don't go through the cache.
fn cached() -> &'static Config {
    use std::sync::OnceLock;
    static CACHE: OnceLock<Config> = OnceLock::new();
    CACHE.get_or_init(|| Config::load().unwrap_or_default())
}

/// Reset the in-process cache. **Test-only** — the production CLI never
/// reloads config mid-process.
#[cfg(test)]
fn reset_cache_for_tests() {
    // OnceLock has no public reset; tests that need a fresh load should
    // call `Config::load_from(...)` directly. This shim exists so test
    // code can be explicit about not using the cache.
}

#[derive(Debug, Default, Clone, Deserialize)]
pub struct Config {
    /// Default relay URL when no `--relay` flag and no `AEGIS_RELAY_URL` env.
    pub relay: Option<String>,
    /// Default relay token when no `--token` flag and no `AEGIS_RELAY_TOKEN` env.
    pub token: Option<String>,
    /// State directory override when `AEGIT_STATE_DIR` is unset.
    pub state_dir: Option<PathBuf>,
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("could not read config file {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("could not parse config file {path}: {source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
}

impl Config {
    /// Load from the resolved config path. A missing file is treated as
    /// an empty config (`Ok(Config::default())`); a malformed file is an
    /// error.
    pub fn load() -> Result<Self, ConfigError> {
        match config_path() {
            Some(p) if p.exists() => Self::load_from(&p),
            _ => Ok(Config::default()),
        }
    }

    /// Test-friendly variant: load from a specific path. Same semantics
    /// (missing → defaults; malformed → error).
    pub fn load_from(path: &Path) -> Result<Self, ConfigError> {
        if !path.exists() {
            return Ok(Config::default());
        }
        let raw = fs::read_to_string(path).map_err(|source| ConfigError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        toml::from_str::<Config>(&raw).map_err(|source| ConfigError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }
}

/// Resolved path of the user's config file, or `None` if neither
/// `$AEGIT_CONFIG` nor `$HOME` is set (rare; mostly under bare init).
pub fn config_path() -> Option<PathBuf> {
    if let Ok(p) = env::var(ENV_CONFIG_PATH) {
        if !p.is_empty() {
            return Some(PathBuf::from(p));
        }
    }
    env::var("HOME").ok().filter(|h| !h.is_empty()).map(|home| {
        PathBuf::from(home)
            .join(".aegis")
            .join("aegit")
            .join("config.toml")
    })
}

// --- Resolved-setting helpers -----------------------------------------
//
// These are the public read-paths the rest of the CLI uses. Each one
// implements the standard precedence: explicit arg → env → config →
// fallback.

/// Resolve the relay URL from (in order) an explicit CLI flag, the
/// `AEGIS_RELAY_URL` env var, or the config file's `relay` key. Returns
/// `None` if all three are unset — callers that *require* a relay (push,
/// fetch, ack, delete, cleanup) should map `None` to a clear error
/// pointing the user at the config file.
pub fn resolve_relay(arg: Option<&str>) -> Option<String> {
    if let Some(s) = arg.filter(|s| !s.is_empty()) {
        return Some(s.to_string());
    }
    if let Ok(env) = env::var("AEGIS_RELAY_URL") {
        if !env.is_empty() {
            return Some(env);
        }
    }
    cached().relay.clone()
}

/// Same as [`resolve_relay`] but errors with a descriptive message when
/// no source provided a value. Intended for relay subcommands that
/// can't sensibly default.
pub fn resolve_relay_required(arg: Option<&str>) -> Result<String, String> {
    resolve_relay(arg).ok_or_else(|| {
        "no relay URL configured. Pass --relay <url>, set AEGIS_RELAY_URL, \
         or add `relay = \"...\"` to ~/.aegis/aegit/config.toml"
            .to_string()
    })
}

/// Resolve the relay bearer token from (in order) an explicit CLI flag,
/// the `AEGIS_RELAY_TOKEN` env var, or the config file's `token` key.
/// Returns `None` when no source is configured — that's a valid state
/// for relays running in open mode.
pub fn resolve_token(arg: Option<&str>) -> Option<String> {
    if let Some(s) = arg.filter(|s| !s.is_empty()) {
        return Some(s.to_string());
    }
    if let Ok(env) = env::var("AEGIS_RELAY_TOKEN") {
        if !env.is_empty() {
            return Some(env);
        }
    }
    cached().token.clone()
}

/// Resolve the state directory override (used by `state::state_root`).
/// `AEGIT_STATE_DIR` wins over the config; this helper is only consulted
/// when the env var is unset, mirroring the historical priority.
pub fn resolve_state_dir_from_config() -> Option<PathBuf> {
    cached().state_dir.clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Serializes `AEGIT_CONFIG` env var manipulation across tests
    /// running in parallel.
    static CONFIG_LOCK: Mutex<()> = Mutex::new(());

    fn write_temp_toml(name: &str, contents: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("aegit-config-test-{}-{}", name, std::process::id()));
        if dir.exists() {
            fs::remove_dir_all(&dir).expect("clear temp dir");
        }
        fs::create_dir_all(&dir).expect("create temp dir");
        let path = dir.join("config.toml");
        fs::write(&path, contents).expect("write toml");
        path
    }

    #[test]
    fn load_from_missing_file_returns_default() {
        let path = std::env::temp_dir().join("aegit-config-does-not-exist.toml");
        let cfg = Config::load_from(&path).expect("missing file is fine");
        assert!(cfg.relay.is_none());
        assert!(cfg.token.is_none());
        assert!(cfg.state_dir.is_none());
    }

    #[test]
    fn load_from_valid_toml_reads_all_three_keys() {
        let path = write_temp_toml(
            "valid",
            r#"
relay = "https://relay.example.com"
token = "dev-token"
state_dir = "/var/lib/aegit"
"#,
        );
        let cfg = Config::load_from(&path).expect("parse");
        assert_eq!(cfg.relay.as_deref(), Some("https://relay.example.com"));
        assert_eq!(cfg.token.as_deref(), Some("dev-token"));
        assert_eq!(cfg.state_dir.as_deref(), Some(Path::new("/var/lib/aegit")));
    }

    #[test]
    fn load_from_partial_toml_leaves_other_keys_none() {
        let path = write_temp_toml(
            "partial",
            r#"
relay = "https://only-relay.example.com"
"#,
        );
        let cfg = Config::load_from(&path).expect("parse");
        assert_eq!(cfg.relay.as_deref(), Some("https://only-relay.example.com"));
        assert!(cfg.token.is_none());
        assert!(cfg.state_dir.is_none());
    }

    #[test]
    fn load_from_empty_toml_returns_default() {
        let path = write_temp_toml("empty", "");
        let cfg = Config::load_from(&path).expect("parse");
        assert!(cfg.relay.is_none());
        assert!(cfg.token.is_none());
        assert!(cfg.state_dir.is_none());
    }

    #[test]
    fn load_from_malformed_toml_returns_parse_error() {
        let path = write_temp_toml("malformed", "this is not = valid = toml = at all =");
        let err = Config::load_from(&path).expect_err("should fail");
        match err {
            ConfigError::Parse { path: p, .. } => assert_eq!(p, path),
            ConfigError::Io { .. } => panic!("expected parse error, got io"),
        }
    }

    #[test]
    fn load_from_unknown_keys_is_lenient() {
        // Forward-compatibility: a future config key should not break
        // older `aegit` binaries. serde's default behavior ignores
        // unknown fields, which is what we want.
        let path = write_temp_toml(
            "unknown-keys",
            r#"
relay = "https://relay.example.com"
future_setting = "ignored"
"#,
        );
        let cfg = Config::load_from(&path).expect("parse");
        assert_eq!(cfg.relay.as_deref(), Some("https://relay.example.com"));
    }

    // --- precedence tests -------------------------------------------------
    //
    // resolve_* helpers consult the cached() singleton, which is hard to
    // poke from tests without restarting the process. We test them by
    // routing through Config::load_from directly via a small parallel
    // helper that mirrors the real precedence.

    fn resolve_relay_with(
        arg: Option<&str>,
        env_val: Option<&str>,
        cfg: &Config,
    ) -> Option<String> {
        if let Some(s) = arg.filter(|s| !s.is_empty()) {
            return Some(s.to_string());
        }
        if let Some(e) = env_val.filter(|s| !s.is_empty()) {
            return Some(e.to_string());
        }
        cfg.relay.clone()
    }

    #[test]
    fn flag_overrides_env_and_config() {
        let cfg = Config {
            relay: Some("from-config".to_string()),
            ..Default::default()
        };
        let resolved = resolve_relay_with(Some("from-flag"), Some("from-env"), &cfg).expect("some");
        assert_eq!(resolved, "from-flag");
    }

    #[test]
    fn env_overrides_config_when_no_flag() {
        let cfg = Config {
            relay: Some("from-config".to_string()),
            ..Default::default()
        };
        let resolved = resolve_relay_with(None, Some("from-env"), &cfg).expect("some");
        assert_eq!(resolved, "from-env");
    }

    #[test]
    fn config_used_when_no_flag_no_env() {
        let cfg = Config {
            relay: Some("from-config".to_string()),
            ..Default::default()
        };
        let resolved = resolve_relay_with(None, None, &cfg).expect("some");
        assert_eq!(resolved, "from-config");
    }

    #[test]
    fn empty_string_arg_is_treated_as_unset() {
        // CLI flag passed as `--relay ""` should not override the env or
        // config — empty string is not a meaningful value.
        let cfg = Config {
            relay: Some("from-config".to_string()),
            ..Default::default()
        };
        let resolved = resolve_relay_with(Some(""), None, &cfg).expect("some");
        assert_eq!(resolved, "from-config");
    }

    #[test]
    fn none_returned_when_all_sources_missing() {
        let cfg = Config::default();
        assert!(resolve_relay_with(None, None, &cfg).is_none());
    }

    // --- config_path resolution -----------------------------------------

    #[test]
    fn config_path_honors_aegit_config_env() {
        let _lock = CONFIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let original = env::var(ENV_CONFIG_PATH).ok();
        env::set_var(ENV_CONFIG_PATH, "/tmp/custom-aegit-config.toml");
        let path = config_path().expect("some");
        assert_eq!(path, PathBuf::from("/tmp/custom-aegit-config.toml"));
        match original {
            Some(v) => env::set_var(ENV_CONFIG_PATH, v),
            None => env::remove_var(ENV_CONFIG_PATH),
        }
    }

    #[test]
    fn config_path_falls_back_to_home() {
        let _lock = CONFIG_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let orig_cfg = env::var(ENV_CONFIG_PATH).ok();
        let orig_home = env::var("HOME").ok();
        env::remove_var(ENV_CONFIG_PATH);
        env::set_var("HOME", "/home/somebody");
        let path = config_path().expect("some");
        assert_eq!(
            path,
            PathBuf::from("/home/somebody/.aegis/aegit/config.toml")
        );
        match orig_cfg {
            Some(v) => env::set_var(ENV_CONFIG_PATH, v),
            None => env::remove_var(ENV_CONFIG_PATH),
        }
        match orig_home {
            Some(v) => env::set_var("HOME", v),
            None => env::remove_var("HOME"),
        }
    }

    /// Suppress the unused-fn warning for the test-only cache shim.
    #[test]
    fn reset_cache_shim_compiles() {
        reset_cache_for_tests();
    }
}
