//! Server configuration, read from a TOML file.
//!
//! Spec: `spec/zip-draft-1435.md` § Mailbox Servers (L314–318) for retention
//! and deletion, § Open issues (L450–451) for quotas and retention, which the
//! draft leaves to each server.

use std::fmt;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use zunker_wire::MAX_FETCH_ITEM_LEN;

/// Server configuration.
///
/// Spec: § Mailbox Servers (L279–283 `server_id`, L314–318), § Open issues (L450–451).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address to listen on, e.g. `127.0.0.1:7878`.
    pub listen: SocketAddr,
    /// This server's 32-byte `server_id`, as 64 hex characters. Fetch
    /// signatures are bound to it.
    #[serde(deserialize_with = "server_id_from_hex")]
    pub server_id: [u8; 32],
    /// SQLite database path. `:memory:` keeps everything in memory.
    pub database: PathBuf,
    /// Retention and deletion.
    #[serde(default)]
    pub retention: Retention,
    /// Size and rate limits.
    #[serde(default)]
    pub limits: Limits,
}

/// How long Envelopes are kept.
///
/// Spec: § Mailbox Servers (L316–318).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Retention {
    /// Envelopes older than this are discarded, fetched or not
    /// ("discard Envelopes after a retention period of its choosing").
    pub max_age_hours: u64,
    /// Whether a Fetch deletes Envelopes with `seq <= after`. Off by default,
    /// so that several devices sharing a viewing key can each fetch every
    /// Envelope (the multi-device proposal on zcash/zips#1435).
    pub delete_on_fetch: bool,
    /// With `delete_on_fetch`, an Envelope is only deleted once it is at
    /// least this old.
    pub min_age_before_delete_hours: u64,
}

impl Default for Retention {
    /// 30 days' retention, deletion on fetch off, 7 days' minimum age.
    /// Spec: § Mailbox Servers (L316–318).
    fn default() -> Self {
        Retention {
            max_age_hours: 30 * 24,
            delete_on_fetch: false,
            min_age_before_delete_hours: 7 * 24,
        }
    }
}

/// Size and rate limits.
///
/// Spec: § Mailbox Servers (L316 "up to a size of the server's choosing"),
/// § Privacy Implications (L138–139), § Open issues (L450–451).
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields, default)]
pub struct Limits {
    /// Maximum bytes of `(seq, len, Envelope)` triples in one Fetch response.
    /// Must fit at least one largest Envelope.
    pub fetch_byte_budget: usize,
    /// Deposits to a mailbox holding this many Envelopes are dropped.
    pub max_envelopes_per_mailbox: u32,
    /// Deposits accepted per mailbox in each quota window; the rest are dropped.
    pub deposit_quota: u32,
    /// Length of a quota window, in seconds.
    pub deposit_quota_window_secs: u64,
    /// A connection must deliver its request and take its response within
    /// this many seconds.
    pub io_timeout_secs: u64,
    /// Maximum concurrent connections.
    pub max_connections: usize,
}

impl Default for Limits {
    /// Spec: none (operational defaults).
    fn default() -> Self {
        Limits {
            fetch_byte_budget: 4 * 1024 * 1024,
            max_envelopes_per_mailbox: 1000,
            deposit_quota: 100,
            deposit_quota_window_secs: 3600,
            io_timeout_secs: 30,
            max_connections: 1024,
        }
    }
}

/// Why a configuration was rejected.
#[derive(Debug)]
pub enum ConfigError {
    /// The file could not be read.
    Io(std::io::Error),
    /// The file is not valid TOML for [`Config`].
    Parse(toml::de::Error),
    /// A value is out of range.
    Invalid(&'static str),
}

impl fmt::Display for ConfigError {
    /// Spec: none (diagnostics only).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "cannot read config: {e}"),
            ConfigError::Parse(e) => write!(f, "invalid config: {e}"),
            ConfigError::Invalid(why) => write!(f, "invalid config: {why}"),
        }
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Reads and validates a TOML config file. Spec: none (configuration).
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(ConfigError::Io)?;
        Self::from_toml(&text)
    }

    /// Parses and validates TOML. Spec: none (configuration).
    pub fn from_toml(text: &str) -> Result<Self, ConfigError> {
        let config: Config = toml::from_str(text).map_err(ConfigError::Parse)?;
        config.validate()?;
        Ok(config)
    }

    /// Checks that limits are usable.
    ///
    /// Spec: § Mailbox Servers (L315–317): every Envelope must be fetchable, so
    /// the byte budget fits at least one Envelope of the largest size.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let l = &self.limits;
        if l.fetch_byte_budget < MAX_FETCH_ITEM_LEN {
            return Err(ConfigError::Invalid(
                "limits.fetch_byte_budget must fit one 262144-byte envelope (262205 bytes)",
            ));
        }
        if u32::try_from(l.fetch_byte_budget).is_err() {
            return Err(ConfigError::Invalid(
                "limits.fetch_byte_budget must fit in a u32 frame length",
            ));
        }
        if l.max_envelopes_per_mailbox == 0 || l.deposit_quota == 0 {
            return Err(ConfigError::Invalid(
                "limits.max_envelopes_per_mailbox and limits.deposit_quota must be positive",
            ));
        }
        if l.deposit_quota_window_secs == 0 || l.io_timeout_secs == 0 || l.max_connections == 0 {
            return Err(ConfigError::Invalid(
                "limits.deposit_quota_window_secs, io_timeout_secs and max_connections must be positive",
            ));
        }
        if self.retention.max_age_hours == 0 {
            return Err(ConfigError::Invalid(
                "retention.max_age_hours must be positive",
            ));
        }
        Ok(())
    }
}

/// Decodes `server_id` from 64 hex characters.
/// Spec: § Mailboxes (L279–280): a 32-byte `server_id`.
fn server_id_from_hex<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
    let s = String::deserialize(d)?;
    let bytes = hex::decode(s.trim()).map_err(serde::de::Error::custom)?;
    bytes
        .try_into()
        .map_err(|_| serde::de::Error::custom("server_id must be 32 bytes (64 hex characters)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    const MINIMAL: &str = r#"
        listen = "127.0.0.1:7878"
        server_id = "0101010101010101010101010101010101010101010101010101010101010101"
        database = ":memory:"
    "#;

    /// Defaults: deletion on fetch off, 7-day minimum age.
    /// Spec: § Mailbox Servers (L316–318).
    #[test]
    fn minimal_config_uses_defaults() {
        let c = Config::from_toml(MINIMAL).unwrap();
        assert_eq!(c.server_id, [1u8; 32]);
        assert!(!c.retention.delete_on_fetch);
        assert_eq!(c.retention.min_age_before_delete_hours, 168);
        assert_eq!(c.limits.max_envelopes_per_mailbox, 1000);
    }

    /// Every field can be set. Spec: § Mailbox Servers (L314–318).
    #[test]
    fn full_config() {
        let text = format!(
            "{MINIMAL}\n[retention]\nmax_age_hours = 48\ndelete_on_fetch = true\nmin_age_before_delete_hours = 1\n\
             [limits]\nfetch_byte_budget = 300000\nmax_envelopes_per_mailbox = 5\ndeposit_quota = 3\n\
             deposit_quota_window_secs = 60\nio_timeout_secs = 5\nmax_connections = 8\n"
        );
        let c = Config::from_toml(&text).unwrap();
        assert!(c.retention.delete_on_fetch);
        assert_eq!(c.retention.max_age_hours, 48);
        assert_eq!(c.limits.deposit_quota, 3);
    }

    /// Bad `server_id`, unknown keys and unusable limits are rejected.
    /// Spec: § Mailboxes (L279–280), § Mailbox Servers (L316).
    #[test]
    fn rejects_bad_values() {
        let short = MINIMAL.replace(
            "0101010101010101010101010101010101010101010101010101010101010101",
            "0101",
        );
        assert!(Config::from_toml(&short).is_err());
        assert!(Config::from_toml(&format!("{MINIMAL}\nextra = 1\n")).is_err());
        let small = format!("{MINIMAL}\n[limits]\nfetch_byte_budget = 1000\n");
        assert!(matches!(
            Config::from_toml(&small),
            Err(ConfigError::Invalid(_))
        ));
        let zero = format!("{MINIMAL}\n[limits]\ndeposit_quota = 0\n");
        assert!(matches!(
            Config::from_toml(&zero),
            Err(ConfigError::Invalid(_))
        ));
    }
}
