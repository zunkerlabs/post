//! The Server List: which Mailbox Servers exist and how to reach them.
//!
//! **Provisional.** The draft leaves the Server List unspecified (`spec/zip-
//! draft-1435.md` § Mailboxes L279–285, § Open issues L446–449). Until our
//! Server List proposal lands, this is a JSON file of our own design:
//!
//! ```json
//! {
//!   "format": "zunker-provisional-1",
//!   "servers": [
//!     { "server_id": "<64 hex characters>", "onion": "<56 base32>.onion:7878" }
//!   ]
//! }
//! ```
//!
//! Each entry is a 32-byte `server_id` and, for the Tor network, an address in
//! the Tor Routing Binding's format (L279–280, Appendix A L494–495).

use std::collections::HashSet;
use std::fmt;
use std::path::Path;

use serde::Deserialize;
use zunker_core::mailbox::MailboxId;
use zunker_core::server_select::select;

use crate::transport::OnionAddr;

/// The only accepted `format` value. Spec: § Open issues (L446–449).
pub const FORMAT: &str = "zunker-provisional-1";

/// One Server List entry. Spec: § Mailboxes (L279–280).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerEntry {
    /// The 32-byte `server_id` used for selection and bound into Fetch
    /// signatures.
    pub server_id: [u8; 32],
    /// The server's onion service address.
    pub onion: OnionAddr,
}

/// A validated, non-empty Server List. Spec: § Mailboxes (L279–285).
#[derive(Clone, Debug)]
pub struct ServerList {
    entries: Vec<ServerEntry>,
}

/// Why a Server List was rejected.
#[derive(Debug)]
pub enum ServerListError {
    /// The file could not be read.
    Io(std::io::Error),
    /// Not valid JSON for the provisional format.
    Parse(serde_json::Error),
    /// A value is unusable.
    Invalid(String),
}

impl fmt::Display for ServerListError {
    /// Spec: none (diagnostics only).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ServerListError::Io(e) => write!(f, "cannot read server list: {e}"),
            ServerListError::Parse(e) => write!(f, "invalid server list: {e}"),
            ServerListError::Invalid(why) => write!(f, "invalid server list: {why}"),
        }
    }
}

impl std::error::Error for ServerListError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawList {
    format: String,
    servers: Vec<RawEntry>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntry {
    server_id: String,
    onion: String,
}

impl ServerList {
    /// Builds a list from entries. Rejects an empty list and repeated
    /// `server_id`s (selection would then depend on order).
    /// Spec: § Mailboxes (L279–283).
    pub fn new(entries: Vec<ServerEntry>) -> Result<Self, ServerListError> {
        if entries.is_empty() {
            return Err(ServerListError::Invalid("no servers".into()));
        }
        let mut ids = HashSet::new();
        if !entries.iter().all(|e| ids.insert(e.server_id)) {
            return Err(ServerListError::Invalid("repeated server_id".into()));
        }
        Ok(ServerList { entries })
    }

    /// Reads a list in the provisional JSON format. Spec: § Open issues (L446–449).
    pub fn load(path: &Path) -> Result<Self, ServerListError> {
        let text = std::fs::read_to_string(path).map_err(ServerListError::Io)?;
        Self::from_json(&text)
    }

    /// Parses the provisional JSON format. Spec: § Mailboxes (L279–280).
    pub fn from_json(text: &str) -> Result<Self, ServerListError> {
        let raw: RawList = serde_json::from_str(text).map_err(ServerListError::Parse)?;
        if raw.format != FORMAT {
            return Err(ServerListError::Invalid(format!(
                "format must be \"{FORMAT}\""
            )));
        }
        let entries = raw
            .servers
            .into_iter()
            .map(|e| {
                let id = hex::decode(e.server_id.trim())
                    .ok()
                    .and_then(|b| <[u8; 32]>::try_from(b).ok())
                    .ok_or_else(|| ServerListError::Invalid("server_id must be 64 hex".into()))?;
                let onion = e
                    .onion
                    .parse()
                    .map_err(|err| ServerListError::Invalid(format!("{}: {err}", e.onion)))?;
                Ok(ServerEntry {
                    server_id: id,
                    onion,
                })
            })
            .collect::<Result<Vec<_>, ServerListError>>()?;
        Self::new(entries)
    }

    /// The Mailbox Server of `id`: the entry with the smallest selection hash.
    /// Spec: § Mailboxes (L281–283).
    pub fn server_for(&self, id: &MailboxId) -> &ServerEntry {
        select(&self.entries, |e| &e.server_id, id).expect("the list is never empty")
    }

    /// Every entry. Spec: § Mailboxes (L279–280).
    pub fn entries(&self) -> &[ServerEntry] {
        &self.entries
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: &str = "pg6mmjiyjmcrsslvykfwnntlaru7p5svn6y2ymmju6nubxndf4pscryd.onion:7878";
    const B: &str = "vww6ybal4bd7szmgncyruucpgfkqahzddi37ktceo3ah7ngmcopnpyyd.onion:7878";

    /// Spec: § Mailboxes (L279–280), § Open issues (L446–449).
    #[test]
    fn parses_provisional_format() {
        let json = format!(
            r#"{{"format":"{FORMAT}","servers":[
                {{"server_id":"{}","onion":"{A}"}},
                {{"server_id":"{}","onion":"{B}"}}]}}"#,
            "01".repeat(32),
            "02".repeat(32)
        );
        let list = ServerList::from_json(&json).unwrap();
        assert_eq!(list.entries().len(), 2);
        assert_eq!(list.entries()[1].server_id, [2; 32]);
        assert_eq!(list.entries()[0].onion.to_string(), A);
    }

    /// Spec: § Mailboxes (L279–283).
    #[test]
    fn rejects_bad_lists() {
        let one = |id: &str, onion: &str| {
            format!(
                r#"{{"format":"{FORMAT}","servers":[{{"server_id":"{id}","onion":"{onion}"}}]}}"#
            )
        };
        let id = "01".repeat(32);
        assert!(ServerList::from_json(&one(&id, A)).is_ok());
        assert!(ServerList::from_json(&one("0101", A)).is_err());
        assert!(ServerList::from_json(&one(&id, "127.0.0.1:7878")).is_err());
        assert!(ServerList::from_json(&one(&id, A).replace(FORMAT, "v2")).is_err());
        assert!(
            ServerList::from_json(&format!(r#"{{"format":"{FORMAT}","servers":[]}}"#)).is_err()
        );
        let entry = ServerEntry {
            server_id: [1; 32],
            onion: A.parse().unwrap(),
        };
        assert!(ServerList::new(vec![entry.clone(), entry]).is_err());
    }
}
