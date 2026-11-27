//! What the client remembers between runs: fetch cursors, Conversations, and
//! the `ephemeralKey`s already processed.
//!
//! Spec: `spec/zip-draft-1435.md` § Envelopes (L243), § Conversations
//! (L287–305), § Wallet behaviour (L374–376).
//!
//! The file holds each Conversation's `κ`, which reads and writes it (§ Privacy
//! Implications, L97–104). It is written with owner-only permissions; it is not
//! encrypted at rest (testnet only, see `SECURITY.md`).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zunker_core::envelope::{Conversation, Direction, ReplayGuard};
use zunker_core::mailbox::epoch;
use zunker_core::receiver::Receiver;

/// Hours after an epoch ends during which its mailbox is still fetched.
/// Spec: § Conversations (L300–301).
pub const ENDED_EPOCH_GRACE_HOURS: u32 = 24;

/// Our role in a Conversation. Spec: § Envelopes (L214–215).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// We sent the first Envelope (`δ = 0`).
    Initiator,
    /// We received it (`δ = 1`).
    Responder,
}

impl Role {
    /// The direction of Envelopes we send. Spec: § Envelopes (L214–215).
    pub fn sends(self) -> Direction {
        match self {
            Role::Initiator => Direction::Initiator,
            Role::Responder => Direction::Responder,
        }
    }

    /// The direction of Envelopes we receive. Spec: § Conversations (L294–297).
    pub fn receives(self) -> Direction {
        match self {
            Role::Initiator => Direction::Responder,
            Role::Responder => Direction::Initiator,
        }
    }
}

/// Fetch progress for one Pairwise Mailbox (one epoch, receiving direction).
/// Spec: § Conversations (L300–301), § Wallet behaviour (L374–376).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochState {
    /// The last `seq` received, or 0.
    pub cursor: u64,
    /// Fetched at least 24 hours after the epoch ended; no longer fetched.
    pub done: bool,
}

/// One Conversation. Spec: § Envelopes (L214–231), § Conversations (L287–305).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConversationState {
    /// `κ`, hex. Secret.
    pub kappa: String,
    /// The responder's raw Orchard Receiver, hex.
    pub responder: String,
    /// Our role.
    pub role: Role,
    /// Initiator only: whether an Envelope from the responder has arrived. Until
    /// then the initiator MUST NOT send in this Conversation.
    pub received_reply: bool,
    /// When (hours) we started fetching the other side's Pairwise Mailboxes:
    /// on sending the first Envelope (initiator), or on first sending in the
    /// Conversation (responder). `None` until then.
    pub fetch_from_hours: Option<u32>,
    /// Per-epoch progress for the Pairwise Mailboxes we fetch.
    #[serde(default)]
    pub epochs: BTreeMap<u32, EpochState>,
}

impl ConversationState {
    /// Builds the core Conversation. `None` if the stored values are corrupt.
    /// Spec: § Envelopes (L214–217).
    pub fn conversation(&self) -> Option<Conversation> {
        let kappa: [u8; 32] = hex::decode(&self.kappa).ok()?.try_into().ok()?;
        let raw: [u8; 43] = hex::decode(&self.responder).ok()?.try_into().ok()?;
        Some(Conversation::from_parts(kappa, Receiver::from_raw(&raw)?))
    }

    /// Stores a Conversation. Spec: § Envelopes (L214–217).
    pub fn new(conv: &Conversation, role: Role, fetch_from_hours: Option<u32>) -> Self {
        ConversationState {
            kappa: hex::encode(conv.kappa()),
            responder: hex::encode(conv.responder().raw()),
            role,
            received_reply: false,
            fetch_from_hours,
            epochs: BTreeMap::new(),
        }
    }

    /// Whether we may send in this Conversation now: the responder always,
    /// the initiator only after receiving an Envelope in it.
    /// Spec: § Conversations (L296–299).
    pub fn may_send(&self) -> bool {
        self.role == Role::Responder || self.received_reply
    }

    /// The epochs whose Pairwise Mailbox (receiving direction) should be
    /// fetched at `now_hours`: the current one, and every earlier one since
    /// fetching started that has not yet been fetched 24 hours after it ended.
    /// Adds entries for epochs not yet tracked.
    ///
    /// Spec: § Conversations (L292–301).
    pub fn active_epochs(&mut self, now_hours: u32) -> Vec<u32> {
        let Some(from) = self.fetch_from_hours else {
            return Vec::new();
        };
        let (first, current) = (epoch(from), epoch(now_hours));
        for e in first..=current {
            self.epochs.entry(e).or_default();
        }
        self.epochs
            .iter()
            .filter(|(_, s)| !s.done)
            .map(|(&e, _)| e)
            .collect()
    }

    /// Records a fetch of epoch `e` at `now_hours` that reached `cursor`; an
    /// ended epoch fetched at least 24 hours after its end is done.
    /// Spec: § Conversations (L300–301).
    pub fn fetched(&mut self, e: u32, cursor: u64, now_hours: u32) {
        let end = (e + 1).saturating_mul(zunker_core::mailbox::EPOCH_HOURS);
        let s = self.epochs.entry(e).or_default();
        s.cursor = s.cursor.max(cursor);
        if now_hours >= end.saturating_add(ENDED_EPOCH_GRACE_HOURS) {
            s.done = true;
        }
    }
}

/// Everything persisted. Spec: § Envelopes (L243), § Conversations (L287–305).
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct State {
    /// Contact Mailbox cursor per diversifier index.
    #[serde(default)]
    pub contacts: BTreeMap<u32, u64>,
    /// Conversations by id (16 random bytes, hex).
    #[serde(default)]
    pub conversations: BTreeMap<String, ConversationState>,
    /// Processed `ephemeralKey`s (hex) and the `expiry_time` of their Envelope.
    #[serde(default)]
    pub seen: BTreeMap<String, u32>,
}

impl State {
    /// Forgets `ephemeralKey`s of expired Envelopes: those would be dropped by
    /// the expiry rule anyway, so the replay set need not keep them.
    /// Spec: § Envelopes (L242–243).
    pub fn prune_seen(&mut self, now_hours: u32) {
        self.seen.retain(|_, &mut expiry| expiry > now_hours);
    }
}

/// [`ReplayGuard`] over [`State::seen`]. An inserted key is stored with a
/// placeholder expiry until [`Seen::set_expiry`] records the real one.
/// Spec: § Envelopes (L243).
pub struct Seen<'a> {
    map: &'a mut BTreeMap<String, u32>,
    last: Option<String>,
}

impl<'a> Seen<'a> {
    /// Wraps the persisted set. Spec: § Envelopes (L243).
    pub fn new(map: &'a mut BTreeMap<String, u32>) -> Self {
        Seen { map, last: None }
    }

    /// Records the expiry of the last inserted key. Spec: § Envelopes (L242–243).
    pub fn set_expiry(&mut self, expiry: u32) {
        if let Some(k) = self.last.take() {
            self.map.insert(k, expiry);
        }
    }
}

impl ReplayGuard for Seen<'_> {
    /// Spec: § Envelopes (L243).
    fn contains(&self, ephemeral_key: &[u8; 32]) -> bool {
        self.map.contains_key(&hex::encode(ephemeral_key))
    }

    /// Spec: § Envelopes (L243).
    fn insert(&mut self, ephemeral_key: [u8; 32]) {
        let k = hex::encode(ephemeral_key);
        self.map.insert(k.clone(), u32::MAX);
        self.last = Some(k);
    }
}

/// A JSON state file, replaced atomically on every save.
/// Spec: § Wallet behaviour (L374–376): cursors survive restarts.
#[derive(Clone, Debug)]
pub struct StateFile {
    path: PathBuf,
}

impl StateFile {
    /// A state file at `path`. Spec: none (storage).
    pub fn new(path: impl Into<PathBuf>) -> Self {
        StateFile { path: path.into() }
    }

    /// Loads the state, or an empty one if the file does not exist yet.
    /// Spec: none (storage).
    pub fn load(&self) -> std::io::Result<State> {
        match std::fs::read(&self.path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(State::default()),
            Err(e) => Err(e),
        }
    }

    /// Writes the state to a temporary file with owner-only permissions, then
    /// renames it over the old one. Spec: none (storage).
    pub fn save(&self, state: &State) -> std::io::Result<()> {
        let bytes = serde_json::to_vec_pretty(state).map_err(std::io::Error::other)?;
        let tmp = tmp_path(&self.path);
        let mut f = private_file(&tmp)?;
        f.write_all(&bytes)?;
        f.sync_all()?;
        drop(f);
        std::fs::rename(&tmp, &self.path)
    }
}

/// `<path>.tmp`. Spec: none (storage).
fn tmp_path(path: &Path) -> PathBuf {
    let mut s = path.as_os_str().to_owned();
    s.push(".tmp");
    PathBuf::from(s)
}

/// Creates (truncating) a file readable only by its owner.
/// Spec: none (storage; the file holds secrets).
pub fn private_file(path: &Path) -> std::io::Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    opts.open(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zunker_core::mailbox::EPOCH_HOURS;

    /// Test fixture. Spec: § Envelopes (L214–217).
    fn conv_state(role: Role, from: Option<u32>) -> ConversationState {
        ConversationState {
            kappa: "00".repeat(32),
            responder: "00".repeat(43),
            role,
            received_reply: false,
            fetch_from_hours: from,
            epochs: BTreeMap::new(),
        }
    }

    /// The initiator waits for a reply; the responder may always send.
    /// Spec: § Conversations (L296–299).
    #[test]
    fn initiator_waits_for_reply() {
        let mut c = conv_state(Role::Initiator, Some(0));
        assert!(!c.may_send());
        c.received_reply = true;
        assert!(c.may_send());
        assert!(conv_state(Role::Responder, None).may_send());
    }

    /// Nothing is fetched before fetching starts; then the current epoch, and
    /// an ended epoch until it has been fetched 24 hours after its end.
    /// Spec: § Conversations (L292–301).
    #[test]
    fn epochs_and_grace_period() {
        let e = 1000u32;
        let start = e * EPOCH_HOURS + 100;
        assert!(conv_state(Role::Responder, None)
            .active_epochs(start)
            .is_empty());

        let mut c = conv_state(Role::Initiator, Some(start));
        assert_eq!(c.active_epochs(start), [e]);
        // Next epoch: both are fetched.
        let next = (e + 1) * EPOCH_HOURS;
        assert_eq!(c.active_epochs(next), [e, e + 1]);
        // A fetch of e within 24 h of its end does not finish it.
        c.fetched(e, 5, next + 23);
        assert_eq!(c.active_epochs(next + 23), [e, e + 1]);
        assert_eq!(c.epochs[&e].cursor, 5);
        // One at 24 h does.
        c.fetched(e, 5, next + 24);
        assert_eq!(c.active_epochs(next + 24), [e + 1]);
        // The current epoch is never done while current.
        c.fetched(e + 1, 0, next + 24);
        assert_eq!(c.active_epochs(next + 24), [e + 1]);
        // Several missed epochs are all fetched on return.
        assert_eq!(
            c.active_epochs(next + 3 * EPOCH_HOURS),
            [e + 1, e + 2, e + 3, e + 4]
        );
    }

    /// Replay entries keep their expiry and are pruned after it.
    /// Spec: § Envelopes (L242–243).
    #[test]
    fn seen_and_prune() {
        let mut st = State::default();
        let mut seen = Seen::new(&mut st.seen);
        assert!(!seen.contains(&[1; 32]));
        seen.insert([1; 32]);
        seen.set_expiry(50);
        assert!(seen.contains(&[1; 32]));
        st.prune_seen(49);
        assert_eq!(st.seen.len(), 1);
        st.prune_seen(50);
        assert!(st.seen.is_empty());
    }

    /// Save and load round-trip, owner-only on Unix. Spec: none (storage).
    #[test]
    fn state_file_round_trip() {
        let dir = std::env::temp_dir().join(format!("zunker-state-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let f = StateFile::new(dir.join("state.json"));
        assert!(f.load().unwrap().conversations.is_empty());
        let mut st = State::default();
        st.contacts.insert(0, 42);
        st.conversations
            .insert("ab".into(), conv_state(Role::Responder, Some(3)));
        f.save(&st).unwrap();
        let back = f.load().unwrap();
        assert_eq!(back.contacts[&0], 42);
        assert_eq!(back.conversations["ab"].fetch_from_hours, Some(3));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.join("state.json"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
