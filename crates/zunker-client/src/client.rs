//! The client: deposit, reply, and fetch, with state persisted after each step.
//!
//! Spec: `spec/zip-draft-1435.md` § Conversations (L287–305), § Mailbox
//! Servers (L307–330), § Routing (L348–350), § Wallet behaviour (L372–386).

use std::fmt;
use std::time::{SystemTime, UNIX_EPOCH};

use zunker_core::envelope::{open, open_first, seal, seal_first, Message, SealError};
use zunker_core::mailbox::{
    contact_mailbox_id, contact_mailbox_key, epoch, pairwise_mailbox_key, MailboxKey,
};
use zunker_core::sig::FetchRequest;
use zunker_server::wire::{decode_fetch_response, encode_deposit};

use crate::address::{orchard_receiver, Account, AddressError};
use crate::schedule::{MailboxRef, Schedule};
use crate::server_list::ServerList;
use crate::state::{ConversationState, Role, Seen, State, StateFile};
use crate::transport::{Transport, TransportError};

/// Why an operation failed.
#[derive(Debug)]
pub enum ClientError {
    /// The recipient address or payload was rejected.
    Address(AddressError),
    /// The Envelope could not be sealed.
    Seal(SealError),
    /// The request could not be carried over Tor.
    Transport(TransportError),
    /// The state file could not be read or written.
    State(std::io::Error),
    /// No Conversation with that id.
    UnknownConversation,
    /// The initiator has not yet received a reply, so it MUST NOT send again
    /// in this Conversation; send a new first Envelope instead.
    AwaitingReply,
    /// The operating system's random generator failed.
    OsRandomUnavailable,
    /// A derivation produced no mailbox (negligible probability).
    NoMailbox,
}

impl fmt::Display for ClientError {
    /// Spec: none (diagnostics only).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ClientError::Address(e) => e.fmt(f),
            ClientError::Seal(e) => e.fmt(f),
            ClientError::Transport(e) => e.fmt(f),
            ClientError::State(e) => write!(f, "state file: {e}"),
            ClientError::UnknownConversation => f.write_str("unknown conversation"),
            ClientError::AwaitingReply => f.write_str(
                "no reply yet in this conversation; the initiator may not send again until one arrives",
            ),
            ClientError::OsRandomUnavailable => f.write_str("the OS random generator failed"),
            ClientError::NoMailbox => f.write_str("mailbox derivation failed"),
        }
    }
}

impl std::error::Error for ClientError {}

impl From<AddressError> for ClientError {
    /// Spec: none (error conversion).
    fn from(e: AddressError) -> Self {
        ClientError::Address(e)
    }
}

impl From<SealError> for ClientError {
    /// Spec: none (error conversion).
    fn from(e: SealError) -> Self {
        ClientError::Seal(e)
    }
}

impl From<TransportError> for ClientError {
    /// Spec: none (error conversion).
    fn from(e: TransportError) -> Self {
        ClientError::Transport(e)
    }
}

/// A message that arrived. Spec: § Envelopes (L233–246).
#[derive(Debug)]
pub struct Received {
    /// The Conversation it belongs to; reply with [`Client::reply`].
    pub conversation: String,
    /// Where it was fetched from.
    pub mailbox: MailboxRef,
    /// The decrypted message.
    pub message: Message,
}

/// The result of fetching several mailboxes. Spec: § Wallet behaviour (L374–376).
#[derive(Debug, Default)]
pub struct FetchOutcome {
    /// Messages that passed every drop rule.
    pub received: Vec<Received>,
    /// Mailboxes whose fetch failed (for example, Tor errors). Their cursors
    /// are unchanged and they are tried again next time.
    pub failed: Vec<(MailboxRef, String)>,
}

/// Current time in seconds since the Unix epoch. Spec: § Notation (L184–185).
pub fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Seconds to whole hours, as Envelopes and Fetch use. Spec: § Notation (L184–185).
pub fn hours(secs: u64) -> u32 {
    u32::try_from(secs / 3600).unwrap_or(u32::MAX)
}

/// A messaging client. Spec: § Conversations (L287–305), § Wallet behaviour (L372–386).
pub struct Client {
    transport: Transport,
    servers: ServerList,
    file: StateFile,
    state: State,
}

impl Client {
    /// A client using `transport`, `servers`, and the state in `file`.
    /// Spec: § Mailboxes (L279–283), § Routing (L332–350).
    pub fn new(
        transport: Transport,
        servers: ServerList,
        file: StateFile,
    ) -> Result<Self, ClientError> {
        let state = file.load().map_err(ClientError::State)?;
        Ok(Client {
            transport,
            servers,
            file,
            state,
        })
    }

    /// The persisted state. Spec: none (inspection).
    pub fn state(&self) -> &State {
        &self.state
    }

    /// Saves the state. Spec: § Wallet behaviour (L374–376).
    fn save(&self) -> Result<(), ClientError> {
        self.file.save(&self.state).map_err(ClientError::State)
    }

    /// Sends `msg` as a first Envelope to the Orchard Receiver of `to_ua`,
    /// starting a Conversation in which we are the initiator. The Envelope goes
    /// to the recipient's Contact Mailbox on its selected server, in a new
    /// session. Returns the Conversation id.
    ///
    /// Spec: § Envelopes (L225–231), § Mailboxes (L262–268, L281–283),
    /// § Conversations (L289–290, L296–299), § Routing (L348).
    pub async fn deposit(&mut self, to_ua: &str, msg: &Message) -> Result<String, ClientError> {
        self.deposit_at(to_ua, msg, now_secs()).await
    }

    /// [`Client::deposit`] at a given time. Spec: as for [`Client::deposit`].
    pub async fn deposit_at(
        &mut self,
        to_ua: &str,
        msg: &Message,
        now: u64,
    ) -> Result<String, ClientError> {
        let to = orchard_receiver(to_ua)?;
        let mailbox = contact_mailbox_id(&to).ok_or(ClientError::NoMailbox)?;
        let (envelope, conv) = seal_first(&to, msg, &mut rand::rng())?;
        self.send_deposit(&mailbox, &envelope).await?;
        let id = new_conversation_id()?;
        // The initiator fetches the responder's mailboxes from now on.
        let state = ConversationState::new(&conv, Role::Initiator, Some(hours(now)));
        self.state.conversations.insert(id.clone(), state);
        self.save()?;
        Ok(id)
    }

    /// Sends `msg` in a Conversation, to the Pairwise Mailbox of our direction
    /// and the current epoch. The initiator may do so only after receiving an
    /// Envelope in it ([`ClientError::AwaitingReply`] otherwise). The
    /// responder's first send starts its fetching of the initiator's mailboxes.
    ///
    /// Spec: § Conversations (L292–299), § Mailboxes (L272–277), § Routing (L348).
    pub async fn reply(&mut self, conversation: &str, msg: &Message) -> Result<(), ClientError> {
        self.reply_at(conversation, msg, now_secs()).await
    }

    /// [`Client::reply`] at a given time. Spec: as for [`Client::reply`].
    pub async fn reply_at(
        &mut self,
        conversation: &str,
        msg: &Message,
        now: u64,
    ) -> Result<(), ClientError> {
        let cs = self
            .state
            .conversations
            .get(conversation)
            .ok_or(ClientError::UnknownConversation)?;
        if !cs.may_send() {
            return Err(ClientError::AwaitingReply);
        }
        let conv = cs.conversation().ok_or(ClientError::UnknownConversation)?;
        let from = cs.role.sends();
        let key =
            pairwise_mailbox_key(&conv, from, epoch(hours(now))).ok_or(ClientError::NoMailbox)?;
        let envelope = seal(&conv, from, msg, &mut rand::rng())?;
        self.send_deposit(&key.id(), &envelope).await?;
        let cs = self
            .state
            .conversations
            .get_mut(conversation)
            .expect("checked above");
        cs.fetch_from_hours.get_or_insert(hours(now));
        self.save()
    }

    /// Forgets a Conversation; the other wallet is not told.
    /// Spec: § Conversations (L304–305).
    pub fn forget(&mut self, conversation: &str) -> Result<bool, ClientError> {
        let existed = self.state.conversations.remove(conversation).is_some();
        self.save()?;
        Ok(existed)
    }

    /// Deposits an Envelope over a new session. Spec: § Mailbox Servers (L311),
    /// § Routing (L348).
    async fn send_deposit(
        &self,
        mailbox: &zunker_core::mailbox::MailboxId,
        envelope: &[u8],
    ) -> Result<(), ClientError> {
        let server = self.servers.server_for(mailbox);
        self.transport
            .request(&server.onion, &encode_deposit(mailbox, envelope), false)
            .await?;
        Ok(())
    }

    /// Every mailbox to fetch at `now`: the Contact Mailbox of each account
    /// address, and the active Pairwise Mailboxes of each Conversation.
    /// Spec: § Conversations (L292–301).
    pub fn active_mailboxes(&mut self, account: &Account, now: u64) -> Vec<MailboxRef> {
        let mut out: Vec<MailboxRef> = account
            .indices()
            .iter()
            .map(|&j| MailboxRef::Contact(j))
            .collect();
        for (id, cs) in self.state.conversations.iter_mut() {
            for e in cs.active_epochs(hours(now)) {
                out.push(MailboxRef::Pairwise {
                    conversation: id.clone(),
                    epoch: e,
                });
            }
        }
        out
    }

    /// Fetches every active mailbox once, each in its own session, in random
    /// order. Spec: § Routing (L348–349), § Wallet behaviour (L374–376).
    pub async fn fetch(&mut self, account: &Account) -> Result<FetchOutcome, ClientError> {
        self.fetch_at(account, now_secs()).await
    }

    /// [`Client::fetch`] at a given time. Spec: as for [`Client::fetch`].
    pub async fn fetch_at(
        &mut self,
        account: &Account,
        now: u64,
    ) -> Result<FetchOutcome, ClientError> {
        let mut mailboxes = self.active_mailboxes(account, now);
        shuffle(&mut mailboxes)?;
        let mut outcome = FetchOutcome::default();
        for m in mailboxes {
            self.fetch_into(account, &m, now, &mut outcome).await?;
        }
        Ok(outcome)
    }

    /// Fetches the mailboxes `schedule` says are due at `now`, then reschedules
    /// them. Spec: § Wallet behaviour (L374–376).
    pub async fn fetch_due(
        &mut self,
        account: &Account,
        schedule: &mut Schedule,
        now: u64,
    ) -> Result<FetchOutcome, ClientError> {
        let active = self.active_mailboxes(account, now);
        schedule.sync(&active, now);
        let mut outcome = FetchOutcome::default();
        for m in schedule.due(now) {
            self.fetch_into(account, &m, now, &mut outcome).await?;
            schedule.fetched(&m, now);
        }
        Ok(outcome)
    }

    /// Fetches one mailbox and adds the result to `outcome`. Transport and
    /// server failures are recorded and do not stop other mailboxes; state
    /// errors do. Spec: § Mailbox Servers (L312, L315–317, L320–322).
    async fn fetch_into(
        &mut self,
        account: &Account,
        m: &MailboxRef,
        now: u64,
        outcome: &mut FetchOutcome,
    ) -> Result<(), ClientError> {
        match self.fetch_one(account, m, now).await {
            Ok(mut got) => outcome.received.append(&mut got),
            Err(ClientError::State(e)) => return Err(ClientError::State(e)),
            Err(e) => outcome.failed.push((m.clone(), e.to_string())),
        }
        Ok(())
    }

    /// Signs and sends a Fetch for `m` from its cursor, opens what comes back,
    /// advances and saves the cursor. Envelopes that fail any drop rule are
    /// skipped without a trace. Spec: § Mailbox Servers (L312, L320–322),
    /// § Envelopes (L233–246), § Wallet behaviour (L374–376).
    pub async fn fetch_one(
        &mut self,
        account: &Account,
        m: &MailboxRef,
        now: u64,
    ) -> Result<Vec<Received>, ClientError> {
        let now_h = hours(now);
        let (key, after) = self.mailbox_key(account, m)?;
        let server = self.servers.server_for(&key.id()).clone();
        let request = FetchRequest::sign(&key, after, now_h, &server.server_id, &mut rand::rng())
            .map_err(|_| ClientError::OsRandomUnavailable)?;
        let frame = self
            .transport
            .request(&server.onion, &request, true)
            .await?
            .ok_or(ClientError::Transport(TransportError::Connect(
                "the server dropped the fetch".into(),
            )))?;
        let items = decode_fetch_response(&frame).ok_or(ClientError::Transport(
            TransportError::Connect("malformed fetch response".into()),
        ))?;

        let mut received = Vec::new();
        let mut cursor = after;
        for item in items {
            cursor = cursor.max(item.seq);
            if let Some(r) = self.open_item(account, m, &item.envelope, now_h)? {
                received.push(r);
            }
        }
        match m {
            MailboxRef::Contact(j) => {
                self.state.contacts.insert(*j, cursor);
            }
            MailboxRef::Pairwise {
                conversation,
                epoch,
            } => {
                if let Some(cs) = self.state.conversations.get_mut(conversation) {
                    cs.fetched(*epoch, cursor, now_h);
                }
            }
        }
        self.state.prune_seen(now_h);
        self.save()?;
        Ok(received)
    }

    /// The signing key and cursor for a mailbox. Spec: § Mailboxes (L266–277).
    fn mailbox_key(
        &self,
        account: &Account,
        m: &MailboxRef,
    ) -> Result<(MailboxKey, u64), ClientError> {
        match m {
            MailboxRef::Contact(j) => {
                let owned = account.owned(*j).ok_or(ClientError::NoMailbox)?;
                let key = contact_mailbox_key(&owned).ok_or(ClientError::NoMailbox)?;
                Ok((key, self.state.contacts.get(j).copied().unwrap_or(0)))
            }
            MailboxRef::Pairwise {
                conversation,
                epoch,
            } => {
                let cs = self
                    .state
                    .conversations
                    .get(conversation)
                    .ok_or(ClientError::UnknownConversation)?;
                let conv = cs.conversation().ok_or(ClientError::UnknownConversation)?;
                let key = pairwise_mailbox_key(&conv, cs.role.receives(), *epoch)
                    .ok_or(ClientError::NoMailbox)?;
                Ok((key, cs.epochs.get(epoch).map_or(0, |s| s.cursor)))
            }
        }
    }

    /// Opens one fetched Envelope as a first Envelope (Contact Mailbox) or in
    /// its Conversation and direction (Pairwise Mailbox). A first Envelope
    /// starts a Conversation in which we are the responder; we do not fetch
    /// its mailboxes until we first send in it. A reply to our first Envelope
    /// lets us send again.
    ///
    /// Spec: § Envelopes (L233–246), § Conversations (L292–299).
    fn open_item(
        &mut self,
        account: &Account,
        m: &MailboxRef,
        envelope: &[u8],
        now_h: u32,
    ) -> Result<Option<Received>, ClientError> {
        match m {
            MailboxRef::Contact(j) => {
                let owned = account.owned(*j).ok_or(ClientError::NoMailbox)?;
                let mut seen = Seen::new(&mut self.state.seen);
                let Ok((message, conv)) = open_first(&owned, envelope, now_h, &mut seen) else {
                    return Ok(None);
                };
                seen.set_expiry(message.expiry_time);
                let id = new_conversation_id()?;
                self.state.conversations.insert(
                    id.clone(),
                    ConversationState::new(&conv, Role::Responder, None),
                );
                Ok(Some(Received {
                    conversation: id,
                    mailbox: m.clone(),
                    message,
                }))
            }
            MailboxRef::Pairwise { conversation, .. } => {
                let Some(cs) = self.state.conversations.get_mut(conversation) else {
                    return Ok(None);
                };
                let conv = cs.conversation().ok_or(ClientError::UnknownConversation)?;
                let mut seen = Seen::new(&mut self.state.seen);
                let Ok(message) = open(&conv, cs.role.receives(), envelope, now_h, &mut seen)
                else {
                    return Ok(None);
                };
                seen.set_expiry(message.expiry_time);
                cs.received_reply = true;
                Ok(Some(Received {
                    conversation: conversation.clone(),
                    mailbox: m.clone(),
                    message,
                }))
            }
        }
    }
}

/// 16 random bytes, hex: a local name for a Conversation, never sent.
/// Spec: none (local bookkeeping).
fn new_conversation_id() -> Result<String, ClientError> {
    let mut b = [0u8; 16];
    getrandom::fill(&mut b).map_err(|_| ClientError::OsRandomUnavailable)?;
    Ok(hex::encode(b))
}

/// Fisher–Yates shuffle from OS randomness, so the fetch order of mailboxes
/// carries no pattern. Spec: § Privacy Implications (L120–122).
fn shuffle<T>(v: &mut [T]) -> Result<(), ClientError> {
    for i in (1..v.len()).rev() {
        let mut b = [0u8; 8];
        getrandom::fill(&mut b).map_err(|_| ClientError::OsRandomUnavailable)?;
        let j = (u64::from_le_bytes(b) % (i as u64 + 1)) as usize;
        v.swap(i, j);
    }
    Ok(())
}
