//! Addresses, account keys and payloads: the wallet-side inputs to the core.
//!
//! Spec: `spec/zip-draft-1435.md` § Notation (L187–190) for Receivers, §
//! Payloads (L248–258), and § Requirements (L142–144): a sender needs only the
//! recipient's Unified Address.

use std::fmt;

use orchard::keys::IncomingViewingKey as OrchardIvk;
use zcash_keys::address::Address;
use zcash_protocol::consensus::Network;
use zunker_core::envelope::{payload_type, Message};
use zunker_core::receiver::{IncomingViewingKey, OwnedReceiver, Receiver};

/// Every key and address here is for testnet. Spec: none (project status).
pub const NETWORK: Network = Network::TestNetwork;

/// How long an Envelope stays valid by default: 30 days, the reference
/// server's default retention. Spec: § Envelopes (L207, L242).
pub const DEFAULT_EXPIRY_HOURS: u32 = 30 * 24;

/// Why an address or payload was rejected.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddressError {
    /// Not a testnet Unified Address.
    NotTestnetUnified,
    /// The Unified Address has no Orchard Receiver.
    NoOrchardReceiver,
    /// The Orchard Receiver is not usable (its mailbox derivation fails).
    BadReceiver,
    /// Not a valid ZIP 321 payment request URI.
    BadPaymentRequest(String),
}

impl fmt::Display for AddressError {
    /// Spec: none (diagnostics only).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AddressError::NotTestnetUnified => f.write_str("not a testnet Unified Address"),
            AddressError::NoOrchardReceiver => {
                f.write_str("the Unified Address has no Orchard receiver")
            }
            AddressError::BadReceiver => f.write_str("unusable Orchard receiver"),
            AddressError::BadPaymentRequest(why) => {
                write!(f, "not a valid ZIP 321 payment request: {why}")
            }
        }
    }
}

impl std::error::Error for AddressError {}

/// The Orchard Receiver of a testnet Unified Address.
///
/// Spec: § Notation (L187–190), § Requirements (L142–144).
pub fn orchard_receiver(ua: &str) -> Result<Receiver, AddressError> {
    let Some(Address::Unified(ua)) = Address::decode(&NETWORK, ua.trim()) else {
        return Err(AddressError::NotTestnetUnified);
    };
    let orchard = ua.orchard().ok_or(AddressError::NoOrchardReceiver)?;
    Receiver::from_raw(&orchard.to_raw_address_bytes()).ok_or(AddressError::BadReceiver)
}

/// The testnet Unified Address with only this Orchard Receiver.
///
/// Spec: § Requirements (L142–144); ZIP 316 encoding is `zcash_keys`'.
pub fn unified_address(orchard: orchard::Address) -> String {
    // `from_receivers` takes a Sapling argument only with zcash_keys' `sapling`
    // feature, which this workspace keeps off.
    zcash_keys::address::UnifiedAddress::from_receivers(Some(orchard), None, None, None)
        .expect("an Orchard receiver is enough for a Unified Address")
        .encode(&NETWORK)
}

/// An account's Orchard incoming viewing key and the diversifier indices of
/// the addresses it has given out. Each index has its own Contact Mailbox.
///
/// Spec: § Mailboxes (L266–270), § Privacy Implications (L106–110).
#[derive(Clone, Debug)]
pub struct Account {
    ivk: OrchardIvk,
    indices: Vec<u32>,
}

impl Account {
    /// An account from its external-scope Orchard IVK. Spec: § Notation (L187–190).
    pub fn new(ivk: OrchardIvk, indices: Vec<u32>) -> Self {
        Account { ivk, indices }
    }

    /// The diversifier indices whose Contact Mailboxes are fetched.
    /// Spec: § Mailboxes (L266–270).
    pub fn indices(&self) -> &[u32] {
        &self.indices
    }

    /// The owned Receiver at diversifier index `j`. Spec: § Notation (L187–190).
    pub fn owned(&self, j: u32) -> Option<OwnedReceiver> {
        let ivk = IncomingViewingKey::from_bytes(&self.ivk.to_bytes())?;
        let raw = self.ivk.address_at(j).to_raw_address_bytes();
        OwnedReceiver::new(ivk, Receiver::from_raw(&raw)?)
    }
}

/// A Text payload expiring [`DEFAULT_EXPIRY_HOURS`] after `now_hours`.
/// Spec: § Payloads (L252).
pub fn text(text: &str, now_hours: u32) -> Message {
    Message {
        payload_type: payload_type::TEXT,
        ack_requested: false,
        expiry_time: now_hours.saturating_add(DEFAULT_EXPIRY_HOURS),
        fast_reply: Vec::new(),
        payload: text.as_bytes().to_vec(),
    }
}

/// A Payment request payload, after checking that `uri` parses as ZIP 321.
/// Spec: § Payloads (L253).
pub fn payment_request(uri: &str, now_hours: u32) -> Result<Message, AddressError> {
    let uri = uri.trim();
    zip321::TransactionRequest::from_uri(uri)
        .map_err(|e| AddressError::BadPaymentRequest(e.to_string()))?;
    Ok(Message {
        payload_type: payload_type::PAYMENT_REQUEST,
        ack_requested: false,
        expiry_time: now_hours.saturating_add(DEFAULT_EXPIRY_HOURS),
        fast_reply: Vec::new(),
        payload: uri.as_bytes().to_vec(),
    })
}

/// A Payment request payload whose single payment carries `text` as its
/// ZIP 321 `message`, so a note travels with the request in one Envelope.
/// The URI is re-encoded by the `zip321` crate, which percent-encodes the
/// message. Rejects requests with several payments (which one would the
/// note belong to?) and ones that already have a message.
///
/// Spec: § Payloads (L253); ZIP 321 `message` parameter.
pub fn payment_request_with_message(
    uri: &str,
    text: &str,
    now_hours: u32,
) -> Result<Message, AddressError> {
    let bad = |why: &str| AddressError::BadPaymentRequest(why.to_owned());
    let req = zip321::TransactionRequest::from_uri(uri.trim())
        .map_err(|e| AddressError::BadPaymentRequest(e.to_string()))?;
    let payments = req.payments();
    if payments.len() != 1 {
        return Err(bad(
            "a text can only be attached to a request with exactly one payment",
        ));
    }
    let p = payments.values().next().expect("one payment");
    if p.message().is_some() {
        return Err(bad("the request already has a message"));
    }
    let with_text = zip321::Payment::new(
        p.recipient_address().clone(),
        p.amount(),
        p.memo().cloned(),
        p.label().cloned(),
        Some(text.to_owned()),
        p.other_params().to_vec(),
    )
    .map_err(|e| AddressError::BadPaymentRequest(e.to_string()))?;
    let uri = zip321::TransactionRequest::new(vec![with_text])
        .map_err(|e| AddressError::BadPaymentRequest(e.to_string()))?
        .to_uri();
    payment_request(&uri, now_hours)
}

#[cfg(test)]
pub(crate) mod testing {
    use orchard::keys::{FullViewingKey, Scope, SpendingKey};

    use super::*;

    /// A deterministic test account `n` and its Unified Address at index 0.
    /// Spec: none (test fixture).
    pub(crate) fn account(n: u8) -> (Account, String) {
        let sk = (0u8..=255)
            .find_map(|i| {
                SpendingKey::from_bytes([n, i, 0x5a, 0xa5].repeat(8).try_into().unwrap())
                    .into_option()
            })
            .unwrap();
        let fvk = FullViewingKey::from(&sk);
        let addr = fvk.address_at(0u32, Scope::External);
        (
            Account::new(fvk.to_ivk(Scope::External), vec![0]),
            unified_address(addr),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::testing::account;
    use super::*;

    /// A testnet UA yields its Orchard Receiver, which the account owns.
    /// Spec: § Notation (L187–190).
    #[test]
    fn ua_round_trip() {
        let (acct, ua) = account(1);
        assert!(ua.starts_with("utest1"));
        let r = orchard_receiver(&ua).unwrap();
        assert_eq!(r.raw(), acct.owned(0).unwrap().receiver().raw());
        assert!(orchard_receiver("not an address").is_err());
        assert_eq!(
            orchard_receiver(&ua.replacen("utest1", "u1", 1)),
            Err(AddressError::NotTestnetUnified)
        );
    }

    /// ZIP 321 URIs are checked before sending. Spec: § Payloads (L253).
    #[test]
    fn payment_requests_are_validated() {
        let (_, ua) = account(1);
        let uri = format!("zcash:{ua}?amount=0.5&message=lunch");
        let m = payment_request(&uri, 100).unwrap();
        assert_eq!(m.payload_type, payload_type::PAYMENT_REQUEST);
        assert_eq!(m.payload, uri.as_bytes());
        assert_eq!(m.expiry_time, 100 + DEFAULT_EXPIRY_HOURS);
        assert!(payment_request("https://example.com", 100).is_err());
        assert!(payment_request("zcash:?amount=1", 100).is_err());
    }

    /// The text becomes the payment's `message`, percent-encoded, and parses
    /// back unchanged; everything else in the request is kept.
    /// Spec: § Payloads (L253); ZIP 321.
    #[test]
    fn text_goes_into_message() {
        let (_, ua) = account(1);
        let note = "Zunker Post demo & co: 100% ?=#";
        let uri = format!("zcash:{ua}?amount=0.1&label=Shop");
        let m = payment_request_with_message(&uri, note, 7).unwrap();
        assert_eq!(m.payload_type, payload_type::PAYMENT_REQUEST);
        let sent = std::str::from_utf8(&m.payload).unwrap();
        assert!(
            !sent.contains(' ') && !sent.contains('#'),
            "percent-encoded: {sent}"
        );
        assert_eq!(
            sent.matches('&').count(),
            2,
            "only the parameter separators: {sent}"
        );
        let back = zip321::TransactionRequest::from_uri(sent).unwrap();
        let p = &back.payments()[&0];
        assert_eq!(p.message().unwrap(), note);
        assert_eq!(p.label().unwrap(), "Shop");
        assert_eq!(p.amount().unwrap().into_u64(), 10_000_000);
        assert_eq!(p.recipient_address().encode(), ua);

        // Already has a message, or several payments: refused.
        let has = format!("zcash:{ua}?amount=0.1&message=hi");
        assert!(payment_request_with_message(&has, note, 7).is_err());
        let two = format!("zcash:?address={ua}&amount=0.1&address.1={ua}&amount.1=0.2");
        assert!(payment_request_with_message(&two, note, 7).is_err());
        assert!(payment_request_with_message("https://x", note, 7).is_err());
    }
}
