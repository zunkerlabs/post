//! Testnet Orchard account keys, stored locally.
//!
//! Spec: `spec/zip-draft-1435.md` § Requirements (L142–146): messaging needs
//! only an account's existing Orchard keys and addresses, no chain access.
//! Keys follow ZIP 32 (`m/32'/1'/account'`, coin type 1 for testnet), derived
//! with the `orchard` crate.

use std::io::Write;
use std::path::Path;

use orchard::keys::{FullViewingKey, Scope, SpendingKey};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
use zunker_client::address::unified_address;
use zunker_client::Account;

/// ZIP 32 coin type for testnet. Spec: none (ZIP 32 / SLIP 44).
const TESTNET_COIN_TYPE: u32 = 1;

/// The key file. The seed is stored unencrypted: testnet only.
/// Spec: § Requirements (L142–146).
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyFile {
    /// Always `"testnet"`.
    network: String,
    /// 32-byte ZIP 32 seed, hex.
    seed: String,
    /// ZIP 32 account index.
    account: u32,
    /// Diversifier indices of the addresses given out; each has a Contact
    /// Mailbox that `fetch` checks.
    indices: Vec<u32>,
}

/// Loaded keys. Spec: § Mailboxes (L266–270).
pub struct Keys {
    fvk: FullViewingKey,
    indices: Vec<u32>,
}

impl Keys {
    /// The account for messaging: external IVK and address indices.
    /// Spec: § Mailboxes (L266–270).
    pub fn account(&self) -> Account {
        Account::new(self.fvk.to_ivk(Scope::External), self.indices.clone())
    }

    /// The testnet Unified Address (Orchard only) at diversifier index `j`.
    /// Spec: § Requirements (L142–144).
    pub fn address(&self, j: u32) -> String {
        unified_address(self.fvk.address_at(j, Scope::External))
    }

    /// The address indices. Spec: § Mailboxes (L266–270).
    pub fn indices(&self) -> &[u32] {
        &self.indices
    }
}

/// Derives the full viewing key of `account` from a ZIP 32 seed.
/// Spec: none (ZIP 32, protocol spec §4.2.3).
fn derive(seed: &[u8], account: u32) -> Result<FullViewingKey, String> {
    let account = zip32::AccountId::try_from(account).map_err(|e| e.to_string())?;
    let sk = SpendingKey::from_zip32_seed(seed, TESTNET_COIN_TYPE, account)
        .map_err(|e| e.to_string())?;
    Ok(FullViewingKey::from(&sk))
}

/// Generates a seed from the OS random generator, derives account 0, and
/// writes the key file with owner-only permissions. Refuses to overwrite an
/// existing key file. Spec: § Requirements (L142–146).
pub fn generate(path: &Path) -> Result<Keys, String> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::fill(&mut *seed).map_err(|e| format!("no OS randomness: {e}"))?;
    let fvk = derive(&*seed, 0)?;
    let mut file = KeyFile {
        network: "testnet".into(),
        seed: hex::encode(&seed[..]),
        account: 0,
        indices: vec![0],
    };
    let json = Zeroizing::new(serde_json::to_vec_pretty(&file).map_err(|e| e.to_string())?);
    zeroize::Zeroize::zeroize(&mut file.seed);
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| match e.kind() {
        std::io::ErrorKind::AlreadyExists => format!(
            "{} already exists; refusing to overwrite existing keys",
            path.display()
        ),
        _ => format!("cannot create {}: {e}", path.display()),
    })?;
    f.write_all(&json)
        .and_then(|_| f.sync_all())
        .map_err(|e| e.to_string())?;
    Ok(Keys {
        fvk,
        indices: file.indices,
    })
}

/// Reads the key file. Spec: § Mailboxes (L266–270).
pub fn load(path: &Path) -> Result<Keys, String> {
    let bytes = Zeroizing::new(std::fs::read(path).map_err(|e| {
        format!(
            "cannot read {} ({e}); run `zunker-cli keygen` first",
            path.display()
        )
    })?);
    let file: KeyFile = serde_json::from_slice(&bytes).map_err(|e| format!("bad key file: {e}"))?;
    let seed = Zeroizing::new(hex::decode(&file.seed).map_err(|_| "bad seed in key file")?);
    if file.network != "testnet" {
        return Err("only testnet keys are supported".into());
    }
    if file.indices.is_empty() {
        return Err("the key file lists no address indices".into());
    }
    Ok(Keys {
        fvk: derive(&seed, file.account)?,
        indices: file.indices,
    })
}

/// A fixed testnet Unified Address, for tests. Spec: none (fixture).
#[cfg(test)]
pub fn tests_address() -> String {
    unified_address(
        derive(&[9u8; 32], 0)
            .unwrap()
            .address_at(0u32, Scope::External),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Generate, reload, same address; a second keygen does not overwrite.
    /// Spec: § Requirements (L142–146).
    #[test]
    fn generate_load_and_no_overwrite() {
        let dir = std::env::temp_dir().join(format!("zunker-keys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("keys.json");
        let k = generate(&path).unwrap();
        let ua = k.address(0);
        assert!(ua.starts_with("utest1"));
        assert_eq!(load(&path).unwrap().address(0), ua);
        let before = std::fs::read(&path).unwrap();
        match generate(&path) {
            Err(e) => assert!(e.contains("refusing to overwrite"), "{e}"),
            Ok(_) => panic!("overwrote existing keys"),
        }
        assert_eq!(std::fs::read(&path).unwrap(), before);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }
        // The account owns its address.
        let owned = k.account().owned(0).unwrap();
        assert_eq!(
            owned.receiver().raw(),
            zunker_client::orchard_receiver(&ua).unwrap().raw()
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// ZIP 32 derivation is deterministic. Spec: none (ZIP 32).
    #[test]
    fn derivation_is_deterministic() {
        let a = derive(&[7u8; 32], 0).unwrap();
        let b = derive(&[7u8; 32], 0).unwrap();
        assert_eq!(a.to_bytes(), b.to_bytes());
        assert_ne!(a.to_bytes(), derive(&[7u8; 32], 1).unwrap().to_bytes());
    }
}
