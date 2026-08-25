//! Process-local opaque authority tokens.
//!
//! The key is generated once from the process CSPRNG and is never persisted,
//! logged, or sent over the wire.  Length-prefixed fields keep every token's
//! canonical input unambiguous; callers must provide a fixed domain string.

use std::sync::OnceLock;

use hmac::{Hmac, KeyInit, Mac as _};
use rand::Rng as _;
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

fn process_key() -> &'static [u8; 32] {
    static KEY: OnceLock<[u8; 32]> = OnceLock::new();
    KEY.get_or_init(|| {
        let mut key = [0_u8; 32];
        rand::rng().fill(&mut key);
        key
    })
}

pub(crate) fn mint(domain: &'static [u8], fields: &[&[u8]]) -> String {
    let mut mac =
        <HmacSha256 as KeyInit>::new_from_slice(process_key()).expect("HMAC accepts a 32-byte key");
    mac.update(b"cockpit-daemon-authority-token-v1\0");
    mac.update(&(domain.len() as u64).to_le_bytes());
    mac.update(domain);
    for field in fields {
        mac.update(&(field.len() as u64).to_le_bytes());
        mac.update(field);
    }
    crate::intel::hex_lower(&mac.finalize().into_bytes())
}
