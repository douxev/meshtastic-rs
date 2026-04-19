//! Meshtastic channel-packet cryptography.
//!
//! This crate is a thin, allocation-free, `no_std` implementation of the
//! two small crypto primitives used by Meshtastic channels:
//!
//! - [`channel_hash`] — the XOR-based 8-bit hash that flavours a [`MeshPacket`]
//!   header so receivers can quickly filter packets not encrypted under their
//!   key. Matches the firmware's `Channels::generateHash`.
//! - [`expand_psk`] — expands a channel's stored PSK into an actual AES key:
//!   handles the zero-length "no encryption" case, the 1-byte short-PSK
//!   shorthand (where the byte is a 1-based index into a per-byte-offset
//!   family derived from `DEFAULT_PSK`), and the zero-pad cases for AES-128
//!   and AES-256 when the stored PSK is shorter than the key size.
//! - [`encrypt_packet`] / [`decrypt_packet`] — AES-CTR (128-bit or 256-bit,
//!   chosen by key length) with the nonce layout defined by the firmware:
//!   `packet_id` little-endian u64 || `from_node` little-endian u32 || four
//!   zero bytes. Counter size is 4 bytes.
//!
//! The implementations mirror the C++ firmware behaviour (the "oracle")
//! byte-for-byte; see `test/rust-golden-vectors/gen_vectors.cpp` and the
//! integration tests under `tests/`.
//!
//! **Note on AEAD:** Meshtastic's channel crypto is AES-CTR, which is a
//! confidentiality-only stream mode, **not** authenticated encryption. The
//! protocol does not provide integrity over channel messages; a receiver
//! gets a ciphertext it can always "decrypt" to *something*. That is a
//! property of the on-the-wire protocol, not a bug in this crate. The PKI
//! direct-message path (out of scope here) uses AES-CCM and does provide
//! integrity.
//!
//! [`MeshPacket`]: https://meshtastic.org/docs/

#![cfg_attr(not(feature = "std"), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

use aes::{Aes128, Aes256};
use cipher::{KeyIvInit, StreamCipher};
use ctr::Ctr32BE;
use zeroize::Zeroize;

/// The built-in AES-128 PSK used for the default public channel on all
/// Meshtastic networks. Mirrored from `src/mesh/Channels.h`.
pub const DEFAULT_PSK: [u8; 16] = [
    0xd4, 0xf1, 0xbb, 0x3a, 0x20, 0x29, 0x07, 0x59, 0xf0, 0xbc, 0xff, 0xab, 0xcf, 0x4e, 0x69, 0x01,
];

/// Built-in AES-256 "event" PSK used by event-mode builds. Mirrored from
/// `src/mesh/Channels.h`.
pub const EVENT_PSK: [u8; 32] = [
    0x38, 0x4b, 0xbc, 0xc0, 0x1d, 0xc0, 0x22, 0xd1, 0x81, 0xbf, 0x36, 0xb8, 0x61, 0x21, 0xe1, 0xfb, 0x96, 0xb7, 0x2e,
    0x55, 0xbf, 0x74, 0x22, 0x7e, 0x9d, 0x6a, 0xfb, 0x48, 0xd6, 0x4c, 0xb1, 0xa1,
];

/// Maximum size (in bytes) of a packet payload the firmware will encrypt or
/// decrypt with [`encrypt_packet`] / [`decrypt_packet`]. Mirrors
/// `MAX_BLOCKSIZE` in `src/mesh/CryptoEngine.h`.
pub const MAX_PACKET_PAYLOAD: usize = 256;

/// Errors returned by [`encrypt_packet`] / [`decrypt_packet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoError {
    /// The key length is neither 16 (AES-128) nor 32 (AES-256) bytes.
    ///
    /// Callers must expand short/padded PSKs via [`expand_psk`] before
    /// handing them off.
    InvalidKeyLength(usize),
    /// Payload is larger than [`MAX_PACKET_PAYLOAD`], matching the firmware's
    /// `MAX_BLOCKSIZE` guard.
    PayloadTooLarge(usize),
}

impl core::fmt::Display for CryptoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::InvalidKeyLength(n) => write!(f, "invalid AES key length: {n} (expected 16 or 32)"),
            Self::PayloadTooLarge(n) => write!(
                f,
                "packet payload {n} exceeds MAX_PACKET_PAYLOAD={}",
                MAX_PACKET_PAYLOAD
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for CryptoError {}

// ---------------------------------------------------------------------------
// Channel hash
// ---------------------------------------------------------------------------

/// XOR-based 8-bit hash of a channel name and its (expanded) PSK.
///
/// Matches `Channels::generateHash` in `src/mesh/Channels.cpp:39`. Concretely:
/// XOR all bytes of the UTF-8 channel name, then XOR all bytes of the PSK,
/// returning a single `u8`.
///
/// This is *not* cryptographic; it is used as a quick-filter tag in the
/// packet header so receivers can skip packets they cannot decrypt.
#[must_use]
pub fn channel_hash(name: &str, expanded_psk: &[u8]) -> u8 {
    let mut h = 0u8;
    for &b in name.as_bytes() {
        h ^= b;
    }
    for &b in expanded_psk {
        h ^= b;
    }
    h
}

// ---------------------------------------------------------------------------
// PSK expansion
// ---------------------------------------------------------------------------

/// Expand a stored channel PSK into an actual AES key, returning an empty
/// slice if the channel is unencrypted.
///
/// Mirrors the logic in `Channels::getKey` at `src/mesh/Channels.cpp:228`:
///
/// | Input                               | Output                            |
/// |-------------------------------------|-----------------------------------|
/// | length 0                            | empty (no encryption)             |
/// | length 1, byte == 0                 | empty (no encryption)             |
/// | length 1, byte `i` in `1..=255`     | [`DEFAULT_PSK`] with last byte `+= i - 1` (wraps mod 256), length 16 |
/// | length `2..=15`                     | input zero-padded to 16 bytes     |
/// | length 16                           | unchanged (AES-128)               |
/// | length `17..=31`                    | input zero-padded to 32 bytes     |
/// | length 32                           | unchanged (AES-256)               |
/// | length > 32                         | unchanged (caller beware; matches oracle) |
///
/// The output is always returned as a freshly allocated `Vec<u8>` so the
/// caller can pass it by reference to [`encrypt_packet`] / [`decrypt_packet`]
/// without worrying about lifetimes.
#[must_use]
pub fn expand_psk(psk: &[u8]) -> alloc::vec::Vec<u8> {
    use alloc::vec::Vec;

    if psk.is_empty() {
        return Vec::new();
    }
    if psk.len() == 1 {
        let idx = psk[0];
        if idx == 0 {
            return Vec::new();
        }
        let mut out = DEFAULT_PSK.to_vec();
        // Wrapping add is deliberate: matches the unchecked `uint8_t +=` in C++.
        let last = out.len() - 1;
        out[last] = out[last].wrapping_add(idx - 1);
        return out;
    }
    if psk.len() < 16 {
        let mut out = Vec::with_capacity(16);
        out.extend_from_slice(psk);
        out.resize(16, 0);
        return out;
    }
    if psk.len() < 32 && psk.len() != 16 {
        let mut out = Vec::with_capacity(32);
        out.extend_from_slice(psk);
        out.resize(32, 0);
        return out;
    }
    psk.to_vec()
}

// ---------------------------------------------------------------------------
// Nonce construction
// ---------------------------------------------------------------------------

/// Build the 16-byte AES-CTR IV used for a given channel packet.
///
/// Layout, matching `CryptoEngine::initNonce` in
/// `src/mesh/CryptoEngine.cpp:290`:
///
/// ```text
///   bytes 0..8   : packet_id (u64, little-endian)
///   bytes 8..12  : from_node (u32, little-endian)
///   bytes 12..16 : zero
/// ```
///
/// The trailing four zero bytes are the AES-CTR counter region (counter
/// size 4).
#[must_use]
pub fn build_nonce(from_node: u32, packet_id: u64) -> [u8; 16] {
    let mut nonce = [0u8; 16];
    nonce[..8].copy_from_slice(&packet_id.to_le_bytes());
    nonce[8..12].copy_from_slice(&from_node.to_le_bytes());
    nonce
}

// ---------------------------------------------------------------------------
// AES-CTR packet encryption
// ---------------------------------------------------------------------------

type Aes128Ctr32Be = Ctr32BE<Aes128>;
type Aes256Ctr32Be = Ctr32BE<Aes256>;

/// Encrypt a channel-packet payload in place under AES-CTR.
///
/// `key` must be 16 or 32 bytes (i.e. already passed through
/// [`expand_psk`]). `data` is both input and output; it must be no longer
/// than [`MAX_PACKET_PAYLOAD`]. On success the plaintext is overwritten by
/// ciphertext of the same length.
///
/// AES-CTR is symmetric, so [`decrypt_packet`] is exactly the same
/// operation and the two functions are provided only as documentation.
///
/// # Errors
///
/// Returns [`CryptoError::InvalidKeyLength`] or
/// [`CryptoError::PayloadTooLarge`].
pub fn encrypt_packet(key: &[u8], from_node: u32, packet_id: u64, data: &mut [u8]) -> Result<(), CryptoError> {
    if data.len() > MAX_PACKET_PAYLOAD {
        return Err(CryptoError::PayloadTooLarge(data.len()));
    }
    let iv = build_nonce(from_node, packet_id);

    match key.len() {
        16 => {
            let mut c = Aes128Ctr32Be::new(key.into(), (&iv).into());
            c.apply_keystream(data);
        }
        32 => {
            let mut c = Aes256Ctr32Be::new(key.into(), (&iv).into());
            c.apply_keystream(data);
        }
        n => return Err(CryptoError::InvalidKeyLength(n)),
    }
    Ok(())
}

/// Decrypt a channel-packet payload in place. See [`encrypt_packet`]; the
/// operation is identical because CTR is its own inverse.
///
/// # Errors
///
/// Returns the same errors as [`encrypt_packet`].
#[inline]
pub fn decrypt_packet(key: &[u8], from_node: u32, packet_id: u64, data: &mut [u8]) -> Result<(), CryptoError> {
    encrypt_packet(key, from_node, packet_id, data)
}

// ---------------------------------------------------------------------------
// Zeroizing key wrapper
// ---------------------------------------------------------------------------

/// Owned AES key that zeroes itself on drop.
///
/// This is a thin convenience for callers that want defence-in-depth for
/// key material at rest. All the crypto primitives in this crate accept a
/// raw `&[u8]`, so use of this wrapper is optional.
#[derive(Clone)]
pub struct ChannelKey(alloc::vec::Vec<u8>);

impl ChannelKey {
    /// Build a key from an already-expanded 16- or 32-byte AES key.
    ///
    /// # Errors
    ///
    /// Returns [`CryptoError::InvalidKeyLength`] for any other length.
    pub fn from_expanded(bytes: &[u8]) -> Result<Self, CryptoError> {
        if matches!(bytes.len(), 16 | 32) {
            Ok(Self(bytes.to_vec()))
        } else {
            Err(CryptoError::InvalidKeyLength(bytes.len()))
        }
    }

    /// Expand a raw stored PSK via [`expand_psk`] and wrap the result.
    /// Returns `None` if the channel is unencrypted.
    #[must_use]
    pub fn from_stored_psk(psk: &[u8]) -> Option<Self> {
        let expanded = expand_psk(psk);
        if expanded.is_empty() {
            None
        } else {
            Some(Self(expanded))
        }
    }

    /// Borrow the raw key bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl core::fmt::Debug for ChannelKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ChannelKey(<{} bytes redacted>)", self.0.len())
    }
}

impl Drop for ChannelKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    #[test]
    fn channel_hash_empty() {
        assert_eq!(channel_hash("", &[]), 0);
    }

    #[test]
    fn channel_hash_default_longfast() {
        // Same as the JSON vector but computed inline as a smoke test.
        let h = channel_hash("LongFast", &DEFAULT_PSK);
        let mut x = 0u8;
        for &b in b"LongFast" {
            x ^= b;
        }
        for &b in &DEFAULT_PSK {
            x ^= b;
        }
        assert_eq!(h, x);
    }

    #[test]
    fn expand_empty_and_zero() {
        assert!(expand_psk(&[]).is_empty());
        assert!(expand_psk(&[0]).is_empty());
    }

    #[test]
    fn expand_short_index_1_is_default_psk() {
        assert_eq!(expand_psk(&[1]), DEFAULT_PSK.to_vec());
    }

    #[test]
    fn expand_short_index_bumps_last_byte() {
        let mut expected = DEFAULT_PSK.to_vec();
        let last = expected.len() - 1;
        expected[last] = expected[last].wrapping_add(9); // index 10 → bump by 9
        assert_eq!(expand_psk(&[10]), expected);
    }

    #[test]
    fn expand_short_index_255_wraps() {
        let mut expected = DEFAULT_PSK.to_vec();
        let last = expected.len() - 1;
        expected[last] = expected[last].wrapping_add(254);
        assert_eq!(expand_psk(&[255]), expected);
    }

    #[test]
    fn expand_pads_subkey_to_16() {
        let got = expand_psk(&[1, 2, 3]);
        assert_eq!(got.len(), 16);
        assert_eq!(&got[..3], &[1, 2, 3]);
        assert!(got[3..].iter().all(|&b| b == 0));
    }

    #[test]
    fn expand_pads_subkey_to_32() {
        let input = vec![0xaau8; 17];
        let got = expand_psk(&input);
        assert_eq!(got.len(), 32);
        assert_eq!(&got[..17], &input[..]);
        assert!(got[17..].iter().all(|&b| b == 0));
    }

    #[test]
    fn expand_passthrough_16_and_32() {
        assert_eq!(expand_psk(&DEFAULT_PSK), DEFAULT_PSK.to_vec());
        assert_eq!(expand_psk(&EVENT_PSK), EVENT_PSK.to_vec());
    }

    #[test]
    fn build_nonce_layout() {
        let n = build_nonce(0x12345678, 0x0123_4567_89ab_cdef);
        assert_eq!(&n[..8], &0x0123_4567_89ab_cdef_u64.to_le_bytes());
        assert_eq!(&n[8..12], &0x12345678_u32.to_le_bytes());
        assert_eq!(&n[12..], &[0, 0, 0, 0]);
    }

    #[test]
    fn encrypt_roundtrip_aes128() {
        let mut payload = b"hello world".to_vec();
        let original = payload.clone();
        encrypt_packet(&DEFAULT_PSK, 42, 99, &mut payload).unwrap();
        assert_ne!(payload, original);
        decrypt_packet(&DEFAULT_PSK, 42, 99, &mut payload).unwrap();
        assert_eq!(payload, original);
    }

    #[test]
    fn encrypt_roundtrip_aes256() {
        let mut payload = vec![0x5au8; 100];
        let original = payload.clone();
        encrypt_packet(&EVENT_PSK, 7, 11, &mut payload).unwrap();
        assert_ne!(payload, original);
        decrypt_packet(&EVENT_PSK, 7, 11, &mut payload).unwrap();
        assert_eq!(payload, original);
    }

    #[test]
    fn encrypt_rejects_bad_key_length() {
        let mut payload = [0u8; 1];
        assert_eq!(
            encrypt_packet(&[0u8; 15], 0, 0, &mut payload),
            Err(CryptoError::InvalidKeyLength(15))
        );
        assert_eq!(
            encrypt_packet(&[0u8; 24], 0, 0, &mut payload),
            Err(CryptoError::InvalidKeyLength(24))
        );
    }

    #[test]
    fn encrypt_rejects_oversize_payload() {
        let mut payload = vec![0u8; MAX_PACKET_PAYLOAD + 1];
        assert_eq!(
            encrypt_packet(&DEFAULT_PSK, 0, 0, &mut payload),
            Err(CryptoError::PayloadTooLarge(MAX_PACKET_PAYLOAD + 1))
        );
    }

    #[test]
    fn encrypt_empty_payload_is_noop() {
        let mut payload: [u8; 0] = [];
        encrypt_packet(&DEFAULT_PSK, 0, 0, &mut payload).unwrap();
    }

    #[test]
    fn channel_key_wrapper() {
        let k = ChannelKey::from_expanded(&DEFAULT_PSK).unwrap();
        assert_eq!(k.as_bytes(), &DEFAULT_PSK);
        assert!(ChannelKey::from_expanded(&[0u8; 8]).is_err());
        assert!(ChannelKey::from_stored_psk(&[]).is_none());
        assert!(ChannelKey::from_stored_psk(&[0]).is_none());
        let k2 = ChannelKey::from_stored_psk(&[1]).unwrap();
        assert_eq!(k2.as_bytes(), &DEFAULT_PSK);
        // Debug must not leak key material.
        let dbg = alloc::format!("{k:?}");
        assert!(dbg.contains("redacted"));
        assert!(!dbg.contains("d4f1bb"));
    }
}
