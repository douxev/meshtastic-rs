//! The MeshPacket encrypt/decrypt pipeline.
//!
//! This is the adapter between the wire-format [`MeshPacket`] (produced
//! and consumed by peer nodes and phones) and the plaintext
//! [`Data`][meshtastic_proto::meshtastic::Data] proto that mesh modules
//! work with.
//!
//! Two top-level entry points:
//!
//! - [`encrypt`]: takes a `MeshPacket` with `PayloadVariant::Decoded(Data)`
//!   and the channel index to send on; serialises the `Data`, encrypts it
//!   in place with [`meshtastic-crypto`], swaps in
//!   `PayloadVariant::Encrypted(bytes)`, and overwrites the packet's
//!   `channel` field with the channel **hash** (per the on-wire
//!   convention documented in `mesh.proto:1542`).
//!
//! - [`decrypt`]: takes a `MeshPacket` with `PayloadVariant::Encrypted(bytes)`,
//!   uses the packet's `channel` field (the 8-bit hash) to enumerate
//!   candidate channel slots, attempts AES-CTR decrypt + protobuf decode
//!   on each, and on success overwrites the packet with
//!   `PayloadVariant::Decoded(Data)` and sets `channel` to the matching
//!   channel **index**.
//!
//! The semantics mirror `Router::send` / `Router::handleReceived` in the
//! firmware. Two quirks are worth calling out:
//!
//! 1. **The `channel` field is overloaded**: it is a channel hash
//!    while the packet is encrypted on the wire, and a channel index
//!    after it has been decrypted. The proto documents this explicitly.
//!    [`encrypt`] and [`decrypt`] maintain that invariant.
//!
//! 2. **AES-CTR is not authenticated.** A receiver cannot distinguish a
//!    genuinely-decryptable packet from one that landed on a matching
//!    hash-tag by coincidence but was encrypted with a different key.
//!    The firmware's (and our) final arbiter is whether the decrypted
//!    plaintext parses as a valid `Data` proto and has a recognised
//!    `portnum`. We reject non-parsing plaintext, which gives a practical
//!    ~2^-N false-accept rate bounded by protobuf structural redundancy.

use alloc::vec::Vec;
use core::fmt;

use meshtastic_crypto::{decrypt_packet, encrypt_packet, CryptoError, MAX_PACKET_PAYLOAD};
use meshtastic_proto::meshtastic::{mesh_packet::PayloadVariant, Data, MeshPacket};
use meshtastic_proto::prost::Message;

use crate::channels::Channels;

/// Errors from the packet-level crypto pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PacketError {
    /// The caller passed a channel index outside the table.
    InvalidChannelIndex(u8),
    /// The channel is disabled, or has an empty PSK with no primary
    /// fallback available.
    ChannelUnencrypted(u8),
    /// [`encrypt`] was called on a packet that was not in the
    /// `Decoded(Data)` state.
    NotDecoded,
    /// [`decrypt`] was called on a packet that was not in the
    /// `Encrypted(bytes)` state.
    NotEncrypted,
    /// [`decrypt`] could not find any channel in the table whose 8-bit
    /// hash matches the packet's `channel` field, or every matching
    /// channel failed to produce a parsable `Data` proto.
    NoMatchingChannel {
        /// The 8-bit channel-hash tag from the packet's `channel` field.
        hash: u8,
    },
    /// Serialising the `Data` proto produced a buffer larger than
    /// [`MAX_PACKET_PAYLOAD`]. The firmware imposes the same limit.
    PayloadTooLarge(usize),
    /// An unexpected error from the crypto primitive. In normal operation
    /// this only fires for [`CryptoError::PayloadTooLarge`] or
    /// [`CryptoError::InvalidKeyLength`], both of which should have been
    /// filtered by the channel table.
    Crypto(CryptoError),
}

impl fmt::Display for PacketError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidChannelIndex(i) => write!(f, "channel index {i} is out of range"),
            Self::ChannelUnencrypted(i) => write!(f, "channel {i} has no usable key"),
            Self::NotDecoded => f.write_str("packet is not in Decoded(Data) state"),
            Self::NotEncrypted => f.write_str("packet is not in Encrypted(bytes) state"),
            Self::NoMatchingChannel { hash } => write!(f, "no channel matches hash 0x{hash:02x}"),
            Self::PayloadTooLarge(n) => {
                write!(
                    f,
                    "serialised Data is {n} bytes, over MAX_PACKET_PAYLOAD={MAX_PACKET_PAYLOAD}"
                )
            }
            Self::Crypto(e) => write!(f, "crypto error: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PacketError {}

impl From<CryptoError> for PacketError {
    fn from(e: CryptoError) -> Self {
        match e {
            CryptoError::PayloadTooLarge(n) => Self::PayloadTooLarge(n),
            other => Self::Crypto(other),
        }
    }
}

/// Encrypt a [`MeshPacket`] on the given channel, in place.
///
/// Preconditions:
/// - `packet.payload_variant` is `Some(PayloadVariant::Decoded(Data))`.
/// - `channel_index` is a valid index into the [`Channels`] table.
/// - The channel has a usable key (primary fallback applies for
///   secondary channels with an empty stored PSK, matching the
///   firmware).
///
/// Postconditions, on success:
/// - `packet.payload_variant` becomes `Some(PayloadVariant::Encrypted(ciphertext))`.
/// - `packet.channel` is set to the channel **hash** as a `u32`, matching
///   the wire convention.
///
/// Packet fields `from`, `to`, `id`, `hop_limit`, `want_ack`, etc. are
/// not touched.
pub fn encrypt(channels: &Channels, channel_index: u8, packet: &mut MeshPacket) -> Result<(), PacketError> {
    // Take ownership of the Data to avoid a clone; we'll replace the
    // variant in one step at the end.
    let data = match packet.payload_variant.take() {
        Some(PayloadVariant::Decoded(d)) => d,
        Some(other) => {
            // Put it back so the caller's packet isn't corrupted on error.
            packet.payload_variant = Some(other);
            return Err(PacketError::NotDecoded);
        }
        None => return Err(PacketError::NotDecoded),
    };

    let slot = match channels.by_index(channel_index) {
        Some(s) => s,
        None => {
            packet.payload_variant = Some(PayloadVariant::Decoded(data));
            return Err(PacketError::InvalidChannelIndex(channel_index));
        }
    };
    let hash = match slot.hash {
        Some(h) => h,
        None => {
            packet.payload_variant = Some(PayloadVariant::Decoded(data));
            return Err(PacketError::ChannelUnencrypted(channel_index));
        }
    };
    let key = match channels.effective_key(channel_index) {
        Some(k) => k,
        None => {
            packet.payload_variant = Some(PayloadVariant::Decoded(data));
            return Err(PacketError::ChannelUnencrypted(channel_index));
        }
    };

    let mut buf: Vec<u8> = Vec::with_capacity(data.encoded_len());
    data.encode(&mut buf).expect("writing to Vec cannot fail");
    if buf.len() > MAX_PACKET_PAYLOAD {
        // Restore the packet state so the caller can react / fragment.
        packet.payload_variant = Some(PayloadVariant::Decoded(data));
        return Err(PacketError::PayloadTooLarge(buf.len()));
    }

    encrypt_packet(key, packet.from, packet.id as u64, &mut buf)?;

    packet.channel = u32::from(hash);
    packet.payload_variant = Some(PayloadVariant::Encrypted(buf));
    Ok(())
}

/// Decrypt a [`MeshPacket`] in place by searching the channel table for a
/// slot whose hash matches the packet's `channel` field.
///
/// Preconditions:
/// - `packet.payload_variant` is `Some(PayloadVariant::Encrypted(bytes))`.
///
/// Postconditions, on success:
/// - `packet.payload_variant` becomes `Some(PayloadVariant::Decoded(Data))`.
/// - `packet.channel` is set to the matching channel **index**, replacing
///   the hash tag.
/// - Returns the matching channel index.
///
/// If multiple channels share the same 8-bit hash (a collision), they are
/// tried in ascending-index order. The first candidate whose plaintext
/// parses as a valid [`Data`] proto wins.
///
/// # Errors
///
/// - [`PacketError::NotEncrypted`] — packet was not in the encrypted
///   state.
/// - [`PacketError::NoMatchingChannel`] — no channel's hash matched or all
///   candidates failed to decode.
pub fn decrypt(channels: &Channels, packet: &mut MeshPacket) -> Result<u8, PacketError> {
    let ciphertext = match packet.payload_variant.take() {
        Some(PayloadVariant::Encrypted(bytes)) => bytes,
        Some(other) => {
            packet.payload_variant = Some(other);
            return Err(PacketError::NotEncrypted);
        }
        None => return Err(PacketError::NotEncrypted),
    };

    // The on-wire channel tag is an 8-bit hash. `packet.channel` is a u32
    // solely because protobuf has no u8; the upper bits are always zero.
    let hash = (packet.channel & 0xff) as u8;

    // Try each candidate channel in ascending index order.
    let mut scratch = Vec::new();
    for (ch_index, _slot) in channels.find_by_hash(hash) {
        let Some(key) = channels.effective_key(ch_index) else {
            continue;
        };
        scratch.clear();
        scratch.extend_from_slice(&ciphertext);
        // AES-CTR cannot fail on valid inputs we already vetted (length
        // ≤ MAX_PACKET_PAYLOAD bound enforced by `encrypt_packet`, or
        // here on decrypt for over-the-wire packets).
        if decrypt_packet(key, packet.from, packet.id as u64, &mut scratch).is_err() {
            continue;
        }
        if let Ok(data) = Data::decode(&scratch[..]) {
            packet.channel = u32::from(ch_index);
            packet.payload_variant = Some(PayloadVariant::Decoded(data));
            return Ok(ch_index);
        }
    }

    // No candidate worked — restore the original ciphertext so the caller
    // can e.g. forward the packet without decoding.
    packet.payload_variant = Some(PayloadVariant::Encrypted(ciphertext));
    Err(PacketError::NoMatchingChannel { hash })
}
