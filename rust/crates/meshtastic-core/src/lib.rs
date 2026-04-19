//! Meshtastic mesh-protocol core types.
//!
//! This crate is a ground-floor layer sitting between [`meshtastic-proto`]
//! (wire types) and [`meshtastic-crypto`] (AES-CTR primitives) on the one
//! hand, and higher-level routing / module code on the other. It provides
//! the two fundamental building blocks that every mesh action needs:
//!
//! - [`channels::Channels`] — an 8-slot channel table with precomputed
//!   per-slot expanded PSK and 8-bit hash, matching the firmware's
//!   `Channels` class (`src/mesh/Channels.cpp`).
//! - [`packet::encrypt`] / [`packet::decrypt`] — the MeshPacket
//!   encrypt/decrypt pipeline: transforms a `MeshPacket` with
//!   `PayloadVariant::Decoded(Data)` into one with
//!   `PayloadVariant::Encrypted(bytes)` (and vice-versa) by serialising
//!   the `Data` proto, running [`meshtastic-crypto`] over it with the
//!   correct nonce, and populating the packet's `channel` field with the
//!   channel *hash* (wire convention) or *index* (local convention) as
//!   appropriate.
//!
//! Deliberately **not** in scope for this phase:
//!
//! - NodeDB (known-nodes table with LRU eviction) — planned for Phase 4b.
//! - Router (retransmission, flood, priority queue) — planned for 4b.
//! - PKI / Curve25519 DM encryption — planned for a later phase; the
//!   `pki_encrypted`/`public_key` fields on `MeshPacket` are passed
//!   through untouched today.
//! - Persistence to flash — the `Channels` type roundtrips to
//!   [`ChannelFile`][meshtastic_proto::meshtastic::ChannelFile] so that
//!   the platform layer can persist it however it likes.
//!
//! # Quick example
//!
//! ```
//! use meshtastic_core::{channels::Channels, packet};
//! use meshtastic_proto::meshtastic::{Data, MeshPacket, PortNum,
//!     mesh_packet::PayloadVariant};
//!
//! let channels = Channels::with_default_primary();
//! let primary = channels.primary_index();
//!
//! let mut pkt = MeshPacket {
//!     from: 0x1234_5678,
//!     to: 0xffff_ffff,
//!     id: 0xcafe_f00d,
//!     channel: primary as u32,
//!     payload_variant: Some(PayloadVariant::Decoded(Data {
//!         portnum: PortNum::TextMessageApp as i32,
//!         payload: b"hello mesh".to_vec(),
//!         ..Default::default()
//!     })),
//!     ..Default::default()
//! };
//!
//! packet::encrypt(&channels, primary, &mut pkt).unwrap();
//! assert!(matches!(pkt.payload_variant, Some(PayloadVariant::Encrypted(_))));
//!
//! let idx = packet::decrypt(&channels, &mut pkt).unwrap();
//! assert_eq!(idx, primary);
//! match pkt.payload_variant {
//!     Some(PayloadVariant::Decoded(data)) => {
//!         assert_eq!(data.payload, b"hello mesh");
//!     }
//!     _ => panic!("expected decoded after decrypt"),
//! }
//! ```

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

pub mod channels;
pub mod packet;

pub use channels::{ChannelSlot, Channels, ChannelsError, MAX_NUM_CHANNELS};
pub use packet::{decrypt, encrypt, PacketError};
