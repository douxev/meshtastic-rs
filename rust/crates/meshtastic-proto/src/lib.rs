//! Generated [Meshtastic](https://meshtastic.org) protobuf types.
//!
//! This crate is a thin wrapper over [`prost`]-generated code: every message
//! and enum defined under `protobufs/meshtastic/*.proto` is re-exported from
//! the [`meshtastic`] module.
//!
//! The generated code is wire-compatible with all other Meshtastic
//! implementations (firmware, Android, iOS, web, Python, Go, …).
//!
//! # Example
//!
//! ```
//! use meshtastic_proto::meshtastic::{MeshPacket, mesh_packet::PayloadVariant};
//! use prost::Message;
//!
//! let packet = MeshPacket {
//!     from: 0x1234_5678,
//!     to: 0xffff_ffff,
//!     channel: 0,
//!     hop_limit: 3,
//!     want_ack: false,
//!     payload_variant: Some(PayloadVariant::Encrypted(vec![1, 2, 3, 4])),
//!     ..Default::default()
//! };
//!
//! let bytes = packet.encode_to_vec();
//! let decoded = MeshPacket::decode(&bytes[..]).unwrap();
//! assert_eq!(packet, decoded);
//! ```

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

// Re-export `prost` so downstream crates don't need a direct dependency just
// to call `Message::encode` / `Message::decode`.
pub use prost;

/// All generated Meshtastic protobuf types.
///
/// Lints are intentionally relaxed here: this module is produced by
/// `prost-build` from `protobufs/meshtastic/*.proto` and inherits the
/// upstream documentation verbatim, including formatting that doesn't
/// conform to Rust doc conventions. Suppressing the lints in one place
/// keeps `clippy -D warnings` clean across the whole workspace without
/// having to patch generated code.
#[allow(
    clippy::all,
    clippy::pedantic,
    clippy::nursery,
    clippy::restriction,
    clippy::doc_lazy_continuation,
    clippy::doc_overindented_list_items,
    clippy::large_enum_variant,
    clippy::derive_partial_eq_without_eq,
    rustdoc::all,
    missing_docs,
    non_snake_case,
    deprecated,
    unused_qualifications
)]
pub mod meshtastic {
    include!(concat!(env!("OUT_DIR"), "/meshtastic.rs"));
}
