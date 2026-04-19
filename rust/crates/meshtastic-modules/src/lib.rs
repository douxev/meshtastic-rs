//! Meshtastic mesh-protocol modules.
//!
//! This crate is the Rust equivalent of `src/modules/` in the firmware.
//! It provides:
//!
//! - [`module::MeshModule`] — the trait that every feature module
//!   implements, ported from the firmware's `MeshModule` /
//!   `SinglePortModule` pair.
//! - [`module::ModuleDispatcher`] — the "`callModules`" loop that fans
//!   a received packet out to each registered module, honouring
//!   per-module flags (promiscuous, encrypted-ok, loopback-ok,
//!   bound-channel security check) and collecting at most one reply
//!   packet.
//! - [`text_message::TextMessageModule`] — the first concrete port,
//!   mirroring `src/modules/TextMessageModule.cpp`. Tracks a
//!   rolling ring of recently-seen text-message ids (used by
//!   `FloodingRouter::shouldFilterReceived` to implicit-ACK repeated
//!   reliable texts) and stashes the most-recent received text for the
//!   phone/UI layer.
//!
//! Deliberately **not** in scope for this phase: admin messages, UI
//! frames, periodic broadcasts, and the full set of concrete modules
//! (Position, NodeInfo, Routing, …). The trait is shaped so those can
//! slot in without breaking existing callers.

#![cfg_attr(not(any(test, feature = "std")), no_std)]
#![forbid(unsafe_code)]
#![deny(missing_docs)]

extern crate alloc;

pub mod module;
pub mod text_message;

pub use module::{ModuleContext, ModuleDispatcher, ProcessMessage, RxSource};
pub use text_message::TextMessageModule;
