//! Port of `src/modules/TextMessageModule.cpp`.
//!
//! Handles incoming `TEXT_MESSAGE_APP` (plain-text chat) packets:
//!
//! - maintains a fixed-size ring of recently-seen packet ids used by
//!   `FloodingRouter::shouldFilterReceived` as an implicit-ACK signal;
//!   exposed as [`TextMessageModule::recently_seen`]
//! - stashes the most-recent received text packet so the phone/UI can
//!   render it (firmware `devicestate.rx_text_message`); exposed as
//!   [`TextMessageModule::last_text`]
//! - invokes a user-supplied observer closure for every accepted
//!   packet — the Rust analogue of the C++ `Observable<const
//!   meshtastic_MeshPacket *>` pattern

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use meshtastic_proto::meshtastic::{mesh_packet::PayloadVariant, MeshPacket, PortNum};

use crate::module::{MeshModule, ModuleContext, ProcessMessage};

/// Default size of the recently-seen id ring. Matches firmware
/// `TEXT_PACKET_LIST_SIZE = 50` in `src/modules/TextMessageModule.h:4`.
pub const DEFAULT_RECENT_CAPACITY: usize = 50;

/// Observer callback invoked for every accepted text packet.
type Observer = Box<dyn FnMut(&MeshPacket) + Send + 'static>;

/// The text-message module.
pub struct TextMessageModule {
    recent_ids: Vec<u32>,
    recent_idx: usize,
    last_text: Option<MeshPacket>,
    observers: Vec<Observer>,
}

impl core::fmt::Debug for TextMessageModule {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TextMessageModule")
            .field("recent_capacity", &self.recent_ids.len())
            .field("last_text", &self.last_text.as_ref().map(|p| p.id))
            .field("observer_count", &self.observers.len())
            .finish()
    }
}

impl Default for TextMessageModule {
    fn default() -> Self {
        Self::with_recent_capacity(DEFAULT_RECENT_CAPACITY)
    }
}

impl TextMessageModule {
    /// Create a new module with the default ring capacity.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Create a new module with a specific recently-seen ring
    /// capacity. Capacity is clamped to at least 1.
    #[must_use]
    pub fn with_recent_capacity(capacity: usize) -> Self {
        let cap = capacity.max(1);
        Self {
            recent_ids: vec![0; cap],
            recent_idx: 0,
            last_text: None,
            observers: Vec::new(),
        }
    }

    /// Register an observer. Every subsequent accepted text packet
    /// will invoke `cb`. Multiple observers may be registered and
    /// they fire in registration order.
    pub fn add_observer<F>(&mut self, cb: F)
    where
        F: FnMut(&MeshPacket) + Send + 'static,
    {
        self.observers.push(Box::new(cb));
    }

    /// `true` if `id` is in the rolling recently-seen list. Matches
    /// firmware `recentlySeen`. `id == 0` is the empty-slot sentinel
    /// and always returns `false`.
    #[must_use]
    pub fn recently_seen(&self, id: u32) -> bool {
        if id == 0 {
            return false;
        }
        self.recent_ids.contains(&id)
    }

    /// The most-recent text packet we've received, if any.
    #[must_use]
    pub fn last_text(&self) -> Option<&MeshPacket> {
        self.last_text.as_ref()
    }

    /// Clear the "last text" slot. Useful for tests and for the UI
    /// after it has consumed the message.
    pub fn clear_last_text(&mut self) {
        self.last_text = None;
    }

    fn note_id(&mut self, id: u32) {
        if id == 0 {
            return;
        }
        self.recent_ids[self.recent_idx] = id;
        self.recent_idx = (self.recent_idx + 1) % self.recent_ids.len();
    }
}

impl MeshModule for TextMessageModule {
    fn name(&self) -> &str {
        "text"
    }

    fn want_packet(&self, packet: &MeshPacket) -> bool {
        match &packet.payload_variant {
            Some(PayloadVariant::Decoded(d)) => d.portnum == PortNum::TextMessageApp as i32,
            _ => false,
        }
    }

    fn handle_received(&mut self, packet: &MeshPacket, _ctx: &ModuleContext<'_>) -> ProcessMessage {
        self.note_id(packet.id);
        self.last_text = Some(packet.clone());
        for cb in &mut self.observers {
            cb(packet);
        }
        // Firmware returns CONTINUE so later modules (e.g. the routing
        // module that emits ACKs) also get a chance to see the text.
        ProcessMessage::Continue
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::sync::Arc;
    use core::sync::atomic::{AtomicUsize, Ordering};
    use meshtastic_proto::meshtastic::Data;

    fn text(id: u32, body: &[u8]) -> MeshPacket {
        MeshPacket {
            from: 0x42,
            to: 0x1234,
            id,
            payload_variant: Some(PayloadVariant::Decoded(Data {
                portnum: PortNum::TextMessageApp as i32,
                payload: body.to_vec(),
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    fn other(id: u32) -> MeshPacket {
        MeshPacket {
            id,
            payload_variant: Some(PayloadVariant::Decoded(Data {
                portnum: PortNum::PositionApp as i32,
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    fn ctx() -> ModuleContext<'static> {
        ModuleContext {
            our_node_num: 0x1234,
            src: crate::module::RxSource::Radio,
            channel: None,
        }
    }

    #[test]
    fn accepts_only_text_portnum() {
        let m = TextMessageModule::new();
        assert!(m.want_packet(&text(1, b"hi")));
        assert!(!m.want_packet(&other(1)));
    }

    #[test]
    fn encrypted_packets_are_ignored() {
        let m = TextMessageModule::new();
        let p = MeshPacket {
            id: 1,
            payload_variant: Some(PayloadVariant::Encrypted(Vec::new())),
            ..Default::default()
        };
        assert!(!m.want_packet(&p));
    }

    #[test]
    fn handle_records_last_text_and_id() {
        let mut m = TextMessageModule::new();
        assert!(m.last_text().is_none());
        let p = text(42, b"hello");
        let decision = m.handle_received(&p, &ctx());
        assert!(matches!(decision, ProcessMessage::Continue));
        assert!(m.recently_seen(42));
        assert_eq!(m.last_text().unwrap().id, 42);
    }

    #[test]
    fn recently_seen_zero_is_never_true() {
        let m = TextMessageModule::new();
        assert!(!m.recently_seen(0));
    }

    #[test]
    fn ring_evicts_oldest() {
        let mut m = TextMessageModule::with_recent_capacity(3);
        m.handle_received(&text(1, b"a"), &ctx());
        m.handle_received(&text(2, b"b"), &ctx());
        m.handle_received(&text(3, b"c"), &ctx());
        assert!(m.recently_seen(1));
        m.handle_received(&text(4, b"d"), &ctx());
        assert!(!m.recently_seen(1), "oldest must be evicted");
        assert!(m.recently_seen(2));
        assert!(m.recently_seen(3));
        assert!(m.recently_seen(4));
    }

    #[test]
    fn clear_last_text_works() {
        let mut m = TextMessageModule::new();
        m.handle_received(&text(1, b"x"), &ctx());
        assert!(m.last_text().is_some());
        m.clear_last_text();
        assert!(m.last_text().is_none());
    }

    #[test]
    fn observer_is_invoked_per_packet() {
        let mut m = TextMessageModule::new();
        let count = Arc::new(AtomicUsize::new(0));
        let c2 = count.clone();
        m.add_observer(move |_p| {
            c2.fetch_add(1, Ordering::SeqCst);
        });
        m.handle_received(&text(1, b"a"), &ctx());
        m.handle_received(&text(2, b"b"), &ctx());
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn capacity_clamp_to_one() {
        let mut m = TextMessageModule::with_recent_capacity(0);
        m.handle_received(&text(1, b"x"), &ctx());
        assert!(m.recently_seen(1));
        m.handle_received(&text(2, b"y"), &ctx());
        assert!(!m.recently_seen(1));
        assert!(m.recently_seen(2));
    }
}
