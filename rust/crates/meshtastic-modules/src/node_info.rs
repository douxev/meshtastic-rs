//! Port of `src/modules/NodeInfoModule.cpp`.
//!
//! The firmware's `NodeInfoModule` is a
//! `ProtobufModule<meshtastic_User>` that:
//!
//! 1. Decodes an incoming `User` protobuf from a `NODEINFO_APP` payload.
//! 2. Updates the local `NodeDB` entry for the sender (`updateUser`),
//!    stamping the node's `channel` and `has_user` flags.
//! 3. Applies a 12-hour "don't reply to the same requester I just
//!    replied to" suppression window (`lastNodeInfoSeen` map).
//! 4. On demand, produces a reply packet whose payload is our own
//!    `User` protobuf (`allocReply`).
//! 5. Periodically broadcasts its own `User` (the `runOnce` / airTime
//!    throttling path — deferred; belongs with the HAL phase).
//!
//! In this Rust port the module is **pure**: it does not hold a
//! `NodeDb` handle. Instead it records
//! [`NodeUserUpdate`]s that the integrating code drains with
//! [`NodeInfoModule::take_pending_updates`] and applies to its own
//! `NodeDb`. This keeps `MeshModule` object-safe and avoids lifetime
//! gymnastics while still faithfully mirroring the on-wire behaviour.
//!
//! Also deliberately out of scope for this slice:
//!
//! - The airTime / `transmitHistory` throttle in `allocReply`. That
//!   belongs with the HAL-phase scheduler; for now every
//!   non-suppressed request gets a reply.
//! - The "re-encode with coerced `user.id`" payload rewrite the
//!   firmware does for non-broadcast non-to-us packets so the phone
//!   sees a normalised id. The `NodeUserUpdate.user.id` returned here
//!   is already normalised, so consumers that forward to a phone can
//!   re-encode on their side.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;

use meshtastic_core::mesh::{get_from, is_from_us, NodeNum};
use meshtastic_proto::meshtastic::{mesh_packet::PayloadVariant, Data, MeshPacket, PortNum, User};
use prost::Message;

use crate::module::{MeshModule, ModuleContext, ProcessMessage};

/// 12 hours in seconds. Matches firmware
/// `USERPREFS_NODEINFO_REPLY_SUPPRESS_SECS = 12 * 60 * 60` in
/// `src/modules/NodeInfoModule.cpp:15`.
pub const DEFAULT_REPLY_SUPPRESS_SECS: u32 = 12 * 60 * 60;

/// An update that the integrating code should apply to its `NodeDb`
/// after a successful packet dispatch.
///
/// Mirrors the side-effects of the firmware's
/// `NodeDB::updateUser(nodeId, p, channelIndex)` in
/// `src/mesh/NodeDB.cpp:1857`.
#[derive(Debug, Clone, PartialEq)]
pub struct NodeUserUpdate {
    /// The node this `User` belongs to (derived via `get_from`).
    pub num: NodeNum,
    /// The decoded (and id-normalised) `User` protobuf.
    pub user: User,
    /// Channel index the packet arrived on. Firmware records this on
    /// the `NodeInfoLite.channel` field so future unicast replies know
    /// which channel to use.
    pub channel: u32,
}

/// The nodeinfo module.
pub struct NodeInfoModule {
    our_node_num: NodeNum,
    owner: User,
    last_node_info_seen: BTreeMap<NodeNum, u32>,
    pending_updates: Vec<NodeUserUpdate>,
    suppress_reply_for_current_request: bool,
    last_reply_suppressed: bool,
    suppress_secs: u32,
    last_node_info_seen_capacity: usize,
}

impl core::fmt::Debug for NodeInfoModule {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NodeInfoModule")
            .field("our_node_num", &self.our_node_num)
            .field("owner_long_name", &self.owner.long_name)
            .field("owner_short_name", &self.owner.short_name)
            .field("pending_updates", &self.pending_updates.len())
            .field("last_seen_entries", &self.last_node_info_seen.len())
            .finish()
    }
}

impl NodeInfoModule {
    /// Create a new NodeInfo module.
    ///
    /// `our_node_num` is used for:
    /// - dropping packets that claim to be from us (`mp.from ==
    ///   our_node_num`),
    /// - coercing `user.id` to `!xxxxxxxx` form from the sender's
    ///   node number, matching firmware
    ///   `src/modules/NodeInfoModule.cpp:54` and `…:81`.
    ///
    /// `owner` is the local node's `User` protobuf; its fields are
    /// returned as the reply body. The `id` is recomputed on every
    /// reply from `our_node_num`, so callers don't have to keep it in
    /// sync.
    #[must_use]
    pub fn new(our_node_num: NodeNum, owner: User) -> Self {
        Self {
            our_node_num,
            owner,
            last_node_info_seen: BTreeMap::new(),
            pending_updates: Vec::new(),
            suppress_reply_for_current_request: false,
            last_reply_suppressed: false,
            suppress_secs: DEFAULT_REPLY_SUPPRESS_SECS,
            last_node_info_seen_capacity: 80,
        }
    }

    /// Override the reply-suppression window. Defaults to
    /// [`DEFAULT_REPLY_SUPPRESS_SECS`] (12 h).
    pub fn set_suppress_secs(&mut self, secs: u32) -> &mut Self {
        self.suppress_secs = secs;
        self
    }

    /// Cap on the `last_node_info_seen` LRU map. Firmware prunes down
    /// to `meshNodes->size()`; we let callers bound it directly and
    /// default to the same `MAX_NUM_NODES = 80` figure as the ESP32
    /// build.
    pub fn set_last_seen_capacity(&mut self, cap: usize) -> &mut Self {
        self.last_node_info_seen_capacity = cap.max(1);
        self.prune_last_seen_cache();
        self
    }

    /// Update the local owner protobuf. Used when the user changes
    /// their name / short name / role, etc.
    pub fn set_owner(&mut self, owner: User) -> &mut Self {
        self.owner = owner;
        self
    }

    /// Our own `User` protobuf (as it would go on the wire, with a
    /// normalised id).
    #[must_use]
    pub fn owner(&self) -> User {
        self.render_owner()
    }

    /// Drain pending `NodeDb` updates. The integrating code should
    /// call this after [`ModuleDispatcher::dispatch`] returns and
    /// apply each update to its `NodeDb`.
    #[must_use]
    pub fn take_pending_updates(&mut self) -> Vec<NodeUserUpdate> {
        core::mem::take(&mut self.pending_updates)
    }

    /// `true` if the most recent `alloc_reply` call suppressed the
    /// reply because the requester was heard from within the
    /// suppression window. Mirrors firmware `ignoreRequest`.
    #[must_use]
    pub fn last_reply_was_suppressed(&self) -> bool {
        self.last_reply_suppressed
    }

    fn render_owner(&self) -> User {
        let mut u = self.owner.clone();
        u.id = format_user_id(self.our_node_num);
        // Strip the public key if licensed, per firmware
        // `src/modules/NodeInfoModule.cpp:165`.
        if u.is_licensed {
            u.public_key.clear();
        }
        u
    }

    fn prune_last_seen_cache(&mut self) {
        while self.last_node_info_seen.len() > self.last_node_info_seen_capacity {
            // Evict the oldest entry.
            if let Some((&key, _)) = self.last_node_info_seen.iter().min_by_key(|(_, &ts)| ts) {
                self.last_node_info_seen.remove(&key);
            } else {
                break;
            }
        }
    }
}

/// Format a node number as `!xxxxxxxx`, matching firmware
/// `snprintf(p.id, sizeof(p.id), "!%08x", nodeId)` in
/// `src/mesh/NodeDB.cpp:1898`.
fn format_user_id(num: NodeNum) -> String {
    let mut s = String::with_capacity(9);
    s.push('!');
    // Lower-case hex, zero-padded to 8 chars.
    let mut buf = [0u8; 8];
    for (i, b) in buf.iter_mut().enumerate() {
        let shift = 4 * (7 - i);
        let nibble = ((num >> shift) & 0xf) as u8;
        *b = match nibble {
            0..=9 => b'0' + nibble,
            _ => b'a' + (nibble - 10),
        };
    }
    // SAFETY equivalent: all bytes are ASCII hex digits.
    s.push_str(core::str::from_utf8(&buf).unwrap_or("00000000"));
    s
}

impl MeshModule for NodeInfoModule {
    fn name(&self) -> &str {
        "nodeinfo"
    }

    fn is_promiscuous(&self) -> bool {
        // Matches firmware `isPromiscuous = true` in
        // `src/modules/NodeInfoModule.cpp:209`: we want to update the
        // NodeDB even for packets that are only passing through.
        true
    }

    fn want_packet(&self, packet: &MeshPacket) -> bool {
        match &packet.payload_variant {
            Some(PayloadVariant::Decoded(d)) => d.portnum == PortNum::NodeinfoApp as i32,
            _ => false,
        }
    }

    fn handle_received(&mut self, packet: &MeshPacket, _ctx: &ModuleContext<'_>) -> ProcessMessage {
        self.suppress_reply_for_current_request = false;

        // `mp.from == our_node_num` → firmware logs a warning and
        // returns (no update).
        if packet.from == self.our_node_num {
            return ProcessMessage::Continue;
        }

        let data = match &packet.payload_variant {
            Some(PayloadVariant::Decoded(d)) => d,
            _ => return ProcessMessage::Continue,
        };

        let mut user = match User::decode(data.payload.as_slice()) {
            Ok(u) => u,
            Err(_) => return ProcessMessage::Continue,
        };

        // Suppression window: if we've replied to this same requester
        // within `suppress_secs`, skip the reply.
        if data.want_response && !is_from_us(packet, self.our_node_num) {
            let sender = get_from(packet, self.our_node_num);
            let now = if packet.rx_time != 0 { packet.rx_time } else { 0 };
            if let Some(&last) = self.last_node_info_seen.get(&sender) {
                let since = now.saturating_sub(last);
                if since < self.suppress_secs {
                    self.suppress_reply_for_current_request = true;
                }
            }
            self.last_node_info_seen.insert(sender, now);
            self.prune_last_seen_cache();
        }

        // is_licensed mismatch → drop (firmware returns `true`, i.e.
        // STOP, to avoid confusing downstream consumers).
        if user.is_licensed != self.owner.is_licensed {
            return ProcessMessage::Stop;
        }

        // Normalise user.id from node number.
        let num = get_from(packet, self.our_node_num);
        user.id = format_user_id(num);

        self.pending_updates.push(NodeUserUpdate {
            num,
            user,
            channel: packet.channel,
        });

        ProcessMessage::Continue
    }

    fn alloc_reply(&mut self, _request: &MeshPacket) -> Option<MeshPacket> {
        if self.suppress_reply_for_current_request {
            self.suppress_reply_for_current_request = false;
            self.last_reply_suppressed = true;
            return None;
        }
        self.last_reply_suppressed = false;

        let owner = self.render_owner();
        let mut buf = Vec::with_capacity(owner.encoded_len());
        owner.encode(&mut buf).ok()?;

        Some(MeshPacket {
            from: 0,
            to: 0,
            payload_variant: Some(PayloadVariant::Decoded(Data {
                portnum: PortNum::NodeinfoApp as i32,
                payload: buf,
                ..Default::default()
            })),
            ..Default::default()
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshtastic_proto::meshtastic::HardwareModel;

    const OURS: NodeNum = 0x1000_0000;
    const PEER: NodeNum = 0x2000_0000;

    fn owner() -> User {
        User {
            id: "!old_id".into(),
            long_name: "Alice".into(),
            short_name: "Al".into(),
            hw_model: HardwareModel::TDeck as i32,
            ..Default::default()
        }
    }

    fn mk_peer_user(name: &str) -> User {
        User {
            id: "!bogus".into(),
            long_name: name.into(),
            short_name: "BB".into(),
            hw_model: HardwareModel::HeltecV1 as i32,
            ..Default::default()
        }
    }

    fn nodeinfo_packet(from: NodeNum, to: NodeNum, id: u32, user: &User, want_response: bool) -> MeshPacket {
        let mut buf = Vec::with_capacity(user.encoded_len());
        user.encode(&mut buf).unwrap();
        MeshPacket {
            from,
            to,
            id,
            channel: 0,
            rx_time: 1_700_000_000,
            payload_variant: Some(PayloadVariant::Decoded(Data {
                portnum: PortNum::NodeinfoApp as i32,
                payload: buf,
                want_response,
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    fn ctx() -> ModuleContext<'static> {
        ModuleContext {
            our_node_num: OURS,
            src: crate::module::RxSource::Radio,
            channel: None,
        }
    }

    #[test]
    fn accepts_nodeinfo_portnum_only() {
        let m = NodeInfoModule::new(OURS, owner());
        assert!(m.want_packet(&nodeinfo_packet(PEER, OURS, 1, &mk_peer_user("Bob"), false)));
        let mut other = nodeinfo_packet(PEER, OURS, 1, &mk_peer_user("Bob"), false);
        if let Some(PayloadVariant::Decoded(d)) = other.payload_variant.as_mut() {
            d.portnum = PortNum::TextMessageApp as i32;
        }
        assert!(!m.want_packet(&other));
    }

    #[test]
    fn is_promiscuous() {
        let m = NodeInfoModule::new(OURS, owner());
        assert!(m.is_promiscuous());
    }

    #[test]
    fn self_originated_packets_produce_no_update() {
        let mut m = NodeInfoModule::new(OURS, owner());
        let p = nodeinfo_packet(OURS, PEER, 1, &mk_peer_user("Self"), false);
        m.handle_received(&p, &ctx());
        assert!(m.take_pending_updates().is_empty());
    }

    #[test]
    fn update_is_recorded_and_user_id_normalised() {
        let mut m = NodeInfoModule::new(OURS, owner());
        let p = nodeinfo_packet(PEER, OURS, 1, &mk_peer_user("Bob"), false);
        m.handle_received(&p, &ctx());
        let updates = m.take_pending_updates();
        assert_eq!(updates.len(), 1);
        assert_eq!(updates[0].num, PEER);
        assert_eq!(updates[0].user.long_name, "Bob");
        assert_eq!(updates[0].user.id, "!20000000");
        assert_eq!(updates[0].channel, 0);
    }

    #[test]
    fn license_mismatch_drops_update_and_stops_chain() {
        let mut m = NodeInfoModule::new(OURS, owner());
        let mut bob = mk_peer_user("Bob");
        bob.is_licensed = true;
        let p = nodeinfo_packet(PEER, OURS, 1, &bob, false);
        let decision = m.handle_received(&p, &ctx());
        assert!(matches!(decision, ProcessMessage::Stop));
        assert!(m.take_pending_updates().is_empty());
    }

    #[test]
    fn alloc_reply_returns_encoded_owner_user() {
        let mut m = NodeInfoModule::new(OURS, owner());
        let p = nodeinfo_packet(PEER, OURS, 1, &mk_peer_user("Bob"), true);
        m.handle_received(&p, &ctx());
        let reply = m.alloc_reply(&p).expect("expected a reply");
        let data = match reply.payload_variant {
            Some(PayloadVariant::Decoded(d)) => d,
            _ => panic!("reply must be decoded"),
        };
        assert_eq!(data.portnum, PortNum::NodeinfoApp as i32);
        let decoded = User::decode(data.payload.as_slice()).unwrap();
        assert_eq!(decoded.long_name, "Alice");
        assert_eq!(decoded.id, "!10000000");
    }

    #[test]
    fn reply_is_suppressed_within_window_for_same_requester() {
        let mut m = NodeInfoModule::new(OURS, owner());
        let p1 = nodeinfo_packet(PEER, OURS, 1, &mk_peer_user("Bob"), true);
        m.handle_received(&p1, &ctx());
        let _ = m.alloc_reply(&p1).unwrap();

        // Second request from same peer within the default 12h window.
        let mut p2 = nodeinfo_packet(PEER, OURS, 2, &mk_peer_user("Bob"), true);
        if let Some(PayloadVariant::Decoded(_)) = p2.payload_variant.as_ref() {
            p2.rx_time = 1_700_000_000 + 60; // 1 minute later
        }
        m.handle_received(&p2, &ctx());
        assert!(m.alloc_reply(&p2).is_none(), "reply must be suppressed");
        assert!(m.last_reply_was_suppressed());
    }

    #[test]
    fn reply_is_not_suppressed_after_window() {
        let mut m = NodeInfoModule::new(OURS, owner());
        m.set_suppress_secs(30); // very short window for test
        let p1 = nodeinfo_packet(PEER, OURS, 1, &mk_peer_user("Bob"), true);
        m.handle_received(&p1, &ctx());
        let _ = m.alloc_reply(&p1).unwrap();

        let mut p2 = nodeinfo_packet(PEER, OURS, 2, &mk_peer_user("Bob"), true);
        p2.rx_time = 1_700_000_000 + 60; // 60s later > 30s window
        m.handle_received(&p2, &ctx());
        assert!(m.alloc_reply(&p2).is_some(), "reply must be sent");
        assert!(!m.last_reply_was_suppressed());
    }

    #[test]
    fn suppression_is_per_requester() {
        let mut m = NodeInfoModule::new(OURS, owner());
        let p1 = nodeinfo_packet(PEER, OURS, 1, &mk_peer_user("Bob"), true);
        m.handle_received(&p1, &ctx());
        let _ = m.alloc_reply(&p1).unwrap();

        let other_peer = 0x3000_0000;
        let p2 = nodeinfo_packet(other_peer, OURS, 2, &mk_peer_user("Carol"), true);
        m.handle_received(&p2, &ctx());
        assert!(m.alloc_reply(&p2).is_some());
    }

    #[test]
    fn licensed_owner_public_key_is_stripped_from_reply() {
        let mut owner_u = owner();
        owner_u.is_licensed = true;
        owner_u.public_key = vec![0xab; 32];
        let mut m = NodeInfoModule::new(OURS, owner_u);
        let mut bob = mk_peer_user("Bob");
        bob.is_licensed = true; // must match to avoid drop
        let p = nodeinfo_packet(PEER, OURS, 1, &bob, true);
        m.handle_received(&p, &ctx());
        let reply = m.alloc_reply(&p).unwrap();
        let Some(PayloadVariant::Decoded(d)) = reply.payload_variant else {
            panic!()
        };
        let decoded = User::decode(d.payload.as_slice()).unwrap();
        assert!(decoded.public_key.is_empty());
        assert!(decoded.is_licensed);
    }

    #[test]
    fn last_seen_cache_is_bounded() {
        let mut m = NodeInfoModule::new(OURS, owner());
        m.set_last_seen_capacity(3);
        for i in 1..=5u32 {
            let mut p = nodeinfo_packet(0x1000 + i, OURS, i, &mk_peer_user("X"), true);
            p.rx_time = 1_700_000_000 + i;
            m.handle_received(&p, &ctx());
        }
        assert_eq!(m.last_node_info_seen.len(), 3);
        // The three most recent senders should remain.
        assert!(m.last_node_info_seen.contains_key(&0x1005));
        assert!(m.last_node_info_seen.contains_key(&0x1004));
        assert!(m.last_node_info_seen.contains_key(&0x1003));
    }

    #[test]
    fn pending_updates_are_drained_by_take() {
        let mut m = NodeInfoModule::new(OURS, owner());
        let p = nodeinfo_packet(PEER, OURS, 1, &mk_peer_user("Bob"), false);
        m.handle_received(&p, &ctx());
        assert_eq!(m.take_pending_updates().len(), 1);
        assert!(m.take_pending_updates().is_empty());
    }

    #[test]
    fn format_user_id_is_zero_padded_lowercase() {
        assert_eq!(format_user_id(0), "!00000000");
        assert_eq!(format_user_id(0xdead_beef), "!deadbeef");
        assert_eq!(format_user_id(0x1234_5678), "!12345678");
    }
}
