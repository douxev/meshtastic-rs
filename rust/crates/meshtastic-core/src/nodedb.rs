//! Bounded in-memory table of known mesh nodes.
//!
//! Ports the core behaviour of the firmware's
//! [`NodeDB`](src/mesh/NodeDB.cpp) class — specifically the state that
//! every mesh-protocol decision needs and that is easy to isolate from
//! the platform layer:
//!
//! - keyed by `NodeNum`, each entry is a
//!   [`NodeInfoLite`][meshtastic_proto::meshtastic::NodeInfoLite] proto
//! - bounded capacity with LRU-ish eviction (oldest non-favourite,
//!   non-ignored, non-manually-verified node wins; "boring" nodes
//!   without a PKI pubkey are preferred over ones that have one)
//! - `update_from(packet)` mirrors `NodeDB::updateFrom` — touches
//!   `last_heard`, `snr`, `via_mqtt`, and `hops_away`
//! - favourite / ignore accessors and a fast "is the packet
//!   from/to a favourite" check, used later by router-rebroadcast rules
//! - roundtrips through the
//!   [`NodeDatabase`][meshtastic_proto::meshtastic::NodeDatabase] proto
//!   so flash persistence is the platform layer's job, not ours
//!
//! Deliberately **not** ported in this phase:
//!
//! - `updateUser`, `updatePosition`, `updateTelemetry` — these live
//!   with the Position/Telemetry/User modules (Phase 5).
//! - Sorting for UI display order — a UI concern (Phase 6+).
//! - `getNumOnlineMeshNodes` — needs a wall-clock `now`, addressed in a
//!   later pass.

use alloc::vec::Vec;
use core::fmt;

use meshtastic_proto::meshtastic::{mesh_packet::PayloadVariant, MeshPacket, NodeDatabase, NodeInfoLite};

use crate::mesh::{get_from, hops_away, is_broadcast, NodeNum, NODENUM_BROADCAST};

/// Default capacity for the in-memory node table. Matches the firmware
/// ESP32 build's `MAX_NUM_NODES = 80` in
/// `src/mesh/mesh-pb-constants.h:49`. Small-memory builds override via
/// [`NodeDb::with_capacity`].
pub const DEFAULT_CAPACITY: usize = 80;

/// `NodeInfoLite.bitfield` flag: the user manually verified this node's
/// public key. Firmware
/// `NODEINFO_BITFIELD_IS_KEY_MANUALLY_VERIFIED_MASK` in
/// `src/mesh/NodeDB.h:401`.
pub const BITFIELD_IS_KEY_MANUALLY_VERIFIED: u32 = 1 << 0;

/// `NodeInfoLite.bitfield` flag: the user muted notifications for this
/// node. Firmware `NODEINFO_BITFIELD_IS_MUTED_MASK` in
/// `src/mesh/NodeDB.h:403`.
pub const BITFIELD_IS_MUTED: u32 = 1 << 1;

/// Current on-disk version tag written into
/// `NodeDatabase.version`. Matches firmware `DEVICESTATE_CUR_VER = 24`
/// in `src/mesh/NodeDB.h:85`.
pub const NODE_DATABASE_VERSION: u32 = 24;

/// Errors returned by [`NodeDb::from_proto`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeDbError {
    /// The proto contains more nodes than `capacity` — load aborted to
    /// avoid silent truncation.
    TooManyNodes {
        /// Number of nodes in the proto.
        got: usize,
        /// Configured capacity.
        max: usize,
    },
    /// The proto contained two entries with the same `num`.
    DuplicateNode(NodeNum),
}

impl fmt::Display for NodeDbError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeDbError::TooManyNodes { got, max } => {
                write!(f, "node database has {got} nodes; capacity is {max}")
            }
            NodeDbError::DuplicateNode(n) => write!(f, "duplicate node num {n:#x} in database"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NodeDbError {}

/// Bounded in-memory node table.
#[derive(Debug, Clone)]
pub struct NodeDb {
    our_node_num: NodeNum,
    capacity: usize,
    /// Invariant: `our_node_num` (if present) is always at index 0, to
    /// mirror the firmware where `meshNodes->at(0)` is the self-entry
    /// and the eviction loop starts at `i = 1`.
    nodes: Vec<NodeInfoLite>,
}

impl NodeDb {
    /// Create an empty DB that will hold up to [`DEFAULT_CAPACITY`]
    /// entries. `our_node_num` is the local node's identifier; packets
    /// from this node are ignored by [`NodeDb::update_from`].
    #[must_use]
    pub fn new(our_node_num: NodeNum) -> Self {
        Self::with_capacity(our_node_num, DEFAULT_CAPACITY)
    }

    /// Create an empty DB with the given capacity. `capacity` is
    /// clamped to at least 1 so there's always room for our-own-node.
    #[must_use]
    pub fn with_capacity(our_node_num: NodeNum, capacity: usize) -> Self {
        Self {
            our_node_num,
            capacity: capacity.max(1),
            nodes: Vec::new(),
        }
    }

    /// Our own node num.
    #[inline]
    #[must_use]
    pub fn our_node_num(&self) -> NodeNum {
        self.our_node_num
    }

    /// Number of nodes currently in the table (including ourselves, if
    /// we've been inserted).
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// `true` if the table contains no entries.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// Configured capacity.
    #[inline]
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// `true` once we've hit capacity. Matches `NodeDB::isFull` but
    /// without the free-heap check (that's a platform concern).
    #[inline]
    #[must_use]
    pub fn is_full(&self) -> bool {
        self.nodes.len() >= self.capacity
    }

    /// Iterate over every stored node.
    pub fn iter(&self) -> impl Iterator<Item = &NodeInfoLite> {
        self.nodes.iter()
    }

    /// Lookup by node num. `None` for broadcast (never stored) or
    /// unknown.
    #[must_use]
    pub fn get(&self, num: NodeNum) -> Option<&NodeInfoLite> {
        if is_broadcast(num) {
            return None;
        }
        self.nodes.iter().find(|n| n.num == num)
    }

    /// Mutable lookup.
    #[must_use]
    pub fn get_mut(&mut self, num: NodeNum) -> Option<&mut NodeInfoLite> {
        if is_broadcast(num) {
            return None;
        }
        self.nodes.iter_mut().find(|n| n.num == num)
    }

    /// Remove a node by num. Returns `true` if it was present.
    pub fn remove(&mut self, num: NodeNum) -> bool {
        if let Some(idx) = self.nodes.iter().position(|n| n.num == num) {
            self.nodes.remove(idx);
            return true;
        }
        false
    }

    /// Insert or merge a fully-populated [`NodeInfoLite`]. If an entry
    /// with the same `num` exists, it is replaced. If capacity would be
    /// exceeded, [`NodeDb::evict_one`] is called first.
    pub fn insert(&mut self, info: NodeInfoLite) -> &mut NodeInfoLite {
        if let Some(idx) = self.nodes.iter().position(|n| n.num == info.num) {
            self.nodes[idx] = info;
            return &mut self.nodes[idx];
        }
        if self.is_full() {
            self.evict_one();
        }
        // Self-entry goes to index 0 so the eviction loop skips it.
        if info.num == self.our_node_num {
            self.nodes.insert(0, info);
            return &mut self.nodes[0];
        }
        self.nodes.push(info);
        let idx = self.nodes.len() - 1;
        &mut self.nodes[idx]
    }

    /// Return a mutable entry for `num`, creating a zeroed
    /// [`NodeInfoLite`] if not present. Matches firmware
    /// `NodeDB::getOrCreateMeshNode` in `src/mesh/NodeDB.cpp:2104`,
    /// modulo the global-heap check.
    pub fn get_or_create(&mut self, num: NodeNum) -> &mut NodeInfoLite {
        if is_broadcast(num) {
            panic!("cannot create entry for NODENUM_BROADCAST");
        }
        if let Some(idx) = self.nodes.iter().position(|n| n.num == num) {
            return &mut self.nodes[idx];
        }
        if self.is_full() {
            self.evict_one();
        }
        let fresh = NodeInfoLite {
            num,
            ..Default::default()
        };
        if num == self.our_node_num {
            self.nodes.insert(0, fresh);
            return &mut self.nodes[0];
        }
        self.nodes.push(fresh);
        let idx = self.nodes.len() - 1;
        &mut self.nodes[idx]
    }

    /// Update the DB from a received [`MeshPacket`], mirroring
    /// `NodeDB::updateFrom` (`src/mesh/NodeDB.cpp:1934`). Packets
    /// originating from ourselves are ignored. Only `Decoded` packets
    /// touch the DB — until a packet is decrypted we can't trust the
    /// `bitfield`/`hop_start` checks that the firmware uses for
    /// `hops_away`.
    ///
    /// Returns the updated entry's node num on success, or `None` if
    /// the packet was not applied.
    pub fn update_from(&mut self, packet: &MeshPacket) -> Option<NodeNum> {
        if packet.from == self.our_node_num {
            return None;
        }
        if !matches!(packet.payload_variant, Some(PayloadVariant::Decoded(_))) {
            return None;
        }
        // from==0 is a legacy-firmware "this is from me" signal — the
        // sender doesn't know its own nodenum yet, so we can't add it.
        if packet.from == 0 {
            return None;
        }

        let num = get_from(packet, self.our_node_num);
        let hops = hops_away(packet);
        let rx_time = packet.rx_time;
        let rx_snr = packet.rx_snr;
        let via_mqtt = packet.via_mqtt;

        let info = self.get_or_create(num);
        if rx_time != 0 {
            info.last_heard = rx_time;
        }
        if rx_snr != 0.0 {
            info.snr = rx_snr;
        }
        info.via_mqtt = via_mqtt;
        if let Some(h) = hops {
            info.hops_away = Some(u32::from(h));
        }
        Some(num)
    }

    /// Mark a node as favourite or unfavourite. Returns `true` if the
    /// flag was changed (or `false` if the node was absent or already
    /// in the requested state).
    pub fn set_favorite(&mut self, num: NodeNum, favourite: bool) -> bool {
        if let Some(info) = self.get_mut(num) {
            if info.is_favorite == favourite {
                return false;
            }
            info.is_favorite = favourite;
            return true;
        }
        false
    }

    /// `true` if the named node is present and marked as favourite.
    /// Firmware `NodeDB::isFavorite` in `src/mesh/NodeDB.cpp:1976`.
    #[must_use]
    pub fn is_favorite(&self, num: NodeNum) -> bool {
        if num == NODENUM_BROADCAST {
            return false;
        }
        self.get(num).is_some_and(|n| n.is_favorite)
    }

    /// `true` if either the packet's `from` *or* `to` is a favourited
    /// node. Broadcast destinations only check `from`. Firmware
    /// `NodeDB::isFromOrToFavoritedNode` in `src/mesh/NodeDB.cpp:1992`.
    #[must_use]
    pub fn is_from_or_to_favorited(&self, packet: &MeshPacket) -> bool {
        if is_broadcast(packet.to) {
            return self.is_favorite(packet.from);
        }
        // Single-pass early exit, matching the firmware optimisation.
        let mut seen_from = false;
        let mut seen_to = false;
        for n in &self.nodes {
            if !seen_from && n.num == packet.from {
                if n.is_favorite {
                    return true;
                }
                seen_from = true;
            }
            if !seen_to && n.num == packet.to {
                if n.is_favorite {
                    return true;
                }
                seen_to = true;
            }
            if seen_from && seen_to {
                break;
            }
        }
        false
    }

    /// Mark a node as ignored or un-ignored. Returns `true` if the flag
    /// was changed.
    pub fn set_ignored(&mut self, num: NodeNum, ignored: bool) -> bool {
        if let Some(info) = self.get_mut(num) {
            if info.is_ignored == ignored {
                return false;
            }
            info.is_ignored = ignored;
            return true;
        }
        false
    }

    /// `true` if the named node is present and marked as ignored.
    #[must_use]
    pub fn is_ignored(&self, num: NodeNum) -> bool {
        if num == NODENUM_BROADCAST {
            return false;
        }
        self.get(num).is_some_and(|n| n.is_ignored)
    }

    /// Evict one entry when the table is full. Mirrors the policy in
    /// `NodeDB::getOrCreateMeshNode` (`src/mesh/NodeDB.cpp:2104`):
    ///
    /// - Never evict index 0 (our own node).
    /// - Never evict a favourite, ignored, or manually-verified node.
    /// - Prefer the oldest "boring" node (no PKI public key).
    /// - Otherwise evict the oldest non-pinned node by `last_heard`.
    ///
    /// If every non-self node is pinned this is a no-op; the caller
    /// then inserts over capacity, which is how the firmware also
    /// behaves (it logs a warning and continues).
    fn evict_one(&mut self) {
        let start = if self.nodes.first().is_some_and(|n| n.num == self.our_node_num) {
            1
        } else {
            0
        };

        let mut oldest_idx: Option<usize> = None;
        let mut oldest_ts = u32::MAX;
        let mut oldest_boring_idx: Option<usize> = None;
        let mut oldest_boring_ts = u32::MAX;

        for i in start..self.nodes.len() {
            let n = &self.nodes[i];
            let pinned = n.is_favorite || n.is_ignored || (n.bitfield & BITFIELD_IS_KEY_MANUALLY_VERIFIED) != 0;
            if pinned {
                continue;
            }
            if n.last_heard < oldest_ts {
                oldest_ts = n.last_heard;
                oldest_idx = Some(i);
            }
            // "Boring" = no PKI public key attached to the user.
            let boring = n.user.as_ref().is_none_or(|u| u.public_key.is_empty());
            if boring && n.last_heard < oldest_boring_ts {
                oldest_boring_ts = n.last_heard;
                oldest_boring_idx = Some(i);
            }
        }

        let victim = oldest_boring_idx.or(oldest_idx);
        if let Some(idx) = victim {
            self.nodes.remove(idx);
        }
    }

    /// Serialise the table to a [`NodeDatabase`] protobuf (what the
    /// firmware writes to `/prefs/nodes.proto`).
    #[must_use]
    pub fn to_proto(&self) -> NodeDatabase {
        NodeDatabase {
            version: NODE_DATABASE_VERSION,
            nodes: self.nodes.clone(),
        }
    }

    /// Load a table from a [`NodeDatabase`] protobuf. Rejects proto
    /// payloads with more nodes than `capacity` or with duplicate
    /// `num`s.
    pub fn from_proto(our_node_num: NodeNum, capacity: usize, proto: NodeDatabase) -> Result<Self, NodeDbError> {
        let cap = capacity.max(1);
        if proto.nodes.len() > cap {
            return Err(NodeDbError::TooManyNodes {
                got: proto.nodes.len(),
                max: cap,
            });
        }
        let mut db = Self::with_capacity(our_node_num, cap);
        // Reserve exact slots to keep behaviour deterministic.
        for info in proto.nodes {
            if db.nodes.iter().any(|n| n.num == info.num) {
                return Err(NodeDbError::DuplicateNode(info.num));
            }
            if info.num == our_node_num {
                db.nodes.insert(0, info);
            } else {
                db.nodes.push(info);
            }
        }
        Ok(db)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshtastic_proto::meshtastic::{mesh_packet::PayloadVariant, Data, UserLite};

    const OUR: NodeNum = 0x1111_1111;

    fn decoded_pkt(from: NodeNum) -> MeshPacket {
        MeshPacket {
            from,
            to: NODENUM_BROADCAST,
            hop_start: 3,
            hop_limit: 2,
            rx_time: 1000,
            rx_snr: 5.5,
            via_mqtt: false,
            payload_variant: Some(PayloadVariant::Decoded(Data::default())),
            ..Default::default()
        }
    }

    fn node(num: NodeNum, last_heard: u32) -> NodeInfoLite {
        NodeInfoLite {
            num,
            last_heard,
            ..Default::default()
        }
    }

    #[test]
    fn new_db_is_empty() {
        let db = NodeDb::new(OUR);
        assert!(db.is_empty());
        assert_eq!(db.len(), 0);
        assert_eq!(db.capacity(), DEFAULT_CAPACITY);
        assert!(!db.is_full());
    }

    #[test]
    fn get_or_create_inserts_new_node() {
        let mut db = NodeDb::new(OUR);
        let n = db.get_or_create(0x42);
        assert_eq!(n.num, 0x42);
        assert_eq!(db.len(), 1);
        // Second call returns the same entry, no duplicate.
        let _ = db.get_or_create(0x42);
        assert_eq!(db.len(), 1);
    }

    #[test]
    fn update_from_skips_self() {
        let mut db = NodeDb::new(OUR);
        let p = decoded_pkt(OUR);
        assert!(db.update_from(&p).is_none());
        assert!(db.is_empty());
    }

    #[test]
    fn update_from_skips_encrypted() {
        let mut db = NodeDb::new(OUR);
        let p = MeshPacket {
            from: 0x42,
            payload_variant: Some(PayloadVariant::Encrypted(Vec::new())),
            ..Default::default()
        };
        assert!(db.update_from(&p).is_none());
        assert!(db.is_empty());
    }

    #[test]
    fn update_from_populates_fields() {
        let mut db = NodeDb::new(OUR);
        let mut p = decoded_pkt(0x42);
        p.via_mqtt = true;
        let num = db.update_from(&p).expect("should insert");
        assert_eq!(num, 0x42);
        let info = db.get(0x42).unwrap();
        assert_eq!(info.last_heard, 1000);
        assert!((info.snr - 5.5).abs() < 1e-6);
        assert!(info.via_mqtt);
        assert_eq!(info.hops_away, Some(1)); // hop_start - hop_limit = 3 - 2
    }

    #[test]
    fn update_from_ignores_from_zero() {
        let mut db = NodeDb::new(OUR);
        let p = decoded_pkt(0);
        assert!(db.update_from(&p).is_none());
        assert!(db.is_empty());
    }

    #[test]
    fn favorite_and_ignored_flags() {
        let mut db = NodeDb::new(OUR);
        db.insert(node(0x42, 10));
        assert!(!db.is_favorite(0x42));
        assert!(db.set_favorite(0x42, true));
        assert!(db.is_favorite(0x42));
        assert!(!db.set_favorite(0x42, true)); // no change returns false
        assert!(db.set_favorite(0x42, false));

        assert!(!db.is_ignored(0x42));
        assert!(db.set_ignored(0x42, true));
        assert!(db.is_ignored(0x42));
    }

    #[test]
    fn favorite_lookup_rejects_broadcast() {
        let db = NodeDb::new(OUR);
        assert!(!db.is_favorite(NODENUM_BROADCAST));
        assert!(!db.is_ignored(NODENUM_BROADCAST));
    }

    #[test]
    fn is_from_or_to_favorited_broadcast_checks_from_only() {
        let mut db = NodeDb::new(OUR);
        db.insert(node(0x42, 10));
        db.set_favorite(0x42, true);
        let pkt = MeshPacket {
            from: 0x42,
            to: NODENUM_BROADCAST,
            ..Default::default()
        };
        assert!(db.is_from_or_to_favorited(&pkt));

        let pkt2 = MeshPacket {
            from: 0x99,
            to: NODENUM_BROADCAST,
            ..Default::default()
        };
        assert!(!db.is_from_or_to_favorited(&pkt2));
    }

    #[test]
    fn is_from_or_to_favorited_dm_checks_both() {
        let mut db = NodeDb::new(OUR);
        db.insert(node(0x42, 10));
        db.insert(node(0x99, 20));
        db.set_favorite(0x99, true);
        let pkt = MeshPacket {
            from: 0x42,
            to: 0x99,
            ..Default::default()
        };
        assert!(db.is_from_or_to_favorited(&pkt));
    }

    #[test]
    fn eviction_prefers_boring_nodes() {
        let mut db = NodeDb::with_capacity(OUR, 3);
        // Self first.
        db.insert(node(OUR, 999_999));
        // Non-favourite without pubkey, old rx
        db.insert(node(0x10, 100));
        // Non-favourite WITH pubkey, older rx (would win by rx, but
        // boring wins).
        let mut has_key = node(0x20, 50);
        has_key.user = Some(UserLite {
            public_key: vec![1, 2, 3],
            ..Default::default()
        });
        db.insert(has_key);

        assert!(db.is_full());
        db.insert(node(0x30, 200));
        // The boring 0x10 should be gone; 0x20 and ourselves kept.
        assert_eq!(db.len(), 3);
        assert!(db.get(0x10).is_none());
        assert!(db.get(0x20).is_some());
        assert!(db.get(0x30).is_some());
        assert!(db.get(OUR).is_some());
    }

    #[test]
    fn eviction_never_evicts_self_favorites_or_verified() {
        let mut db = NodeDb::with_capacity(OUR, 3);
        db.insert(node(OUR, 0));
        let mut fav = node(0x10, 0);
        fav.is_favorite = true;
        db.insert(fav);
        let mut verified = node(0x20, 0);
        verified.bitfield = BITFIELD_IS_KEY_MANUALLY_VERIFIED;
        db.insert(verified);

        // Full, every non-self entry is pinned. Insert over capacity.
        db.insert(node(0x30, 100));
        // All four remain: the eviction helper found no victim, and
        // insert falls through and appends, matching the firmware's
        // "log and continue" behaviour.
        assert_eq!(db.len(), 4);
        assert!(db.get(OUR).is_some());
        assert!(db.get(0x10).is_some());
        assert!(db.get(0x20).is_some());
        assert!(db.get(0x30).is_some());
    }

    #[test]
    fn eviction_falls_back_to_oldest_non_boring() {
        let mut db = NodeDb::with_capacity(OUR, 3);
        db.insert(node(OUR, 999));
        for (n, ts) in [(0x10u32, 500u32), (0x20, 100)] {
            let mut info = node(n, ts);
            info.user = Some(UserLite {
                public_key: vec![1, 2, 3],
                ..Default::default()
            });
            db.insert(info);
        }
        assert!(db.is_full());
        db.insert(node(0x30, 1000));
        // Oldest non-boring (0x20, rx=100) evicted.
        assert!(db.get(0x20).is_none());
        assert!(db.get(0x10).is_some());
        assert!(db.get(0x30).is_some());
    }

    #[test]
    fn proto_roundtrip_preserves_entries() {
        let mut db = NodeDb::with_capacity(OUR, 10);
        db.insert(node(OUR, 0));
        db.insert(node(0x10, 50));
        let mut fav = node(0x20, 100);
        fav.is_favorite = true;
        db.insert(fav);

        let proto = db.to_proto();
        assert_eq!(proto.version, NODE_DATABASE_VERSION);
        assert_eq!(proto.nodes.len(), 3);

        let restored = NodeDb::from_proto(OUR, 10, proto).unwrap();
        assert_eq!(restored.len(), 3);
        assert!(restored.get(OUR).is_some());
        assert!(restored.is_favorite(0x20));
        // Self must be at index 0.
        assert_eq!(restored.iter().next().unwrap().num, OUR);
    }

    #[test]
    fn from_proto_rejects_overflow() {
        let proto = NodeDatabase {
            version: NODE_DATABASE_VERSION,
            nodes: (0..5).map(|i| node(i + 1, 0)).collect(),
        };
        let err = NodeDb::from_proto(OUR, 3, proto).unwrap_err();
        assert!(matches!(err, NodeDbError::TooManyNodes { got: 5, max: 3 }));
    }

    #[test]
    fn from_proto_rejects_duplicate_num() {
        let proto = NodeDatabase {
            version: NODE_DATABASE_VERSION,
            nodes: vec![node(0x42, 1), node(0x42, 2)],
        };
        let err = NodeDb::from_proto(OUR, 10, proto).unwrap_err();
        assert_eq!(err, NodeDbError::DuplicateNode(0x42));
    }

    #[test]
    fn remove_works() {
        let mut db = NodeDb::new(OUR);
        db.insert(node(0x42, 10));
        assert!(db.remove(0x42));
        assert!(!db.remove(0x42));
    }
}
