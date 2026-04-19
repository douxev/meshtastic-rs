//! Packet-dedup ring buffer, a port of the firmware's
//! [`PacketHistory`](src/mesh/PacketHistory.h) class.
//!
//! Nodes re-broadcast packets to flood them through the mesh. Without a
//! per-packet memory each node would endlessly relay every packet it
//! overhears. [`PacketHistory`] remembers recent `(sender, id)` pairs so
//! the router can ask "have we seen this before?" and skip the
//! retransmission if so.
//!
//! Each record also carries:
//!
//! - `rx_time_ms` — monotonic receive timestamp, used for eviction when
//!   the buffer is full (oldest slot wins).
//! - `next_hop` — the original packet's `next_hop` field, so the router
//!   can distinguish "targeted forward to us" from "fallback flood".
//! - `hop_bits` — packs **highest-observed hop_limit** (bits 0-2) and
//!   **our-tx hop_limit** (bits 3-5); these let the router detect
//!   "upgraded" duplicates that travelled further than previous copies.
//! - `relayed_by` — fixed-size array of up to [`NUM_RELAYERS`] last-byte
//!   node-IDs that relayed this packet. The router uses this to avoid
//!   cancelling its own rebroadcast just because another node heard
//!   itself.
//!
//! The algorithm in [`PacketHistory::was_seen_recently`] is a direct
//! port of `PacketHistory::wasSeenRecently` in
//! `src/mesh/PacketHistory.cpp`.

use alloc::vec;
use alloc::vec::Vec;

use meshtastic_proto::meshtastic::MeshPacket;

use crate::mesh::{get_from, NodeNum, NO_RELAY_NODE};

/// Number of relayer IDs tracked per packet record, matching firmware
/// `NUM_RELAYERS = 6` in `src/mesh/PacketHistory.h:6`.
pub const NUM_RELAYERS: usize = 6;

/// Default number of packet records. Matches the firmware's fallback of
/// 100 when `MAX_NUM_NODES * 2` would be smaller (see
/// `PACKETHISTORY_MAX` in `src/mesh/PacketHistory.cpp:10`).
pub const DEFAULT_CAPACITY: usize = 100;

/// Minimum allowed capacity — below this the dedup window is too small
/// for realistic mesh traffic. Mirrors the `< 4` clamp in
/// `PacketHistory::PacketHistory`.
pub const MIN_CAPACITY: usize = 4;

const HOP_LIMIT_HIGHEST_MASK: u8 = 0x07; // bits 0-2
const HOP_LIMIT_OUR_TX_MASK: u8 = 0x38; // bits 3-5
const HOP_LIMIT_OUR_TX_SHIFT: u32 = 3;

/// A single entry in [`PacketHistory`]. Public for inspection by tests
/// and the router layer; fields are deliberately `pub(crate)` so
/// external callers use the accessor methods.
#[derive(Debug, Clone, Default)]
pub struct PacketRecord {
    pub(crate) sender: NodeNum,
    pub(crate) id: u32,
    /// Monotonic receive timestamp in ms. `0` marks an empty slot.
    pub(crate) rx_time_ms: u64,
    pub(crate) next_hop: u8,
    hop_bits: u8,
    pub(crate) relayed_by: [u8; NUM_RELAYERS],
}

impl PacketRecord {
    /// Sender node num.
    #[inline]
    #[must_use]
    pub fn sender(&self) -> NodeNum {
        self.sender
    }
    /// Packet id.
    #[inline]
    #[must_use]
    pub fn id(&self) -> u32 {
        self.id
    }
    /// Receive time in ms.
    #[inline]
    #[must_use]
    pub fn rx_time_ms(&self) -> u64 {
        self.rx_time_ms
    }
    /// The next-hop preference of the packet that created this record.
    #[inline]
    #[must_use]
    pub fn next_hop(&self) -> u8 {
        self.next_hop
    }
    /// Highest `hop_limit` value we have observed for this packet (bits
    /// 0-2 of the packed hop field). Used to detect "upgraded" copies.
    #[inline]
    #[must_use]
    pub fn highest_hop_limit(&self) -> u8 {
        self.hop_bits & HOP_LIMIT_HIGHEST_MASK
    }
    /// The `hop_limit` we used when we ourselves rebroadcast this
    /// packet (bits 3-5 of the packed hop field). `0` if we never
    /// forwarded it.
    #[inline]
    #[must_use]
    pub fn our_tx_hop_limit(&self) -> u8 {
        (self.hop_bits & HOP_LIMIT_OUR_TX_MASK) >> HOP_LIMIT_OUR_TX_SHIFT
    }
    /// Iterator over non-zero relayer last-byte IDs.
    pub fn relayers(&self) -> impl Iterator<Item = u8> + '_ {
        self.relayed_by.iter().copied().filter(|b| *b != 0)
    }
    /// `true` if `relayer` is recorded as a relayer of this packet.
    #[must_use]
    pub fn was_relayer(&self, relayer: u8) -> bool {
        if relayer == 0 {
            return false;
        }
        self.relayed_by.contains(&relayer)
    }

    fn is_empty(&self) -> bool {
        self.id == 0 && self.sender == 0
    }

    fn set_highest_hop_limit(&mut self, v: u8) {
        self.hop_bits = (self.hop_bits & !HOP_LIMIT_HIGHEST_MASK) | (v & HOP_LIMIT_HIGHEST_MASK);
    }
    fn set_our_tx_hop_limit(&mut self, v: u8) {
        let masked = (v & HOP_LIMIT_HIGHEST_MASK) << HOP_LIMIT_OUR_TX_SHIFT;
        self.hop_bits = (self.hop_bits & !HOP_LIMIT_OUR_TX_MASK) | masked;
    }
}

/// Result of [`PacketHistory::was_seen_recently`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct SeenInfo {
    /// `true` if `(sender, id)` was already in the history before this
    /// call. `false` for fresh packets (and for packets with `id == 0`).
    pub seen_recently: bool,
    /// `true` if we've seen this packet before *and* the current copy
    /// has a strictly higher `hop_limit` than any previous copy —
    /// meaning it came via a shorter route and rebroadcasters may want
    /// to upgrade their pending retransmit.
    pub was_upgraded: bool,
    /// `true` if the stored record's `next_hop` matches our relay id —
    /// i.e. a previous copy of this packet was explicitly addressed to
    /// us as the next hop.
    pub we_were_next_hop: bool,
    /// `true` if this looks like a "fallback to flooding" retransmission
    /// (previous copy had a specific next_hop, new copy has
    /// `NO_NEXT_HOP_PREFERENCE`, and the current relayer already relayed
    /// once before but we haven't).
    pub was_fallback: bool,
}

/// A bounded ring buffer of recent packet records. See the module-level
/// docs for the algorithm.
#[derive(Debug, Clone)]
pub struct PacketHistory {
    records: Vec<PacketRecord>,
}

impl PacketHistory {
    /// Construct a new history with the given capacity, clamping to
    /// [`MIN_CAPACITY`].
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        let cap = capacity.max(MIN_CAPACITY);
        Self {
            records: vec![PacketRecord::default(); cap],
        }
    }

    /// Capacity of the history buffer.
    #[inline]
    #[must_use]
    pub fn capacity(&self) -> usize {
        self.records.len()
    }

    /// Number of records currently populated.
    #[must_use]
    pub fn len(&self) -> usize {
        self.records.iter().filter(|r| !r.is_empty()).count()
    }

    /// `true` if the history is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.iter().all(PacketRecord::is_empty)
    }

    /// Iterate over populated records.
    pub fn iter(&self) -> impl Iterator<Item = &PacketRecord> {
        self.records.iter().filter(|r| !r.is_empty())
    }

    /// Find a record by `(sender, id)`. `None` if not present or if
    /// either key is zero (zero is the empty-slot sentinel).
    #[must_use]
    pub fn find(&self, sender: NodeNum, id: u32) -> Option<&PacketRecord> {
        if sender == 0 || id == 0 {
            return None;
        }
        self.records.iter().find(|r| r.id == id && r.sender == sender)
    }

    /// Core dedup check. Updates the history iff `update` is true.
    ///
    /// `our_node_num` is the local node's number, used for the `from==0`
    /// legacy substitution. `our_relay_id` is the local node's
    /// single-byte relay id (see [`last_byte_of_node_num`][crate::mesh::last_byte_of_node_num]).
    /// `now_ms` is a monotonic timestamp in milliseconds; `0` is
    /// reserved and will be promoted to `1` internally.
    pub fn was_seen_recently(
        &mut self,
        packet: &MeshPacket,
        now_ms: u64,
        update: bool,
        our_node_num: NodeNum,
        our_relay_id: u8,
    ) -> SeenInfo {
        // Packets with id==0 are simple broadcasts that are never flooded.
        if packet.id == 0 {
            return SeenInfo::default();
        }

        let sender = get_from(packet, our_node_num);
        let id = packet.id;

        let rx = if now_ms == 0 { 1 } else { now_ms };

        // hop_limit is a proto uint32 but the on-wire field is actually
        // 3 bits — clamp defensively.
        let hop_limit_u8 = (packet.hop_limit & 0x07) as u8;

        // Observe existing record (if any) without holding a borrow
        // across the potential mutation below.
        let (seen_recently, stored_highest, stored_next_hop, stored_was_relayer_us, stored_relayed_by, stored_our_tx) =
            match self.find(sender, id) {
                Some(r) => (
                    true,
                    r.highest_hop_limit(),
                    r.next_hop,
                    r.was_relayer(our_relay_id),
                    r.relayed_by,
                    r.our_tx_hop_limit(),
                ),
                None => (false, 0, 0, false, [0u8; NUM_RELAYERS], 0),
            };

        let mut info = SeenInfo {
            seen_recently,
            ..SeenInfo::default()
        };

        if seen_recently {
            info.was_upgraded = stored_highest < hop_limit_u8;
            info.we_were_next_hop = stored_next_hop == our_relay_id && our_relay_id != 0;

            // Firmware "fallback to flood" heuristic: previous copy was
            // routed to someone other than us, new copy has no next-hop
            // preference, the current relayer already relayed before,
            // and we were not previously asked to relay.
            let relay_node = (packet.relay_node & 0xff) as u8;
            if sender != our_node_num
                && stored_next_hop != crate::mesh::NO_NEXT_HOP_PREFERENCE
                && stored_next_hop != our_relay_id
                && packet.next_hop == u32::from(crate::mesh::NO_NEXT_HOP_PREFERENCE)
                && stored_relayed_by.iter().any(|&b| b == relay_node && relay_node != 0)
                && !stored_was_relayer_us
                && !stored_relayed_by
                    .iter()
                    .any(|&b| b == stored_next_hop && stored_next_hop != 0)
            {
                info.was_fallback = true;
            }
        }

        if update {
            let mut new = PacketRecord {
                sender,
                id,
                rx_time_ms: rx,
                next_hop: (packet.next_hop & 0xff) as u8,
                hop_bits: 0,
                relayed_by: [0; NUM_RELAYERS],
            };
            new.set_highest_hop_limit(hop_limit_u8);

            let we_will_relay = (packet.relay_node & 0xff) as u8 == our_relay_id && our_relay_id != NO_RELAY_NODE;

            if we_will_relay {
                new.set_our_tx_hop_limit(hop_limit_u8);
                new.relayed_by[0] = our_relay_id;
            }

            if seen_recently {
                // Preserve the strictly-greater highest hop_limit seen.
                if stored_highest > new.highest_hop_limit() {
                    new.set_highest_hop_limit(stored_highest);
                }

                // Keep existing next_hop so the "we were originally
                // asked" check remains stable across re-insertions.
                new.next_hop = stored_next_hop;

                let mut start_idx = if we_will_relay { 1 } else { 0 };
                if !we_will_relay {
                    // If we previously relayed this packet and the
                    // current copy's hop_limit is within one of the
                    // tx'd one, the incoming relayer heard us directly.
                    if stored_was_relayer_us
                        && (hop_limit_u8 == stored_our_tx || (stored_our_tx > 0 && hop_limit_u8 == stored_our_tx - 1))
                    {
                        new.relayed_by[0] = (packet.relay_node & 0xff) as u8;
                        start_idx = 1;
                    }
                    // Keep the original our_tx value if we didn't just
                    // relay.
                    new.set_our_tx_hop_limit(stored_our_tx);
                }

                // Merge stored relayers into the new record, avoiding
                // dups, starting at `start_idx`.
                let mut write = start_idx;
                for &b in &stored_relayed_by {
                    if b == 0 {
                        continue;
                    }
                    if new.relayed_by.contains(&b) {
                        continue;
                    }
                    if write >= NUM_RELAYERS {
                        break;
                    }
                    new.relayed_by[write] = b;
                    write += 1;
                }
            }

            self.insert(new);
        }

        info
    }

    /// Insert a relayer byte for an existing `(sender, id)`. No-op if
    /// the record isn't present or if `relayer == 0`.
    pub fn add_relayer(&mut self, sender: NodeNum, id: u32, relayer: u8) {
        if relayer == 0 {
            return;
        }
        if let Some(slot) = self.records.iter_mut().find(|r| r.id == id && r.sender == sender) {
            if slot.relayed_by.contains(&relayer) {
                return;
            }
            if let Some(empty) = slot.relayed_by.iter_mut().find(|b| **b == 0) {
                *empty = relayer;
            }
        }
    }

    /// Remove a relayer from an existing `(sender, id)` record.
    pub fn remove_relayer(&mut self, sender: NodeNum, id: u32, relayer: u8) {
        if let Some(slot) = self.records.iter_mut().find(|r| r.id == id && r.sender == sender) {
            for b in slot.relayed_by.iter_mut() {
                if *b == relayer {
                    *b = 0;
                }
            }
        }
    }

    /// Insert or replace a record. Firmware `PacketHistory::insert`:
    /// prefer an empty slot; else replace matching (sender,id); else
    /// evict the oldest slot by rx_time.
    fn insert(&mut self, r: PacketRecord) {
        // Pass 1: exact match or free slot short-circuit.
        if let Some((idx, _)) = self
            .records
            .iter()
            .enumerate()
            .find(|(_, rec)| rec.id == r.id && rec.sender == r.sender)
        {
            self.records[idx] = r;
            return;
        }
        if let Some((idx, _)) = self.records.iter().enumerate().find(|(_, rec)| rec.is_empty()) {
            self.records[idx] = r;
            return;
        }
        // Pass 2: evict oldest. Smallest rx_time_ms wins; if all are
        // equal (shouldn't happen given we only reach here when full
        // and no empties) the first slot is reused.
        let mut oldest_idx = 0usize;
        let mut oldest_rx = u64::MAX;
        for (i, rec) in self.records.iter().enumerate() {
            if rec.rx_time_ms < oldest_rx {
                oldest_rx = rec.rx_time_ms;
                oldest_idx = i;
            }
        }
        self.records[oldest_idx] = r;
    }
}

impl Default for PacketHistory {
    fn default() -> Self {
        Self::with_capacity(DEFAULT_CAPACITY)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshtastic_proto::meshtastic::{mesh_packet::PayloadVariant, Data, MeshPacket};

    const OUR_NUM: NodeNum = 0x1234_5678;
    const OUR_RELAY: u8 = 0x78;

    fn pkt(from: NodeNum, id: u32, hop_limit: u32) -> MeshPacket {
        MeshPacket {
            from,
            id,
            hop_limit,
            hop_start: hop_limit,
            payload_variant: Some(PayloadVariant::Decoded(Data::default())),
            ..Default::default()
        }
    }

    #[test]
    fn capacity_is_clamped_to_min() {
        let h = PacketHistory::with_capacity(0);
        assert_eq!(h.capacity(), MIN_CAPACITY);
        assert!(h.is_empty());
        assert_eq!(h.len(), 0);
    }

    #[test]
    fn id_zero_is_never_seen() {
        let mut h = PacketHistory::with_capacity(8);
        let p = pkt(1, 0, 3);
        let info = h.was_seen_recently(&p, 1000, true, OUR_NUM, OUR_RELAY);
        assert!(!info.seen_recently);
        // No record is inserted for id==0 packets.
        assert!(h.is_empty());
    }

    #[test]
    fn first_sight_then_dedup() {
        let mut h = PacketHistory::with_capacity(8);
        let p = pkt(42, 0xdead, 3);

        let first = h.was_seen_recently(&p, 1000, true, OUR_NUM, OUR_RELAY);
        assert!(!first.seen_recently);
        assert_eq!(h.len(), 1);

        let second = h.was_seen_recently(&p, 2000, true, OUR_NUM, OUR_RELAY);
        assert!(second.seen_recently);
        assert!(!second.was_upgraded);
        assert_eq!(h.len(), 1, "same (sender,id) must not double-insert");
    }

    #[test]
    fn fresh_packet_without_update_is_not_inserted() {
        let mut h = PacketHistory::with_capacity(8);
        let p = pkt(42, 0xbeef, 3);
        let info = h.was_seen_recently(&p, 1000, false, OUR_NUM, OUR_RELAY);
        assert!(!info.seen_recently);
        assert!(h.is_empty());
    }

    #[test]
    fn higher_hop_limit_flags_as_upgraded() {
        let mut h = PacketHistory::with_capacity(8);
        let low = pkt(42, 0xaa, 1);
        h.was_seen_recently(&low, 100, true, OUR_NUM, OUR_RELAY);

        let high = pkt(42, 0xaa, 5);
        let info = h.was_seen_recently(&high, 200, true, OUR_NUM, OUR_RELAY);
        assert!(info.seen_recently);
        // 5 > 3-bit max of 7, so clamped to 5 itself; previous is 1.
        assert!(info.was_upgraded);
    }

    #[test]
    fn lower_hop_limit_is_not_upgraded_and_preserves_highest() {
        let mut h = PacketHistory::with_capacity(8);
        h.was_seen_recently(&pkt(42, 0xaa, 5), 100, true, OUR_NUM, OUR_RELAY);
        let later = h.was_seen_recently(&pkt(42, 0xaa, 3), 200, true, OUR_NUM, OUR_RELAY);
        assert!(later.seen_recently);
        assert!(!later.was_upgraded);
        // Stored record should still report 5 as highest.
        let rec = h.find(42, 0xaa).expect("must find record");
        assert_eq!(rec.highest_hop_limit(), 5);
    }

    #[test]
    fn find_rejects_zero_keys() {
        let h = PacketHistory::with_capacity(4);
        assert!(h.find(0, 1).is_none());
        assert!(h.find(1, 0).is_none());
    }

    #[test]
    fn evicts_oldest_when_full() {
        let mut h = PacketHistory::with_capacity(4);
        for i in 1..=4u32 {
            h.was_seen_recently(&pkt(100, i, 3), u64::from(i) * 1000, true, OUR_NUM, OUR_RELAY);
        }
        assert_eq!(h.len(), 4);
        // Insert one more — oldest (id=1, rx=1000) must be evicted.
        h.was_seen_recently(&pkt(100, 5, 3), 5000, true, OUR_NUM, OUR_RELAY);
        assert_eq!(h.len(), 4);
        assert!(h.find(100, 1).is_none());
        assert!(h.find(100, 5).is_some());
    }

    #[test]
    fn add_and_remove_relayer() {
        let mut h = PacketHistory::with_capacity(4);
        h.was_seen_recently(&pkt(7, 0x11, 3), 100, true, OUR_NUM, OUR_RELAY);
        h.add_relayer(7, 0x11, 0xaa);
        h.add_relayer(7, 0x11, 0xbb);
        // Duplicate should be no-op.
        h.add_relayer(7, 0x11, 0xaa);
        let r = h.find(7, 0x11).unwrap();
        let relayers: Vec<u8> = r.relayers().collect();
        assert_eq!(relayers, vec![0xaa, 0xbb]);

        h.remove_relayer(7, 0x11, 0xaa);
        let r = h.find(7, 0x11).unwrap();
        let relayers: Vec<u8> = r.relayers().collect();
        assert_eq!(relayers, vec![0xbb]);
    }

    #[test]
    fn we_were_next_hop_is_reported() {
        let mut h = PacketHistory::with_capacity(4);
        let p = MeshPacket {
            from: 7,
            id: 0x22,
            hop_limit: 3,
            hop_start: 3,
            next_hop: u32::from(OUR_RELAY),
            payload_variant: Some(PayloadVariant::Decoded(Data::default())),
            ..Default::default()
        };
        h.was_seen_recently(&p, 100, true, OUR_NUM, OUR_RELAY);
        let info = h.was_seen_recently(&p, 200, false, OUR_NUM, OUR_RELAY);
        assert!(info.we_were_next_hop);
    }

    #[test]
    fn legacy_from_zero_resolves_to_our_num() {
        let mut h = PacketHistory::with_capacity(4);
        let p = pkt(0, 0x33, 3);
        h.was_seen_recently(&p, 100, true, OUR_NUM, OUR_RELAY);
        assert!(h.find(OUR_NUM, 0x33).is_some());
        assert!(h.find(0, 0x33).is_none());
    }

    #[test]
    fn now_zero_is_promoted_to_one() {
        let mut h = PacketHistory::with_capacity(4);
        h.was_seen_recently(&pkt(1, 1, 1), 0, true, OUR_NUM, OUR_RELAY);
        // Empty-slot sentinel is rx_time_ms==0; our record must therefore
        // be discoverable (i.e. not treated as empty).
        let rec = h.find(1, 1).expect("stored");
        assert_eq!(rec.rx_time_ms(), 1);
    }
}
