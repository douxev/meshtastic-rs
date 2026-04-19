//! Shared mesh-layer helpers: node-num types, broadcast constants, and
//! packet-inspection helpers used by both the [`nodedb`][crate::nodedb]
//! and [`packet_history`][crate::packet_history] modules.
//!
//! These are straight ports of the free functions in
//! `src/mesh/MeshTypes.h` + `src/mesh/NodeDB.cpp` (`getFrom`, `isFromUs`,
//! `classifyHopStart`, `getHopsAway`).

use meshtastic_proto::meshtastic::{mesh_packet::PayloadVariant, MeshPacket};

/// A node number. Matches the firmware's `NodeNum` typedef (a `uint32_t`).
pub type NodeNum = u32;

/// The broadcast node number. Matches firmware `NODENUM_BROADCAST`
/// (`UINT32_MAX`) in `src/mesh/MeshTypes.h:12`.
pub const NODENUM_BROADCAST: NodeNum = u32::MAX;

/// Sentinel value for [`MeshPacket::next_hop`] meaning "no next-hop
/// preference". Matches firmware `NO_NEXT_HOP_PREFERENCE` in
/// `src/mesh/MeshTypes.h:44`.
pub const NO_NEXT_HOP_PREFERENCE: u8 = 0;

/// Sentinel value for [`MeshPacket::relay_node`] meaning "no relay node
/// was recorded" (e.g. legacy firmware). Matches firmware `NO_RELAY_NODE`
/// in `src/mesh/MeshTypes.h:46`.
pub const NO_RELAY_NODE: u8 = 0;

/// Resolve a packet's effective sender. Legacy firmware omitted the
/// `from` field when it originated the packet locally; the firmware's
/// `getFrom()` substitutes the local node num in that case. Callers
/// supply `our_node_num` so this helper has no global state.
///
/// See `src/mesh/NodeDB.cpp:459`.
#[inline]
#[must_use]
pub fn get_from(packet: &MeshPacket, our_node_num: NodeNum) -> NodeNum {
    if packet.from == 0 {
        our_node_num
    } else {
        packet.from
    }
}

/// `true` if `packet` originated from the local node. See
/// `src/mesh/NodeDB.cpp:465`.
#[inline]
#[must_use]
pub fn is_from_us(packet: &MeshPacket, our_node_num: NodeNum) -> bool {
    packet.from == 0 || packet.from == our_node_num
}

/// `true` if `packet` is addressed to a broadcast node num.
#[inline]
#[must_use]
pub fn is_broadcast(to: NodeNum) -> bool {
    to == NODENUM_BROADCAST
}

/// Classification of a packet's `hop_start` field. Mirrors
/// `HopStartStatus` in `src/mesh/NodeDB.h:117`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HopStartStatus {
    /// `hop_start` is present and plausibly correct.
    Valid,
    /// `hop_start` is 0 and we can't tell if the originator populated it
    /// — legacy pre-2.3.0 firmware lacked the field.
    MissingOrUnknown,
    /// `hop_start < hop_limit`, which indicates tampering or corruption.
    Invalid,
}

/// Classify the `hop_start` field for forwarding decisions. Ports
/// `classifyHopStart` in `src/mesh/NodeDB.cpp:1653`.
#[must_use]
pub fn classify_hop_start(packet: &MeshPacket) -> HopStartStatus {
    if packet.hop_start < packet.hop_limit {
        return HopStartStatus::Invalid;
    }
    if packet.hop_start == 0 {
        // The `bitfield` field was added in 2.5.0 and is always present
        // from that version on. Its presence on a *decoded* packet
        // therefore implies the originator's firmware is new enough to
        // populate hop_start, so a zero value means "legitimately zero".
        // We can only check this on decoded packets because the bitfield
        // lives inside the encrypted Data.
        if let Some(PayloadVariant::Decoded(data)) = &packet.payload_variant {
            if data.bitfield.is_some() {
                return HopStartStatus::Valid;
            }
        }
        return HopStartStatus::MissingOrUnknown;
    }
    HopStartStatus::Valid
}

/// Compute how many hops this packet has travelled, or `None` if we
/// can't tell. Mirrors `getHopsAway` in `src/mesh/NodeDB.cpp:1672` but
/// returns `Option<u8>` rather than taking a default-if-unknown
/// sentinel.
#[must_use]
pub fn hops_away(packet: &MeshPacket) -> Option<u8> {
    // If hop_start is 0 we can only trust it on decoded packets that
    // carry the (always-populated-since-2.5.0) bitfield.
    if packet.hop_start == 0 {
        match &packet.payload_variant {
            Some(PayloadVariant::Decoded(data)) if data.bitfield.is_some() => {}
            _ => return None,
        }
    }
    // Guard against tampered values.
    if packet.hop_start < packet.hop_limit {
        return None;
    }
    Some((packet.hop_start - packet.hop_limit) as u8)
}

/// Last byte of a node num, with the firmware quirk that `0x00` is
/// remapped to `0xff` so the one-byte `relay_node` field can never
/// collide with its "no relay" sentinel. Mirrors
/// `NodeDB::getLastByteOfNodeNum` in `src/mesh/NodeDB.h:236`.
#[inline]
#[must_use]
pub fn last_byte_of_node_num(num: NodeNum) -> u8 {
    let last = (num & 0xff) as u8;
    if last == 0 {
        0xff
    } else {
        last
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshtastic_proto::meshtastic::Data;

    fn decoded(bitfield: Option<u32>) -> MeshPacket {
        MeshPacket {
            payload_variant: Some(PayloadVariant::Decoded(Data {
                bitfield,
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    #[test]
    fn get_from_substitutes_local_node_when_zero() {
        let p = MeshPacket {
            from: 0,
            ..Default::default()
        };
        assert_eq!(get_from(&p, 0x1234), 0x1234);
        let p2 = MeshPacket {
            from: 0xabcd,
            ..Default::default()
        };
        assert_eq!(get_from(&p2, 0x1234), 0xabcd);
    }

    #[test]
    fn is_from_us_matches_zero_or_our_num() {
        let p = MeshPacket {
            from: 0,
            ..Default::default()
        };
        assert!(is_from_us(&p, 0x42));
        let p2 = MeshPacket {
            from: 0x42,
            ..Default::default()
        };
        assert!(is_from_us(&p2, 0x42));
        let p3 = MeshPacket {
            from: 0x43,
            ..Default::default()
        };
        assert!(!is_from_us(&p3, 0x42));
    }

    #[test]
    fn classify_hop_start_invalid_when_less_than_limit() {
        let p = MeshPacket {
            hop_start: 1,
            hop_limit: 3,
            ..Default::default()
        };
        assert_eq!(classify_hop_start(&p), HopStartStatus::Invalid);
    }

    #[test]
    fn classify_hop_start_valid_when_nonzero() {
        let p = MeshPacket {
            hop_start: 3,
            hop_limit: 2,
            ..Default::default()
        };
        assert_eq!(classify_hop_start(&p), HopStartStatus::Valid);
    }

    #[test]
    fn classify_hop_start_missing_on_encrypted_zero() {
        let p = MeshPacket {
            hop_start: 0,
            hop_limit: 0,
            payload_variant: Some(PayloadVariant::Encrypted(Vec::new())),
            ..Default::default()
        };
        assert_eq!(classify_hop_start(&p), HopStartStatus::MissingOrUnknown);
    }

    #[test]
    fn classify_hop_start_valid_on_decoded_with_bitfield() {
        let p = decoded(Some(0));
        assert_eq!(classify_hop_start(&p), HopStartStatus::Valid);
    }

    #[test]
    fn classify_hop_start_missing_on_decoded_without_bitfield() {
        let p = decoded(None);
        assert_eq!(classify_hop_start(&p), HopStartStatus::MissingOrUnknown);
    }

    #[test]
    fn hops_away_computes_diff() {
        let p = MeshPacket {
            hop_start: 5,
            hop_limit: 3,
            ..Default::default()
        };
        assert_eq!(hops_away(&p), Some(2));
    }

    #[test]
    fn hops_away_none_when_unknown() {
        let p = MeshPacket {
            hop_start: 0,
            hop_limit: 0,
            payload_variant: Some(PayloadVariant::Encrypted(Vec::new())),
            ..Default::default()
        };
        assert_eq!(hops_away(&p), None);
    }

    #[test]
    fn hops_away_none_when_invalid() {
        let p = MeshPacket {
            hop_start: 1,
            hop_limit: 5,
            ..Default::default()
        };
        assert_eq!(hops_away(&p), None);
    }

    #[test]
    fn last_byte_remaps_zero_to_ff() {
        assert_eq!(last_byte_of_node_num(0xdead_be00), 0xff);
        assert_eq!(last_byte_of_node_num(0xdead_be42), 0x42);
    }
}
