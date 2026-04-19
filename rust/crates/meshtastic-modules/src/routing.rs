//! Port of `src/modules/RoutingModule.cpp`.
//!
//! The firmware's `RoutingModule` is a `ProtobufModule<Routing>` that:
//!
//! 1. Sees **every** packet (`wantPacket` returns `true`, `isPromiscuous
//!    = true`, `encryptedOk = true`).
//! 2. Applies rebroadcast-mode filtering: drops packets whose rebroadcast
//!    would violate the device's `RebroadcastMode` setting
//!    (`LOCAL_ONLY`, `KNOWN_ONLY`) or the "no rebroadcast to/from
//!    unlicensed peers if we are licensed" HAM rule.
//! 3. Delegates to `router->sniffReceived` (ACK/NAK bookkeeping) and
//!    `service->handleFromRadio` (forward to phone). Those side-effects
//!    are platform concerns and live outside this crate.
//! 4. Never auto-replies — `allocReply` always returns `NULL`. ACK/NAK
//!    packets are instead sent explicitly via `sendAckNak` /
//!    `allocAckNak`.
//! 5. Computes a "hop limit for response" based on how many hops the
//!    request used (`getHopLimitForResponse`).
//!
//! This port exposes:
//!
//! - A minimal [`RoutingModule`] `MeshModule` impl with the right
//!   flags and a no-op `handle_received` (the side-effects the
//!   firmware chains through `router` and `service` belong to the
//!   integrator).
//! - Pure helpers the integrator can reach for:
//!   [`rebroadcast_decision`], [`hop_limit_for_response`],
//!   [`alloc_ack_nak`].

use alloc::vec::Vec;

use meshtastic_core::mesh::{hops_away, is_broadcast, NodeNum};
use meshtastic_proto::meshtastic::{
    config::device_config::RebroadcastMode, mesh_packet::PayloadVariant, routing, Data, MeshPacket, PortNum, Routing,
};
use prost::Message;

use crate::module::{MeshModule, ModuleContext};

/// `HOP_MAX` from `src/mesh/MeshTypes.h:38`. Caps hop-limit at 7.
pub const HOP_MAX: u8 = 7;

/// `HOP_RELIABLE` from `src/mesh/MeshTypes.h:41`. Default hop-limit
/// used by most broadcasts.
pub const HOP_RELIABLE: u8 = 3;

/// Minimal port of `src/modules/RoutingModule.cpp`.
///
/// The interesting parts (rebroadcast-mode filtering, hop-limit
/// computation, ACK/NAK packet building) are exposed as free functions
/// so callers can reach them without going through the trait — the
/// trait impl itself is a thin shell that gets the module registered
/// with the correct flags (`is_promiscuous`, `encrypted_ok`,
/// `want_packet`).
#[derive(Debug, Default, Clone, Copy)]
pub struct RoutingModule;

impl RoutingModule {
    /// Create a new `RoutingModule`. Carries no state.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl MeshModule for RoutingModule {
    fn name(&self) -> &str {
        "routing"
    }

    fn is_promiscuous(&self) -> bool {
        // Firmware `isPromiscuous = true` in
        // `src/modules/RoutingModule.cpp:88`.
        true
    }

    fn encrypted_ok(&self) -> bool {
        // Firmware `encryptedOk = true` in
        // `src/modules/RoutingModule.cpp:93`.
        true
    }

    fn want_packet(&self, _packet: &MeshPacket) -> bool {
        // Firmware `wantPacket` overridden to always return `true` in
        // `src/modules/RoutingModule.h:39`.
        true
    }

    fn alloc_reply(&mut self, _request: &MeshPacket) -> Option<MeshPacket> {
        // Firmware `allocReply` always returns `NULL` in
        // `src/modules/RoutingModule.cpp:44`.
        None
    }
}

/// License-status tri-state, ported from the firmware's C++ enum
/// `UserLicenseStatus` in `src/mesh/NodeDB.h:151`. The "unknown" case
/// (firmware `NotKnown`) is important: the rebroadcast filter only
/// drops when it is *certain* a peer is unlicensed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum UserLicenseStatus {
    /// We don't have license information for this node yet.
    #[default]
    Unknown,
    /// We have a `User` record for this node and `is_licensed` is
    /// `false`.
    NotLicensed,
    /// We have a `User` record for this node and `is_licensed` is
    /// `true`.
    Licensed,
}

/// Result of consulting [`rebroadcast_decision`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RebroadcastDecision {
    /// Packet passes all rebroadcast-mode checks.
    Allow,
    /// Packet is blocked by the current `RebroadcastMode` and must
    /// not be forwarded.
    Drop,
}

/// Inputs the integrator needs to look up for
/// [`rebroadcast_decision`]. Keeping this as a struct avoids a
/// 10-parameter function signature and lets the caller cache
/// per-packet lookups.
#[derive(Debug, Clone, Copy)]
pub struct RebroadcastInputs {
    /// Current `device.rebroadcast_mode`.
    pub mode: RebroadcastMode,
    /// `true` if `packet.from` has a NodeDB entry with `has_user =
    /// true`.
    pub sender_known_with_user: bool,
    /// `true` if `packet.to` has a NodeDB entry with `has_user =
    /// true`. (Ignored when the packet is a broadcast.)
    pub recipient_known_with_user: bool,
    /// `true` if the local operator is HAM-licensed
    /// (`owner.is_licensed`).
    pub we_are_licensed: bool,
    /// License status for `packet.from` (from `NodeDB`).
    pub sender_license_status: UserLicenseStatus,
    /// License status for `packet.to` (from `NodeDB`). Ignored for
    /// broadcasts.
    pub recipient_license_status: UserLicenseStatus,
}

/// Port of the `RoutingModule::handleReceivedProtobuf` rebroadcast
/// filter (`src/modules/RoutingModule.cpp:13–29`).
///
/// The decision rules, in firmware order:
///
/// 1. If the packet is **encrypted** and our rebroadcast mode is
///    `LOCAL_ONLY` or `KNOWN_ONLY`:
///    - The packet may be a PKI DM (encrypted + channel==0 + not
///      broadcast). If it isn't a PKI DM, drop.
///    - Otherwise, require at least one of sender/recipient to have a
///      known `NodeDB` entry with `has_user = true`. If neither is
///      known, drop.
/// 2. Otherwise (unencrypted or `ALL`-ish modes), if **we are
///    licensed** and the firmware knows for certain that the sender
///    *or* recipient is **not licensed**, drop — licensed operators
///    must not rebroadcast for unlicensed peers.
/// 3. Otherwise allow.
///
/// Modes other than `LOCAL_ONLY` / `KNOWN_ONLY` share the fallthrough
/// path; the firmware's `ALL`, `ALL_SKIP_DECODING`, `NONE`,
/// `CORE_PORTNUMS_ONLY` are applied elsewhere in the pipeline (the
/// first two are about how the radio layer dispatches a packet at all;
/// `NONE` gates the rebroadcast at the Router; `CORE_PORTNUMS_ONLY` is
/// a portnum allow-list). This function only enforces the two checks
/// the firmware RoutingModule itself performs.
#[must_use]
pub fn rebroadcast_decision(packet: &MeshPacket, inputs: RebroadcastInputs) -> RebroadcastDecision {
    let is_encrypted = matches!(packet.payload_variant, Some(PayloadVariant::Encrypted(_)));
    let maybe_pki = is_encrypted && packet.channel == 0 && !is_broadcast(packet.to);

    if is_encrypted && matches!(inputs.mode, RebroadcastMode::LocalOnly | RebroadcastMode::KnownOnly) {
        if !maybe_pki {
            return RebroadcastDecision::Drop;
        }
        if !inputs.sender_known_with_user && !inputs.recipient_known_with_user {
            return RebroadcastDecision::Drop;
        }
    } else if inputs.we_are_licensed
        && (matches!(inputs.sender_license_status, UserLicenseStatus::NotLicensed)
            || matches!(inputs.recipient_license_status, UserLicenseStatus::NotLicensed))
    {
        return RebroadcastDecision::Drop;
    }

    RebroadcastDecision::Allow
}

/// Port of `RoutingModule::getHopLimitForResponse` in
/// `src/modules/RoutingModule.cpp:62`. Given a request packet and our
/// configured `hop_limit`, decide the hop-limit to put on a reply.
///
/// - If the request used more hops than our config allows (and we're
///   *not* in event mode), mirror that hop count.
/// - If the request was direct (`hop_start == 0`), the reply is
///   direct too.
/// - Otherwise use the hops-used plus a two-hop margin, capped by
///   our configured hop limit.
/// - Fallback: configured hop limit (clamped via
///   `getConfiguredOrDefaultHopLimit`).
///
/// `event_mode` maps to firmware `#if EVENTMODE` — in event mode the
/// "mirror the request's over-limit hop count" branch is suppressed
/// so replies never exceed our default.
#[must_use]
pub fn hop_limit_for_response(request: &MeshPacket, configured_hop_limit: u8, event_mode: bool) -> u8 {
    if let Some(hops_used) = hops_away(request).map(i32::from) {
        let configured = i32::from(configured_hop_limit);
        if hops_used > configured {
            if !event_mode {
                return hops_used.min(i32::from(HOP_MAX)) as u8;
            }
            // else fall through to the configured-or-default path.
        } else if request.hop_start == 0 {
            return 0;
        } else if hops_used + 2 < configured {
            return (hops_used + 2) as u8;
        }
    }
    configured_or_default_hop_limit(configured_hop_limit, event_mode)
}

/// Port of `Default::getConfiguredOrDefaultHopLimit` in
/// `src/mesh/Default.cpp:62`.
///
/// - Event mode caps the configured value at
///   [`HOP_RELIABLE`] (3).
/// - Otherwise, caps at [`HOP_MAX`] (7).
///
/// The firmware does a slightly odd dance of returning
/// `config.lora.hop_limit` in the "under-limit" branch — which is the
/// same variable it was passed — so the cap is effectively the whole
/// contract. This helper keeps the same contract.
#[must_use]
pub fn configured_or_default_hop_limit(configured: u8, event_mode: bool) -> u8 {
    if event_mode {
        if configured > HOP_RELIABLE {
            HOP_RELIABLE
        } else {
            configured
        }
    } else if configured >= HOP_MAX {
        HOP_MAX
    } else {
        configured
    }
}

/// Build a Routing ACK/NAK packet. Ports
/// `MeshModule::allocAckNak` in `src/mesh/MeshModule.cpp:48` (minus
/// the id/from allocation which lives in the Router layer).
///
/// Returns a `MeshPacket` whose:
/// - `to` is the original sender we're acknowledging
/// - `channel` is the channel index the request arrived on
/// - `hop_limit` is whatever the caller computed (typically via
///   [`hop_limit_for_response`])
/// - `priority = ACK`
/// - `decoded.request_id` points back at the request's `id`
/// - `decoded.portnum = ROUTING_APP`, payload is a `Routing` proto
///   with `error_reason = err`
///
/// The caller must still fill in `from` (= our node num) and `id` (a
/// fresh packet id) — those are the Router's responsibility because
/// they need access to the shared packet-id generator.
#[must_use]
pub fn alloc_ack_nak(err: routing::Error, to: NodeNum, id_from: u32, channel: u32, hop_limit: u8) -> MeshPacket {
    let routing = Routing {
        variant: Some(routing::Variant::ErrorReason(err as i32)),
    };
    let mut payload = Vec::with_capacity(routing.encoded_len());
    // `encode` on a heap Vec cannot fail for prost-generated messages.
    routing
        .encode(&mut payload)
        .expect("Routing encode into Vec cannot fail");

    MeshPacket {
        to,
        channel,
        hop_limit: u32::from(hop_limit),
        priority: meshtastic_proto::meshtastic::mesh_packet::Priority::Ack as i32,
        payload_variant: Some(PayloadVariant::Decoded(Data {
            portnum: PortNum::RoutingApp as i32,
            payload,
            request_id: id_from,
            ..Default::default()
        })),
        ..Default::default()
    }
}

impl core::fmt::Display for RebroadcastDecision {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RebroadcastDecision::Allow => f.write_str("allow"),
            RebroadcastDecision::Drop => f.write_str("drop"),
        }
    }
}

/// Convenience: inputs corresponding to the "no filter, no license,
/// ALL mode" baseline. Useful for tests and for platforms that don't
/// model the license system.
impl Default for RebroadcastInputs {
    fn default() -> Self {
        Self {
            mode: RebroadcastMode::All,
            sender_known_with_user: false,
            recipient_known_with_user: false,
            we_are_licensed: false,
            sender_license_status: UserLicenseStatus::Unknown,
            recipient_license_status: UserLicenseStatus::Unknown,
        }
    }
}

// The module impl itself doesn't use `ModuleContext`, but it's part of
// the trait so we keep a blanket acknowledgement here.
const _: fn(&ModuleContext<'_>) = |_| {};

#[cfg(test)]
mod tests {
    use super::*;
    use meshtastic_proto::meshtastic::mesh_packet::PayloadVariant;

    const ALICE: NodeNum = 0x0aaa_aaaa;
    const BOB: NodeNum = 0x0bbb_bbbb;

    fn encrypted_packet(from: NodeNum, to: NodeNum, channel: u32) -> MeshPacket {
        MeshPacket {
            from,
            to,
            channel,
            hop_limit: 3,
            hop_start: 3,
            payload_variant: Some(PayloadVariant::Encrypted(alloc::vec![0xab; 16])),
            ..Default::default()
        }
    }

    fn decoded_packet(from: NodeNum, to: NodeNum, hop_start: u32, hop_limit: u32) -> MeshPacket {
        MeshPacket {
            from,
            to,
            hop_start,
            hop_limit,
            payload_variant: Some(PayloadVariant::Decoded(Data::default())),
            ..Default::default()
        }
    }

    #[test]
    fn module_flags_match_firmware() {
        let m = RoutingModule::new();
        assert!(m.is_promiscuous());
        assert!(m.encrypted_ok());
        assert!(m.want_packet(&decoded_packet(ALICE, BOB, 3, 3)));
        // even encrypted packets.
        assert!(m.want_packet(&encrypted_packet(ALICE, BOB, 0)));
    }

    #[test]
    fn module_never_replies() {
        let mut m = RoutingModule::new();
        let p = decoded_packet(ALICE, BOB, 3, 3);
        assert!(m.alloc_reply(&p).is_none());
    }

    #[test]
    fn rebroadcast_allows_in_all_mode_without_license_concerns() {
        let p = encrypted_packet(ALICE, BOB, 0);
        let inputs = RebroadcastInputs {
            mode: RebroadcastMode::All,
            ..Default::default()
        };
        assert_eq!(rebroadcast_decision(&p, inputs), RebroadcastDecision::Allow);
    }

    #[test]
    fn rebroadcast_local_only_drops_non_pki_encrypted() {
        // channel != 0 → not PKI.
        let p = encrypted_packet(ALICE, BOB, 3);
        let inputs = RebroadcastInputs {
            mode: RebroadcastMode::LocalOnly,
            ..Default::default()
        };
        assert_eq!(rebroadcast_decision(&p, inputs), RebroadcastDecision::Drop);
    }

    #[test]
    fn rebroadcast_local_only_drops_broadcast_encrypted() {
        // broadcast `to` → not PKI even on channel 0.
        let p = encrypted_packet(ALICE, u32::MAX, 0);
        let inputs = RebroadcastInputs {
            mode: RebroadcastMode::LocalOnly,
            ..Default::default()
        };
        assert_eq!(rebroadcast_decision(&p, inputs), RebroadcastDecision::Drop);
    }

    #[test]
    fn rebroadcast_local_only_allows_pki_dm_when_recipient_known() {
        // PKI DM = encrypted + channel == 0 + not broadcast.
        let p = encrypted_packet(ALICE, BOB, 0);
        let inputs = RebroadcastInputs {
            mode: RebroadcastMode::LocalOnly,
            recipient_known_with_user: true,
            ..Default::default()
        };
        assert_eq!(rebroadcast_decision(&p, inputs), RebroadcastDecision::Allow);
    }

    #[test]
    fn rebroadcast_local_only_drops_pki_dm_when_neither_known() {
        let p = encrypted_packet(ALICE, BOB, 0);
        let inputs = RebroadcastInputs {
            mode: RebroadcastMode::LocalOnly,
            sender_known_with_user: false,
            recipient_known_with_user: false,
            ..Default::default()
        };
        assert_eq!(rebroadcast_decision(&p, inputs), RebroadcastDecision::Drop);
    }

    #[test]
    fn rebroadcast_known_only_same_rules_as_local_only() {
        let p = encrypted_packet(ALICE, BOB, 0);
        let inputs = RebroadcastInputs {
            mode: RebroadcastMode::KnownOnly,
            sender_known_with_user: true,
            ..Default::default()
        };
        assert_eq!(rebroadcast_decision(&p, inputs), RebroadcastDecision::Allow);
    }

    #[test]
    fn rebroadcast_licensed_drops_unlicensed_peer() {
        let p = decoded_packet(ALICE, BOB, 3, 3);
        let inputs = RebroadcastInputs {
            mode: RebroadcastMode::All,
            we_are_licensed: true,
            sender_license_status: UserLicenseStatus::NotLicensed,
            recipient_license_status: UserLicenseStatus::Unknown,
            ..Default::default()
        };
        assert_eq!(rebroadcast_decision(&p, inputs), RebroadcastDecision::Drop);
    }

    #[test]
    fn rebroadcast_licensed_drops_unlicensed_recipient() {
        let p = decoded_packet(ALICE, BOB, 3, 3);
        let inputs = RebroadcastInputs {
            mode: RebroadcastMode::All,
            we_are_licensed: true,
            sender_license_status: UserLicenseStatus::Licensed,
            recipient_license_status: UserLicenseStatus::NotLicensed,
            ..Default::default()
        };
        assert_eq!(rebroadcast_decision(&p, inputs), RebroadcastDecision::Drop);
    }

    #[test]
    fn rebroadcast_licensed_allows_unknown_license_status() {
        // Firmware only drops when it *knows* the peer is unlicensed.
        let p = decoded_packet(ALICE, BOB, 3, 3);
        let inputs = RebroadcastInputs {
            mode: RebroadcastMode::All,
            we_are_licensed: true,
            sender_license_status: UserLicenseStatus::Unknown,
            recipient_license_status: UserLicenseStatus::Unknown,
            ..Default::default()
        };
        assert_eq!(rebroadcast_decision(&p, inputs), RebroadcastDecision::Allow);
    }

    #[test]
    fn hop_limit_direct_request_stays_direct() {
        // hop_start == 0 + bitfield present so hops_away is defined.
        let mut p = MeshPacket {
            hop_start: 0,
            hop_limit: 0,
            payload_variant: Some(PayloadVariant::Decoded(Data {
                bitfield: Some(0),
                ..Default::default()
            })),
            ..Default::default()
        };
        assert_eq!(hop_limit_for_response(&p, 5, false), 0);
        // Same on event mode.
        p.hop_limit = 0;
        assert_eq!(hop_limit_for_response(&p, 5, true), 0);
    }

    #[test]
    fn hop_limit_uses_hops_plus_margin_when_within_limit() {
        // hop_start=5, hop_limit=3 → hops_used = 2.
        // configured = 7 → 2+2 = 4 < 7 → return 4.
        let p = decoded_packet(ALICE, BOB, 5, 3);
        assert_eq!(hop_limit_for_response(&p, 7, false), 4);
    }

    #[test]
    fn hop_limit_mirrors_over_limit_request_outside_event_mode() {
        // hops_used = 6, configured = 3 → 6 > 3 → mirror 6.
        let p = decoded_packet(ALICE, BOB, 6, 0);
        assert_eq!(hop_limit_for_response(&p, 3, false), 6);
    }

    #[test]
    fn hop_limit_clamps_to_hop_max_when_mirroring() {
        // hops_used = 10, should clamp to HOP_MAX = 7.
        let p = decoded_packet(ALICE, BOB, 10, 0);
        assert_eq!(hop_limit_for_response(&p, 3, false), HOP_MAX);
    }

    #[test]
    fn hop_limit_event_mode_suppresses_mirroring() {
        // hops_used = 6, configured = 3, event_mode → fall through.
        // configured_or_default_hop_limit(3, event=true) = 3.
        let p = decoded_packet(ALICE, BOB, 6, 0);
        assert_eq!(hop_limit_for_response(&p, 3, true), 3);
    }

    #[test]
    fn hop_limit_falls_through_when_hops_unknown() {
        // Encrypted packet with hop_start == 0 → hops_away = None.
        let mut p = encrypted_packet(ALICE, BOB, 0);
        p.hop_start = 0;
        p.hop_limit = 0;
        // configured = 3 → configured_or_default returns 3.
        assert_eq!(hop_limit_for_response(&p, 3, false), 3);
    }

    #[test]
    fn configured_or_default_caps_at_hop_max() {
        assert_eq!(configured_or_default_hop_limit(HOP_MAX, false), HOP_MAX);
        assert_eq!(configured_or_default_hop_limit(HOP_MAX + 5, false), HOP_MAX);
        assert_eq!(configured_or_default_hop_limit(2, false), 2);
    }

    #[test]
    fn configured_or_default_caps_at_hop_reliable_in_event_mode() {
        assert_eq!(configured_or_default_hop_limit(HOP_MAX, true), HOP_RELIABLE);
        assert_eq!(configured_or_default_hop_limit(HOP_RELIABLE, true), HOP_RELIABLE);
        assert_eq!(configured_or_default_hop_limit(1, true), 1);
    }

    #[test]
    fn alloc_ack_nak_fills_expected_fields() {
        let p = alloc_ack_nak(routing::Error::NoRoute, ALICE, 0xdead_beef, 2, 5);
        assert_eq!(p.to, ALICE);
        assert_eq!(p.channel, 2);
        assert_eq!(p.hop_limit, 5);
        assert_eq!(
            p.priority,
            meshtastic_proto::meshtastic::mesh_packet::Priority::Ack as i32
        );
        let Some(PayloadVariant::Decoded(d)) = p.payload_variant else {
            panic!("decoded payload expected");
        };
        assert_eq!(d.portnum, PortNum::RoutingApp as i32);
        assert_eq!(d.request_id, 0xdead_beef);
        let decoded = Routing::decode(d.payload.as_slice()).unwrap();
        match decoded.variant {
            Some(routing::Variant::ErrorReason(e)) => assert_eq!(e, routing::Error::NoRoute as i32),
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn alloc_ack_nak_none_error_is_a_plain_ack() {
        let p = alloc_ack_nak(routing::Error::None, BOB, 1, 0, 3);
        let Some(PayloadVariant::Decoded(d)) = p.payload_variant else {
            panic!()
        };
        let decoded = Routing::decode(d.payload.as_slice()).unwrap();
        assert!(matches!(decoded.variant, Some(routing::Variant::ErrorReason(0))));
    }
}
