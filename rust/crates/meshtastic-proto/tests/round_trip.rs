//! Round-trip tests for representative Meshtastic protobuf messages.
//!
//! These tests validate that `prost`-generated `encode` / `decode` produce
//! byte-for-byte stable output for the message types most central to v1
//! (mesh packets, service envelopes, channels, users, positions, telemetry,
//! routing). They guard against accidental codegen regressions and against
//! upstream `protobufs/` changes that would alter the wire format in a way
//! `prost` can't represent losslessly.

use meshtastic_proto::meshtastic::{
    mesh_packet::PayloadVariant, telemetry::Variant as TelemetryVariant, Channel, ChannelSettings, DeviceMetrics,
    HardwareModel, MeshPacket, NodeInfo, Position, Routing, ServiceEnvelope, Telemetry, User,
};
use prost::Message;

/// Encode `msg`, decode the bytes, and assert that the result equals the
/// original. Returns the encoded byte vector for further assertions.
fn round_trip<M: Message + Default + PartialEq + std::fmt::Debug + Clone>(msg: &M) -> Vec<u8> {
    let bytes = msg.encode_to_vec();
    let decoded = M::decode(&bytes[..]).expect("decode must succeed");
    assert_eq!(*msg, decoded, "round-trip mismatch");

    // Also verify length agrees with the encoded buffer.
    assert_eq!(msg.encoded_len(), bytes.len(), "encoded_len() mismatch");
    bytes
}

#[test]
fn mesh_packet_encrypted_round_trip() {
    let packet = MeshPacket {
        from: 0x1234_5678,
        to: 0xffff_ffff,
        channel: 1,
        id: 0xdead_beef,
        rx_time: 1_700_000_000,
        rx_snr: -7.5,
        hop_limit: 3,
        want_ack: true,
        priority: 0,
        rx_rssi: -110,
        hop_start: 3,
        payload_variant: Some(PayloadVariant::Encrypted(vec![0xde, 0xad, 0xbe, 0xef, 0x00, 0xff])),
        ..Default::default()
    };
    let bytes = round_trip(&packet);
    assert!(!bytes.is_empty());
}

#[test]
fn service_envelope_round_trip() {
    let inner = MeshPacket {
        from: 0xaaaa_bbbb,
        to: 0xffff_ffff,
        channel: 0,
        payload_variant: Some(PayloadVariant::Encrypted(vec![1, 2, 3])),
        ..Default::default()
    };
    let envelope = ServiceEnvelope {
        packet: Some(inner),
        channel_id: "LongFast".into(),
        gateway_id: "!aabbccdd".into(),
    };
    round_trip(&envelope);
}

#[test]
fn user_with_tdeck_hardware_model_round_trip() {
    let user = User {
        id: "!12345678".into(),
        long_name: "Test Node".into(),
        short_name: "TST".into(),
        hw_model: HardwareModel::TDeck as i32,
        is_licensed: false,
        public_key: vec![0x55; 32],
        ..Default::default()
    };
    round_trip(&user);
}

#[test]
fn position_round_trip_negative_coordinates() {
    let pos = Position {
        latitude_i: Some(-37_812_345),
        longitude_i: Some(144_962_345),
        altitude: Some(123),
        time: 1_700_000_001,
        sats_in_view: 8,
        precision_bits: 16,
        ..Default::default()
    };
    round_trip(&pos);
}

#[test]
fn telemetry_device_metrics_round_trip() {
    let telemetry = Telemetry {
        time: 1_700_000_002,
        variant: Some(TelemetryVariant::DeviceMetrics(DeviceMetrics {
            battery_level: Some(87),
            voltage: Some(3.92),
            channel_utilization: Some(4.2),
            air_util_tx: Some(0.5),
            uptime_seconds: Some(1_234_567),
        })),
    };
    round_trip(&telemetry);
}

#[test]
fn routing_oneof_default() {
    // A defaulted Routing still has a valid wire encoding (empty buffer).
    let routing = Routing::default();
    let bytes = routing.encode_to_vec();
    assert!(bytes.is_empty(), "default Routing must encode to zero bytes");
    let decoded = Routing::decode(&bytes[..]).unwrap();
    assert_eq!(routing, decoded);
}

#[test]
fn channel_with_settings_round_trip() {
    let channel = Channel {
        index: 0,
        settings: Some(ChannelSettings {
            psk: vec![1; 16],
            name: "LongFast".into(),
            id: 0xc0de_d00d,
            uplink_enabled: true,
            downlink_enabled: false,
            ..Default::default()
        }),
        role: 1, // PRIMARY
    };
    round_trip(&channel);
}

#[test]
fn nodeinfo_round_trip_optional_fields() {
    let info = NodeInfo {
        num: 0x9999_8888,
        user: Some(User {
            id: "!99998888".into(),
            long_name: "Neighbour".into(),
            short_name: "NBR".into(),
            ..Default::default()
        }),
        position: Some(Position {
            latitude_i: Some(0),
            longitude_i: Some(0),
            ..Default::default()
        }),
        snr: 6.25,
        last_heard: 1_700_000_003,
        hops_away: Some(2),
        is_favorite: true,
        ..Default::default()
    };
    round_trip(&info);
}

#[test]
fn mesh_packet_default_is_empty_wire() {
    // A zero-valued MeshPacket has no set fields and must serialize to an
    // empty buffer. This is a sanity check on `prost`'s default-handling
    // because every numeric field on the message has a proto3 default of 0.
    let bytes = MeshPacket::default().encode_to_vec();
    assert!(
        bytes.is_empty(),
        "default MeshPacket must serialize to zero bytes; got {bytes:?}"
    );
}

#[test]
fn mesh_packet_id_is_stable_across_encode_cycles() {
    // Encoding/decoding should be idempotent under repeated cycles.
    let mut packet = MeshPacket {
        from: 1,
        to: 2,
        id: 42,
        payload_variant: Some(PayloadVariant::Encrypted(vec![9, 9, 9])),
        ..Default::default()
    };
    for _ in 0..4 {
        let bytes = packet.encode_to_vec();
        packet = MeshPacket::decode(&bytes[..]).unwrap();
        assert_eq!(packet.id, 42);
    }
}
