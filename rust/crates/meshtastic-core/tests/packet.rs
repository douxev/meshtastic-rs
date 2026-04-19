//! Integration tests for the packet encrypt/decrypt pipeline.

use meshtastic_core::{
    channels::{Channels, MAX_NUM_CHANNELS},
    packet, PacketError,
};
use meshtastic_proto::meshtastic::{
    channel::Role, mesh_packet::PayloadVariant, Channel, ChannelFile, ChannelSettings, Data, MeshPacket, PortNum,
};
use meshtastic_proto::prost::Message;

fn make_data(portnum: PortNum, payload: &[u8]) -> Data {
    Data {
        portnum: portnum as i32,
        payload: payload.to_vec(),
        ..Default::default()
    }
}

fn make_packet(from: u32, id: u32, data: Data) -> MeshPacket {
    MeshPacket {
        from,
        to: 0xffff_ffff,
        id,
        hop_limit: 3,
        want_ack: false,
        channel: 0,
        payload_variant: Some(PayloadVariant::Decoded(data)),
        ..Default::default()
    }
}

fn ch(index: i32, role: Role, name: &str, psk: Vec<u8>) -> Channel {
    Channel {
        index,
        role: role as i32,
        settings: Some(ChannelSettings {
            name: name.to_string(),
            psk,
            ..Default::default()
        }),
    }
}

#[test]
fn end_to_end_roundtrip_on_default_channel() {
    let channels = Channels::with_default_primary();
    let primary = channels.primary_index();

    let data = make_data(PortNum::TextMessageApp, b"hello meshtastic");
    let mut pkt = make_packet(0xabcdef01, 0xcafef00d, data.clone());

    packet::encrypt(&channels, primary, &mut pkt).unwrap();
    match &pkt.payload_variant {
        Some(PayloadVariant::Encrypted(b)) => assert!(!b.is_empty()),
        _ => panic!("expected Encrypted after encrypt"),
    }
    // channel now carries the hash tag (u8 stored in a u32)
    assert_eq!(
        pkt.channel,
        u32::from(channels.by_index(primary).unwrap().hash.unwrap())
    );

    // Simulate going over the wire: encode+decode should be transparent.
    let wire = pkt.encode_to_vec();
    let mut rx = MeshPacket::decode(&wire[..]).unwrap();

    let matched = packet::decrypt(&channels, &mut rx).unwrap();
    assert_eq!(matched, primary);
    match &rx.payload_variant {
        Some(PayloadVariant::Decoded(d)) => {
            assert_eq!(d.portnum, data.portnum);
            assert_eq!(d.payload, data.payload);
        }
        _ => panic!("expected Decoded after decrypt"),
    }
    // channel field is back to an index (still just 0 here, but numerically
    // equal to `matched`).
    assert_eq!(rx.channel, u32::from(matched));
}

#[test]
fn decrypt_chooses_correct_channel_when_hashes_differ() {
    let file = ChannelFile {
        channels: vec![
            ch(0, Role::Primary, "primary", vec![1]),
            ch(1, Role::Secondary, "secret", vec![0xaau8; 16]),
        ],
        version: 0,
    };
    let channels = Channels::from_channel_file(&file).unwrap();

    for target in [0u8, 1] {
        let data = make_data(PortNum::NodeinfoApp, b"payload");
        let mut pkt = make_packet(7, 11, data.clone());
        packet::encrypt(&channels, target, &mut pkt).unwrap();
        let wire = pkt.encode_to_vec();
        let mut rx = MeshPacket::decode(&wire[..]).unwrap();
        let matched = packet::decrypt(&channels, &mut rx).unwrap();
        assert_eq!(matched, target);
        if let Some(PayloadVariant::Decoded(d)) = rx.payload_variant {
            assert_eq!(d.payload, data.payload);
        } else {
            panic!("expected Decoded");
        }
    }
}

#[test]
fn decrypt_resolves_hash_collision_to_correct_channel_by_probing() {
    // Two channels with identical name+PSK → identical hashes, but packets
    // encrypted under either should still roundtrip. The decrypt loop
    // tries them in ascending index order; since the key is the same,
    // index 0 will always match first. That matches firmware behaviour.
    let file = ChannelFile {
        channels: vec![
            ch(0, Role::Primary, "dup", vec![1]),
            ch(1, Role::Secondary, "dup", vec![1]),
        ],
        version: 0,
    };
    let channels = Channels::from_channel_file(&file).unwrap();
    assert_eq!(
        channels.by_index(0).unwrap().hash,
        channels.by_index(1).unwrap().hash,
        "test precondition: hash collision"
    );

    let data = make_data(PortNum::TextMessageApp, b"collide");
    let mut pkt = make_packet(1, 1, data.clone());
    packet::encrypt(&channels, 1, &mut pkt).unwrap();
    let wire = pkt.encode_to_vec();
    let mut rx = MeshPacket::decode(&wire[..]).unwrap();
    let matched = packet::decrypt(&channels, &mut rx).unwrap();
    // With identical keys either channel "works"; the lower-index one wins.
    assert_eq!(matched, 0);
    if let Some(PayloadVariant::Decoded(d)) = rx.payload_variant {
        assert_eq!(d.payload, data.payload);
    }
}

#[test]
fn decrypt_rejects_packet_under_different_key() {
    let file_a = ChannelFile {
        channels: vec![ch(0, Role::Primary, "A", vec![0x11u8; 16])],
        version: 0,
    };
    let file_b = ChannelFile {
        channels: vec![ch(0, Role::Primary, "B", vec![0x22u8; 16])],
        version: 0,
    };
    let a = Channels::from_channel_file(&file_a).unwrap();
    let b = Channels::from_channel_file(&file_b).unwrap();

    let data = make_data(PortNum::TextMessageApp, b"secret");
    let mut pkt = make_packet(1, 1, data);
    packet::encrypt(&a, 0, &mut pkt).unwrap();

    // B cannot match A's hash (different name + key), so decrypt should
    // fail at the hash-lookup stage.
    let wire = pkt.encode_to_vec();
    let mut rx = MeshPacket::decode(&wire[..]).unwrap();
    assert!(matches!(
        packet::decrypt(&b, &mut rx),
        Err(PacketError::NoMatchingChannel { .. })
    ));
    // On failure the packet must still be in the Encrypted state.
    assert!(matches!(rx.payload_variant, Some(PayloadVariant::Encrypted(_))));
}

#[test]
fn decrypt_rejects_hash_collision_with_wrong_key() {
    // Force a hash collision between two channels that have *different*
    // keys. The expected behaviour: decrypt tries both, protobuf-decode
    // fails for the wrong key, and we get NoMatchingChannel.
    //
    // channel_hash = XOR(name_bytes) XOR XOR(psk_bytes). If both channels
    // use the same name, then the hashes collide iff XOR(psk_a) ==
    // XOR(psk_b). Build two 16-byte keys with the same byte-XOR but
    // differing bytes: e.g. all-zero vs. two non-zero bytes that cancel
    // ([0,...,0, 0xaa, 0xaa]).
    let key_a = vec![0u8; 16];
    let mut key_b = vec![0u8; 16];
    key_b[14] = 0xaa;
    key_b[15] = 0xaa;

    let file = ChannelFile {
        channels: vec![ch(0, Role::Primary, "x", key_a), ch(1, Role::Secondary, "x", key_b)],
        version: 0,
    };
    let channels = Channels::from_channel_file(&file).unwrap();
    assert_eq!(
        channels.by_index(0).unwrap().hash,
        channels.by_index(1).unwrap().hash,
        "test precondition: hash collision with different keys"
    );

    // Put a *long* payload on channel 1. Short payloads (< ~2 bytes) have
    // a non-negligible chance of "decoding" as a valid (empty) Data proto
    // under an unrelated key purely by luck; a 64-byte payload makes that
    // chance astronomically small.
    let data = make_data(PortNum::TextMessageApp, &[0x5au8; 64]);
    let mut pkt = make_packet(42, 99, data.clone());
    packet::encrypt(&channels, 1, &mut pkt).unwrap();

    let wire = pkt.encode_to_vec();
    let mut rx = MeshPacket::decode(&wire[..]).unwrap();
    let matched = packet::decrypt(&channels, &mut rx).unwrap();
    // Channel 0 (wrong key) will fail to protobuf-decode and be skipped;
    // channel 1 (right key) matches.
    assert_eq!(matched, 1);
    if let Some(PayloadVariant::Decoded(d)) = rx.payload_variant {
        assert_eq!(d.payload, data.payload);
    }
}

#[test]
fn encrypt_rejects_non_decoded_packet() {
    let channels = Channels::with_default_primary();
    let mut pkt = MeshPacket {
        payload_variant: Some(PayloadVariant::Encrypted(vec![1, 2, 3])),
        ..Default::default()
    };
    assert_eq!(packet::encrypt(&channels, 0, &mut pkt), Err(PacketError::NotDecoded));
    // Packet must not have been corrupted on error.
    assert!(matches!(pkt.payload_variant, Some(PayloadVariant::Encrypted(_))));
}

#[test]
fn encrypt_rejects_empty_variant() {
    let channels = Channels::with_default_primary();
    let mut pkt = MeshPacket::default();
    assert_eq!(packet::encrypt(&channels, 0, &mut pkt), Err(PacketError::NotDecoded));
}

#[test]
fn encrypt_rejects_invalid_channel_index() {
    let channels = Channels::with_default_primary();
    let mut pkt = make_packet(1, 1, make_data(PortNum::TextMessageApp, b"x"));
    assert_eq!(
        packet::encrypt(&channels, MAX_NUM_CHANNELS as u8, &mut pkt),
        Err(PacketError::InvalidChannelIndex(MAX_NUM_CHANNELS as u8))
    );
    // On error the packet must still be in the Decoded state.
    assert!(matches!(pkt.payload_variant, Some(PayloadVariant::Decoded(_))));
}

#[test]
fn encrypt_rejects_disabled_channel() {
    let file = ChannelFile {
        channels: vec![ch(0, Role::Primary, "", vec![1]), ch(1, Role::Disabled, "", vec![])],
        version: 0,
    };
    let channels = Channels::from_channel_file(&file).unwrap();
    let mut pkt = make_packet(1, 1, make_data(PortNum::TextMessageApp, b"x"));
    assert_eq!(
        packet::encrypt(&channels, 1, &mut pkt),
        Err(PacketError::ChannelUnencrypted(1))
    );
    assert!(matches!(pkt.payload_variant, Some(PayloadVariant::Decoded(_))));
}

#[test]
fn decrypt_rejects_non_encrypted_packet() {
    let channels = Channels::with_default_primary();
    let mut pkt = make_packet(1, 1, make_data(PortNum::TextMessageApp, b"x"));
    assert_eq!(packet::decrypt(&channels, &mut pkt), Err(PacketError::NotEncrypted));
    assert!(matches!(pkt.payload_variant, Some(PayloadVariant::Decoded(_))));
}

#[test]
fn empty_data_payload_still_roundtrips() {
    // Genuinely empty (portnum = Unknown, empty payload) still encodes to
    // an empty proto, and must roundtrip.
    let channels = Channels::with_default_primary();
    let data = Data::default();
    let mut pkt = make_packet(1, 1, data.clone());
    packet::encrypt(&channels, 0, &mut pkt).unwrap();
    let wire = pkt.encode_to_vec();
    let mut rx = MeshPacket::decode(&wire[..]).unwrap();
    let matched = packet::decrypt(&channels, &mut rx).unwrap();
    assert_eq!(matched, 0);
    if let Some(PayloadVariant::Decoded(d)) = rx.payload_variant {
        assert_eq!(d, data);
    }
}

#[test]
fn payload_too_large_is_rejected_and_state_restored() {
    let channels = Channels::with_default_primary();
    let data = make_data(PortNum::TextMessageApp, &vec![0u8; 512]);
    let mut pkt = make_packet(1, 1, data.clone());
    match packet::encrypt(&channels, 0, &mut pkt) {
        Err(PacketError::PayloadTooLarge(_)) => {}
        other => panic!("expected PayloadTooLarge, got {other:?}"),
    }
    // State must be restored on error.
    if let Some(PayloadVariant::Decoded(d)) = &pkt.payload_variant {
        assert_eq!(d, &data);
    } else {
        panic!("encrypt should have restored Decoded state on error");
    }
}
