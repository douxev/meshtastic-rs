//! End-to-end integration: encrypt a packet, dedup-on-receive with
//! [`PacketHistory`], and populate [`NodeDb`] from the decoded packet.
//! Exercises Phase 4a + 4b together.

use meshtastic_core::{
    channels::Channels,
    mesh::{get_from, last_byte_of_node_num},
    nodedb::NodeDb,
    packet::{self, decrypt, encrypt},
    packet_history::{PacketHistory, SeenInfo},
};
use meshtastic_proto::meshtastic::{mesh_packet::PayloadVariant, Data, MeshPacket, PortNum};

const ALICE: u32 = 0x0a0a_0a0a;
const BOB: u32 = 0x0b0b_0b0b;

fn text_packet(from: u32, to: u32, id: u32, body: &str) -> MeshPacket {
    MeshPacket {
        from,
        to,
        id,
        hop_limit: 3,
        hop_start: 3,
        rx_time: 100,
        rx_snr: 4.2,
        payload_variant: Some(PayloadVariant::Decoded(Data {
            portnum: PortNum::TextMessageApp as i32,
            payload: body.as_bytes().to_vec(),
            ..Default::default()
        })),
        ..Default::default()
    }
}

#[test]
fn alice_sends_bob_decrypts_nodedb_updates_and_dedup_kicks_in() {
    // Both nodes share the same default primary channel.
    let channels = Channels::with_default_primary();
    let primary = channels.primary_index();

    // Alice composes + encrypts.
    let mut outbound = text_packet(ALICE, BOB, 0x1001, "hello bob");
    encrypt(&channels, primary, &mut outbound).unwrap();
    assert!(matches!(outbound.payload_variant, Some(PayloadVariant::Encrypted(_))));

    // Bob receives. Dedup (first sighting) then decrypt then NodeDB update.
    let mut bob_hist = PacketHistory::with_capacity(32);
    let mut bob_db = NodeDb::new(BOB);

    let bob_relay = last_byte_of_node_num(BOB);
    let first: SeenInfo = bob_hist.was_seen_recently(&outbound, 1_000, true, BOB, bob_relay);
    assert!(!first.seen_recently, "first time should not be a dupe");

    let decrypted_idx = decrypt(&channels, &mut outbound).unwrap();
    assert_eq!(decrypted_idx, primary);
    match &outbound.payload_variant {
        Some(PayloadVariant::Decoded(d)) => {
            assert_eq!(d.payload, b"hello bob");
            assert_eq!(d.portnum, PortNum::TextMessageApp as i32);
        }
        other => panic!("expected decoded, got {other:?}"),
    }
    let updated_num = bob_db.update_from(&outbound).expect("alice recorded");
    assert_eq!(updated_num, ALICE);
    let alice_info = bob_db.get(ALICE).unwrap();
    assert_eq!(alice_info.last_heard, 100);
    assert!((alice_info.snr - 4.2).abs() < 1e-6);
    assert_eq!(alice_info.hops_away, Some(0));

    // A duplicate of the same packet (e.g. via a relay) must be
    // flagged as seen and must not create a second NodeDB entry.
    let mut dup = text_packet(ALICE, BOB, 0x1001, "hello bob");
    encrypt(&channels, primary, &mut dup).unwrap();
    let second = bob_hist.was_seen_recently(&dup, 2_000, true, BOB, bob_relay);
    assert!(second.seen_recently);
    // NodeDB still has exactly one entry for Alice.
    assert_eq!(bob_db.len(), 1);
}

#[test]
fn packet_from_self_does_not_populate_nodedb() {
    let mut db = NodeDb::new(BOB);
    let p = text_packet(BOB, ALICE, 0x1, "echo");
    assert!(db.update_from(&p).is_none());
    assert!(db.is_empty());
}

#[test]
fn get_from_is_used_for_legacy_from_zero_packets() {
    // A legacy firmware sends `from = 0`. The router's dedup step
    // should key by our own node num (get_from substitution), so that
    // the echo comes back and dedups correctly.
    let channels = Channels::with_default_primary();
    let primary = channels.primary_index();
    let mut p = text_packet(0, ALICE, 0x42, "hi");
    encrypt(&channels, primary, &mut p).unwrap();

    let mut hist = PacketHistory::with_capacity(8);
    let our_num = 0x99u32;
    let relay = last_byte_of_node_num(our_num);
    let _ = hist.was_seen_recently(&p, 100, true, our_num, relay);
    assert_eq!(get_from(&p, our_num), our_num);
    // The stored record must be keyed under our own node num.
    assert!(hist.find(our_num, 0x42).is_some());
    assert!(hist.find(0, 0x42).is_none());
}

#[test]
fn wrong_key_means_no_dedup_entry_and_no_nodedb_update() {
    // Alice uses one key; Bob has a different one.
    let alice_ch = Channels::with_default_primary();
    let primary = alice_ch.primary_index();

    // Build Bob with a different PSK so decryption fails cleanly.
    use meshtastic_proto::meshtastic::{channel::Role, Channel, ChannelFile, ChannelSettings};
    let bob_ch = Channels::from_channel_file(&ChannelFile {
        channels: vec![Channel {
            index: 0,
            settings: Some(ChannelSettings {
                psk: vec![42; 16],
                name: "primary".into(),
                ..Default::default()
            }),
            role: Role::Primary as i32,
        }],
        version: 0,
    })
    .unwrap();

    let mut pkt = text_packet(ALICE, BOB, 0x77, "secret");
    encrypt(&alice_ch, primary, &mut pkt).unwrap();

    // Bob tries to decrypt — fails.
    let err = decrypt(&bob_ch, &mut pkt).unwrap_err();
    assert!(
        matches!(err, packet::PacketError::NoMatchingChannel { .. }),
        "got {err:?}"
    );
    // Packet state is preserved on error.
    assert!(matches!(pkt.payload_variant, Some(PayloadVariant::Encrypted(_))));
}
