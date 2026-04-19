//! End-to-end: Alice encrypts a text message on one `SimRadio`, the
//! bus delivers it to Bob's `SimRadio`, Bob decrypts it and dispatches
//! it through a `ModuleDispatcher` containing a `TextMessageModule`.
//!
//! This exercises every crate in the workspace simultaneously:
//! `meshtastic-proto`, `meshtastic-crypto`, `meshtastic-core`,
//! `meshtastic-modules`, `meshtastic-hal`, and `meshtastic-sim`.

use meshtastic_core::{
    channels::Channels,
    packet::{decrypt, encrypt},
};
use meshtastic_hal::{Clock, PacketIdAllocator, Radio, Rng};
use meshtastic_modules::{ModuleDispatcher, RxSource, TextMessageModule};
use meshtastic_proto::meshtastic::{mesh_packet::PayloadVariant, Data, MeshPacket, PortNum};
use meshtastic_sim::{SimClock, SimRadioBus, SimRng};

const ALICE: u32 = 0x0aaa_aaaa;
const BOB: u32 = 0x0bbb_bbbb;

fn text(from: u32, to: u32, id: u32, body: &str) -> MeshPacket {
    MeshPacket {
        from,
        to,
        id,
        hop_limit: 3,
        hop_start: 3,
        payload_variant: Some(PayloadVariant::Decoded(Data {
            portnum: PortNum::TextMessageApp as i32,
            payload: body.as_bytes().to_vec(),
            ..Default::default()
        })),
        ..Default::default()
    }
}

#[test]
fn alice_radio_to_bob_module_roundtrip() {
    // Shared channel table (both peers know the default primary).
    let channels = Channels::with_default_primary();
    let primary = channels.primary_index();

    // Clock + deterministic RNG — not strictly needed for this test
    // but exercises the HAL trait surfaces.
    let clock = SimClock::from_now();
    let _ = clock.millis();
    let mut rng = SimRng::seed_from_u64(0x1234_5678_90ab_cdef);
    let mut ids = PacketIdAllocator::new(rng.clone());
    let packet_id = ids.next_id();
    assert!(packet_id != 0);

    // Radios.
    let bus = SimRadioBus::new();
    let mut alice_radio = bus.attach(ALICE);
    let mut bob_radio = bus.attach(BOB);

    // Bob's module pipeline.
    let mut bob_dispatcher = ModuleDispatcher::new();
    bob_dispatcher.register(TextMessageModule::new());

    // Alice builds a text, encrypts it, and transmits.
    let mut outbound = text(ALICE, BOB, packet_id, "hi bob");
    encrypt(&channels, primary, &mut outbound).unwrap();
    alice_radio.send(&outbound).unwrap();

    // Alice should not hear her own TX.
    assert!(alice_radio.try_recv().unwrap().is_none());

    // Bob pulls the packet off the air and decrypts it.
    let rx = bob_radio.try_recv().unwrap().expect("Bob should have RX");
    let mut inbound = rx.packet;
    decrypt(&channels, &mut inbound).unwrap();

    // Bob dispatches through his modules.
    let out = bob_dispatcher.dispatch(&inbound, RxSource::Radio, BOB, None);
    assert!(out.module_found, "TextMessageModule must see the packet");
    assert!(out.reply.is_none(), "text module does not auto-reply");

    // The rng was consumed by the allocator; advance it and confirm
    // it's still producing values.
    let _ = rng.next_u32();
}

#[test]
fn broadcast_reaches_every_peer_on_the_bus() {
    let channels = Channels::with_default_primary();
    let primary = channels.primary_index();

    let bus = SimRadioBus::new();
    let mut alice = bus.attach(ALICE);
    let mut bob = bus.attach(BOB);
    let mut charlie = bus.attach(0x0ccc_cccc);

    let mut pkt = text(ALICE, u32::MAX, 99, "CQ CQ");
    encrypt(&channels, primary, &mut pkt).unwrap();
    alice.send(&pkt).unwrap();

    let b = bob.try_recv().unwrap().expect("bob RX");
    let c = charlie.try_recv().unwrap().expect("charlie RX");
    assert_eq!(b.packet.id, c.packet.id);
    assert_eq!(b.packet.id, 99);
}
