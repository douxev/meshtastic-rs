//! End-to-end: Alice encrypts a text message, Bob decrypts it via
//! `meshtastic-core`, and Bob's `ModuleDispatcher` (holding a
//! `TextMessageModule`) picks it up.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering};

extern crate alloc;

use meshtastic_core::{
    channels::Channels,
    packet::{decrypt, encrypt},
};
use meshtastic_modules::{ModuleDispatcher, RxSource, TextMessageModule};
use meshtastic_proto::meshtastic::{mesh_packet::PayloadVariant, Data, MeshPacket, PortNum};

const ALICE: u32 = 0x0aaa_aaaa;
const BOB: u32 = 0x0bbb_bbbb;

fn text_packet(from: u32, to: u32, id: u32, body: &str) -> MeshPacket {
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
fn alice_sends_text_bob_module_receives_it() {
    let channels = Channels::with_default_primary();
    let primary = channels.primary_index();

    // Alice encrypts.
    let mut on_wire = text_packet(ALICE, BOB, 0x1234, "hi bob");
    encrypt(&channels, primary, &mut on_wire).unwrap();

    // Bob sets up a dispatcher with a text module + observer.
    let mut dispatcher = ModuleDispatcher::new();
    let mut text_mod = TextMessageModule::new();
    let observed = Arc::new(AtomicBool::new(false));
    let obs = observed.clone();
    text_mod.add_observer(move |_p| {
        obs.store(true, Ordering::SeqCst);
    });
    dispatcher.register(text_mod);

    // Bob decrypts + dispatches.
    let idx = decrypt(&channels, &mut on_wire).unwrap();
    assert_eq!(idx, primary);
    let out = dispatcher.dispatch(&on_wire, RxSource::Radio, BOB, None);
    assert!(out.module_found);
    assert!(observed.load(Ordering::SeqCst));
}

#[test]
fn encrypted_packet_is_dropped_by_text_module() {
    let channels = Channels::with_default_primary();
    let primary = channels.primary_index();
    let mut on_wire = text_packet(ALICE, BOB, 0x1, "x");
    encrypt(&channels, primary, &mut on_wire).unwrap();

    // Dispatch without decrypting first.
    let mut dispatcher = ModuleDispatcher::new();
    dispatcher.register(TextMessageModule::new());
    let out = dispatcher.dispatch(&on_wire, RxSource::Radio, BOB, None);
    assert!(!out.module_found, "text module should never see encrypted packets");
}

#[test]
fn want_response_triggers_no_reply_from_text_module() {
    let mut dispatcher = ModuleDispatcher::new();
    dispatcher.register(TextMessageModule::new());
    let mut p = text_packet(ALICE, BOB, 0x7, "ping");
    if let Some(PayloadVariant::Decoded(d)) = p.payload_variant.as_mut() {
        d.want_response = true;
    }
    let out = dispatcher.dispatch(&p, RxSource::Radio, BOB, None);
    assert!(out.module_found);
    assert!(out.reply.is_none(), "TextMessageModule does not produce replies");
}
