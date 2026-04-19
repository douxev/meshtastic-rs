//! Property tests for the packet pipeline: any well-formed Data on any
//! properly-keyed channel must roundtrip exactly.

use meshtastic_core::{packet, Channels};
use meshtastic_proto::meshtastic::{
    channel::Role, mesh_packet::PayloadVariant, Channel, ChannelFile, ChannelSettings, Data, MeshPacket, PortNum,
};
use meshtastic_proto::prost::Message;
use proptest::prelude::*;

fn channels_with_key(name: &str, key: Vec<u8>) -> Channels {
    let file = ChannelFile {
        channels: vec![Channel {
            index: 0,
            role: Role::Primary as i32,
            settings: Some(ChannelSettings {
                name: name.to_string(),
                psk: key,
                ..Default::default()
            }),
        }],
        version: 0,
    };
    Channels::from_channel_file(&file).unwrap()
}

// Keep the payload under the ~220-byte protobuf encode budget so we stay
// well below MAX_PACKET_PAYLOAD (256) after header overhead.
proptest! {
    #[test]
    fn prop_roundtrip_default_psk(
        from in any::<u32>(),
        id in any::<u32>(),
        portnum in 0i32..=256,
        payload in proptest::collection::vec(any::<u8>(), 0..=200),
        name in "[a-zA-Z0-9]{0,8}",
    ) {
        let channels = channels_with_key(&name, vec![1]);
        let data = Data { portnum, payload: payload.clone(), ..Default::default() };

        let mut pkt = MeshPacket {
            from,
            to: 0xffff_ffff,
            id,
            hop_limit: 3,
            channel: 0,
            payload_variant: Some(PayloadVariant::Decoded(data.clone())),
            ..Default::default()
        };

        packet::encrypt(&channels, 0, &mut pkt).unwrap();
        let wire = pkt.encode_to_vec();
        let mut rx = MeshPacket::decode(&wire[..]).unwrap();
        prop_assert_eq!(packet::decrypt(&channels, &mut rx).unwrap(), 0);
        if let Some(PayloadVariant::Decoded(d)) = rx.payload_variant {
            prop_assert_eq!(d.portnum, data.portnum);
            prop_assert_eq!(d.payload, data.payload);
        } else {
            prop_assert!(false, "expected Decoded after decrypt");
        }
    }

    #[test]
    fn prop_roundtrip_aes256_random_key(
        from in any::<u32>(),
        id in any::<u32>(),
        key in proptest::collection::vec(any::<u8>(), 32..=32),
        payload in proptest::collection::vec(any::<u8>(), 0..=180),
    ) {
        let channels = channels_with_key("ch", key);
        let data = Data { portnum: PortNum::TextMessageApp as i32, payload: payload.clone(), ..Default::default() };

        let mut pkt = MeshPacket {
            from, id, to: 0xffff_ffff, channel: 0,
            payload_variant: Some(PayloadVariant::Decoded(data.clone())),
            ..Default::default()
        };
        packet::encrypt(&channels, 0, &mut pkt).unwrap();
        let wire = pkt.encode_to_vec();
        let mut rx = MeshPacket::decode(&wire[..]).unwrap();
        prop_assert_eq!(packet::decrypt(&channels, &mut rx).unwrap(), 0);
        if let Some(PayloadVariant::Decoded(d)) = rx.payload_variant {
            prop_assert_eq!(d.payload, payload);
        }
    }
}
