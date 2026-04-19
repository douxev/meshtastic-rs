//! Integration tests for the `channels` module.

use meshtastic_core::{channels::MAX_NUM_CHANNELS, Channels, ChannelsError};
use meshtastic_proto::meshtastic::{channel::Role, Channel, ChannelFile, ChannelSettings};

fn make_channel(index: i32, role: Role, name: &str, psk: Vec<u8>) -> Channel {
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
fn default_primary_has_one_slot_with_short_psk() {
    let c = Channels::with_default_primary();
    assert_eq!(c.num_channels(), 1);
    assert_eq!(c.num_enabled(), 1);
    assert_eq!(c.primary_index(), 0);
    let primary = c.by_index(0).unwrap();
    assert_eq!(primary.role(), Role::Primary);
    // The default is the 1-byte shorthand, so expanded should be the full
    // 16-byte DEFAULT_PSK.
    assert_eq!(primary.expanded_psk, meshtastic_crypto::DEFAULT_PSK);
    assert!(primary.hash.is_some());
    assert!(c.uses_default_psk(0));
}

#[test]
fn channel_file_roundtrip_preserves_proto() {
    let file = ChannelFile {
        channels: vec![
            make_channel(0, Role::Primary, "", vec![1]),
            make_channel(1, Role::Secondary, "alpha", vec![0u8; 16]),
            make_channel(2, Role::Disabled, "", vec![]),
        ],
        version: 42,
    };
    let c = Channels::from_channel_file(&file).unwrap();
    assert_eq!(c.num_channels(), 3);
    assert_eq!(c.primary_index(), 0);

    let back = c.to_channel_file();
    assert_eq!(back.channels, file.channels);
    // The to_channel_file intentionally doesn't propagate the version
    // field; callers re-set it when persisting.
    assert_eq!(back.version, 0);
}

#[test]
fn rejects_too_many_channels() {
    let channels: Vec<Channel> = (0..=MAX_NUM_CHANNELS)
        .map(|i| {
            make_channel(
                i as i32,
                if i == 0 { Role::Primary } else { Role::Secondary },
                "",
                vec![1],
            )
        })
        .collect();
    let file = ChannelFile { channels, version: 0 };
    assert_eq!(
        Channels::from_channel_file(&file).unwrap_err(),
        ChannelsError::TooManyChannels(MAX_NUM_CHANNELS + 1)
    );
}

#[test]
fn rejects_no_primary() {
    let file = ChannelFile {
        channels: vec![make_channel(0, Role::Secondary, "x", vec![1])],
        version: 0,
    };
    assert_eq!(
        Channels::from_channel_file(&file).unwrap_err(),
        ChannelsError::NoPrimaryChannel
    );
}

#[test]
fn rejects_multiple_primaries() {
    let file = ChannelFile {
        channels: vec![
            make_channel(0, Role::Primary, "", vec![1]),
            make_channel(1, Role::Primary, "b", vec![1]),
        ],
        version: 0,
    };
    assert_eq!(
        Channels::from_channel_file(&file).unwrap_err(),
        ChannelsError::MultiplePrimaryChannels
    );
}

#[test]
fn secondary_with_empty_psk_falls_back_to_primary_key() {
    let file = ChannelFile {
        channels: vec![
            make_channel(0, Role::Primary, "", vec![1]),
            // Secondary with empty PSK: per firmware, uses primary's key.
            make_channel(1, Role::Secondary, "fwd", vec![]),
        ],
        version: 0,
    };
    let c = Channels::from_channel_file(&file).unwrap();
    let primary_key = c.effective_key(0).unwrap();
    let secondary_key = c.effective_key(1).unwrap();
    assert_eq!(primary_key, secondary_key);
    assert_eq!(primary_key, meshtastic_crypto::DEFAULT_PSK);
}

#[test]
fn disabled_channel_has_no_key_or_hash() {
    let file = ChannelFile {
        channels: vec![
            make_channel(0, Role::Primary, "", vec![1]),
            make_channel(1, Role::Disabled, "", vec![]),
        ],
        version: 0,
    };
    let c = Channels::from_channel_file(&file).unwrap();
    assert!(c.effective_key(1).is_none());
    assert!(c.by_index(1).unwrap().hash.is_none());
}

#[test]
fn find_by_hash_returns_all_matches() {
    // Two slots contrived to share the same hash: same expanded PSK, names
    // whose XORs are equal. "ab" XOR = 0x61^0x62 = 0x03; "ca" XOR =
    // 0x63^0x61 = 0x02. We can just use identical names.
    let file = ChannelFile {
        channels: vec![
            make_channel(0, Role::Primary, "dup", vec![1]),
            make_channel(1, Role::Secondary, "dup", vec![1]),
        ],
        version: 0,
    };
    let c = Channels::from_channel_file(&file).unwrap();
    let h = c.by_index(0).unwrap().hash.unwrap();
    assert_eq!(h, c.by_index(1).unwrap().hash.unwrap());
    let matches: Vec<u8> = c.find_by_hash(h).map(|(i, _)| i).collect();
    assert_eq!(matches, vec![0, 1]);
}

#[test]
fn refresh_slot_updates_cached_hash_after_mutation() {
    let file = ChannelFile {
        channels: vec![make_channel(0, Role::Primary, "a", vec![1])],
        version: 0,
    };
    let mut c = Channels::from_channel_file(&file).unwrap();
    let old_hash = c.by_index(0).unwrap().hash.unwrap();

    // Rename. Cache is now stale until refresh_slot.
    c.by_index_mut(0).unwrap().channel.settings.as_mut().unwrap().name = "abcdef".into();
    c.refresh_slot(0);
    let new_hash = c.by_index(0).unwrap().hash.unwrap();
    assert_ne!(old_hash, new_hash, "hash should change when the name changes");
}

#[test]
fn uses_default_psk_for_both_shorthand_and_full_bytes() {
    let file = ChannelFile {
        channels: vec![
            make_channel(0, Role::Primary, "", vec![1]),
            make_channel(1, Role::Secondary, "", meshtastic_crypto::DEFAULT_PSK.to_vec()),
            make_channel(2, Role::Secondary, "custom", vec![0u8; 16]),
        ],
        version: 0,
    };
    let c = Channels::from_channel_file(&file).unwrap();
    assert!(c.uses_default_psk(0));
    assert!(c.uses_default_psk(1));
    assert!(!c.uses_default_psk(2));
    assert!(!c.uses_default_psk(3)); // out of range
}
