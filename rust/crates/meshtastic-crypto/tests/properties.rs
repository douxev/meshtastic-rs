//! Property tests: AES-CTR roundtrip, channel_hash stability, PSK expansion
//! invariants. These exercise the crate against `proptest`-generated inputs
//! well beyond what the hand-picked golden vectors cover.

use meshtastic_crypto::{
    build_nonce, channel_hash, decrypt_packet, encrypt_packet, expand_psk, CryptoError, DEFAULT_PSK, EVENT_PSK,
    MAX_PACKET_PAYLOAD,
};
use proptest::prelude::*;

proptest! {
    #[test]
    fn prop_aes128_roundtrip(
        from_node in any::<u32>(),
        packet_id in any::<u64>(),
        payload in proptest::collection::vec(any::<u8>(), 0..=MAX_PACKET_PAYLOAD),
    ) {
        let mut buf = payload.clone();
        encrypt_packet(&DEFAULT_PSK, from_node, packet_id, &mut buf).unwrap();
        decrypt_packet(&DEFAULT_PSK, from_node, packet_id, &mut buf).unwrap();
        prop_assert_eq!(buf, payload);
    }

    #[test]
    fn prop_aes256_roundtrip(
        from_node in any::<u32>(),
        packet_id in any::<u64>(),
        payload in proptest::collection::vec(any::<u8>(), 0..=MAX_PACKET_PAYLOAD),
    ) {
        let mut buf = payload.clone();
        encrypt_packet(&EVENT_PSK, from_node, packet_id, &mut buf).unwrap();
        decrypt_packet(&EVENT_PSK, from_node, packet_id, &mut buf).unwrap();
        prop_assert_eq!(buf, payload);
    }

    #[test]
    fn prop_arbitrary_key_roundtrip(
        key_is_256 in any::<bool>(),
        key_bytes in proptest::collection::vec(any::<u8>(), 0..=32),
        from_node in any::<u32>(),
        packet_id in any::<u64>(),
        payload in proptest::collection::vec(any::<u8>(), 0..=MAX_PACKET_PAYLOAD),
    ) {
        // Build a well-formed key of the chosen size.
        let mut key = key_bytes;
        key.resize(if key_is_256 { 32 } else { 16 }, 0);
        let mut buf = payload.clone();
        encrypt_packet(&key, from_node, packet_id, &mut buf).unwrap();
        decrypt_packet(&key, from_node, packet_id, &mut buf).unwrap();
        prop_assert_eq!(buf, payload);
    }

    #[test]
    fn prop_oversize_rejected(
        extra in 1usize..64,
    ) {
        let mut buf = vec![0u8; MAX_PACKET_PAYLOAD + extra];
        prop_assert_eq!(
            encrypt_packet(&DEFAULT_PSK, 0, 0, &mut buf),
            Err(CryptoError::PayloadTooLarge(MAX_PACKET_PAYLOAD + extra))
        );
    }

    #[test]
    fn prop_bad_key_length_rejected(
        // pick any length that isn't exactly 16 or 32, including the empty key
        len in (0usize..64).prop_filter("valid keylen", |n| *n != 16 && *n != 32),
    ) {
        let key = vec![0u8; len];
        let mut buf = [1u8, 2, 3];
        prop_assert_eq!(
            encrypt_packet(&key, 0, 0, &mut buf),
            Err(CryptoError::InvalidKeyLength(len))
        );
    }

    #[test]
    fn prop_channel_hash_is_xor_fold(
        name in "[\\x20-\\x7e]{0,16}",
        psk in proptest::collection::vec(any::<u8>(), 0..=32),
    ) {
        let mut expected = 0u8;
        for &b in name.as_bytes() { expected ^= b; }
        for &b in &psk          { expected ^= b; }
        prop_assert_eq!(channel_hash(&name, &psk), expected);
    }

    #[test]
    fn prop_expand_psk_length_is_0_16_or_32_or_passthrough(
        input in proptest::collection::vec(any::<u8>(), 0..=48),
    ) {
        let out = expand_psk(&input);
        let n = out.len();
        prop_assert!(
            n == 0 || n == 16 || n == 32 || (n > 32 && n == input.len()),
            "expand_psk produced unexpected length {n}"
        );
    }

    #[test]
    fn prop_nonce_is_deterministic(
        from_node in any::<u32>(),
        packet_id in any::<u64>(),
    ) {
        prop_assert_eq!(
            build_nonce(from_node, packet_id),
            build_nonce(from_node, packet_id)
        );
    }

    #[test]
    fn prop_different_nonce_produces_different_ciphertext(
        from_a in any::<u32>(),
        from_b in any::<u32>(),
        id_a in any::<u64>(),
        id_b in any::<u64>(),
        payload in proptest::collection::vec(any::<u8>(), 1..=64),
    ) {
        // Only assert when the nonces actually differ.
        prop_assume!((from_a, id_a) != (from_b, id_b));
        // And the payload isn't all-zeros (where identical plaintext blocks
        // across different keystreams could theoretically collide for very
        // short messages; all-zero payload makes ct == keystream prefix).
        prop_assume!(payload.iter().any(|&b| b != 0) || payload.len() >= 2);

        let mut a = payload.clone();
        let mut b = payload.clone();
        encrypt_packet(&DEFAULT_PSK, from_a, id_a, &mut a).unwrap();
        encrypt_packet(&DEFAULT_PSK, from_b, id_b, &mut b).unwrap();
        prop_assert_ne!(a, b);
    }
}
