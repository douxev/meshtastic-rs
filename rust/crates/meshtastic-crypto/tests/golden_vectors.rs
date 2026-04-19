//! Golden-vector tests: the Rust implementation must reproduce, byte-for-byte,
//! the output of the C++ firmware oracle for every case in
//! `test/rust-golden-vectors/vectors.json`.
//!
//! The vectors are produced by a small, self-contained C++ program under
//! `test/rust-golden-vectors/gen_vectors.cpp` that re-derives the firmware's
//! algorithms against OpenSSL; see that directory's README for details.

use meshtastic_crypto::{channel_hash, decrypt_packet, encrypt_packet, expand_psk};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
struct Vectors {
    channel_hash: Vec<ChannelHashCase>,
    psk_expansion: Vec<PskExpansionCase>,
    aes_ctr_packet: Vec<AesCtrCase>,
}

#[derive(Debug, Deserialize)]
struct ChannelHashCase {
    name: String,
    channel_name: String,
    psk_hex: String,
    hash: u8,
}

#[derive(Debug, Deserialize)]
struct PskExpansionCase {
    name: String,
    input_hex: String,
    expanded_hex: String,
}

#[derive(Debug, Deserialize)]
struct AesCtrCase {
    name: String,
    psk_hex: String,
    from_node: u32,
    packet_id: u64,
    nonce_hex: String,
    plaintext_hex: String,
    ciphertext_hex: String,
}

fn load_vectors() -> Vectors {
    // Path resolution: CARGO_MANIFEST_DIR = <repo>/rust/crates/meshtastic-crypto
    // and the vectors live at <repo>/test/rust-golden-vectors/vectors.json.
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let vectors_path = manifest_dir
        .ancestors()
        .nth(3)
        .expect("repository root")
        .join("test/rust-golden-vectors/vectors.json");

    let bytes =
        std::fs::read(&vectors_path).unwrap_or_else(|e| panic!("reading vectors at {}: {e}", vectors_path.display()));
    serde_json::from_slice(&bytes).expect("parsing vectors.json")
}

fn unhex(s: &str) -> Vec<u8> {
    hex::decode(s).expect("valid hex")
}

#[test]
fn golden_channel_hash_vectors() {
    let v = load_vectors();
    assert!(!v.channel_hash.is_empty(), "vectors.json has no channel_hash cases");
    for case in v.channel_hash {
        let psk = unhex(&case.psk_hex);
        let got = channel_hash(&case.channel_name, &psk);
        assert_eq!(
            got, case.hash,
            "channel_hash mismatch for '{}' (name={:?}, psk={}): got {} expected {}",
            case.name, case.channel_name, case.psk_hex, got, case.hash
        );
    }
}

#[test]
fn golden_psk_expansion_vectors() {
    let v = load_vectors();
    assert!(!v.psk_expansion.is_empty(), "vectors.json has no psk_expansion cases");
    for case in v.psk_expansion {
        let input = unhex(&case.input_hex);
        let expected = unhex(&case.expanded_hex);
        let got = expand_psk(&input);
        assert_eq!(
            got,
            expected,
            "expand_psk mismatch for '{}': input={} got={} expected={}",
            case.name,
            case.input_hex,
            hex::encode(&got),
            case.expanded_hex,
        );
    }
}

#[test]
fn golden_aes_ctr_packet_vectors() {
    let v = load_vectors();
    assert!(!v.aes_ctr_packet.is_empty(), "vectors.json has no aes_ctr_packet cases");
    for case in v.aes_ctr_packet {
        let psk = unhex(&case.psk_hex);
        let plaintext = unhex(&case.plaintext_hex);
        let expected_ct = unhex(&case.ciphertext_hex);

        // Nonce construction must match.
        let nonce = meshtastic_crypto::build_nonce(case.from_node, case.packet_id);
        assert_eq!(hex::encode(nonce), case.nonce_hex, "nonce mismatch for '{}'", case.name,);

        // Encryption must be byte-identical.
        let mut buf = plaintext.clone();
        encrypt_packet(&psk, case.from_node, case.packet_id, &mut buf).expect("encrypt");
        assert_eq!(
            buf,
            expected_ct,
            "ciphertext mismatch for '{}' ({} bytes): got {} expected {}",
            case.name,
            plaintext.len(),
            hex::encode(&buf),
            case.ciphertext_hex
        );

        // And round-trips back to the plaintext.
        decrypt_packet(&psk, case.from_node, case.packet_id, &mut buf).expect("decrypt");
        assert_eq!(buf, plaintext, "round-trip mismatch for '{}'", case.name);
    }
}
