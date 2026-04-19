# Golden vectors for `meshtastic-crypto`

This directory contains a small, **self-contained** C++ harness that
reproduces the exact algorithms used by the Meshtastic firmware's
`CryptoEngine` and `Channels::generateHash`, and dumps the inputs/outputs
as JSON so the Rust port can be tested for byte-for-byte equivalence
without any hardware.

## What this is not

- It is **not** built by CI — no host-CI runner gets OpenSSL pinned
  against a specific version, and reproducibility of the crypto output
  doesn't require re-running this harness (AES-CTR is a deterministic,
  NIST-standard algorithm: given key/IV/plaintext the output is fixed).
- It is **not** a new implementation of the algorithms. It re-derives
  them directly from `src/mesh/CryptoEngine.cpp` and
  `src/mesh/Channels.cpp` (the oracle) using OpenSSL for the AES
  primitive, so reviewers can compare line-by-line.

## How to regenerate `vectors.json`

```sh
cd test/rust-golden-vectors
make            # or: g++ -std=c++17 -O2 -Wall -Wextra gen_vectors.cpp -o gen_vectors -lcrypto
./gen_vectors > vectors.json
```

The committed `vectors.json` is what the Rust tests consume. Regenerating
it should produce identical output on any system with OpenSSL ≥ 1.1.

## What it covers

- **`channel_hash`**: XOR-based hash of channel name and PSK, matching
  `Channels::generateHash` in `src/mesh/Channels.cpp:39`.
- **`psk_expansion`**: The 1-byte "short PSK" shorthand that expands to
  `defaultpsk` with the last byte bumped, per
  `src/mesh/Channels.cpp:228`.
- **`aes_ctr_packet`**: Full packet-payload encryption under AES-CTR
  with the firmware's 16-byte nonce layout
  (`packet_id` u64 little-endian || `from_node` u32 little-endian
  || 4 zero bytes) and counter-size 4, matching
  `CryptoEngine::encryptPacket` and `CryptoEngine::encryptAESCtr` in
  `src/mesh/CryptoEngine.cpp:250`. Covers both AES-128 (16-byte PSK,
  the overwhelmingly common case) and AES-256 (32-byte PSK, event PSK).
