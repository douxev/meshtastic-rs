# Meshtastic Rust Workspace

Work-in-progress Rust port of the Meshtastic firmware, scoped to the
**LilyGO T-Deck (ESP32-S3 + SX1262)** for v1. The existing C++ tree at the
repository root is untouched and remains the canonical/reference implementation
during the port.

Short version of the plan: rewrite as little as possible — reuse community
Rust crates (`esp-hal`, `lora-phy`, `mipidsi`, `gt911`, `prost`, `aes`/`ccm`,
`esp32-nimble`, …) and only write the genuinely new glue: mesh protocol logic,
NodeDB, Channels, Router, PowerFSM, module dispatch, BLE/Serial client API,
and the T-Deck wiring layer.

## Layout

```
rust/
├── Cargo.toml                     # workspace root
├── rust-toolchain.toml            # pinned to stable
├── crates/
│   └── meshtastic-proto/          # Phase 1: prost codegen from ../protobufs
│   # future:
│   # ├── meshtastic-crypto/
│   # ├── meshtastic-core/
│   # ├── meshtastic-modules/
│   # ├── meshtastic-hal/
│   # ├── meshtastic-sim/
│   # └── meshtastic-tdeck/        # esp-hal-embassy bin crate
```

## Prerequisites

- Rust **stable** (see [`rust-toolchain.toml`](./rust-toolchain.toml))
- `protoc` (Protocol Buffers compiler), e.g. `apt install protobuf-compiler`
- The `protobufs` git submodule initialised at the repository root:
  `git submodule update --init protobufs`

## Common commands

Run from the `rust/` directory:

```sh
cargo build --workspace
cargo test  --workspace
cargo fmt   --all --check
cargo clippy --workspace --all-targets -- -D warnings
```

## Phase status

| Phase | Description                                                | Status        |
|-------|------------------------------------------------------------|---------------|
| 1     | Workspace skeleton + `meshtastic-proto` + CI               | in progress   |
| 2     | Golden-vector harness from C++ `CryptoEngine` / `Router`   | not started   |
| 3     | `meshtastic-crypto` (AES-CCM, channel hash)                | not started   |
| 4     | `meshtastic-core` (MeshPacket, Channels, NodeDB, Router)   | not started   |
| 5     | `meshtastic-modules` (text, nodeinfo, position, routing…)  | not started   |
| 6     | `meshtastic-hal` traits + `meshtastic-sim` host fakes      | not started   |
| 7     | `meshtastic-tdeck` binary (esp-hal-embassy + drivers)      | not started   |
| 8     | BLE client API                                             | not started   |
| 9     | Polish (deep sleep, OTA, persistent config)                | not started   |
