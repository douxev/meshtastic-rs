# Meshtastic — Rust port (`rust/` workspace)

Work-in-progress Rust port of the [Meshtastic](https://meshtastic.org) firmware,
initially scoped to the [**LilyGO T-Deck (ESP32-S3 + SX1262)**](https://www.lilygo.cc/products/t-deck).
The existing C++ tree at the repository root remains the **canonical / oracle
implementation** and is untouched by this port; it's the reference we validate
against via golden vectors and behavioural parity tests.

> **Status: protocol core is green, hardware target not yet wired.**
> 218 unit/integration tests pass under `cargo test --workspace --locked`;
> `clippy -D warnings` is clean; every protocol-layer crate builds
> `--no-default-features` for `no_std` targets. The T-Deck `bin` crate
> (Phase 7, needs the xtensa-esp toolchain) is intentionally deferred
> until a hardware-equipped session.

## Table of contents

- [Design philosophy](#design-philosophy)
- [Workspace layout](#workspace-layout)
- [Crate graph](#crate-graph)
- [External libraries used](#external-libraries-used)
- [Firmware ↔ Rust crosswalk](#firmware--rust-crosswalk)
- [Intentional deviations from the C++ firmware](#intentional-deviations-from-the-c-firmware)
- [Phase status](#phase-status)
- [Building, testing, linting](#building-testing-linting)
- [Running the host simulator](#running-the-host-simulator)
- [no_std and embedded targets](#no_std-and-embedded-targets)
- [Golden vectors](#golden-vectors)
- [Contributing](#contributing)
- [License](#license)

## Design philosophy

The C++ firmware is ~250 kLOC carrying a decade of accumulated device drivers,
UI variants, and platform glue. Porting line-by-line is neither realistic nor
useful. The port follows three rules:

1. **Rewrite as little as possible.** Everywhere a maintained community Rust
   crate already does the job (`lora-phy`, `mipidsi`, `esp-hal`, `aes`, …) we
   consume it rather than re-implementing the C++ driver. What's left is
   Meshtastic-specific glue: mesh protocol, node database, channels, router,
   PowerFSM, module dispatch, and the BLE/serial client protocol.
2. **`no_std` + `alloc` by default for protocol crates.** Every crate that
   could plausibly run on-device compiles without `std`. `std` is a feature —
   usually just to opt into `std::error::Error` impls or host-only helpers
   like the filesystem-backed config store.
3. **Firmware-faithful byte-for-byte on the wire.** Packet crypto, channel
   hashing, protobuf framing, and the ToRadio/FromRadio handshake are all
   verified either with checked-in [golden vectors from the C++ oracle](../test/rust-golden-vectors/)
   or through behavioural tests cross-referenced against specific firmware
   source lines in doc-comments.

## Workspace layout

```
rust/
├── Cargo.toml                  # workspace root (resolver = "2")
├── Cargo.lock                  # committed; CI uses --locked
├── rust-toolchain.toml         # pinned stable toolchain
└── crates/
    ├── meshtastic-proto/       # Phase 1 — prost-generated protobuf bindings
    ├── meshtastic-crypto/      # Phase 3 — AES-CTR channel crypto + channel hash
    ├── meshtastic-core/        # Phases 4a+4b — Channels, MeshPacket enc/dec,
    │                           #                NodeDb, PacketHistory
    ├── meshtastic-modules/     # Phase 5  — MeshModule trait + ModuleDispatcher,
    │                           #            TextMessage / NodeInfo / Routing
    ├── meshtastic-hal/         # Phase 6  — Clock / Rng / Radio traits
    ├── meshtastic-sim/         # Phase 6  — host-side fakes (SimClock / SimRng /
    │                           #            SimRadioBus) + end-to-end integration
    ├── meshtastic-phone-api/   # Phase 8  — transport-agnostic port of PhoneAPI
    │                           #            (ToRadio/FromRadio state machine)
    ├── meshtastic-config/      # Phase 9  — persistent storage for LocalConfig /
    │                           #            LocalModuleConfig / ChannelFile / …
    │
    │ # planned, not yet started:
    └── meshtastic-tdeck/       # Phase 7 — esp-hal-embassy binary target
```

## Crate graph

Arrows point from *dependent* to *dependency*.

```
                       ┌──────────────────┐
                       │  meshtastic-proto│         (prost codegen — used by all)
                       └──────────▲───────┘
                                  │
        ┌──────────────┬──────────┴─────────┬──────────────┬──────────────┐
        │              │                    │              │              │
┌───────┴──────┐ ┌─────┴────────┐  ┌────────┴─────┐ ┌──────┴──────┐ ┌─────┴──────┐
│meshtastic-   │ │ meshtastic-  │  │ meshtastic-  │ │ meshtastic- │ │meshtastic- │
│crypto        │ │ core         │  │ config       │ │ phone-api   │ │ hal        │
└───────▲──────┘ └──────▲───────┘  └──────────────┘ └─────▲───────┘ └─────▲──────┘
        │               │                                 │                │
        │        ┌──────┴──────┐                          │                │
        └────────┤ meshtastic- ├──────────────────────────┘                │
                 │ modules     │                                           │
                 └──────▲──────┘                                           │
                        │                                                  │
                 ┌──────┴──────────────────────────────────────────────────┴┐
                 │ meshtastic-sim (std, host-only, integrates everything)   │
                 └──────────────────────────────────────────────────────────┘
```

Each crate's `lib.rs` has a module-level doc comment listing the firmware
source files it ports, and every nontrivial function cites the specific
lines it mirrors.

### Per-crate summary

| Crate | Purpose | `no_std`? | Ports / builds on |
|---|---|---|---|
| [`meshtastic-proto`](crates/meshtastic-proto) | All protobuf message types generated by `prost-build` from `../protobufs/meshtastic/*.proto`. Re-exports `prost` so downstreams don't depend on it twice. | yes (with `alloc`) | `../protobufs` submodule |
| [`meshtastic-crypto`](crates/meshtastic-crypto) | `expand_psk`, `channel_hash`, AES-CTR `encrypt`/`decrypt` for channel payloads. Keys are zeroed on drop. | yes (with `alloc`) | `src/mesh/CryptoEngine.cpp`, `src/mesh/Channels.cpp` |
| [`meshtastic-core`](crates/meshtastic-core) | `Channels` table with hash-collision resolution, MeshPacket `encrypt`/`decrypt` pipeline (respecting the dual-use `channel` field on the wire), `NodeDb` with LRU eviction, `PacketHistory` duplicate-suppression ring. | yes (with `alloc`) | `src/mesh/Channels.cpp`, `src/mesh/NodeDB.cpp`, `src/mesh/Router.cpp` |
| [`meshtastic-modules`](crates/meshtastic-modules) | `MeshModule` trait (port of firmware `MeshModule`/`SinglePortModule`/`ProtobufModule`), `ModuleDispatcher` (port of `MeshModule::callModules`), and three ported modules: `TextMessageModule`, `NodeInfoModule`, `RoutingModule`. The `RoutingModule` carries the rebroadcast filter including the `UserLicenseStatus` tri-state. | yes (with `alloc`) | `src/mesh/MeshModule.cpp`, `src/modules/*.cpp` |
| [`meshtastic-hal`](crates/meshtastic-hal) | Platform traits: `Clock` (`millis() -> u64`), `Rng` (`fill(&mut [u8])`), `Radio` (non-blocking `send` + polled `try_recv`). `PacketIdAllocator` utility. Deliberately callback-free — poll-driven by the executor. | yes | `src/mesh/RadioInterface.h`, firmware RNG/clock conventions |
| [`meshtastic-sim`](crates/meshtastic-sim) | Host-only fakes: `SimClock` (wall or manual), `SimRng` (ChaCha8, u64-seeded), `SimRadioBus` (mutex broker, TX fans out to every *other* peer). Used by the end-to-end test that exercises every other crate at once. | **std only** | n/a (tooling) |
| [`meshtastic-phone-api`](crates/meshtastic-phone-api) | Transport-agnostic port of `PhoneAPI.cpp`. Caller feeds `handle_to_radio(bytes)`, drains `pop_from_radio()`. Drives the full `want_config_id → MyInfo → Metadata → Channels → Config → ModuleConfig → NodeInfo → ConfigCompleteId → SendingPackets` handshake, plus 20-id ToRadio dedup matching firmware. | yes (with `alloc`) | `src/mesh/PhoneAPI.cpp` |
| [`meshtastic-config`](crates/meshtastic-config) | Persistent storage for the six on-flash blobs (DeviceState, NodeDatabase, LocalConfig, LocalModuleConfig, ChannelFile, DeviceUiConfig). `ConfigStore` trait, `MemoryConfigStore`, and `FsConfigStore` (`std`-only, with atomic `.tmp` → `rename` writes matching firmware `SafeFile`). Tracks `DEVICESTATE_CUR_VER = 24`. | yes (with `alloc`; `FsConfigStore` needs `std`) | `src/mesh/NodeDB.cpp`, `src/mesh/SafeFile.h` |

## External libraries used

All versions are resolved in [`Cargo.lock`](Cargo.lock). The following is the
curated first-party list; transitive deps (`aho-corasick`, `fastrand`, `libc`, …)
are omitted.

### Protocol-layer crates (on-device-portable)

| Dep | Used by | Why |
|---|---|---|
| [`prost`](https://crates.io/crates/prost) 0.13 + `prost-build` + `prost-types` | `meshtastic-proto` (all downstream) | Pure-Rust protobuf codegen. Chosen over `protobuf`/`rust-protobuf` for its mature `no_std+alloc` support and smaller derived code. |
| [`aes`](https://crates.io/crates/aes) 0.8 | `meshtastic-crypto` | RustCrypto AES-128/256 block cipher. `no_std`, `default-features = false`. |
| [`ctr`](https://crates.io/crates/ctr) 0.9 | `meshtastic-crypto` | CTR block-mode wrapper over `aes`, matching the firmware's AES-CTR construction (key + 16-byte IV = `packet_id ‖ from_node ‖ 4 zero bytes`, counter size 4). |
| [`cipher`](https://crates.io/crates/cipher) 0.4 | `meshtastic-crypto` | `KeyIvInit`, `StreamCipher` traits shared by `aes`/`ctr`. |
| [`zeroize`](https://crates.io/crates/zeroize) 1 | `meshtastic-crypto` | Zero-on-drop for expanded AES keys. |

### Host-only crates

| Dep | Used by | Why |
|---|---|---|
| [`rand`](https://crates.io/crates/rand) 0.9, [`rand_chacha`](https://crates.io/crates/rand_chacha) 0.9, [`rand_core`](https://crates.io/crates/rand_core) 0.9 | `meshtastic-sim` | Deterministic ChaCha8 RNG for reproducible sim runs. |
| [`tempfile`](https://crates.io/crates/tempfile) 3 | `meshtastic-config` (dev-only) | Per-test tmp directories for `FsConfigStore` integration tests. |

### Test-only crates

| Dep | Used by | Why |
|---|---|---|
| [`proptest`](https://crates.io/crates/proptest) 1 | `meshtastic-core`, `meshtastic-crypto` | Property-based tests for encrypt-decrypt round-trips and channel-hash distribution. |
| [`hex`](https://crates.io/crates/hex) 0.4 | `meshtastic-crypto` | Decoding the hex strings in the golden-vector JSON. |
| [`serde`](https://crates.io/crates/serde) 1 + `serde_json` | `meshtastic-crypto` | Parsing the golden-vector JSON. |

### Deliberately **not** used (yet)

- `tokio` — not needed anywhere in the protocol stack, and the on-device target
  will use `embassy` instead. The sim harness is synchronous.
- `anyhow` / `thiserror` — each crate defines a small hand-written error
  enum, so the `no_std` crates can keep their error types `#[derive(Debug, …)]`
  without pulling in proc-macro deps. `std::error::Error` impls are gated
  behind the `std` feature.

## Firmware ↔ Rust crosswalk

The most useful navigation mapping for contributors who already know the C++:

| C++ firmware concept | Rust location |
|---|---|
| `src/mesh/generated/meshtastic/*.h` (nanopb) | `meshtastic_proto::meshtastic::*` |
| `CryptoEngine::encrypt`/`decrypt` | `meshtastic_crypto::{encrypt_ctr, decrypt_ctr}` |
| `Channels::hash` | `meshtastic_crypto::channel_hash` |
| `Channels` table | `meshtastic_core::channels::Channels` |
| `Router::perhapsDecode` / `encodeAndEncrypt` | `meshtastic_core::packet::{decrypt, encrypt}` |
| `NodeDB` (subset used by mesh layer) | `meshtastic_core::nodedb::NodeDb` |
| `PacketHistory` | `meshtastic_core::packet_history::PacketHistory` |
| `MeshModule` / `SinglePortModule` / `ProtobufModule<T>` | `meshtastic_modules::MeshModule` trait |
| `MeshModule::callModules` | `meshtastic_modules::ModuleDispatcher::dispatch` |
| `TextMessageModule` | `meshtastic_modules::TextMessageModule` |
| `NodeInfoModule` | `meshtastic_modules::NodeInfoModule` (pure: queues `NodeUserUpdate` for the caller to apply) |
| `RoutingModule` + rebroadcast filter | `meshtastic_modules::RoutingModule` + `UserLicenseStatus` |
| `PhoneAPI` state machine | `meshtastic_phone_api::PhoneApi` |
| `SafeFile` / `NodeDB::saveProto`+`loadProto` | `meshtastic_config::{ConfigStore, FsConfigStore}` |
| `DEVICESTATE_CUR_VER` | `meshtastic_config::DEVICESTATE_CUR_VER` (= 24) |

## Intentional deviations from the C++ firmware

Documenting these up front so reviewers don't mistake them for bugs.

1. **Modules don't own `&mut NodeDb`.** The firmware's `NodeInfoModule`
   mutates the global `nodeDB` from `handleReceived()`. The Rust port
   queues `NodeUserUpdate` values which the integrating code drains via
   `take_pending_updates()` after each dispatch. This keeps the module
   trait `&mut self`-only and makes testing trivial. The same pattern
   will apply to Position/Telemetry when they're ported.

2. **`PhoneApi` holds no global pointers.** The firmware class pulls
   live pointers to `service`, `channels`, `config`, `moduleConfig`,
   `nodeDB`, `xModem`, `mqtt`, etc. The Rust port accepts a
   caller-supplied snapshot (`set_my_info`, `set_metadata`,
   `set_channels`, `set_config_snapshot`, `set_node_db`) so the
   protocol layer is transport- *and* source-of-truth-agnostic.

3. **`Radio` trait is poll-driven, not callback-driven.** The firmware
   uses ISR callbacks into C++ virtuals. The Rust `Radio` trait exposes
   `try_recv() -> Option<ReceivedPacket>` and lets the executor decide
   how to drive it — fits `embassy` on-device and a simple loop in the
   sim harness without any `Pin<Box<dyn Fn>>` gymnastics.

4. **`UserLicenseStatus` is a Rust enum, not a protobuf enum.** Firmware
   C++ defines it as `enum UserLicenseStatus { NotKnown, NotLicensed,
   Licensed }` in `src/mesh/NodeDB.h:151`. Since it's not in any
   `.proto`, the Rust port defines it in `meshtastic_modules::routing`
   as `Unknown`/`NotLicensed`/`Licensed`. The `Unknown` tri-state is
   load-bearing: firmware only *drops* when it's certain the sender is
   unlicensed, so "don't know yet" must not be collapsed into either
   extreme.

5. **MeshPacket `channel` field is correctly dual-use.** On the wire
   (while encrypted) it holds the 8-bit channel hash; after decryption
   it holds the channel index. `meshtastic_core::packet::{encrypt,
   decrypt}` maintain this invariant and the property-based tests cover
   it. Secondary channels with an empty PSK fall back to the primary
   channel's key, matching `src/mesh/Channels.cpp:222`.

6. **`PhoneApi` frame-size cap is 512 bytes** (firmware
   `MAX_TO_FROM_RADIO_SIZE` in `PhoneAPI.h:14`). Anything larger is
   rejected up front — it would never fit a single BLE characteristic
   write anyway.

## Phase status

| Phase | Scope | Status |
|---|---|---|
| 1 | Workspace skeleton + `meshtastic-proto` + Rust CI | **done** |
| 2 | Golden-vector harness + committed `vectors.json` | **done** |
| 3 | `meshtastic-crypto` (AES-CTR channel crypto, channel hash, PSK expansion) | **done** |
| 4a | `meshtastic-core`: `Channels` table + MeshPacket encrypt/decrypt | **done** |
| 4b | `meshtastic-core`: `NodeDb` + `PacketHistory` | **done** |
| 5 | `meshtastic-modules`: module trait + dispatcher + TextMessage + NodeInfo + Routing | **done for the ported modules; Position/Admin/Telemetry not started** |
| 6 | `meshtastic-hal` traits + `meshtastic-sim` host fakes | **done** |
| 7 | `meshtastic-tdeck` binary (esp-hal-embassy + LoRa + display + buttons) | **not started** (needs xtensa toolchain, hardware-equipped session) |
| 8 | Transport-agnostic `meshtastic-phone-api` | **done** |
| 9 | Host-portable `meshtastic-config` (deep-sleep + OTA still deferred to Phase 7) | **partial — persistence done; deep-sleep/OTA deferred** |

## Building, testing, linting

All commands run from the `rust/` directory.

### Prerequisites

- Rust **stable** (version pinned in [`rust-toolchain.toml`](rust-toolchain.toml)).
- `protoc` (Protocol Buffers compiler). On Debian/Ubuntu:
  `sudo apt-get install -y protobuf-compiler`.
- The `protobufs` git submodule, initialised at the repo root:
  `git submodule update --init protobufs`.

### Everyday commands

```sh
# Compile everything (the CI uses --locked; Cargo.lock is committed).
cargo build --workspace --locked

# Run the whole test matrix (unit + integration + doc tests).
cargo test --workspace --locked

# Style / lint gates. Both are hard-required by CI.
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
```

Expected baseline (April 2026 snapshot): **218 tests pass**, 0 failures.

### Per-crate tests

```sh
cargo test -p meshtastic-crypto         # includes golden_vectors.rs
cargo test -p meshtastic-core
cargo test -p meshtastic-modules
cargo test -p meshtastic-phone-api
cargo test -p meshtastic-config
cargo test -p meshtastic-sim            # includes end_to_end.rs
```

## Running the host simulator

`meshtastic-sim` provides a deterministic, `std`-only set of fakes that stand in
for the HAL. The workspace's end-to-end test puts it through its paces: two
nodes sharing a single `SimRadioBus`, each with their own `SimClock` /
`SimRng`, exchanging an encrypted text message that round-trips through
`meshtastic-core`'s packet pipeline and gets dispatched by a full
`ModuleDispatcher` with a `TextMessageModule` plugged in.

Read the test at [`crates/meshtastic-sim/tests/end_to_end.rs`](crates/meshtastic-sim/tests/end_to_end.rs) —
it's the best single-file tour of how the protocol crates compose. Run it with:

```sh
cargo test -p meshtastic-sim --test end_to_end -- --nocapture
```

## `no_std` and embedded targets

Every protocol-layer crate compiles `--no-default-features` with `alloc`
only:

```sh
cargo build -p meshtastic-proto      --no-default-features
cargo build -p meshtastic-crypto     --no-default-features
cargo build -p meshtastic-core       --no-default-features
cargo build -p meshtastic-modules    --no-default-features
cargo build -p meshtastic-hal        --no-default-features
cargo build -p meshtastic-phone-api  --no-default-features
cargo build -p meshtastic-config     --no-default-features
```

Turning off the default `std` feature drops the `std::error::Error` impls
and, for `meshtastic-config`, the filesystem-backed `FsConfigStore`. No
other functionality is gated.

`meshtastic-sim` is `std`-only by design — it's a host-side testing aid,
not something you'd run on an ESP32.

## Golden vectors

Because the channel crypto and channel-hash algorithms are byte-identical
to the firmware's C++ implementation, the Rust port validates itself
against a checked-in JSON file of vectors generated by the C++ oracle:

- **Vectors:** [`test/rust-golden-vectors/vectors.json`](../test/rust-golden-vectors/vectors.json)
- **Generator:** [`test/rust-golden-vectors/gen_vectors.cpp`](../test/rust-golden-vectors/gen_vectors.cpp)
  (OpenSSL-based; mirrors firmware algorithms)
- **Consumer:** [`crates/meshtastic-crypto/tests/golden_vectors.rs`](crates/meshtastic-crypto/tests/golden_vectors.rs)

The generator is **intentionally not built in CI** — it pulls OpenSSL in, and
the committed `vectors.json` is the artifact Rust tests rely on. If you
change the firmware crypto, regenerate it locally and commit the updated
JSON.

## Contributing

1. Read the module-level doc comment in the crate you're touching — it
   points at the firmware source files it ports.
2. Add tests next to the code. Prefer unit tests that cite specific
   firmware line numbers in the test body when behaviour is
   bug-compatible by design.
3. Keep `cargo clippy -D warnings` and `cargo fmt --check` clean.
4. If you add a new dependency, run the GitHub Advisory database check
   and prefer crates that already ship `no_std` support.
5. **Never** modify the C++ tree from inside a Rust-port PR. The C++
   firmware is the oracle; it stays green independently.

## License

Same as the parent project — **GPL-3.0-or-later**. See [`LICENSE`](../LICENSE)
at the repository root.
