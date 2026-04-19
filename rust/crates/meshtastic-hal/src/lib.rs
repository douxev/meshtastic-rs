//! Hardware-abstraction-layer traits for the Rust Meshtastic port.
//!
//! The firmware's HAL is implicit: `millis()` is a global, `random()` is
//! a global, and radios are singletons (`RF95Interface`,
//! `SX126xInterface`, …) selected at compile time by `-D USE_...`
//! defines. This crate makes those dependencies explicit so higher
//! layers (`meshtastic-core`, `meshtastic-modules`, the future Router)
//! can be written once and plugged into any platform — real hardware
//! (`meshtastic-tdeck`) or tests/sim (`meshtastic-sim`).
//!
//! The traits model **behaviour only**. No `Send`/`Sync` bounds, no
//! `'static` requirements, no async — the consumers drive these from
//! their own thread/task loops.
//!
//! ## Overview
//!
//! - [`Clock`] — monotonic milliseconds since boot. Mirrors firmware
//!   `millis()`.
//! - [`Rng`] — fill arbitrary byte slices with cryptographic-quality
//!   entropy. Also provides default [`Rng::next_u32`] /
//!   [`Rng::next_u64`] helpers.
//! - [`Radio`] — the LoRa PHY layer: enqueue an outbound packet,
//!   drain at most one inbound packet, inspect/cancel the TX queue.
//!   Mirrors `RadioInterface` in `src/mesh/RadioInterface.h` minus the
//!   per-chip quirks.
//! - [`PacketIdAllocator`] — a small utility that burns one [`Rng`]
//!   into a stream of non-zero packet ids, matching the firmware's
//!   `generatePacketId()` contract.
//!
//! ## What's deliberately **not** here
//!
//! - Display, GPS, buttons, I²C, SPI — those are platform concerns
//!   and will live in `meshtastic-tdeck` and peer crates when we get
//!   to Phase 7.
//! - Async / executor abstractions — `embassy-time` on T-Deck, plain
//!   blocking on host. The trait shapes don't need to know.

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]

extern crate alloc;

use core::fmt;

use meshtastic_core::mesh::NodeNum;
use meshtastic_proto::meshtastic::MeshPacket;

/// Packet sequence number. Mirrors firmware `PacketId = uint32_t`
/// (`src/mesh/MeshTypes.h:10`). `0` is reserved as "no id".
pub type PacketId = u32;

/// Monotonic wall clock, measured in milliseconds since some arbitrary
/// epoch (conventionally "boot"). Ports the firmware global
/// `millis()` which is used everywhere for interval throttling.
///
/// Implementors must guarantee that successive calls return
/// non-decreasing values.
pub trait Clock {
    /// Milliseconds since the implementation's epoch.
    fn millis(&self) -> u64;
}

/// Source of entropy used for packet-id allocation and anywhere else
/// we need a fresh nonce / random u32. Parallels firmware
/// `random()` / `esp_random()`.
///
/// No guarantees are made about cryptographic strength at the trait
/// level — individual implementations are expected to document
/// theirs. Callers that need authenticated crypto (PKI DMs) should
/// use a stronger source explicitly.
pub trait Rng {
    /// Fill `dest` with random bytes.
    fn fill(&mut self, dest: &mut [u8]);

    /// Produce a random `u32`. Default impl fills 4 bytes.
    #[inline]
    fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill(&mut b);
        u32::from_le_bytes(b)
    }

    /// Produce a random `u64`. Default impl fills 8 bytes.
    #[inline]
    fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill(&mut b);
        u64::from_le_bytes(b)
    }
}

/// Per-reception metadata that the PHY records and the mesh layer
/// consumes. Mirrors the `rx_rssi`, `rx_snr`, `rx_time` fields that
/// `RadioInterface::handleReceive` stamps on `meshtastic_MeshPacket`.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct RxMeta {
    /// Received signal strength indicator, in dBm. `0` = unknown.
    pub rssi: i32,
    /// Signal-to-noise ratio in dB (LoRa PHY metric).
    pub snr: f32,
    /// Clock reading at receive time, in ms. `0` = unknown.
    pub rx_time: u64,
}

/// TX-queue snapshot. Maps 1:1 onto firmware `meshtastic_QueueStatus`
/// in `mesh.proto`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct QueueStatus {
    /// Most recent `Radio::send` result code (0 = OK).
    pub res: i32,
    /// Number of free slots currently available.
    pub free: u32,
    /// Maximum queue capacity.
    pub maxlen: u32,
    /// Packet id of the most recently enqueued packet (0 if none).
    pub mesh_packet_id: u32,
}

/// Errors producible by a [`Radio`] implementation. The set is
/// deliberately small — LoRa drivers have wildly varying error
/// vocabularies; keeping the common shape coarse avoids leaking
/// driver specifics into the mesh layer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RadioError {
    /// The TX queue is full — try again after the radio makes
    /// progress.
    TxQueueFull,
    /// The packet is larger than the PHY can transmit in a single
    /// frame.
    PacketTooLarge,
    /// The radio is disabled (either deliberately via sleep or by
    /// early-init failure).
    Disabled,
    /// Some implementation-defined hardware/driver error. `kind` is
    /// opaque but useful for logging.
    HardwareFailure {
        /// Driver-defined error category.
        kind: u16,
    },
}

impl fmt::Display for RadioError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RadioError::TxQueueFull => f.write_str("TX queue is full"),
            RadioError::PacketTooLarge => f.write_str("packet too large for PHY"),
            RadioError::Disabled => f.write_str("radio is disabled"),
            RadioError::HardwareFailure { kind } => write!(f, "radio hardware failure (kind={kind})"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for RadioError {}

/// A received packet plus the PHY metadata it came with.
#[derive(Debug, Clone, PartialEq)]
pub struct ReceivedPacket {
    /// The raw packet as it came off the air. Still encrypted; the
    /// mesh layer is responsible for calling
    /// [`meshtastic_core::packet::decrypt`] on it.
    pub packet: MeshPacket,
    /// PHY-level metadata (RSSI/SNR/rx_time).
    pub meta: RxMeta,
}

/// LoRa PHY abstraction. Mirrors the firmware's `RadioInterface`
/// (`src/mesh/RadioInterface.h`) at the level of its public API, with
/// three intentional simplifications:
///
/// 1. **Receive is polled**, not callback-based. Firmware uses
///    `deliverToReceiver` to hand packets to the router; here the
///    caller pulls with [`Radio::try_recv`]. This keeps the trait
///    object-safe and avoids imposing a concurrency model.
/// 2. **No `reconfigure()`** — for v1 the radio config is set at
///    construction and not hot-reloadable.
/// 3. **Packets are owned**, not pool-allocated. `MeshPacket` is a
///    prost-generated struct that already manages its own allocation.
///
/// Implementations are expected to:
///
/// - Encode the packet to bytes (the firmware does this inside
///   `Router::send` via a `MeshPacket → on-air bytes` serializer);
///   the HAL layer assumes the packet is already "ready to send" —
///   i.e. encrypted with `channel` holding the channel hash.
/// - Preserve packet ordering within priority class (firmware
///   doesn't guarantee this across priorities, neither do we).
pub trait Radio {
    /// Enqueue a packet for transmission. The call **must not
    /// block**; if the queue is full, return
    /// [`RadioError::TxQueueFull`].
    ///
    /// The packet is already encrypted (`PayloadVariant::Encrypted`)
    /// and its `channel` field holds the channel hash — see
    /// `meshtastic-core::packet::encrypt`.
    fn send(&mut self, packet: &MeshPacket) -> Result<(), RadioError>;

    /// Pull at most one received packet off the RX queue. Returns
    /// `Ok(None)` when the queue is empty. Returns `Err` only for
    /// hard PHY errors (not "queue empty").
    fn try_recv(&mut self) -> Result<Option<ReceivedPacket>, RadioError>;

    /// Current TX-queue snapshot. Default returns a zero/unknown
    /// status; PHYs that care should override.
    #[inline]
    fn queue_status(&self) -> QueueStatus {
        QueueStatus::default()
    }

    /// Attempt to cancel a previously-enqueued TX packet that hasn't
    /// been transmitted yet. Returns `true` on success. Mirrors
    /// `RadioInterface::cancelSending`.
    #[inline]
    fn cancel(&mut self, from: NodeNum, id: PacketId) -> bool {
        let _ = (from, id);
        false
    }

    /// `true` if a packet with this `(from, id)` is still in the TX
    /// queue. Mirrors `RadioInterface::findInTxQueue`.
    #[inline]
    fn find_in_tx_queue(&self, from: NodeNum, id: PacketId) -> bool {
        let _ = (from, id);
        false
    }

    /// Return `true` when the radio has no work in flight and is
    /// safe to put into deep sleep. Mirrors `canSleep`.
    #[inline]
    fn can_sleep(&self) -> bool {
        true
    }
}

/// Stream of non-zero packet ids, ported from firmware
/// `generatePacketId()` in `src/mesh/NodeDB.cpp`. The firmware uses
/// a seeded LCG/XOR sequence; we instead burn an [`Rng`] one `u32`
/// at a time, with zero rejection.
///
/// This is a *utility*, not a trait — every platform needs the same
/// logic and there's no point in making implementations swap it out.
#[derive(Debug)]
pub struct PacketIdAllocator<R: Rng> {
    rng: R,
}

impl<R: Rng> PacketIdAllocator<R> {
    /// Create a new allocator backed by `rng`.
    #[inline]
    pub fn new(rng: R) -> Self {
        Self { rng }
    }

    /// Produce the next packet id. Guaranteed non-zero. Uniformly
    /// distributed across `1..=u32::MAX`.
    pub fn next_id(&mut self) -> PacketId {
        // Firmware's `generatePacketId()` returns a 32-bit id and
        // treats 0 as the "no id" sentinel (see `MeshPacket.id` in
        // mesh.proto). We match that by rerolling on zero.
        loop {
            let id = self.rng.next_u32();
            if id != 0 {
                return id;
            }
        }
    }

    /// Consume the allocator and return the underlying RNG, for
    /// reuse elsewhere.
    #[inline]
    pub fn into_inner(self) -> R {
        self.rng
    }
}

// -------- Blanket / convenience impls -----------------------------

impl<T: Clock + ?Sized> Clock for &T {
    #[inline]
    fn millis(&self) -> u64 {
        (**self).millis()
    }
}

impl<T: Clock + ?Sized> Clock for alloc::boxed::Box<T> {
    #[inline]
    fn millis(&self) -> u64 {
        (**self).millis()
    }
}

impl<T: Rng + ?Sized> Rng for &mut T {
    #[inline]
    fn fill(&mut self, dest: &mut [u8]) {
        (**self).fill(dest)
    }
}

impl<T: Rng + ?Sized> Rng for alloc::boxed::Box<T> {
    #[inline]
    fn fill(&mut self, dest: &mut [u8]) {
        (**self).fill(dest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A deliberately-bad RNG that returns the same pattern every
    // call. Lets us exercise the zero-rejection path of
    // `PacketIdAllocator` without pulling in a real PRNG.
    struct FixedRng {
        seq: alloc::vec::Vec<u32>,
        idx: usize,
    }
    impl Rng for FixedRng {
        fn fill(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(4) {
                let v = self.seq[self.idx % self.seq.len()];
                self.idx += 1;
                let bytes = v.to_le_bytes();
                chunk.copy_from_slice(&bytes[..chunk.len()]);
            }
        }
    }

    #[test]
    fn packet_id_allocator_skips_zero() {
        let rng = FixedRng {
            seq: alloc::vec![0, 0, 0, 0x1234_5678],
            idx: 0,
        };
        let mut alloc = PacketIdAllocator::new(rng);
        assert_eq!(alloc.next_id(), 0x1234_5678);
    }

    #[test]
    fn packet_id_allocator_produces_distinct_ids_from_good_rng() {
        let rng = FixedRng {
            seq: alloc::vec![1, 2, 3, 4, 5],
            idx: 0,
        };
        let mut alloc = PacketIdAllocator::new(rng);
        let ids: alloc::vec::Vec<_> = (0..5).map(|_| alloc.next_id()).collect();
        assert_eq!(ids, alloc::vec![1, 2, 3, 4, 5]);
    }

    #[test]
    fn rng_next_helpers_match_fill() {
        struct R;
        impl Rng for R {
            fn fill(&mut self, dest: &mut [u8]) {
                for (i, b) in dest.iter_mut().enumerate() {
                    *b = i as u8 + 1;
                }
            }
        }
        let mut r = R;
        assert_eq!(r.next_u32(), u32::from_le_bytes([1, 2, 3, 4]));
        assert_eq!(r.next_u64(), u64::from_le_bytes([1, 2, 3, 4, 5, 6, 7, 8]));
    }

    #[test]
    fn clock_blanket_impl_refs_delegate() {
        struct C(u64);
        impl Clock for C {
            fn millis(&self) -> u64 {
                self.0
            }
        }
        let c = C(42);
        let r: &dyn Clock = &c;
        assert_eq!(r.millis(), 42);
    }

    #[test]
    fn radio_error_display() {
        extern crate alloc as a;
        use a::format;
        assert_eq!(format!("{}", RadioError::TxQueueFull), "TX queue is full");
        assert_eq!(format!("{}", RadioError::PacketTooLarge), "packet too large for PHY");
        assert_eq!(format!("{}", RadioError::Disabled), "radio is disabled");
        assert_eq!(
            format!("{}", RadioError::HardwareFailure { kind: 7 }),
            "radio hardware failure (kind=7)"
        );
    }
}
