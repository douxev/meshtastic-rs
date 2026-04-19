//! Host-side fakes for [`meshtastic_hal`], used for integration
//! testing of the higher layers on developer workstations.
//!
//! Nothing in this crate is suitable for on-device use: the simulator
//! holds all state in host memory and relies on `std`.
//!
//! ## What's here
//!
//! - [`SimClock`] — a settable, monotonic-by-construction clock.
//!   Tests can either let wall-clock time drive it
//!   ([`SimClock::from_now`]) or advance it manually
//!   ([`SimClock::advance`]).
//! - [`SimRng`] — a `ChaCha8`-backed deterministic RNG. Tests that
//!   seed it with the same `u64` always see the same byte stream.
//! - [`SimRadioBus`] — an in-memory mesh: every [`SimRadio`]
//!   connected to the same bus sees every other radio's
//!   transmissions. Attenuation, collisions, and realistic airtime
//!   are deliberately **not** modelled — this is a logical fidelity
//!   harness, not a PHY simulator.
//!
//! ## Example
//!
//! ```no_run
//! # use meshtastic_sim::{SimClock, SimRng, SimRadioBus};
//! # use meshtastic_hal::Rng;
//! let clock = SimClock::from_now();
//! let mut rng = SimRng::seed_from_u64(0x42);
//! let bus = SimRadioBus::new();
//! let (mut alice, mut bob) = (bus.attach(0x0aaa_aaaa), bus.attach(0x0bbb_bbbb));
//! // ... use `alice` / `bob` as `meshtastic_hal::Radio`s ...
//! # let _ = (clock.millis(), rng.next_u32(), alice, bob);
//! # trait M { fn millis(&self) -> u64; }
//! # impl M for SimClock { fn millis(&self) -> u64 { 0 } }
//! ```

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use meshtastic_core::mesh::{is_broadcast, NodeNum};
use meshtastic_hal::{Clock, QueueStatus, Radio, RadioError, ReceivedPacket, Rng, RxMeta};
use meshtastic_proto::meshtastic::MeshPacket;
use rand::SeedableRng;
use rand_chacha::ChaCha8Rng;
use rand_core::RngCore;

/// Monotonic clock backed by either wall time or a manually-advanced
/// counter. Cheap to [`Clone`] — the underlying counter is shared.
#[derive(Debug, Clone)]
pub struct SimClock {
    inner: Arc<SimClockInner>,
}

#[derive(Debug)]
enum SimClockInner {
    /// Wall-clock mode: `millis()` returns elapsed ms since `origin`.
    Wall { origin: Instant },
    /// Manual mode: `millis()` returns whatever
    /// [`SimClock::advance`] / [`SimClock::set`] set.
    Manual { counter: AtomicU64 },
}

impl SimClock {
    /// Wall-clock mode anchored at "now". `millis()` returns 0 at
    /// the instant of the call; thereafter it reads
    /// `Instant::elapsed()`.
    #[must_use]
    pub fn from_now() -> Self {
        Self {
            inner: Arc::new(SimClockInner::Wall { origin: Instant::now() }),
        }
    }

    /// Manual-mode clock initialised to `ms`.
    #[must_use]
    pub fn manual(ms: u64) -> Self {
        Self {
            inner: Arc::new(SimClockInner::Manual {
                counter: AtomicU64::new(ms),
            }),
        }
    }

    /// Advance a manual clock. No-op on wall-clock mode.
    pub fn advance(&self, delta_ms: u64) {
        if let SimClockInner::Manual { counter } = &*self.inner {
            counter.fetch_add(delta_ms, Ordering::SeqCst);
        }
    }

    /// Set a manual clock. No-op on wall-clock mode.
    pub fn set(&self, ms: u64) {
        if let SimClockInner::Manual { counter } = &*self.inner {
            counter.store(ms, Ordering::SeqCst);
        }
    }
}

impl Clock for SimClock {
    fn millis(&self) -> u64 {
        match &*self.inner {
            SimClockInner::Wall { origin } => u64::try_from(origin.elapsed().as_millis()).unwrap_or(u64::MAX),
            SimClockInner::Manual { counter } => counter.load(Ordering::SeqCst),
        }
    }
}

/// Deterministic [`Rng`] backed by ChaCha8. Seeded with a `u64` so
/// tests can replay failures exactly.
///
/// Not a cryptographic-strength source on its own — use only where
/// firmware itself uses `random()` (packet ids, jitter, etc.).
#[derive(Debug, Clone)]
pub struct SimRng {
    inner: ChaCha8Rng,
}

impl SimRng {
    /// Seed from a `u64`. Equivalent runs produce equivalent byte
    /// streams.
    #[must_use]
    pub fn seed_from_u64(seed: u64) -> Self {
        Self {
            inner: ChaCha8Rng::seed_from_u64(seed),
        }
    }
}

impl Rng for SimRng {
    fn fill(&mut self, dest: &mut [u8]) {
        self.inner.fill_bytes(dest);
    }

    fn next_u32(&mut self) -> u32 {
        self.inner.next_u32()
    }

    fn next_u64(&mut self) -> u64 {
        self.inner.next_u64()
    }
}

// ---------------- Radio bus --------------------------------------

/// Shared broker that connects a set of [`SimRadio`]s together. Any
/// packet sent by one radio is immediately delivered to every
/// *other* radio on the bus (broadcasts are seen by everyone;
/// unicasts are filtered by `to` on the receive side).
///
/// Cheap to [`Clone`] — cloning produces another handle to the same
/// bus so helper threads / closures can share access.
#[derive(Debug, Clone)]
pub struct SimRadioBus {
    inner: Arc<Mutex<BusInner>>,
}

#[derive(Debug, Default)]
struct BusInner {
    /// Per-radio receive queues. Indexed by `NodeNum`.
    queues: std::collections::HashMap<NodeNum, std::collections::VecDeque<ReceivedPacket>>,
    /// Monotonically-increasing `rx_time` stamp.
    rx_time: u64,
}

impl SimRadioBus {
    /// Create an empty bus.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(BusInner::default())),
        }
    }

    /// Attach a new radio identified by `node_num`. Returns a
    /// [`SimRadio`] that the caller can pass to mesh modules.
    ///
    /// If a radio with this `node_num` was already attached, its
    /// queue is reset.
    pub fn attach(&self, node_num: NodeNum) -> SimRadio {
        let mut guard = self.inner.lock().expect("SimRadioBus poisoned");
        guard.queues.insert(node_num, std::collections::VecDeque::new());
        SimRadio {
            node_num,
            bus: self.clone(),
            last_status: QueueStatus::default(),
        }
    }

    /// Detach the radio identified by `node_num`. Subsequent
    /// broadcasts will no longer enqueue to its queue.
    pub fn detach(&self, node_num: NodeNum) {
        let mut guard = self.inner.lock().expect("SimRadioBus poisoned");
        guard.queues.remove(&node_num);
    }

    /// Number of currently-attached radios.
    #[must_use]
    pub fn attached_count(&self) -> usize {
        self.inner.lock().expect("SimRadioBus poisoned").queues.len()
    }
}

impl Default for SimRadioBus {
    fn default() -> Self {
        Self::new()
    }
}

/// A single radio endpoint on a [`SimRadioBus`].
#[derive(Debug)]
pub struct SimRadio {
    node_num: NodeNum,
    bus: SimRadioBus,
    last_status: QueueStatus,
}

impl SimRadio {
    /// The `NodeNum` this radio is registered under on its bus.
    #[must_use]
    pub fn node_num(&self) -> NodeNum {
        self.node_num
    }

    /// Number of RX packets currently buffered for this radio.
    #[must_use]
    pub fn rx_queue_len(&self) -> usize {
        self.bus
            .inner
            .lock()
            .expect("SimRadioBus poisoned")
            .queues
            .get(&self.node_num)
            .map_or(0, std::collections::VecDeque::len)
    }
}

impl Radio for SimRadio {
    fn send(&mut self, packet: &MeshPacket) -> Result<(), RadioError> {
        let mut guard = self.bus.inner.lock().expect("SimRadioBus poisoned");
        guard.rx_time = guard.rx_time.saturating_add(1);
        let rx_time = guard.rx_time;
        // Copy the packet into each OTHER radio's queue. A firmware
        // radio never loops its own TX back; the sim mirrors that.
        let rx = ReceivedPacket {
            packet: packet.clone(),
            meta: RxMeta {
                rssi: -60,
                snr: 10.0,
                rx_time,
            },
        };
        let to = packet.to;
        let is_bcast = is_broadcast(to);
        let sender = self.node_num;
        for (&peer, queue) in guard.queues.iter_mut() {
            if peer == sender {
                continue;
            }
            // A firmware-style receiver still sees unicasts
            // addressed to other nodes (and may rebroadcast). Match
            // that: every peer except the sender gets a copy, the
            // mesh layer decides whether to act on it.
            let _ = is_bcast; // kept for future "drop non-matching unicasts" modes
            queue.push_back(rx.clone());
        }
        self.last_status = QueueStatus {
            res: 0,
            free: 0,
            maxlen: 0,
            mesh_packet_id: packet.id,
        };
        Ok(())
    }

    fn try_recv(&mut self) -> Result<Option<ReceivedPacket>, RadioError> {
        let mut guard = self.bus.inner.lock().expect("SimRadioBus poisoned");
        Ok(guard
            .queues
            .get_mut(&self.node_num)
            .and_then(std::collections::VecDeque::pop_front))
    }

    fn queue_status(&self) -> QueueStatus {
        self.last_status
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALICE: NodeNum = 0x0aaa_aaaa;
    const BOB: NodeNum = 0x0bbb_bbbb;
    const CHARLIE: NodeNum = 0x0ccc_cccc;

    #[test]
    fn manual_clock_advances() {
        let c = SimClock::manual(0);
        assert_eq!(c.millis(), 0);
        c.advance(250);
        assert_eq!(c.millis(), 250);
        c.advance(750);
        assert_eq!(c.millis(), 1000);
        c.set(42);
        assert_eq!(c.millis(), 42);
    }

    #[test]
    fn wall_clock_monotonic() {
        let c = SimClock::from_now();
        let a = c.millis();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let b = c.millis();
        assert!(b >= a);
    }

    #[test]
    fn rng_is_deterministic_across_instances() {
        let mut a = SimRng::seed_from_u64(0xdead_beef_cafe_babe);
        let mut b = SimRng::seed_from_u64(0xdead_beef_cafe_babe);
        for _ in 0..10 {
            assert_eq!(a.next_u32(), b.next_u32());
        }
    }

    #[test]
    fn different_seeds_produce_different_streams() {
        let mut a = SimRng::seed_from_u64(1);
        let mut b = SimRng::seed_from_u64(2);
        // Probability of collision across 4 u32s from ChaCha8 is
        // negligible.
        let av: Vec<_> = (0..4).map(|_| a.next_u32()).collect();
        let bv: Vec<_> = (0..4).map(|_| b.next_u32()).collect();
        assert_ne!(av, bv);
    }

    fn dummy_packet(from: NodeNum, to: NodeNum, id: u32) -> MeshPacket {
        MeshPacket {
            from,
            to,
            id,
            ..Default::default()
        }
    }

    #[test]
    fn bus_delivers_broadcast_to_all_peers() {
        let bus = SimRadioBus::new();
        let mut a = bus.attach(ALICE);
        let mut b = bus.attach(BOB);
        let mut c = bus.attach(CHARLIE);

        a.send(&dummy_packet(ALICE, u32::MAX, 1)).unwrap();

        // Bob and Charlie see it, Alice doesn't.
        assert_eq!(a.rx_queue_len(), 0);
        assert_eq!(b.rx_queue_len(), 1);
        assert_eq!(c.rx_queue_len(), 1);

        let rx = b.try_recv().unwrap().unwrap();
        assert_eq!(rx.packet.id, 1);
        assert_eq!(rx.packet.from, ALICE);
        assert!(rx.meta.rx_time > 0);

        // Charlie can still receive it independently.
        let rx2 = c.try_recv().unwrap().unwrap();
        assert_eq!(rx2.packet.id, 1);
    }

    #[test]
    fn bus_delivers_unicast_to_everyone_except_sender() {
        // Firmware radios don't filter unicast at the PHY — the
        // mesh layer does. The sim matches that.
        let bus = SimRadioBus::new();
        let mut a = bus.attach(ALICE);
        let b = bus.attach(BOB);
        let c = bus.attach(CHARLIE);

        a.send(&dummy_packet(ALICE, BOB, 2)).unwrap();

        assert_eq!(a.rx_queue_len(), 0);
        assert_eq!(b.rx_queue_len(), 1);
        assert_eq!(c.rx_queue_len(), 1);
    }

    #[test]
    fn try_recv_returns_none_when_empty() {
        let bus = SimRadioBus::new();
        let mut a = bus.attach(ALICE);
        assert!(a.try_recv().unwrap().is_none());
    }

    #[test]
    fn detach_stops_delivery() {
        let bus = SimRadioBus::new();
        let mut a = bus.attach(ALICE);
        let mut b = bus.attach(BOB);
        bus.detach(BOB);

        a.send(&dummy_packet(ALICE, u32::MAX, 3)).unwrap();
        assert!(b.try_recv().unwrap().is_none());
    }

    #[test]
    fn queue_status_tracks_last_send() {
        let bus = SimRadioBus::new();
        let mut a = bus.attach(ALICE);
        assert_eq!(a.queue_status().mesh_packet_id, 0);
        a.send(&dummy_packet(ALICE, BOB, 0xcafe)).unwrap();
        assert_eq!(a.queue_status().mesh_packet_id, 0xcafe);
    }

    #[test]
    fn attached_count_tracks_lifecycle() {
        let bus = SimRadioBus::new();
        assert_eq!(bus.attached_count(), 0);
        let _a = bus.attach(ALICE);
        let _b = bus.attach(BOB);
        assert_eq!(bus.attached_count(), 2);
        bus.detach(ALICE);
        assert_eq!(bus.attached_count(), 1);
    }
}
