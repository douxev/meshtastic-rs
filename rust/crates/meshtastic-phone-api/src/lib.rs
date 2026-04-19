//! Transport-agnostic port of the firmware's
//! [`PhoneAPI`](src/mesh/PhoneAPI.cpp) — the protocol Meshtastic
//! exposes to phones (and PC clients) over BLE, serial, TCP, UDP.
//!
//! The firmware class couples three concerns:
//!
//! 1. **Protocol** — frame [`ToRadio`]/[`FromRadio`] protobuf messages
//!    in/out, drive a config-handshake state machine on
//!    `ToRadio::want_config_id`.
//! 2. **Transport** — virtual hooks (`onNowHasData`, `onConfigStart`,
//!    `checkIsConnected`, …) that the BLE/serial subclasses fill in.
//! 3. **Source-of-truth glue** — pulls live pointers to global
//!    `service`, `nodeDB`, `channels`, `config`, `moduleConfig`,
//!    `xModem`, `mqtt`, … to assemble the FromRadio stream.
//!
//! This crate ports concern (1) only. The transport is not the
//! protocol — let it be a [`SimRadioBus`-style sink][crate]: we
//! produce framed `Vec<u8>` packets to send and consume framed
//! `&[u8]` packets from the wire. We also let the caller supply the
//! "source of truth" snapshot up-front via [`ConfigSnapshot`] /
//! [`PhoneApi::set_my_info`] / [`PhoneApi::set_metadata`] /
//! [`PhoneApi::set_channels`] / [`PhoneApi::set_node_db`], so the
//! protocol layer never reaches into globals.
//!
//! ## State machine
//!
//! Mirrors `PhoneAPI::State` in [`PhoneAPI.h`](src/mesh/PhoneAPI.h):
//!
//! ```text
//! Disconnected --want_config_id--> SendMyInfo
//!     --> SendMetadata
//!     --> SendChannels[0..N]
//!     --> SendConfig[Device, Position, Power, Network, Display, LoRa, Bluetooth, Security, Sessionkey, DeviceUi]
//!     --> SendModuleConfig[Mqtt..Tak]
//!     --> SendNodeInfos[0..M]
//!     --> SendCompleteId  (emits ConfigCompleteId == nonce)
//!     --> SendingPackets   (steady state: drains queued packets / log records / queue status)
//! ```
//!
//! `disconnect`, `close`, or a fresh `want_config_id` from the phone
//! resets the machine.
//!
//! ## What's not ported (yet)
//!
//! - File-manifest / xmodem (firmware Phase 7 hardware concern)
//! - Special "only nodes" / "only config" nonces
//!   (`SPECIAL_NONCE_ONLY_*`) — easy to add when needed
//! - MQTT proxy passthrough (covered by Phase 7 wiring)
//! - Connection-timeout detection (`checkConnectionTimeout` is
//!   left to the transport layer in this design)

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use core::fmt;

use meshtastic_proto::meshtastic::{
    config, from_radio, module_config, to_radio, Channel, Config, DeviceMetadata, FromRadio, LogRecord, MeshPacket,
    ModuleConfig, MyNodeInfo, NodeInfo, QueueStatus, ToRadio,
};
use prost::Message;

/// Maximum size (bytes) for a single ToRadio or FromRadio frame.
/// Mirrors firmware `MAX_TO_FROM_RADIO_SIZE` in `PhoneAPI.h:14`.
/// Anything larger doesn't fit in one BLE characteristic write.
pub const MAX_TO_FROM_RADIO_SIZE: usize = 512;

/// Number of recent ToRadio packet ids tracked for dedup. Mirrors
/// the fixed array `recentToRadioPacketIds[20]` in `PhoneAPI.h:59`.
pub const RECENT_TO_RADIO_DEDUP: usize = 20;

/// Errors producible by [`PhoneApi`].
#[derive(Debug, Clone, PartialEq)]
pub enum PhoneApiError {
    /// The inbound frame did not decode as a [`ToRadio`] proto.
    Decode(prost::DecodeError),
    /// The inbound frame was over [`MAX_TO_FROM_RADIO_SIZE`] bytes.
    FrameTooLarge {
        /// Actual size in bytes.
        size: usize,
    },
    /// The proto encoded to over [`MAX_TO_FROM_RADIO_SIZE`] bytes.
    /// Should never happen for valid configs; indicates a logic bug.
    EncodedTooLarge {
        /// Actual size in bytes.
        size: usize,
    },
}

impl fmt::Display for PhoneApiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PhoneApiError::Decode(e) => write!(f, "ToRadio decode failed: {e}"),
            PhoneApiError::FrameTooLarge { size } => {
                write!(f, "ToRadio frame too large: {size} > {MAX_TO_FROM_RADIO_SIZE}")
            }
            PhoneApiError::EncodedTooLarge { size } => {
                write!(f, "FromRadio encode too large: {size} > {MAX_TO_FROM_RADIO_SIZE}")
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PhoneApiError {}

/// Result of [`PhoneApi::handle_to_radio`]. Ports the side-effect
/// surface of `PhoneAPI::handleToRadio` so the calling transport can
/// drive higher layers without us depending on them.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ToRadioOutcome {
    /// A [`MeshPacket`] the phone is asking us to enqueue for the
    /// mesh. The transport must hand this to the router /
    /// `ModuleDispatcher`. `None` for non-packet ToRadio variants.
    pub packet_to_send: Option<MeshPacket>,
    /// `true` if the ToRadio carried a `disconnect` flag. The
    /// transport should tear down the link after handling.
    pub disconnect: bool,
    /// `true` if the ToRadio carried a heartbeat. Transports may
    /// use this to reset their idle timer.
    pub heartbeat: bool,
    /// `true` if this was a duplicate `Packet` ToRadio (dedup'd).
    /// Useful for log fidelity but never blocks delivery.
    pub deduped: bool,
}

/// Snapshot of the device's configuration that the phone-api
/// surfaces during the initial handshake. The transport / glue layer
/// owns the live data; we hold an `Option` per slot and emit the
/// `Some` ones in order. Missing slots are skipped (firmware would
/// emit a default-init proto; we simply elide them — clients tolerate
/// it).
#[derive(Debug, Clone, Default)]
pub struct ConfigSnapshot {
    /// `Config` oneof variants to emit during `SendConfig`. Order
    /// follows the firmware enum: Device, Position, Power, Network,
    /// Display, LoRa, Bluetooth, Security, Sessionkey, DeviceUi.
    pub config: Vec<config::PayloadVariant>,
    /// `ModuleConfig` oneof variants to emit during
    /// `SendModuleConfig`. Order follows the firmware enum.
    pub module_config: Vec<module_config::PayloadVariant>,
}

/// State machine state — pub for tests / observability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Not connected. `want_config_id` transitions us forward.
    Disconnected,
    /// Send `MyNodeInfo` next.
    SendMyInfo,
    /// Send `DeviceMetadata` next.
    SendMetadata,
    /// Send the next [`Channel`] (index in tuple).
    SendChannel(u8),
    /// Send the next [`Config`] payload variant (index into
    /// snapshot).
    SendConfig(usize),
    /// Send the next [`ModuleConfig`] payload variant.
    SendModuleConfig(usize),
    /// Send the next [`NodeInfo`] (index into snapshot).
    SendNodeInfo(usize),
    /// Send `ConfigCompleteId == nonce`.
    SendCompleteId,
    /// Steady state — drain the per-event queues.
    SendingPackets,
}

/// The phone-api state machine.
#[derive(Debug)]
pub struct PhoneApi {
    state: State,
    config_nonce: u32,
    /// Auto-incrementing id stamped on every outbound `FromRadio`.
    /// Mirrors firmware `fromRadioNum`.
    from_radio_num: u32,

    // -------- handshake source-of-truth (caller-supplied) --------
    my_info: Option<MyNodeInfo>,
    metadata: Option<DeviceMetadata>,
    channels: Vec<Channel>,
    config_snapshot: ConfigSnapshot,
    node_infos: Vec<NodeInfo>,

    // -------- steady-state event queues --------
    out_packets: VecDeque<MeshPacket>,
    out_log_records: VecDeque<LogRecord>,
    out_queue_status: VecDeque<QueueStatus>,

    // -------- inbound dedup --------
    recent_to_radio_ids: VecDeque<u32>,
}

impl Default for PhoneApi {
    fn default() -> Self {
        Self::new()
    }
}

impl PhoneApi {
    /// Construct a freshly-disconnected instance.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: State::Disconnected,
            config_nonce: 0,
            from_radio_num: 0,
            my_info: None,
            metadata: None,
            channels: Vec::new(),
            config_snapshot: ConfigSnapshot::default(),
            node_infos: Vec::new(),
            out_packets: VecDeque::new(),
            out_log_records: VecDeque::new(),
            out_queue_status: VecDeque::new(),
            recent_to_radio_ids: VecDeque::new(),
        }
    }

    // -------- caller-supplied snapshot setters --------

    /// Set the [`MyNodeInfo`] emitted during `SendMyInfo`.
    pub fn set_my_info(&mut self, my_info: MyNodeInfo) {
        self.my_info = Some(my_info);
    }

    /// Set the [`DeviceMetadata`] emitted during `SendMetadata`.
    pub fn set_metadata(&mut self, metadata: DeviceMetadata) {
        self.metadata = Some(metadata);
    }

    /// Replace the channels emitted during `SendChannel`. Order is
    /// the firmware channel-table order (primary first).
    pub fn set_channels(&mut self, channels: Vec<Channel>) {
        self.channels = channels;
    }

    /// Replace the config/module-config variants emitted during the
    /// `SendConfig` / `SendModuleConfig` phases.
    pub fn set_config_snapshot(&mut self, snapshot: ConfigSnapshot) {
        self.config_snapshot = snapshot;
    }

    /// Replace the node-info entries emitted during `SendNodeInfo`.
    /// The first entry should be **our** node's info — firmware
    /// always sends own-nodeinfo first.
    pub fn set_node_db(&mut self, node_infos: Vec<NodeInfo>) {
        self.node_infos = node_infos;
    }

    // -------- runtime accessors --------

    /// Current state. For tests / observability.
    #[must_use]
    pub fn state(&self) -> State {
        self.state
    }

    /// `true` once we've moved past `Disconnected` — i.e. a phone
    /// has issued `want_config_id` and we've started the handshake
    /// (or finished it). Mirrors `PhoneAPI::isConnected`.
    #[must_use]
    pub fn is_connected(&self) -> bool {
        self.state != State::Disconnected
    }

    /// `true` once the handshake is fully complete and we're in
    /// steady-state mesh-packet-relay mode. Mirrors
    /// `PhoneAPI::isSendingPackets`.
    #[must_use]
    pub fn is_sending_packets(&self) -> bool {
        self.state == State::SendingPackets
    }

    /// Active config nonce (the integer the phone wrote into
    /// `want_config_id`). 0 outside a handshake.
    #[must_use]
    pub fn config_nonce(&self) -> u32 {
        self.config_nonce
    }

    // -------- transport hooks --------

    /// Tear down the connection and reset state. Mirrors
    /// `PhoneAPI::close`.
    pub fn close(&mut self) {
        self.state = State::Disconnected;
        self.config_nonce = 0;
        self.from_radio_num = 0;
        self.out_packets.clear();
        self.out_log_records.clear();
        self.out_queue_status.clear();
        self.recent_to_radio_ids.clear();
    }

    /// Process an inbound ToRadio frame. The bytes are the prost-
    /// encoded `ToRadio` message exactly as it arrived on the wire
    /// (BLE characteristic write, serial slip frame, etc.).
    pub fn handle_to_radio(&mut self, buf: &[u8]) -> Result<ToRadioOutcome, PhoneApiError> {
        if buf.len() > MAX_TO_FROM_RADIO_SIZE {
            return Err(PhoneApiError::FrameTooLarge { size: buf.len() });
        }
        let to_radio = ToRadio::decode(buf).map_err(PhoneApiError::Decode)?;
        let mut outcome = ToRadioOutcome::default();
        match to_radio.payload_variant {
            Some(to_radio::PayloadVariant::Packet(packet)) => {
                if packet.id != 0 && self.was_seen_recently(packet.id) {
                    outcome.deduped = true;
                } else {
                    if packet.id != 0 {
                        self.remember_to_radio_id(packet.id);
                    }
                    outcome.packet_to_send = Some(packet);
                }
            }
            Some(to_radio::PayloadVariant::WantConfigId(nonce)) => {
                self.config_nonce = nonce;
                self.start_config();
            }
            Some(to_radio::PayloadVariant::Disconnect(true)) => {
                outcome.disconnect = true;
                self.close();
            }
            Some(to_radio::PayloadVariant::Heartbeat(_)) => {
                outcome.heartbeat = true;
            }
            // XmodemPacket / MqttClientProxyMessage / Disconnect(false)
            // / no payload — silently ignored, matches firmware default.
            _ => {}
        }
        Ok(outcome)
    }

    /// Pull the next FromRadio frame to send to the phone. Returns
    /// `Ok(None)` when nothing to send.
    pub fn pop_from_radio(&mut self) -> Result<Option<Vec<u8>>, PhoneApiError> {
        let Some(payload) = self.next_payload_variant() else {
            return Ok(None);
        };
        let id = self.bump_from_radio_num();
        let frame = FromRadio {
            id,
            payload_variant: Some(payload),
        };
        let mut buf = Vec::with_capacity(frame.encoded_len());
        frame.encode(&mut buf).expect("Vec write is infallible");
        if buf.len() > MAX_TO_FROM_RADIO_SIZE {
            return Err(PhoneApiError::EncodedTooLarge { size: buf.len() });
        }
        Ok(Some(buf))
    }

    // -------- steady-state event ingest --------

    /// Queue a [`MeshPacket`] to be delivered to the phone in the
    /// `SendingPackets` steady state. No-op (not even queued) if
    /// the phone has not yet completed the config handshake — this
    /// matches firmware, which only `releasePhonePacket()`s once
    /// `state == STATE_SEND_PACKETS`.
    ///
    /// Returns `true` if the packet was queued, `false` if dropped
    /// because the phone is mid-handshake.
    pub fn enqueue_packet_for_phone(&mut self, packet: MeshPacket) -> bool {
        if !self.is_sending_packets() {
            return false;
        }
        self.out_packets.push_back(packet);
        true
    }

    /// Queue a [`LogRecord`] to be streamed to the phone.
    pub fn enqueue_log_record(&mut self, record: LogRecord) -> bool {
        if !self.is_sending_packets() {
            return false;
        }
        self.out_log_records.push_back(record);
        true
    }

    /// Queue a [`QueueStatus`] update to be streamed to the phone.
    pub fn enqueue_queue_status(&mut self, status: QueueStatus) -> bool {
        if !self.is_sending_packets() {
            return false;
        }
        self.out_queue_status.push_back(status);
        true
    }

    // -------- internals --------

    fn start_config(&mut self) {
        // Even if we were already connected, the phone re-asking for
        // config restarts the state machine (firmware comment).
        self.state = State::SendMyInfo;
    }

    fn next_payload_variant(&mut self) -> Option<from_radio::PayloadVariant> {
        loop {
            match self.state {
                State::Disconnected => return None,
                State::SendMyInfo => {
                    self.state = State::SendMetadata;
                    if let Some(my_info) = self.my_info.clone() {
                        return Some(from_radio::PayloadVariant::MyInfo(my_info));
                    }
                    // No my_info supplied — skip ahead, don't stall.
                }
                State::SendMetadata => {
                    self.state = State::SendChannel(0);
                    if let Some(metadata) = self.metadata.clone() {
                        return Some(from_radio::PayloadVariant::Metadata(metadata));
                    }
                }
                State::SendChannel(idx) => {
                    let i = idx as usize;
                    if i < self.channels.len() {
                        self.state = State::SendChannel(idx + 1);
                        return Some(from_radio::PayloadVariant::Channel(self.channels[i].clone()));
                    }
                    self.state = State::SendConfig(0);
                }
                State::SendConfig(idx) => {
                    if idx < self.config_snapshot.config.len() {
                        self.state = State::SendConfig(idx + 1);
                        let v = self.config_snapshot.config[idx].clone();
                        return Some(from_radio::PayloadVariant::Config(Config {
                            payload_variant: Some(v),
                        }));
                    }
                    self.state = State::SendModuleConfig(0);
                }
                State::SendModuleConfig(idx) => {
                    if idx < self.config_snapshot.module_config.len() {
                        self.state = State::SendModuleConfig(idx + 1);
                        let v = self.config_snapshot.module_config[idx].clone();
                        return Some(from_radio::PayloadVariant::ModuleConfig(ModuleConfig {
                            payload_variant: Some(v),
                        }));
                    }
                    self.state = State::SendNodeInfo(0);
                }
                State::SendNodeInfo(idx) => {
                    if idx < self.node_infos.len() {
                        self.state = State::SendNodeInfo(idx + 1);
                        return Some(from_radio::PayloadVariant::NodeInfo(self.node_infos[idx].clone()));
                    }
                    self.state = State::SendCompleteId;
                }
                State::SendCompleteId => {
                    let nonce = self.config_nonce;
                    self.config_nonce = 0;
                    self.state = State::SendingPackets;
                    return Some(from_radio::PayloadVariant::ConfigCompleteId(nonce));
                }
                State::SendingPackets => {
                    if let Some(qs) = self.out_queue_status.pop_front() {
                        return Some(from_radio::PayloadVariant::QueueStatus(qs));
                    }
                    if let Some(log) = self.out_log_records.pop_front() {
                        return Some(from_radio::PayloadVariant::LogRecord(log));
                    }
                    if let Some(pkt) = self.out_packets.pop_front() {
                        return Some(from_radio::PayloadVariant::Packet(pkt));
                    }
                    return None;
                }
            }
        }
    }

    fn bump_from_radio_num(&mut self) -> u32 {
        // Firmware allows wraparound; mirror with `wrapping_add`.
        self.from_radio_num = self.from_radio_num.wrapping_add(1);
        self.from_radio_num
    }

    fn was_seen_recently(&self, id: u32) -> bool {
        self.recent_to_radio_ids.contains(&id)
    }

    fn remember_to_radio_id(&mut self, id: u32) {
        if self.recent_to_radio_ids.len() >= RECENT_TO_RADIO_DEDUP {
            self.recent_to_radio_ids.pop_front();
        }
        self.recent_to_radio_ids.push_back(id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;
    use meshtastic_proto::meshtastic::{
        config::{DeviceConfig, LoRaConfig},
        mesh_packet::PayloadVariant as PktPayload,
        module_config::MqttConfig,
        Data, Heartbeat, PortNum,
    };

    fn snapshot() -> ConfigSnapshot {
        ConfigSnapshot {
            config: vec![
                config::PayloadVariant::Device(DeviceConfig::default()),
                config::PayloadVariant::Lora(LoRaConfig::default()),
            ],
            module_config: vec![module_config::PayloadVariant::Mqtt(MqttConfig::default())],
        }
    }

    fn build_phone_api() -> PhoneApi {
        let mut api = PhoneApi::new();
        api.set_my_info(MyNodeInfo {
            my_node_num: 0x0aaa_aaaa,
            ..Default::default()
        });
        api.set_metadata(DeviceMetadata::default());
        api.set_channels(vec![Channel::default(), Channel::default()]);
        api.set_config_snapshot(snapshot());
        api.set_node_db(vec![
            NodeInfo {
                num: 0x0aaa_aaaa,
                ..Default::default()
            },
            NodeInfo {
                num: 0x0bbb_bbbb,
                ..Default::default()
            },
        ]);
        api
    }

    fn want_config(nonce: u32) -> Vec<u8> {
        ToRadio {
            payload_variant: Some(to_radio::PayloadVariant::WantConfigId(nonce)),
        }
        .encode_to_vec()
    }

    fn decode_from_radio(bytes: &[u8]) -> FromRadio {
        FromRadio::decode(bytes).expect("FromRadio must decode")
    }

    #[test]
    fn fresh_instance_is_disconnected() {
        let api = PhoneApi::new();
        assert_eq!(api.state(), State::Disconnected);
        assert!(!api.is_connected());
        assert!(!api.is_sending_packets());
        assert_eq!(api.config_nonce(), 0);
    }

    #[test]
    fn pop_returns_none_until_handshake_starts() {
        let mut api = build_phone_api();
        assert!(api.pop_from_radio().unwrap().is_none());
    }

    #[test]
    fn full_handshake_emits_expected_sequence_with_matching_nonce() {
        let mut api = build_phone_api();
        let outcome = api.handle_to_radio(&want_config(0xdead_beef)).unwrap();
        assert!(outcome.packet_to_send.is_none());
        assert!(api.is_connected());
        assert_eq!(api.config_nonce(), 0xdead_beef);

        let mut emitted = Vec::new();
        let mut last_id = 0;
        while let Some(frame) = api.pop_from_radio().unwrap() {
            let fr = decode_from_radio(&frame);
            assert!(fr.id > last_id, "FromRadio.id must monotonically increase");
            last_id = fr.id;
            emitted.push(fr.payload_variant.expect("payload variant present"));
        }

        // Order: MyInfo, Metadata, Channel x2, Config x2, ModuleConfig x1,
        // NodeInfo x2, ConfigCompleteId. Total = 10.
        assert_eq!(emitted.len(), 10, "got {emitted:#?}");
        assert!(matches!(emitted[0], from_radio::PayloadVariant::MyInfo(_)));
        assert!(matches!(emitted[1], from_radio::PayloadVariant::Metadata(_)));
        assert!(matches!(emitted[2], from_radio::PayloadVariant::Channel(_)));
        assert!(matches!(emitted[3], from_radio::PayloadVariant::Channel(_)));
        assert!(matches!(emitted[4], from_radio::PayloadVariant::Config(_)));
        assert!(matches!(emitted[5], from_radio::PayloadVariant::Config(_)));
        assert!(matches!(emitted[6], from_radio::PayloadVariant::ModuleConfig(_)));
        assert!(matches!(emitted[7], from_radio::PayloadVariant::NodeInfo(_)));
        assert!(matches!(emitted[8], from_radio::PayloadVariant::NodeInfo(_)));
        assert!(matches!(
            emitted[9],
            from_radio::PayloadVariant::ConfigCompleteId(0xdead_beef)
        ));

        assert!(api.is_sending_packets());
        // Nonce cleared after CompleteId.
        assert_eq!(api.config_nonce(), 0);
    }

    #[test]
    fn handshake_skips_missing_optional_pieces() {
        // Construct an API with no my_info / metadata / channels —
        // it should still produce a clean ConfigCompleteId.
        let mut api = PhoneApi::new();
        api.set_config_snapshot(ConfigSnapshot::default());
        api.set_node_db(Vec::new());
        api.handle_to_radio(&want_config(7)).unwrap();

        let mut payloads = Vec::new();
        while let Some(buf) = api.pop_from_radio().unwrap() {
            payloads.push(decode_from_radio(&buf).payload_variant.unwrap());
        }
        assert_eq!(payloads.len(), 1);
        assert!(matches!(payloads[0], from_radio::PayloadVariant::ConfigCompleteId(7)));
        assert!(api.is_sending_packets());
    }

    #[test]
    fn steady_state_emits_queue_status_log_packet_in_order() {
        let mut api = build_phone_api();
        api.handle_to_radio(&want_config(1)).unwrap();
        // Drain handshake.
        while let Some(buf) = api.pop_from_radio().unwrap() {
            let fr = decode_from_radio(&buf);
            if matches!(
                fr.payload_variant,
                Some(from_radio::PayloadVariant::ConfigCompleteId(_))
            ) {
                break;
            }
        }
        assert!(api.is_sending_packets());

        api.enqueue_queue_status(QueueStatus {
            mesh_packet_id: 42,
            ..Default::default()
        });
        api.enqueue_log_record(LogRecord {
            message: "hi".into(),
            ..Default::default()
        });
        let pkt = MeshPacket {
            id: 99,
            payload_variant: Some(PktPayload::Decoded(Data {
                portnum: PortNum::TextMessageApp as i32,
                payload: b"yo".to_vec(),
                ..Default::default()
            })),
            ..Default::default()
        };
        assert!(api.enqueue_packet_for_phone(pkt));

        let v1 = decode_from_radio(&api.pop_from_radio().unwrap().unwrap()).payload_variant;
        assert!(matches!(v1, Some(from_radio::PayloadVariant::QueueStatus(_))));
        let v2 = decode_from_radio(&api.pop_from_radio().unwrap().unwrap()).payload_variant;
        assert!(matches!(v2, Some(from_radio::PayloadVariant::LogRecord(_))));
        let v3 = decode_from_radio(&api.pop_from_radio().unwrap().unwrap()).payload_variant;
        match v3 {
            Some(from_radio::PayloadVariant::Packet(p)) => assert_eq!(p.id, 99),
            other => panic!("expected Packet, got {other:?}"),
        }
        assert!(api.pop_from_radio().unwrap().is_none());
    }

    #[test]
    fn enqueue_before_handshake_complete_is_dropped() {
        let mut api = build_phone_api();
        // No want_config_id yet → still Disconnected.
        assert!(!api.enqueue_packet_for_phone(MeshPacket::default()));
        assert!(!api.enqueue_log_record(LogRecord::default()));
        assert!(!api.enqueue_queue_status(QueueStatus::default()));
    }

    #[test]
    fn to_radio_packet_dispatches_to_caller() {
        let mut api = build_phone_api();
        let pkt = MeshPacket {
            id: 0xcafe,
            from: 0x0aaa_aaaa,
            ..Default::default()
        };
        let to_radio = ToRadio {
            payload_variant: Some(to_radio::PayloadVariant::Packet(pkt.clone())),
        }
        .encode_to_vec();
        let outcome = api.handle_to_radio(&to_radio).unwrap();
        assert_eq!(outcome.packet_to_send.as_ref().map(|p| p.id), Some(0xcafe));
        assert!(!outcome.deduped);

        // Re-sending the same packet should be deduped.
        let outcome2 = api.handle_to_radio(&to_radio).unwrap();
        assert!(outcome2.deduped);
        assert!(outcome2.packet_to_send.is_none());
    }

    #[test]
    fn dedup_only_applies_to_nonzero_ids() {
        let mut api = build_phone_api();
        let pkt = MeshPacket {
            id: 0,
            ..Default::default()
        };
        let bytes = ToRadio {
            payload_variant: Some(to_radio::PayloadVariant::Packet(pkt)),
        }
        .encode_to_vec();
        // Both calls should pass-through; id==0 means "unset".
        let o1 = api.handle_to_radio(&bytes).unwrap();
        let o2 = api.handle_to_radio(&bytes).unwrap();
        assert!(o1.packet_to_send.is_some() && !o1.deduped);
        assert!(o2.packet_to_send.is_some() && !o2.deduped);
    }

    #[test]
    fn dedup_window_is_bounded() {
        let mut api = build_phone_api();
        // Push one more than the dedup capacity; the earliest id
        // should fall out of the window.
        for i in 1..=(RECENT_TO_RADIO_DEDUP as u32 + 1) {
            let bytes = ToRadio {
                payload_variant: Some(to_radio::PayloadVariant::Packet(MeshPacket {
                    id: i,
                    ..Default::default()
                })),
            }
            .encode_to_vec();
            api.handle_to_radio(&bytes).unwrap();
        }
        // id=1 was evicted, so re-sending it is treated as fresh.
        let bytes = ToRadio {
            payload_variant: Some(to_radio::PayloadVariant::Packet(MeshPacket {
                id: 1,
                ..Default::default()
            })),
        }
        .encode_to_vec();
        let outcome = api.handle_to_radio(&bytes).unwrap();
        assert!(!outcome.deduped, "evicted id should not be deduped");
        // After re-inserting id=1, the queue holds {3..=21, 1} — pick
        // an id that's still in the window.
        let bytes = ToRadio {
            payload_variant: Some(to_radio::PayloadVariant::Packet(MeshPacket {
                id: 21,
                ..Default::default()
            })),
        }
        .encode_to_vec();
        let outcome = api.handle_to_radio(&bytes).unwrap();
        assert!(outcome.deduped, "id still in window must be deduped");
    }

    #[test]
    fn disconnect_resets_state() {
        let mut api = build_phone_api();
        api.handle_to_radio(&want_config(11)).unwrap();
        assert!(api.is_connected());

        let bytes = ToRadio {
            payload_variant: Some(to_radio::PayloadVariant::Disconnect(true)),
        }
        .encode_to_vec();
        let outcome = api.handle_to_radio(&bytes).unwrap();
        assert!(outcome.disconnect);
        assert!(!api.is_connected());
        assert_eq!(api.config_nonce(), 0);
    }

    #[test]
    fn restarting_handshake_mid_stream_resets() {
        let mut api = build_phone_api();
        api.handle_to_radio(&want_config(1)).unwrap();
        // Pull a couple of frames to advance the state machine.
        let _ = api.pop_from_radio().unwrap();
        let _ = api.pop_from_radio().unwrap();
        assert!(matches!(api.state(), State::SendChannel(_) | State::SendMetadata));

        api.handle_to_radio(&want_config(2)).unwrap();
        assert_eq!(api.state(), State::SendMyInfo);
        assert_eq!(api.config_nonce(), 2);
    }

    #[test]
    fn heartbeat_sets_flag_only() {
        let mut api = build_phone_api();
        api.handle_to_radio(&want_config(1)).unwrap();
        let bytes = ToRadio {
            payload_variant: Some(to_radio::PayloadVariant::Heartbeat(Heartbeat::default())),
        }
        .encode_to_vec();
        let outcome = api.handle_to_radio(&bytes).unwrap();
        assert!(outcome.heartbeat);
        assert!(outcome.packet_to_send.is_none());
        assert!(!outcome.disconnect);
    }

    #[test]
    fn malformed_to_radio_returns_decode_error() {
        let mut api = PhoneApi::new();
        let err = api.handle_to_radio(&[0xff, 0xff, 0xff, 0xff]).unwrap_err();
        assert!(matches!(err, PhoneApiError::Decode(_)));
    }

    #[test]
    fn oversize_to_radio_rejected() {
        let mut api = PhoneApi::new();
        let big = vec![0u8; MAX_TO_FROM_RADIO_SIZE + 1];
        let err = api.handle_to_radio(&big).unwrap_err();
        assert!(matches!(err, PhoneApiError::FrameTooLarge { .. }));
    }

    #[test]
    fn from_radio_ids_are_monotonic_and_start_at_one() {
        let mut api = build_phone_api();
        api.handle_to_radio(&want_config(5)).unwrap();
        let frame = decode_from_radio(&api.pop_from_radio().unwrap().unwrap());
        assert_eq!(frame.id, 1);
        let frame2 = decode_from_radio(&api.pop_from_radio().unwrap().unwrap());
        assert_eq!(frame2.id, 2);
    }
}
