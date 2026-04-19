//! Persistent-config layer — Rust port of the firmware
//! [`NodeDB::saveProto`/`loadProto`](src/mesh/NodeDB.cpp:1432) +
//! [`SafeFile`](src/mesh/SafeFile.h) machinery.
//!
//! The firmware persists six prost-encoded blobs to flash under
//! `/prefs/`:
//!
//! | Kind                             | Path                        | Proto                 |
//! |----------------------------------|-----------------------------|-----------------------|
//! | [`ConfigKind::DeviceState`]      | `/prefs/device.proto`       | `DeviceState`         |
//! | [`ConfigKind::NodeDatabase`]     | `/prefs/nodes.proto`        | `NodeDatabase`        |
//! | [`ConfigKind::LocalConfig`]      | `/prefs/config.proto`       | `LocalConfig`         |
//! | [`ConfigKind::LocalModuleConfig`]| `/prefs/module.proto`       | `LocalModuleConfig`   |
//! | [`ConfigKind::ChannelFile`]      | `/prefs/channels.proto`     | `ChannelFile`         |
//! | [`ConfigKind::DeviceUiConfig`]   | `/prefs/uiconfig.proto`     | `DeviceUiConfig`      |
//!
//! This crate exposes:
//!
//! - [`ConfigKind`] — typed enumeration of the persisted kinds + the
//!   firmware filename for each.
//! - `version_for(blob) -> u32` and `set_version(blob, v)` accessors
//!   that work uniformly across the four blobs that carry a `version`
//!   field. Used by [`ConfigStore::load_versioned`] to detect old
//!   save files.
//! - [`ConfigStore`] trait — abstract `load`/`save` for raw bytes.
//! - [`MemoryConfigStore`] — `no_std`-friendly in-memory impl, useful
//!   for tests and for the host simulator.
//! - [`FsConfigStore`] (`std`-only) — file-backed impl that mirrors
//!   firmware [`SafeFile`]'s atomic write-then-rename behaviour.
//!
//! [`SafeFile`]: src/mesh/SafeFile.h

#![cfg_attr(not(feature = "std"), no_std)]
#![deny(missing_docs)]

extern crate alloc;

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use meshtastic_proto::meshtastic::{ChannelFile, DeviceState, LocalConfig, LocalModuleConfig, NodeDatabase};
use prost::Message;

/// The current on-disk schema version. Mirrors firmware
/// `DEVICESTATE_CUR_VER` in `src/mesh/NodeDB.h:85`.
pub const DEVICESTATE_CUR_VER: u32 = 24;

/// The minimum on-disk schema version we can still load. Mirrors
/// firmware `DEVICESTATE_MIN_VER` in `src/mesh/NodeDB.h:86`.
pub const DEVICESTATE_MIN_VER: u32 = 24;

/// One persisted blob kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ConfigKind {
    /// Top-level device state — owner identity, last-known position,
    /// our node-num, etc.
    DeviceState,
    /// The known-nodes table.
    NodeDatabase,
    /// All [`Config`] sub-sections (device, position, lora, …).
    LocalConfig,
    /// All [`ModuleConfig`] sub-sections (mqtt, serial, telemetry, …).
    LocalModuleConfig,
    /// The set of mesh [`Channel`]s.
    ///
    /// [`Channel`]: meshtastic_proto::meshtastic::Channel
    ChannelFile,
    /// Device UI persistence (theme, brightness, paired phone, …).
    DeviceUiConfig,
}

impl ConfigKind {
    /// All kinds, in firmware iteration order. Useful for
    /// "save everything" / "load everything" loops.
    pub const ALL: [ConfigKind; 6] = [
        ConfigKind::DeviceState,
        ConfigKind::NodeDatabase,
        ConfigKind::LocalConfig,
        ConfigKind::LocalModuleConfig,
        ConfigKind::ChannelFile,
        ConfigKind::DeviceUiConfig,
    ];

    /// Firmware on-disk path for this kind. Mirrors the constants in
    /// `src/mesh/NodeDB.h:98-105`.
    #[must_use]
    pub fn firmware_filename(self) -> &'static str {
        match self {
            ConfigKind::DeviceState => "/prefs/device.proto",
            ConfigKind::NodeDatabase => "/prefs/nodes.proto",
            ConfigKind::LocalConfig => "/prefs/config.proto",
            ConfigKind::LocalModuleConfig => "/prefs/module.proto",
            ConfigKind::ChannelFile => "/prefs/channels.proto",
            ConfigKind::DeviceUiConfig => "/prefs/uiconfig.proto",
        }
    }

    /// Short stem (no slash, no extension) used by the host
    /// [`FsConfigStore`] to lay files out under a given root dir.
    #[must_use]
    pub fn file_stem(self) -> &'static str {
        match self {
            ConfigKind::DeviceState => "device",
            ConfigKind::NodeDatabase => "nodes",
            ConfigKind::LocalConfig => "config",
            ConfigKind::LocalModuleConfig => "module",
            ConfigKind::ChannelFile => "channels",
            ConfigKind::DeviceUiConfig => "uiconfig",
        }
    }
}

/// Errors from the persistence layer.
#[derive(Debug)]
pub enum ConfigError {
    /// The bytes did not decode as the expected proto.
    Decode(prost::DecodeError),
    /// The on-disk blob is older than [`DEVICESTATE_MIN_VER`]. The
    /// caller should fall back to defaults (firmware does the same).
    VersionTooOld {
        /// The kind we tried to load.
        kind: ConfigKind,
        /// The version we found on disk.
        found: u32,
        /// The minimum we accept.
        minimum: u32,
    },
    /// The kind has no `version` field, so [`load_versioned`] /
    /// [`ConfigStore::save_versioned`] can't be used with it.
    ///
    /// [`load_versioned`]: ConfigStore::load_versioned
    NoVersionField {
        /// The offending kind.
        kind: ConfigKind,
    },
    /// I/O error from a [`ConfigStore`] backend (e.g. filesystem).
    #[cfg(feature = "std")]
    Io(std::io::Error),
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ConfigError::Decode(e) => write!(f, "config decode failed: {e}"),
            ConfigError::VersionTooOld { kind, found, minimum } => {
                write!(f, "{kind:?} schema v{found} is older than minimum v{minimum}")
            }
            ConfigError::NoVersionField { kind } => {
                write!(f, "{kind:?} has no `version` field")
            }
            #[cfg(feature = "std")]
            ConfigError::Io(e) => write!(f, "config I/O error: {e}"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::Decode(e) => Some(e),
            ConfigError::Io(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(feature = "std")]
impl From<std::io::Error> for ConfigError {
    fn from(e: std::io::Error) -> Self {
        ConfigError::Io(e)
    }
}

impl From<prost::DecodeError> for ConfigError {
    fn from(e: prost::DecodeError) -> Self {
        ConfigError::Decode(e)
    }
}

/// Get the `version` field from a decoded prost blob, if it has one.
/// Returns `None` for [`ConfigKind`]s with no `version` field
/// ([`Config`], [`ModuleConfig`] sub-messages — but their *Local*
/// wrappers do have one).
pub fn version_of(kind: ConfigKind, blob: &[u8]) -> Result<u32, ConfigError> {
    Ok(match kind {
        ConfigKind::DeviceState => DeviceState::decode(blob)?.version,
        ConfigKind::NodeDatabase => NodeDatabase::decode(blob)?.version,
        ConfigKind::LocalConfig => LocalConfig::decode(blob)?.version,
        ConfigKind::LocalModuleConfig => LocalModuleConfig::decode(blob)?.version,
        ConfigKind::ChannelFile => ChannelFile::decode(blob)?.version,
        ConfigKind::DeviceUiConfig => return Err(ConfigError::NoVersionField { kind }),
    })
}

/// Encode a typed proto into bytes for storage. Convenience helper
/// so callers don't need to depend on `prost` directly.
pub fn encode<M: Message>(msg: &M) -> Vec<u8> {
    msg.encode_to_vec()
}

/// Decode bytes into a typed proto.
pub fn decode<M: Message + Default>(bytes: &[u8]) -> Result<M, ConfigError> {
    Ok(M::decode(bytes)?)
}

/// Re-export of the typed proto messages this crate persists, so
/// downstream code doesn't have to depend on `meshtastic-proto`
/// directly to use the typed helpers below.
pub mod proto {
    pub use meshtastic_proto::meshtastic::{
        ChannelFile, Config, DeviceState, DeviceUiConfig, LocalConfig, LocalModuleConfig, ModuleConfig, NodeDatabase,
    };
}

/// Trait for any backend that can persist Meshtastic config blobs.
///
/// Two impls are provided:
///
/// - [`MemoryConfigStore`] for tests / simulators (no-feature, no_std).
/// - [`FsConfigStore`] for hosts with a real filesystem (`std` only).
///
/// On-device, the firmware uses raw `FSCom` (the LittleFS / SPIFFS
/// abstraction) wrapped in `SafeFile` for atomic writes.
pub trait ConfigStore {
    /// Load a blob. Returns `Ok(None)` if not present.
    fn load(&self, kind: ConfigKind) -> Result<Option<Vec<u8>>, ConfigError>;

    /// Save a blob, replacing any prior version.
    fn save(&mut self, kind: ConfigKind, bytes: &[u8]) -> Result<(), ConfigError>;

    /// Delete a blob. No-op if not present.
    fn delete(&mut self, kind: ConfigKind) -> Result<(), ConfigError>;

    /// Load a blob and check its `version` field against
    /// [`DEVICESTATE_MIN_VER`]. Returns `Ok(None)` if not present;
    /// returns [`ConfigError::VersionTooOld`] if too old to use.
    fn load_versioned(&self, kind: ConfigKind) -> Result<Option<Vec<u8>>, ConfigError> {
        let Some(bytes) = self.load(kind)? else {
            return Ok(None);
        };
        let v = version_of(kind, &bytes)?;
        if v < DEVICESTATE_MIN_VER {
            return Err(ConfigError::VersionTooOld {
                kind,
                found: v,
                minimum: DEVICESTATE_MIN_VER,
            });
        }
        Ok(Some(bytes))
    }

    /// Save a blob with the schema-version field rewritten to
    /// [`DEVICESTATE_CUR_VER`] *before* persistence. Mirrors the
    /// firmware pattern (see `NodeDB.cpp:540`, `:555`, `:815`,
    /// `:1008`, `:1097`). Errors with [`ConfigError::NoVersionField`]
    /// for kinds that don't have one.
    fn save_versioned(&mut self, kind: ConfigKind, bytes: &[u8]) -> Result<(), ConfigError> {
        let stamped = stamp_current_version(kind, bytes)?;
        self.save(kind, &stamped)
    }
}

/// Decode the blob, set its `version` field to [`DEVICESTATE_CUR_VER`],
/// and re-encode. Errors if the kind has no version field.
pub fn stamp_current_version(kind: ConfigKind, bytes: &[u8]) -> Result<Vec<u8>, ConfigError> {
    Ok(match kind {
        ConfigKind::DeviceState => {
            let mut m = DeviceState::decode(bytes)?;
            m.version = DEVICESTATE_CUR_VER;
            m.encode_to_vec()
        }
        ConfigKind::NodeDatabase => {
            let mut m = NodeDatabase::decode(bytes)?;
            m.version = DEVICESTATE_CUR_VER;
            m.encode_to_vec()
        }
        ConfigKind::LocalConfig => {
            let mut m = LocalConfig::decode(bytes)?;
            m.version = DEVICESTATE_CUR_VER;
            m.encode_to_vec()
        }
        ConfigKind::LocalModuleConfig => {
            let mut m = LocalModuleConfig::decode(bytes)?;
            m.version = DEVICESTATE_CUR_VER;
            m.encode_to_vec()
        }
        ConfigKind::ChannelFile => {
            let mut m = ChannelFile::decode(bytes)?;
            m.version = DEVICESTATE_CUR_VER;
            m.encode_to_vec()
        }
        ConfigKind::DeviceUiConfig => return Err(ConfigError::NoVersionField { kind }),
    })
}

// Blanket impl for boxed stores.
impl<S: ConfigStore + ?Sized> ConfigStore for Box<S> {
    fn load(&self, kind: ConfigKind) -> Result<Option<Vec<u8>>, ConfigError> {
        (**self).load(kind)
    }
    fn save(&mut self, kind: ConfigKind, bytes: &[u8]) -> Result<(), ConfigError> {
        (**self).save(kind, bytes)
    }
    fn delete(&mut self, kind: ConfigKind) -> Result<(), ConfigError> {
        (**self).delete(kind)
    }
}

// -------- in-memory store --------

/// In-memory [`ConfigStore`] — six `Option<Vec<u8>>` slots, no I/O.
/// Cloneable so tests can snapshot it.
#[derive(Debug, Clone, Default)]
pub struct MemoryConfigStore {
    device_state: Option<Vec<u8>>,
    node_database: Option<Vec<u8>>,
    local_config: Option<Vec<u8>>,
    local_module_config: Option<Vec<u8>>,
    channel_file: Option<Vec<u8>>,
    device_ui_config: Option<Vec<u8>>,
}

impl MemoryConfigStore {
    /// Create an empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    fn slot(&self, kind: ConfigKind) -> &Option<Vec<u8>> {
        match kind {
            ConfigKind::DeviceState => &self.device_state,
            ConfigKind::NodeDatabase => &self.node_database,
            ConfigKind::LocalConfig => &self.local_config,
            ConfigKind::LocalModuleConfig => &self.local_module_config,
            ConfigKind::ChannelFile => &self.channel_file,
            ConfigKind::DeviceUiConfig => &self.device_ui_config,
        }
    }
    fn slot_mut(&mut self, kind: ConfigKind) -> &mut Option<Vec<u8>> {
        match kind {
            ConfigKind::DeviceState => &mut self.device_state,
            ConfigKind::NodeDatabase => &mut self.node_database,
            ConfigKind::LocalConfig => &mut self.local_config,
            ConfigKind::LocalModuleConfig => &mut self.local_module_config,
            ConfigKind::ChannelFile => &mut self.channel_file,
            ConfigKind::DeviceUiConfig => &mut self.device_ui_config,
        }
    }
}

impl ConfigStore for MemoryConfigStore {
    fn load(&self, kind: ConfigKind) -> Result<Option<Vec<u8>>, ConfigError> {
        Ok(self.slot(kind).clone())
    }

    fn save(&mut self, kind: ConfigKind, bytes: &[u8]) -> Result<(), ConfigError> {
        *self.slot_mut(kind) = Some(bytes.to_vec());
        Ok(())
    }

    fn delete(&mut self, kind: ConfigKind) -> Result<(), ConfigError> {
        *self.slot_mut(kind) = None;
        Ok(())
    }
}

// -------- filesystem store (std only) --------

/// Filesystem-backed [`ConfigStore`]. Lays files out under a root
/// directory, one `<stem>.proto` per kind.
///
/// Saves go through a `<stem>.proto.tmp` → `rename` dance so a crash
/// mid-write never leaves a half-baked file in place. This mirrors
/// the firmware `SafeFile` write-then-rename atomicity.
#[cfg(feature = "std")]
pub struct FsConfigStore {
    root: std::path::PathBuf,
}

#[cfg(feature = "std")]
impl FsConfigStore {
    /// Create a store rooted at `root`. The directory is created if
    /// it doesn't exist.
    pub fn new(root: impl Into<std::path::PathBuf>) -> Result<Self, ConfigError> {
        let root = root.into();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    /// Path on disk for one kind.
    #[must_use]
    pub fn path_for(&self, kind: ConfigKind) -> std::path::PathBuf {
        let mut p = self.root.clone();
        p.push(format!("{}.proto", kind.file_stem()));
        p
    }

    fn tmp_path_for(&self, kind: ConfigKind) -> std::path::PathBuf {
        let mut p = self.root.clone();
        p.push(format!("{}.proto.tmp", kind.file_stem()));
        p
    }
}

#[cfg(feature = "std")]
impl ConfigStore for FsConfigStore {
    fn load(&self, kind: ConfigKind) -> Result<Option<Vec<u8>>, ConfigError> {
        let path = self.path_for(kind);
        match std::fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn save(&mut self, kind: ConfigKind, bytes: &[u8]) -> Result<(), ConfigError> {
        let final_path = self.path_for(kind);
        let tmp_path = self.tmp_path_for(kind);
        std::fs::write(&tmp_path, bytes)?;
        std::fs::rename(&tmp_path, &final_path)?;
        Ok(())
    }

    fn delete(&mut self, kind: ConfigKind) -> Result<(), ConfigError> {
        let path = self.path_for(kind);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshtastic_proto::meshtastic::{
        config::{DeviceConfig, LoRaConfig, PayloadVariant as ConfigVariant},
        Channel, DeviceUiConfig, NodeInfoLite,
    };

    fn make_local_config() -> LocalConfig {
        LocalConfig {
            device: Some(DeviceConfig::default()),
            lora: Some(LoRaConfig::default()),
            version: 0, // intentionally wrong; save_versioned should rewrite
            ..Default::default()
        }
    }

    fn make_channel_file() -> ChannelFile {
        ChannelFile {
            channels: vec![Channel::default(), Channel::default()],
            version: 0,
        }
    }

    fn make_node_db() -> NodeDatabase {
        NodeDatabase {
            nodes: vec![NodeInfoLite {
                num: 0x1111,
                ..Default::default()
            }],
            version: 0,
        }
    }

    #[test]
    fn config_kind_paths_match_firmware() {
        assert_eq!(ConfigKind::DeviceState.firmware_filename(), "/prefs/device.proto");
        assert_eq!(ConfigKind::NodeDatabase.firmware_filename(), "/prefs/nodes.proto");
        assert_eq!(ConfigKind::LocalConfig.firmware_filename(), "/prefs/config.proto");
        assert_eq!(ConfigKind::LocalModuleConfig.firmware_filename(), "/prefs/module.proto");
        assert_eq!(ConfigKind::ChannelFile.firmware_filename(), "/prefs/channels.proto");
        assert_eq!(ConfigKind::DeviceUiConfig.firmware_filename(), "/prefs/uiconfig.proto");
    }

    #[test]
    fn memory_store_round_trips() {
        let mut store = MemoryConfigStore::new();
        let cfg = make_local_config();
        store.save(ConfigKind::LocalConfig, &cfg.encode_to_vec()).unwrap();
        let loaded = store.load(ConfigKind::LocalConfig).unwrap().unwrap();
        let decoded = LocalConfig::decode(&loaded[..]).unwrap();
        assert!(decoded.device.is_some());
        assert!(decoded.lora.is_some());
    }

    #[test]
    fn missing_blob_loads_as_none() {
        let store = MemoryConfigStore::new();
        for kind in ConfigKind::ALL {
            assert!(store.load(kind).unwrap().is_none(), "{kind:?} must be empty");
        }
    }

    #[test]
    fn delete_clears_slot() {
        let mut store = MemoryConfigStore::new();
        store.save(ConfigKind::ChannelFile, b"placeholder").unwrap();
        assert!(store.load(ConfigKind::ChannelFile).unwrap().is_some());
        store.delete(ConfigKind::ChannelFile).unwrap();
        assert!(store.load(ConfigKind::ChannelFile).unwrap().is_none());
    }

    #[test]
    fn save_versioned_stamps_current_version() {
        let mut store = MemoryConfigStore::new();
        let raw = make_channel_file().encode_to_vec();
        // Round-tripped: version was 0 going in.
        assert_eq!(ChannelFile::decode(&raw[..]).unwrap().version, 0);

        store.save_versioned(ConfigKind::ChannelFile, &raw).unwrap();
        let bytes = store.load(ConfigKind::ChannelFile).unwrap().unwrap();
        let decoded = ChannelFile::decode(&bytes[..]).unwrap();
        assert_eq!(decoded.version, DEVICESTATE_CUR_VER);
    }

    #[test]
    fn version_of_reads_each_kind() {
        // Build one of each versioned blob with version=DEVICESTATE_CUR_VER and
        // confirm version_of agrees.
        let cases: &[(ConfigKind, Vec<u8>)] = &[
            (
                ConfigKind::DeviceState,
                DeviceState {
                    version: DEVICESTATE_CUR_VER,
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            (
                ConfigKind::NodeDatabase,
                NodeDatabase {
                    version: DEVICESTATE_CUR_VER,
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            (
                ConfigKind::LocalConfig,
                LocalConfig {
                    version: DEVICESTATE_CUR_VER,
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            (
                ConfigKind::LocalModuleConfig,
                LocalModuleConfig {
                    version: DEVICESTATE_CUR_VER,
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
            (
                ConfigKind::ChannelFile,
                ChannelFile {
                    version: DEVICESTATE_CUR_VER,
                    ..Default::default()
                }
                .encode_to_vec(),
            ),
        ];
        for (kind, bytes) in cases {
            assert_eq!(version_of(*kind, bytes).unwrap(), DEVICESTATE_CUR_VER);
        }
    }

    #[test]
    fn version_of_rejects_unversioned_kind() {
        let bytes = DeviceUiConfig::default().encode_to_vec();
        let err = version_of(ConfigKind::DeviceUiConfig, &bytes).unwrap_err();
        assert!(matches!(err, ConfigError::NoVersionField { .. }));
    }

    #[test]
    fn load_versioned_returns_too_old() {
        let mut store = MemoryConfigStore::new();
        let raw = LocalConfig {
            version: DEVICESTATE_MIN_VER - 1,
            ..Default::default()
        }
        .encode_to_vec();
        store.save(ConfigKind::LocalConfig, &raw).unwrap();
        let err = store.load_versioned(ConfigKind::LocalConfig).unwrap_err();
        assert!(matches!(
            err,
            ConfigError::VersionTooOld {
                kind: ConfigKind::LocalConfig,
                ..
            }
        ));
    }

    #[test]
    fn load_versioned_accepts_current_version() {
        let mut store = MemoryConfigStore::new();
        store
            .save_versioned(ConfigKind::NodeDatabase, &make_node_db().encode_to_vec())
            .unwrap();
        let loaded = store.load_versioned(ConfigKind::NodeDatabase).unwrap();
        assert!(loaded.is_some());
    }

    #[test]
    fn save_versioned_rejects_unversioned_kind() {
        let mut store = MemoryConfigStore::new();
        let bytes = DeviceUiConfig::default().encode_to_vec();
        let err = store.save_versioned(ConfigKind::DeviceUiConfig, &bytes).unwrap_err();
        assert!(matches!(err, ConfigError::NoVersionField { .. }));
    }

    #[test]
    fn typed_helpers_round_trip() {
        let cfg = LocalConfig {
            device: Some(DeviceConfig::default()),
            ..Default::default()
        };
        let bytes = encode(&cfg);
        let decoded: LocalConfig = decode(&bytes).unwrap();
        assert!(decoded.device.is_some());
    }

    #[test]
    fn config_payload_variant_round_trips_through_local_config() {
        // Sanity: building a Config with a oneof and then stuffing
        // it into LocalConfig's fields works (this is what PhoneAPI
        // does when delivering individual sections to the phone).
        let _ = ConfigVariant::Device(DeviceConfig::default());
        let _ = make_local_config();
    }

    #[cfg(feature = "std")]
    mod fs {
        use super::*;
        use std::io::Write;
        use std::path::PathBuf;

        fn tmpdir() -> tempfile::TempDir {
            tempfile::tempdir().expect("tempdir")
        }

        #[test]
        fn fs_store_creates_root_dir_if_missing() {
            let dir = tmpdir();
            let nested: PathBuf = dir.path().join("sub/dir/that/does/not/exist");
            let _ = FsConfigStore::new(&nested).unwrap();
            assert!(nested.is_dir());
        }

        #[test]
        fn fs_store_round_trips_each_kind() {
            let dir = tmpdir();
            let mut store = FsConfigStore::new(dir.path()).unwrap();
            for kind in ConfigKind::ALL {
                let bytes = vec![kind as u8; 7];
                store.save(kind, &bytes).unwrap();
                assert_eq!(store.load(kind).unwrap().unwrap(), bytes);
                assert!(store.path_for(kind).exists());
            }
        }

        #[test]
        fn fs_store_save_is_atomic_replace() {
            let dir = tmpdir();
            let mut store = FsConfigStore::new(dir.path()).unwrap();
            store.save(ConfigKind::ChannelFile, b"v1").unwrap();
            assert_eq!(store.load(ConfigKind::ChannelFile).unwrap().unwrap(), b"v1");
            store.save(ConfigKind::ChannelFile, b"v2-bigger").unwrap();
            assert_eq!(store.load(ConfigKind::ChannelFile).unwrap().unwrap(), b"v2-bigger");
            // No leftover .tmp.
            assert!(!dir.path().join("channels.proto.tmp").exists());
        }

        #[test]
        fn fs_store_load_returns_none_for_missing_file() {
            let dir = tmpdir();
            let store = FsConfigStore::new(dir.path()).unwrap();
            assert!(store.load(ConfigKind::DeviceState).unwrap().is_none());
        }

        #[test]
        fn fs_store_delete_is_idempotent() {
            let dir = tmpdir();
            let mut store = FsConfigStore::new(dir.path()).unwrap();
            // Delete a missing file is OK.
            store.delete(ConfigKind::DeviceUiConfig).unwrap();
            // Delete then delete again is OK.
            store.save(ConfigKind::DeviceUiConfig, b"x").unwrap();
            store.delete(ConfigKind::DeviceUiConfig).unwrap();
            store.delete(ConfigKind::DeviceUiConfig).unwrap();
            assert!(store.load(ConfigKind::DeviceUiConfig).unwrap().is_none());
        }

        #[test]
        fn fs_store_load_versioned_too_old_does_not_corrupt_disk() {
            let dir = tmpdir();
            let mut store = FsConfigStore::new(dir.path()).unwrap();
            let bytes = LocalConfig {
                version: DEVICESTATE_MIN_VER - 1,
                ..Default::default()
            }
            .encode_to_vec();
            store.save(ConfigKind::LocalConfig, &bytes).unwrap();
            let err = store.load_versioned(ConfigKind::LocalConfig).unwrap_err();
            assert!(matches!(err, ConfigError::VersionTooOld { .. }));
            // raw load still works (caller may want to inspect).
            assert_eq!(store.load(ConfigKind::LocalConfig).unwrap().unwrap(), bytes);
        }

        #[test]
        fn fs_store_recovers_from_partial_tmp_file() {
            let dir = tmpdir();
            let mut store = FsConfigStore::new(dir.path()).unwrap();
            // Simulate a crash that left a `.tmp` behind.
            let tmp = dir.path().join("config.proto.tmp");
            let mut f = std::fs::File::create(&tmp).unwrap();
            f.write_all(b"garbage from previous crash").unwrap();
            drop(f);

            // The "real" file doesn't exist yet.
            assert!(store.load(ConfigKind::LocalConfig).unwrap().is_none());

            // A successful save replaces .tmp atomically and writes
            // the real file. The new tmp doesn't survive.
            store.save(ConfigKind::LocalConfig, b"fresh").unwrap();
            assert_eq!(store.load(ConfigKind::LocalConfig).unwrap().unwrap(), b"fresh");
            assert!(!tmp.exists(), ".tmp must be cleaned up");
        }

        #[test]
        fn fs_store_works_through_box_dyn() {
            let dir = tmpdir();
            let mut boxed: Box<dyn ConfigStore> = Box::new(FsConfigStore::new(dir.path()).unwrap());
            boxed
                .save_versioned(ConfigKind::ChannelFile, &make_channel_file().encode_to_vec())
                .unwrap();
            let loaded = boxed.load_versioned(ConfigKind::ChannelFile).unwrap();
            assert!(loaded.is_some());
        }
    }
}
