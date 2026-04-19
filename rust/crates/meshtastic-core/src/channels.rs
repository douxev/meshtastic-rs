//! The channel table, mirroring the firmware's `Channels` class.
//!
//! A device knows about up to [`MAX_NUM_CHANNELS`] channels at once. Each
//! slot holds:
//!
//! - A [`Channel`][meshtastic_proto::meshtastic::Channel] protobuf (the
//!   persistable configuration).
//! - The *expanded* PSK bytes ready for AES — [`meshtastic-crypto`] handles
//!   the 1-byte shorthand and zero-padding variants via
//!   [`expand_psk`][meshtastic_crypto::expand_psk]; we cache the result so
//!   packet crypto is allocation-free.
//! - The precomputed 8-bit hash (XOR of channel name bytes with expanded
//!   PSK bytes), used as the on-wire "channel" field tag so receivers can
//!   quickly skip packets they cannot decrypt.
//!
//! Secondary channels with an empty PSK fall back to the primary
//! channel's key, matching `Channels::getKey` in
//! `src/mesh/Channels.cpp:222`.
//!
//! # Capacity
//!
//! The firmware caps channels at 8 via the `ChannelFile.channels`
//! `max_count:8` nanopb option. We mirror that as a compile-time constant
//! here so the loader rejects oversized inputs up front rather than
//! silently truncating.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use meshtastic_crypto::{channel_hash, expand_psk};
use meshtastic_proto::meshtastic::{channel::Role, Channel, ChannelFile, ChannelSettings};

/// Maximum number of channels in the table, matching the firmware's
/// `MAX_NUM_CHANNELS` (derived from `ChannelFile.channels` `max_count:8`).
pub const MAX_NUM_CHANNELS: usize = 8;

/// Cached per-slot state derived from a [`Channel`] protobuf.
#[derive(Debug, Clone)]
pub struct ChannelSlot {
    /// The slot's persistable protobuf config. Always has `settings` populated
    /// (even for DISABLED slots, where the settings bytes are all-zero).
    pub channel: Channel,
    /// PSK after expansion via [`expand_psk`]. Empty if the slot is
    /// unencrypted (short PSK byte 0) or DISABLED. Length 16 (AES-128) or
    /// 32 (AES-256) otherwise.
    ///
    /// Note: this is the key **as stored**; for encrypt/decrypt the
    /// effective key may fall back to the primary channel when a secondary
    /// has an empty PSK — see [`Channels::effective_key`].
    pub expanded_psk: Vec<u8>,
    /// 8-bit hash tag used in the on-wire packet header to let receivers
    /// quickly filter packets they can't decrypt. `None` for DISABLED
    /// slots.
    pub hash: Option<u8>,
}

impl ChannelSlot {
    /// Build a slot from a raw [`Channel`], recomputing its expanded PSK and
    /// hash.
    pub fn from_channel(channel: Channel) -> Self {
        let (expanded_psk, hash) = derive(&channel);
        Self {
            channel,
            expanded_psk,
            hash,
        }
    }

    /// Convenience: the slot's short name as stored in the settings.
    #[must_use]
    pub fn name(&self) -> &str {
        match &self.channel.settings {
            Some(s) => s.name.as_str(),
            None => "",
        }
    }

    /// Convenience: the slot's role.
    #[must_use]
    pub fn role(&self) -> Role {
        Role::try_from(self.channel.role).unwrap_or(Role::Disabled)
    }
}

fn derive(channel: &Channel) -> (Vec<u8>, Option<u8>) {
    let role = Role::try_from(channel.role).unwrap_or(Role::Disabled);
    if matches!(role, Role::Disabled) {
        return (Vec::new(), None);
    }
    let Some(settings) = channel.settings.as_ref() else {
        return (Vec::new(), None);
    };
    let expanded = expand_psk(&settings.psk);
    let hash = channel_hash(&settings.name, &expanded);
    (expanded, Some(hash))
}

/// Errors from building a [`Channels`] table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChannelsError {
    /// Input contained more than [`MAX_NUM_CHANNELS`] channels.
    TooManyChannels(usize),
    /// No slot was marked as `PRIMARY`.
    NoPrimaryChannel,
    /// More than one slot was marked as `PRIMARY`.
    MultiplePrimaryChannels,
}

impl fmt::Display for ChannelsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooManyChannels(n) => write!(f, "too many channels: {n} > {MAX_NUM_CHANNELS}"),
            Self::NoPrimaryChannel => f.write_str("no PRIMARY channel in the table"),
            Self::MultiplePrimaryChannels => f.write_str("multiple PRIMARY channels in the table"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ChannelsError {}

/// The channel table.
///
/// Invariants:
///
/// - Exactly one [`Role::Primary`] slot.
/// - `slots.len() <= MAX_NUM_CHANNELS`.
/// - Each slot's `expanded_psk` and `hash` are in sync with its
///   `channel.settings`.
#[derive(Debug, Clone)]
pub struct Channels {
    slots: Vec<ChannelSlot>,
    primary_index: u8,
}

impl Channels {
    /// A fresh, just-out-of-the-box table with a single PRIMARY channel
    /// using the built-in short-PSK shorthand `[1]` (i.e.
    /// [`DEFAULT_PSK`][meshtastic_crypto::DEFAULT_PSK]) and an empty
    /// name (which the UI renders as the current modem preset's name,
    /// "LongFast" by default).
    #[must_use]
    pub fn with_default_primary() -> Self {
        let primary = Channel {
            index: 0,
            role: Role::Primary as i32,
            settings: Some(ChannelSettings {
                psk: alloc::vec![1],
                name: String::new(),
                ..Default::default()
            }),
        };
        Self {
            slots: alloc::vec![ChannelSlot::from_channel(primary)],
            primary_index: 0,
        }
    }

    /// Load from a persisted [`ChannelFile`]. Disabled trailing slots are
    /// truncated to match the firmware's behaviour (`channels_count` only
    /// reflects populated slots).
    ///
    /// # Errors
    ///
    /// - [`ChannelsError::TooManyChannels`] if the file has more than
    ///   [`MAX_NUM_CHANNELS`] entries.
    /// - [`ChannelsError::NoPrimaryChannel`] / [`ChannelsError::MultiplePrimaryChannels`]
    ///   if the PRIMARY invariant is violated. A valid file must have
    ///   exactly one.
    pub fn from_channel_file(file: &ChannelFile) -> Result<Self, ChannelsError> {
        if file.channels.len() > MAX_NUM_CHANNELS {
            return Err(ChannelsError::TooManyChannels(file.channels.len()));
        }

        let mut primary: Option<u8> = None;
        let mut slots = Vec::with_capacity(file.channels.len());
        for (i, ch) in file.channels.iter().enumerate() {
            if ch.role == Role::Primary as i32 {
                if primary.is_some() {
                    return Err(ChannelsError::MultiplePrimaryChannels);
                }
                primary = Some(i as u8);
            }
            slots.push(ChannelSlot::from_channel(ch.clone()));
        }
        let primary_index = primary.ok_or(ChannelsError::NoPrimaryChannel)?;
        Ok(Self { slots, primary_index })
    }

    /// Serialise back to a [`ChannelFile`] for persistence. The `version`
    /// field is not set by this crate — callers should populate it
    /// according to their own save-file compatibility rules (the firmware
    /// uses a build-time constant in `NodeDB.cpp`).
    #[must_use]
    pub fn to_channel_file(&self) -> ChannelFile {
        ChannelFile {
            channels: self.slots.iter().map(|s| s.channel.clone()).collect(),
            version: 0,
        }
    }

    /// Number of occupied slots (0..=[`MAX_NUM_CHANNELS`]).
    #[must_use]
    pub fn num_channels(&self) -> u8 {
        self.slots.len() as u8
    }

    /// Index of the PRIMARY slot. Always valid.
    #[must_use]
    pub fn primary_index(&self) -> u8 {
        self.primary_index
    }

    /// Borrow the slot at the given index.
    #[must_use]
    pub fn by_index(&self, i: u8) -> Option<&ChannelSlot> {
        self.slots.get(i as usize)
    }

    /// Mutably borrow the slot at the given index. Note that after mutating
    /// the underlying [`Channel`] you should call
    /// [`Self::refresh_slot`] so the cached PSK and hash stay consistent.
    #[must_use]
    pub fn by_index_mut(&mut self, i: u8) -> Option<&mut ChannelSlot> {
        self.slots.get_mut(i as usize)
    }

    /// Recompute the cached `expanded_psk` and `hash` for one slot after
    /// an external mutation.
    pub fn refresh_slot(&mut self, i: u8) {
        if let Some(slot) = self.slots.get_mut(i as usize) {
            let (psk, hash) = derive(&slot.channel);
            slot.expanded_psk = psk;
            slot.hash = hash;
        }
    }

    /// Iterate over `(index, slot)` pairs whose 8-bit hash matches `hash`.
    ///
    /// Used during packet decrypt to enumerate candidate channels when the
    /// sender's hash-tag lands on more than one of our slots (8-bit hashes
    /// have collisions).
    pub fn find_by_hash(&self, hash: u8) -> impl Iterator<Item = (u8, &ChannelSlot)> + '_ {
        self.slots
            .iter()
            .enumerate()
            .filter(move |(_, s)| s.hash == Some(hash))
            .map(|(i, s)| (i as u8, s))
    }

    /// Return the AES key that should be used to encrypt/decrypt on the
    /// given channel, or `None` if that channel is disabled / unencrypted.
    ///
    /// Mirrors the primary-fallback in `Channels::getKey`
    /// (`src/mesh/Channels.cpp:222`): a `SECONDARY` slot with an empty PSK
    /// inherits the primary channel's key.
    #[must_use]
    pub fn effective_key(&self, i: u8) -> Option<&[u8]> {
        let slot = self.slots.get(i as usize)?;
        if matches!(slot.role(), Role::Disabled) {
            return None;
        }
        if !slot.expanded_psk.is_empty() {
            return Some(&slot.expanded_psk);
        }
        // Empty PSK on a secondary channel → fall back to primary.
        if matches!(slot.role(), Role::Secondary) {
            let primary = self.slots.get(self.primary_index as usize)?;
            if !primary.expanded_psk.is_empty() {
                return Some(&primary.expanded_psk);
            }
        }
        None
    }

    /// True iff the slot uses the built-in default PSK shorthand. Does
    /// *not* check the channel name against any modem-preset default;
    /// callers that care about that (UI / rate-limiting on the public
    /// channel) should layer their own check on top.
    #[must_use]
    pub fn uses_default_psk(&self, i: u8) -> bool {
        let Some(slot) = self.slots.get(i as usize) else {
            return false;
        };
        let Some(settings) = slot.channel.settings.as_ref() else {
            return false;
        };
        match settings.psk.as_slice() {
            [1] => true,
            full if full == meshtastic_crypto::DEFAULT_PSK => true,
            _ => false,
        }
    }

    /// Number of slots with a non-disabled role. Convenience for metrics.
    #[must_use]
    pub fn num_enabled(&self) -> u8 {
        self.slots
            .iter()
            .filter(|s| !matches!(s.role(), Role::Disabled))
            .count() as u8
    }
}

impl Default for Channels {
    fn default() -> Self {
        Self::with_default_primary()
    }
}
