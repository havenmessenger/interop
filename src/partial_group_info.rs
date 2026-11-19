//! `PartialGroupInfo` (draft-ietf-mls-ratchet-tree-options §4): what a committer sends instead of a full `GroupInfo`
//! when the receiver tracks the group and can rebuild the rest.
//!
//! ```text
//! struct {
//!   RatchetTreePresence ratchet_tree_presence;
//!   /* GroupInfo extensions excluding ratchet_tree */
//!   Extension group_info_extensions<V>;
//!   opaque signature<V>;
//! } PartialGroupInfo;
//! ```
//!
//! The signature is the committer's over the full `GroupInfoTBS` (RFC 9420 §12.4.3): the GroupContext after the Commit,
//! the extensions, the Commit's confirmation tag and the committer's leaf index. When the full GroupInfo carries a
//! `ratchet_tree` extension it is the last in the list (§4: "it MUST be the last element in the extension list"), so a
//! receiver that holds the tree after the Commit appends it to `group_info_extensions` and has the list that was signed.
//! A `PartialGroupInfo` that itself carries a `ratchet_tree` extension is rejected (§4).
//!
//! This module is the codec: it reads a `PartialGroupInfo` and writes the `GroupInfo` it stands for, from the fields
//! the receiver supplies. Checking that GroupInfo's signature is the receiver's job, as for any GroupInfo.

use tls_codec::{DeserializeBytes as _, Serialize as _, VLBytes};

use crate::protocol_wire::WireError;

/// RFC 9420's `ratchet_tree` extension type.
pub const RATCHET_TREE_EXTENSION: u16 = 0x0002;

/// `RatchetTreePresence`: whether the GroupInfo after the Commit, and the one before it, carry a `ratchet_tree`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatchetTreePresence {
    /// In neither epoch.
    NoRatchetTree,
    /// In both.
    Present,
    /// In the previous epoch only.
    Removed,
    /// In the current epoch only.
    Added,
}

impl RatchetTreePresence {
    const fn from_u8(value: u8) -> Option<Self> {
        match value {
            0 => Some(Self::NoRatchetTree),
            1 => Some(Self::Present),
            2 => Some(Self::Removed),
            3 => Some(Self::Added),
            _ => None,
        }
    }

    const fn to_u8(self) -> u8 {
        match self {
            Self::NoRatchetTree => 0,
            Self::Present => 1,
            Self::Removed => 2,
            Self::Added => 3,
        }
    }

    /// Whether the GroupInfo after the Commit carries the `ratchet_tree` extension.
    pub const fn in_current_epoch(self) -> bool {
        matches!(self, Self::Present | Self::Added)
    }
}

/// Where the `ratchet_tree` extension stands in the GroupInfo's extension list.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeAt {
    /// Last, as ratchet-tree-options §4 requires of a GroupInfo sent as a `PartialGroupInfo`.
    Last,
    /// First, where openmls writes it (before `external_pub`, which every GroupInfo it exports carries): a
    /// `PartialGroupInfo` split from such a GroupInfo was signed with the tree there.
    First,
}

/// A decoded `PartialGroupInfo`. `extensions` is the content of `group_info_extensions<V>`: each `Extension` as it was
/// sent, in order, none of them `ratchet_tree`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartialGroupInfo {
    pub ratchet_tree_presence: RatchetTreePresence,
    pub extensions: Vec<u8>,
    pub signature: Vec<u8>,
}

fn wire(what: &'static str, detail: impl std::fmt::Display) -> WireError {
    WireError::Codec {
        what,
        detail: detail.to_string(),
    }
}

/// The extension types in `list`, the content of an `Extension extensions<V>` (each a `uint16` type then `opaque
/// extension_data<V>`), or why it does not read as one.
fn extension_types(mut list: &[u8]) -> Result<Vec<u16>, WireError> {
    let mut types = Vec::new();
    while !list.is_empty() {
        let (extension_type, rest) = u16::tls_deserialize_bytes(list)
            .map_err(|error| wire("PartialGroupInfo.group_info_extensions", error))?;
        let (_data, rest) = VLBytes::tls_deserialize_bytes(rest)
            .map_err(|error| wire("PartialGroupInfo.group_info_extensions", error))?;
        types.push(extension_type);
        list = rest;
    }
    Ok(types)
}

impl PartialGroupInfo {
    /// Read a `PartialGroupInfo` that is the whole of `bytes`. Refuses an unknown presence value, extensions that do
    /// not read as a list of `Extension`s, a `ratchet_tree` among them, and bytes after the signature.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let (&presence, rest) = bytes
            .split_first()
            .ok_or_else(|| wire("PartialGroupInfo", "empty"))?;
        let ratchet_tree_presence = RatchetTreePresence::from_u8(presence).ok_or_else(|| {
            wire(
                "PartialGroupInfo.ratchet_tree_presence",
                format!("invalid value {presence}"),
            )
        })?;
        let (extensions, rest) = VLBytes::tls_deserialize_bytes(rest)
            .map_err(|error| wire("PartialGroupInfo.group_info_extensions", error))?;
        let (signature, rest) = VLBytes::tls_deserialize_bytes(rest)
            .map_err(|error| wire("PartialGroupInfo.signature", error))?;
        if !rest.is_empty() {
            return Err(wire(
                "PartialGroupInfo",
                format!("{} bytes after the signature", rest.len()),
            ));
        }
        let extensions = extensions.as_slice().to_vec();
        if extension_types(&extensions)?.contains(&RATCHET_TREE_EXTENSION) {
            return Err(wire(
                "PartialGroupInfo.group_info_extensions",
                "carries a ratchet_tree extension",
            ));
        }
        Ok(Self {
            ratchet_tree_presence,
            extensions,
            signature: signature.as_slice().to_vec(),
        })
    }

    /// The `PartialGroupInfo` a committer sends for `group_info`, a GroupInfo it signed after its Commit:
    /// `group_info`'s extensions without its `ratchet_tree`, and its signature. `tree_before` says whether the
    /// GroupInfo of the epoch before carried a `ratchet_tree`, which the presence reports beside this one's.
    pub fn split(group_info: &[u8], tree_before: bool) -> Result<Self, WireError> {
        use openmls::messages::group_info::VerifiableGroupInfo;
        use tls_codec::Deserialize as _;
        let info = VerifiableGroupInfo::tls_deserialize_exact(group_info)
            .map_err(|error| wire("GroupInfo", error))?;
        let context = info
            .group_context()
            .tls_serialize_detached()
            .map_err(|error| wire("GroupInfo.group_context", error))?;
        let rest = group_info
            .get(context.len()..)
            .ok_or_else(|| wire("GroupInfo", "shorter than its GroupContext"))?;
        let (list, rest) = VLBytes::tls_deserialize_bytes(rest)
            .map_err(|error| wire("GroupInfo.extensions", error))?;
        let (_confirmation_tag, rest) = VLBytes::tls_deserialize_bytes(rest)
            .map_err(|error| wire("GroupInfo.confirmation_tag", error))?;
        let (_signer, rest) =
            u32::tls_deserialize_bytes(rest).map_err(|error| wire("GroupInfo.signer", error))?;
        let signature = VLBytes::tls_deserialize_exact_bytes(rest)
            .map_err(|error| wire("GroupInfo.signature", error))?;
        let mut extensions = Vec::new();
        let mut tree_now = false;
        let mut list = list.as_slice();
        while !list.is_empty() {
            let (extension_type, after) = u16::tls_deserialize_bytes(list)
                .map_err(|error| wire("GroupInfo.extensions", error))?;
            let (_data, after) = VLBytes::tls_deserialize_bytes(after)
                .map_err(|error| wire("GroupInfo.extensions", error))?;
            if extension_type == RATCHET_TREE_EXTENSION {
                tree_now = true;
            } else {
                extensions.extend_from_slice(&list[..list.len() - after.len()]);
            }
            list = after;
        }
        Ok(Self {
            ratchet_tree_presence: match (tree_before, tree_now) {
                (false, false) => RatchetTreePresence::NoRatchetTree,
                (true, true) => RatchetTreePresence::Present,
                (true, false) => RatchetTreePresence::Removed,
                (false, true) => RatchetTreePresence::Added,
            },
            extensions,
            signature: signature.as_slice().to_vec(),
        })
    }

    /// The `PartialGroupInfo`'s bytes.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let mut out = vec![self.ratchet_tree_presence.to_u8()];
        for (what, field) in [
            ("PartialGroupInfo.group_info_extensions", &self.extensions),
            ("PartialGroupInfo.signature", &self.signature),
        ] {
            VLBytes::new(field.clone())
                .tls_serialize(&mut out)
                .map_err(|error| wire(what, error))?;
        }
        Ok(out)
    }

    /// The `GroupInfo` this stands for: `group_context` (the encoded GroupContext after the Commit), the extensions with
    /// `ratchet_tree` (the encoded tree after the Commit, the extension's content) put at `tree_at` when the presence
    /// says the GroupInfo carries one, `confirmation_tag` (the Commit's, encoded), `signer` (the committer's leaf index
    /// after the Commit), then the signature. Refuses a tree the presence does not call for, and a missing one it does.
    pub fn group_info(
        &self,
        group_context: &[u8],
        ratchet_tree: Option<(&[u8], TreeAt)>,
        confirmation_tag: &[u8],
        signer: u32,
    ) -> Result<Vec<u8>, WireError> {
        let extensions = match (self.ratchet_tree_presence.in_current_epoch(), ratchet_tree) {
            (true, Some((tree, at))) => {
                let mut extension = Vec::new();
                RATCHET_TREE_EXTENSION
                    .tls_serialize(&mut extension)
                    .map_err(|error| wire("GroupInfo.extensions", error))?;
                VLBytes::new(tree.to_vec())
                    .tls_serialize(&mut extension)
                    .map_err(|error| wire("GroupInfo.extensions", error))?;
                match at {
                    TreeAt::Last => [self.extensions.as_slice(), &extension].concat(),
                    TreeAt::First => [extension.as_slice(), &self.extensions].concat(),
                }
            }
            (false, None) => self.extensions.clone(),
            (true, None) => {
                return Err(wire(
                    "GroupInfo.extensions",
                    "the presence calls for a ratchet_tree and none was given",
                ))
            }
            (false, Some(_)) => {
                return Err(wire(
                    "GroupInfo.extensions",
                    "a ratchet_tree was given and the presence calls for none",
                ))
            }
        };
        let mut out = group_context.to_vec();
        VLBytes::new(extensions)
            .tls_serialize(&mut out)
            .map_err(|error| wire("GroupInfo.extensions", error))?;
        out.extend_from_slice(confirmation_tag);
        out.extend_from_slice(&signer.to_be_bytes());
        VLBytes::new(self.signature.clone())
            .tls_serialize(&mut out)
            .map_err(|error| wire("GroupInfo.signature", error))?;
        Ok(out)
    }
}

#[cfg(test)]
#[path = "partial_group_info_tests.rs"]
mod tests;
