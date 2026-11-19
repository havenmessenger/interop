//! What a Commit's AppDataUpdate proposals do to a MIMI room's app data components (draft-ietf-mls-extensions §4.7):
//! one function a room's hub and its clients both use, so they arrive at the same GroupContext.
//!
//! The extensions draft hands an application every update to one component in the Commit's order and lets the
//! component say what they mean together. For the participant list, protocol-07 §7.5 says every update indexes the
//! list as it stood before the Commit ([`crate::participant_list::apply_updates`]). For the room metadata, the
//! operational parameters, the roles list and the base room policy, an update has the same format as the component's
//! data (protocol-07 §7.6 `RoomMetaUpdate`; room-policy-04 `OperationalParametersUpdate`, `RoleUpdate`,
//! `BaseRoomUpdate`), so the last one is the value. Any other component is refused until this crate reads it: an update
//! to one is not always its new value (room-policy-04 `JoinLinksUpdate` is a list of removals and additions).

use crate::participant_list::{
    apply_updates, decode_participant_list_data, decode_participant_list_update,
    encode_participant_list_data, ParticipantListData, ParticipantListError,
};

/// The participant list's component id in a GroupContext's app data dictionary (protocol-07 §10.3).
pub const PARTICIPANT_LIST_COMPONENT: u16 = 0x0022;

/// One change a Commit makes to a component.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ComponentChange<'a> {
    /// An update, with its payload.
    Update(&'a [u8]),
    /// The component's removal.
    Remove,
}

/// Why a Commit's changes to a component are refused.
#[derive(Debug, thiserror::Error)]
pub enum AppDataError {
    /// A participant-list update does not decode.
    #[error("the participant list update is malformed: {0}")]
    Malformed(ParticipantListError),
    /// The participant-list updates do not apply to the list before the Commit.
    #[error("the participant list updates do not apply to the room's list: {0}")]
    DoesNotApply(ParticipantListError),
    /// The list before the Commit does not decode.
    #[error("the room's participant list does not decode: {0}")]
    StoredList(ParticipantListError),
    /// The Commit removes the participant list.
    #[error("the participant list is never removed")]
    ListRemoved,
    /// The Commit removes the component and changes it too, or carries no change for it.
    #[error("component {0:#06x}: a removal is a component's only change")]
    Shape(u16),
    /// A component this crate does not read.
    #[error("component {0:#06x} is not one this implementation reads")]
    Unknown(u16),
}

/// The components whose update is their new value.
const WHOLE_VALUE_COMPONENTS: [u16; 4] = [
    crate::room_metadata::ROOM_METADATA_COMPONENT_ID,
    crate::operational_parameters::OPERATIONAL_POLICY_COMPONENT_ID,
    crate::room_policy_wire::ROLES_LIST_COMPONENT_ID,
    crate::room_policy_wire::BASE_ROOM_POLICY_COMPONENT_ID,
];

/// The value `component` has after a Commit's `changes` to it, in the Commit's order, given its value before the
/// Commit: none when the Commit removes it.
pub fn resolve_component(
    component: u16,
    before: Option<&[u8]>,
    changes: &[ComponentChange<'_>],
) -> Result<Option<Vec<u8>>, AppDataError> {
    let removal = changes
        .iter()
        .any(|change| matches!(change, ComponentChange::Remove));
    if changes.is_empty() || (removal && changes.len() != 1) {
        return Err(AppDataError::Shape(component));
    }
    if component != PARTICIPANT_LIST_COMPONENT {
        if !WHOLE_VALUE_COMPONENTS.contains(&component) {
            return Err(AppDataError::Unknown(component));
        }
        return Ok(match changes.last() {
            Some(ComponentChange::Update(value)) => Some(value.to_vec()),
            _ => None,
        });
    }
    if removal {
        return Err(AppDataError::ListRemoved);
    }
    let current = match before {
        Some(bytes) => decode_participant_list_data(bytes).map_err(AppDataError::StoredList)?,
        None => ParticipantListData::default(),
    };
    let updates = changes
        .iter()
        .map(|change| match change {
            ComponentChange::Update(update) => {
                decode_participant_list_update(update).map_err(AppDataError::Malformed)
            }
            ComponentChange::Remove => Err(AppDataError::Shape(component)),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let next = apply_updates(&current, &updates).map_err(AppDataError::DoesNotApply)?;
    encode_participant_list_data(&next)
        .map(Some)
        .map_err(AppDataError::StoredList)
}

#[cfg(test)]
#[path = "app_data_tests.rs"]
mod tests;
