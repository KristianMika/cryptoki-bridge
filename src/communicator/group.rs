use derive_new::new;

use super::{GroupId, ProtocolType};

/// Represents a single communicator group
///
/// # Arguments
///
/// * `group_id` - Group ID, which is also its public key
/// * `name` - Name of the group
/// * `group_type` - Type of the remote group - determines group's capabilities
#[derive(Clone, new)]
pub(crate) struct Group {
    group_id: GroupId,
    name: String,
    group_type: ProtocolType,
}

impl Group {
    pub(crate) fn get_group_id(&self) -> &GroupId {
        &self.group_id
    }

    pub(crate) fn get_name(&self) -> &str {
        &self.name
    }

    pub(crate) fn get_group_type(&self) -> &ProtocolType {
        &self.group_type
    }
}
