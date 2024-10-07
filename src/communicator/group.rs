use derive_new::new;

use super::GroupId;

/// Represents a single communicator group
///
/// # Arguments
///
/// * `group_id` - Group ID, which is also its public key
/// * `name` - Name of the group
#[derive(Clone, new)]
pub(crate) struct Group {
    group_id: GroupId,
    name: String,
}

impl Group {
    pub(crate) fn get_group_id(&self) -> &GroupId {
        &self.group_id
    }

    pub(crate) fn get_name(&self) -> &str {
        &self.name
    }
}
