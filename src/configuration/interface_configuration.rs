use derive_new::new;
use serde::Deserialize;

use crate::communicator::GroupId;

use super::configuration_provider::controller_configuration::InterfaceConfigurationResponse;

/// A model holding interface configuration attributes
#[derive(Deserialize, Clone, new)]
pub(crate) struct InterfaceConfiguration {
    communicator_hostname: String,
    group_id: Option<GroupId>,
    communicator_certificate_path: String,
}

impl InterfaceConfiguration {
    pub fn get_communicator_hostname(&self) -> &str {
        &self.communicator_hostname
    }

    pub fn get_group_id(&self) -> Option<&GroupId> {
        self.group_id.as_ref()
    }

    pub fn get_communicator_certificate_path(&self) -> &str {
        &self.communicator_certificate_path
    }
}

impl From<InterfaceConfigurationResponse> for InterfaceConfiguration {
    fn from(response: InterfaceConfigurationResponse) -> Self {
        Self {
            communicator_hostname: response.get_communicator_hostname().to_string(),
            group_id: Some(response.get_group_id().clone()),
            communicator_certificate_path: response.get_communicator_certificate_path().to_string(),
        }
    }
}
