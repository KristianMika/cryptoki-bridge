mod interface_configuration_response;

use crate::{
    communicator::task_name_provider,
    configuration::{interface_configuration::InterfaceConfiguration, EffectiveInterfaceType},
};

pub(crate) use self::interface_configuration_response::InterfaceConfigurationResponse;

use super::{configuration_provider_error::ConfigurationProviderError, ConfigurationProvider};

static CONTROLLER_PORT: &str = "11115";

/// Provides the configuration from the controller component
/// that was configured by the user
pub(crate) struct ControllerConfiguration {
    /// Current effective interface type, e.g., Cryptoki
    effective_interface_type: EffectiveInterfaceType,

    /// Name of the tool that is using the library, e.g., ssh
    tool_name: Option<String>,
}

impl ControllerConfiguration {
    pub(crate) fn new() -> Self {
        let effective_interface_type = EffectiveInterfaceType::from_environment();
        let tool_name = task_name_provider::get_binary_name().unwrap_or(None);
        Self {
            effective_interface_type,
            tool_name,
        }
    }
}

impl ConfigurationProvider for ControllerConfiguration {
    fn get_interface_configuration(
        &self,
    ) -> Result<InterfaceConfiguration, ConfigurationProviderError> {
        let effective_interface_type = self.effective_interface_type.to_interface_string();
        let tool_parameter = self
            .tool_name
            .as_ref()
            .map(map_auxiliary_tools)
            .map(|tool_name| format!("tool={}", tool_name))
            .unwrap_or_default();
        let configuration: InterfaceConfigurationResponse = reqwest::blocking::get(format!(
            "http://www.localhost:{CONTROLLER_PORT}/{effective_interface_type}/configuration?{tool_parameter}"
        ))?
        .json()?;
        Ok(configuration.into())
    }
}

/// Maps names of auxiliary tools to the actual tool names, e.g.,
/// `ssh-keygen` will be mapped to `ssh`, otherwise the user would
/// have to configure multiple configurations for auxiliary tools.
/// TODO: this needs some brainstorming and potentially feedback from the users
///
/// # Arguments
///
/// * `tool_name` - The name of the tool to map.
fn map_auxiliary_tools(tool_name: &String) -> String {
    match tool_name.as_str() {
        "ssh-keygen" => "ssh".to_string(),
        _ => tool_name.into(),
    }
}
