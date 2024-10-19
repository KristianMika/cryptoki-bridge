use super::interface_configuration::InterfaceConfiguration;
pub(crate) use configuration_provider_error::ConfigurationProviderError;
pub(crate) use controller_configuration::ControllerConfiguration;
pub(crate) use env_configuration::EnvConfiguration;

mod configuration_provider_error;
pub(super) mod controller_configuration;
mod env_configuration;

/// Provides the configuration for this interface
pub(crate) trait ConfigurationProvider: Send + Sync {
    /// Returns the configuration for this interface
    fn get_interface_configuration(
        &self,
    ) -> Result<InterfaceConfiguration, ConfigurationProviderError>;
}
