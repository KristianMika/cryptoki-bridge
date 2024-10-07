use derive_new::new;

use crate::configuration::EffectiveInterfaceType;

use super::communicator_error::CommunicatorError;

/// Provides names for tasks delegated to the communicator
#[derive(new)]
pub(crate) struct TaskNameProvider {}

impl TaskNameProvider {
    /// Returns a task name informing using which interface the authentication
    /// request was created with, which tool, and in some cases, for which domain.
    ///
    /// # Arguments
    ///
    /// * `originator` - Optional originator of the request, e.g., domain name
    pub(crate) fn get_task_name(&self, originator: Option<String>) -> String {
        let effective_interface_type = EffectiveInterfaceType::from_environment();
        let binary_name = get_binary_name().unwrap_or(None);

        let request_info = Some(format!("{effective_interface_type} authentication request"));
        let mut binary_info = binary_name.map(|binary_name| format!("using {}", binary_name));
        let originator_info = originator.map(|originator| format!("for {originator}"));

        if effective_interface_type == EffectiveInterfaceType::WebAuthn {
            // there is no need to say, that a WebAuthn task was created using softfido
            binary_info = None;
        };

        let task_parts = vec![request_info, binary_info, originator_info];
        let task_parts_joined = task_parts
            .into_iter()
            .flatten()
            .collect::<Vec<String>>()
            .join(" ");
        let task_name = format!("{task_parts_joined}.");
        task_name
    }
}

/// Don't rely on this function for security purposes. The filename can be easily spoofed.
pub(crate) fn get_binary_name() -> Result<Option<String>, CommunicatorError> {
    let filename = std::env::current_exe()?;
    let filename = filename
        .file_name()
        .map(|filename| filename.to_str().map(|value: &str| value.to_string()))
        .and_then(|value| value);
    Ok(filename)
}
