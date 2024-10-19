use tonic::async_trait;

use group::Group;

pub(crate) use communicator_error::CommunicatorError;
pub(crate) use group::Group as ThresholdGroup;

mod communicator_error;
mod group;
pub(crate) mod meesign;
#[cfg(all(feature = "mocked_ecdsa_communicator", debug_assertions))]
pub(crate) mod mocked_ecdsa_communicator;
pub(crate) mod task_name_provider;

type ByteVector = Vec<u8>;
pub(crate) type AuthResponse = ByteVector;
pub(crate) type GroupId = ByteVector;
pub(crate) type TaskId = ByteVector;
pub(crate) type RequestData = ByteVector;

/// Communicates with a remote communicator, e.g., MeeSign server
// TODO: remove macro once rust 1.74 is released
#[async_trait]
pub(crate) trait Communicator: Send + Sync {
    /// Returns a list of groups available for authentication
    async fn get_groups(&mut self) -> Result<Vec<Group>, CommunicatorError>;

    /// Sends an authentication request to the remote communicator
    ///
    /// # Arguments
    ///
    /// * `group_id` - the id of the group that will perform the authentication
    /// * `data` - the data to be sent to the remote communicator, usually a challenge
    /// * `request_originator` - the originator of the request,
    ///     usually the website domain name
    async fn send_auth_request(
        &mut self,
        group_id: GroupId,
        data: RequestData,
        request_originator: Option<String>,
    ) -> Result<TaskId, CommunicatorError>;

    /// Returns the authentication response from the remote communicator
    /// for the given task
    ///
    /// # Arguments
    ///
    /// * `task_id` - the id of the task for which the response is requested
    async fn get_auth_response(
        &mut self,
        task_id: TaskId,
    ) -> Result<AuthResponse, CommunicatorError>;
}
