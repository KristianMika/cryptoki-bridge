mod proto {
    tonic::include_proto!("meesign");
}

use proto::Task;
use tokio::time;
use tonic::{
    async_trait,
    transport::{Certificate, Channel, ClientTlsConfig, Uri},
};

use std::{str::FromStr, time::Duration};

use crate::communicator::meesign::proto::{mee_sign_client::MeeSignClient, GroupsRequest, KeyType};
use crate::communicator::AuthResponse;

use self::proto::{task::TaskState, SignRequest, TaskRequest};
use super::{
    communicator_error::CommunicatorError, group::Group, task_name_provider::TaskNameProvider,
    Communicator, GroupId, RequestData, TaskId,
};

const MAX_WAITING_TIME_SEC: u64 = 120;
const ATTEMPT_SLEEP_SEC: u64 = 3;
const MAX_ATTEMPT_COUNT: usize = (MAX_WAITING_TIME_SEC / ATTEMPT_SLEEP_SEC) as usize;

/// Communicates with the MeeSign server
pub(crate) struct Meesign {
    client: MeeSignClient<Channel>,
}

impl Meesign {
    pub async fn new(
        hostname: String,
        port: u32,
        certificate: Certificate,
    ) -> Result<Self, CommunicatorError> {
        let server_uri = Uri::from_str(&format!("https://{}:{}", &hostname, port))?;
        let client_tls_config = ClientTlsConfig::new()
            .domain_name(hostname)
            .ca_certificate(certificate);
        let channel = Channel::builder(server_uri)
            .tls_config(client_tls_config)?
            .connect()
            .await?;
        let client = MeeSignClient::new(channel);
        Ok(Self { client })
    }
}

#[async_trait]
impl Communicator for Meesign {
    async fn get_groups(&mut self) -> Result<Vec<Group>, CommunicatorError> {
        let request = tonic::Request::new(GroupsRequest { device_id: None });

        let response = self.client.get_groups(request).await?;
        let proto_groups = response.into_inner().groups;
        let groups = proto_groups
            .into_iter()
            .filter(|group| group.key_type == KeyType::SignChallenge as i32)
            .map(|group| Group::new(group.identifier, group.name))
            .collect();
        Ok(groups)
    }

    async fn send_auth_request(
        &mut self,
        group_id: GroupId,
        data: RequestData,
        request_originator: Option<String>,
    ) -> Result<TaskId, CommunicatorError> {
        let task_name_provider = TaskNameProvider::new();
        let task_name = task_name_provider.get_task_name(request_originator);
        let sign_request = SignRequest {
            name: task_name,
            group_id,
            data,
        };
        let tonic_sign_request = tonic::Request::new(sign_request);
        let response = self.client.sign(tonic_sign_request).await?;

        Ok(response.into_inner().id)
    }

    async fn get_auth_response(
        &mut self,
        task_id: TaskId,
    ) -> Result<AuthResponse, CommunicatorError> {
        let task_request = TaskRequest {
            task_id,
            device_id: None,
        };
        for _attempt in 0..MAX_ATTEMPT_COUNT {
            let tonic_task_request = tonic::Request::new(task_request.clone());
            let response = self.client.get_task(tonic_task_request).await?;
            let task = response.into_inner();
            let task_state = task
                .state
                .try_into()
                .map_err(CommunicatorError::TonicDecodeError)?;
            match task_state {
                TaskState::Finished => return extract_auth_response(task),
                TaskState::Failed => return Err(CommunicatorError::TaskFailed),
                _ => {}
            };
            time::sleep(Duration::from_secs(ATTEMPT_SLEEP_SEC)).await;
        }

        Err(CommunicatorError::TaskTimedOut(MAX_WAITING_TIME_SEC))
    }
}

fn extract_auth_response(task: Task) -> Result<AuthResponse, CommunicatorError> {
    match task.data.into_iter().next() {
        Some(val) => Ok(val),
        None => Err(CommunicatorError::ResponseNotPresent),
    }
}
