use super::{
    communicator_error::CommunicatorError, AuthResponse, ByteVector, Communicator, Group, GroupId,
    RequestData, TaskId,
};
use ed25519_dalek::{Signer, SigningKey, SECRET_KEY_LENGTH};
use tonic::async_trait;

type GroupPublicKey = ByteVector;

const SECRET_KEY_BYTES: [u8; SECRET_KEY_LENGTH] = [
    157, 097, 177, 157, 239, 253, 090, 096, 186, 132, 074, 244, 146, 236, 044, 196, 068, 073, 197,
    105, 123, 050, 105, 025, 112, 059, 172, 003, 028, 174, 127, 096,
];

pub(crate) struct MockedEddsaMeesign {
    group_name: String,
    group_public_key: GroupPublicKey,
    private_key: SigningKey,
    signature: Option<AuthResponse>,
}

impl MockedEddsaMeesign {
    pub(crate) fn new(group_name: String) -> Self {
        let private_key = SigningKey::from_bytes(&SECRET_KEY_BYTES);
        let verifying_key = private_key.verifying_key();
        let group_public_key = verifying_key.to_bytes().into();
        Self {
            group_name,
            private_key,
            group_public_key,
            signature: None,
        }
    }
}

#[async_trait]
impl Communicator for MockedEddsaMeesign {
    async fn get_groups(&mut self) -> Result<Vec<Group>, CommunicatorError> {
        Ok(vec![Group::new(
            self.group_public_key.clone(),
            self.group_name.clone(),
        )])
    }

    async fn send_auth_request(
        &mut self,
        _group_id: GroupId,
        data: RequestData,
        _request_originator: Option<String>,
    ) -> Result<TaskId, CommunicatorError> {
        // TODO: we should sign prehashed data
        let signature = self.private_key.sign(&data);
        self.signature = Some(signature.to_vec());
        Ok(vec![])
    }

    async fn get_auth_response(
        &mut self,
        _task_id: TaskId,
    ) -> Result<AuthResponse, CommunicatorError> {
        self.signature
            .clone()
            .ok_or(CommunicatorError::ResponseNotPresent)
    }
}
