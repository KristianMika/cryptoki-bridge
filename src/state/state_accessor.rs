use crate::{
    communicator::{
        group::Group, meesign::Meesign, AuthResponse, Communicator, GroupId, RequestData, TaskId,
    },
    configuration::{
        ConfigurationProvider, ConfigurationProviderError, ControllerConfiguration,
        EnvConfiguration,
    },
    cryptoki::bindings::{
        CK_OBJECT_HANDLE, CK_SESSION_HANDLE, CK_SLOT_ID, CK_SLOT_INFO, CK_TOKEN_INFO,
    },
    cryptoki_error::CryptokiError,
    persistence::SqliteCryptokiRepo,
    COMMUNICATOR, CONFIGURATION, RUNTIME, SESSIONS, SLOTS,
};
use aes::Aes128;
use home::home_dir;
use openssl::hash::Hasher;
use std::{fs, path::PathBuf, sync::Arc};
use tokio::runtime::Runtime;
use tonic::transport::Certificate;

use super::session::sessions::Sessions;
use super::slots::{Slots, TokenStore};

use super::{
    object::{cryptoki_object::CryptokiObject, object_search::ObjectSearch},
    session::single_session::Signer,
};

pub(crate) struct StateAccessor {}

impl StateAccessor {
    pub(crate) fn new() -> Self {
        Self {}
    }

    pub(crate) fn get_encryptor(
        &self,
        session_handle: &CK_SESSION_HANDLE,
    ) -> Result<Aes128, CryptokiError> {
        let sessions = SESSIONS.read()?;
        let session = sessions
            .as_ref()
            .ok_or(CryptokiError::CryptokiNotInitialized)?
            .get_session(session_handle)
            .ok_or(CryptokiError::SessionHandleInvalid)?;
        session
            .get_encryptor()
            .ok_or(CryptokiError::CryptokiNotInitialized)
    }

    pub(crate) fn set_encryptor(
        &self,
        session_handle: &CK_SESSION_HANDLE,
        encryptor: Aes128,
    ) -> Result<(), CryptokiError> {
        let mut sessions = SESSIONS.write()?;
        let mut session = sessions
            .as_mut()
            .ok_or(CryptokiError::CryptokiNotInitialized)?
            .get_session_mut(session_handle);
        let session = session
            .as_mut()
            .ok_or(CryptokiError::SessionHandleInvalid)?;
        session.set_encryptor(encryptor);
        Ok(())
    }

    pub(crate) fn get_object(
        &self,
        session_handle: &CK_SESSION_HANDLE,
        object_handle: &CK_OBJECT_HANDLE,
    ) -> Result<Arc<dyn CryptokiObject>, CryptokiError> {
        let sessions = SESSIONS.read()?;
        let session = sessions
            .as_ref()
            .ok_or(CryptokiError::CryptokiNotInitialized)?
            .get_session(session_handle)
            .ok_or(CryptokiError::SessionHandleInvalid)?;

        session
            .get_object(*object_handle)?
            .ok_or(CryptokiError::ObjectHandleInvalid)
    }

    pub(crate) fn finalize(&self) -> Result<(), CryptokiError> {
        let mut sessions = SESSIONS.write()?;
        sessions
            .as_mut()
            .ok_or(CryptokiError::CryptokiNotInitialized)?
            .close_sessions();
        Ok(())
    }
    pub(crate) fn get_token_info(
        &self,
        slot_id: &CK_SLOT_ID,
    ) -> Result<CK_TOKEN_INFO, CryptokiError> {
        let slots = SLOTS.read()?;
        let toke_info = slots
            .as_ref()
            .ok_or(CryptokiError::CryptokiNotInitialized)?
            .get_token_info(slot_id)
            .ok_or(CryptokiError::SlotIdInvalid)?;
        Ok(toke_info)
    }

    pub(crate) fn get_slot_info(
        &self,
        slot_id: &CK_SLOT_ID,
    ) -> Result<CK_SLOT_INFO, CryptokiError> {
        let slots = SLOTS.read()?;
        let slot_info = slots
            .as_ref()
            .ok_or(CryptokiError::CryptokiNotInitialized)?
            .get_slot_info(slot_id)
            .ok_or(CryptokiError::SlotIdInvalid)?;
        Ok(slot_info)
    }

    pub(crate) fn initialize_state(&self) -> Result<(), CryptokiError> {
        ensure_file_structure()?;

        let env_configuration = EnvConfiguration::new().map_err(|err| {
            eprintln!("Env configuration is not done properly. Please, consult the project documentation.");
            err
        })?;

        let configuration: Arc<dyn ConfigurationProvider> = match env_configuration {
            Some(env_configuration) => Arc::new(env_configuration),
            None => Arc::new(ControllerConfiguration::new()),
        };

        let runtime = Runtime::new().unwrap();

        let cryptoki_repo = Arc::new(SqliteCryptokiRepo::new(get_cryptoki_path())?);
        cryptoki_repo
            .create_tables()
            .expect("Couldn't crate tables");
        let communicator = self.get_communicator(&configuration, &runtime)?;
        let _ = SESSIONS.write()?.insert(Sessions::new(cryptoki_repo));
        let _ = SLOTS.write()?.insert(Slots::new());
        let _ = CONFIGURATION.write()?.insert(configuration);
        let _ = RUNTIME.write()?.insert(runtime);
        let _ = COMMUNICATOR.lock()?.insert(communicator);

        Ok(())
    }

    pub(crate) fn set_hasher(
        &self,
        session: &CK_SESSION_HANDLE,
        hashser: Hasher,
    ) -> Result<(), CryptokiError> {
        let mut sessions = SESSIONS.write()?;
        let session = sessions
            .as_mut()
            .ok_or(CryptokiError::CryptokiNotInitialized)?
            .get_session_mut(session)
            .ok_or(CryptokiError::SessionHandleInvalid)?;
        session.set_hasher(hashser);
        Ok(())
    }

    pub(crate) fn get_hasher(
        &self,
        session_handle: &CK_OBJECT_HANDLE,
    ) -> Result<Hasher, CryptokiError> {
        let sessions = SESSIONS.read()?;
        let session = sessions
            .as_ref()
            .ok_or(CryptokiError::CryptokiNotInitialized)?
            .get_session(session_handle)
            .ok_or(CryptokiError::SessionHandleInvalid)?;
        session.get_hasher().ok_or(CryptokiError::FunctionFailed)
    }

    pub(crate) fn get_groups_blocking(&self) -> Result<Vec<Group>, CryptokiError> {
        let runtime = RUNTIME.read()?;
        let runtime = runtime
            .as_ref()
            .ok_or(CryptokiError::CryptokiNotInitialized)?;
        let mut communicator = COMMUNICATOR.lock()?;
        let communicator = communicator
            .as_mut()
            .ok_or(CryptokiError::CryptokiNotInitialized)?;
        let groups = runtime.block_on(async move { communicator.get_groups().await })?;
        self.filter_groups_based_on_configuration(groups)
    }

    fn filter_groups_based_on_configuration(
        &self,
        groups: Vec<Group>,
    ) -> Result<Vec<Group>, CryptokiError> {
        let configuration = CONFIGURATION.read()?;
        let configuration = match configuration
            .as_ref()
            .ok_or(CryptokiError::CryptokiNotInitialized)?
            .get_interface_configuration()
        {
            Ok(conf) => conf,
            Err(ConfigurationProviderError::ReqwestError(_)) => {
                // TODO:
                // a temporary hot fix before we properly refactor the solution
                // and allow for mocked communicator without the need to mock the configuration
                return Ok(groups);
            }
            Err(err) => return Err(err.into()),
        };

        if let Some(configured_group_id) = configuration.get_group_id() {
            let selected_group = groups
                .iter()
                .find(|group| group.get_group_id() == configured_group_id)
                .ok_or_else(|| {
                    eprintln!("The specified group is not present!");
                    CryptokiError::FunctionFailed
                })?;
            return Ok(vec![selected_group.clone()]);
        }

        Ok(groups)
    }

    pub(crate) fn send_signing_request_wait_for_response(
        &self,
        group_id: GroupId,
        data: RequestData,
        request_originator: Option<String>,
    ) -> Result<TaskId, CryptokiError> {
        let runtime = RUNTIME.read()?;
        let runtime = runtime
            .as_ref()
            .ok_or(CryptokiError::CryptokiNotInitialized)?;
        let mut communicator = COMMUNICATOR.lock()?;
        let communicator = communicator
            .as_mut()
            .ok_or(CryptokiError::CryptokiNotInitialized)?;
        let response = runtime.block_on(async move {
            println!("Waiting for authentication response...");
            let task_id = communicator
                .send_auth_request(group_id, data, request_originator)
                .await?;
            communicator.get_auth_response(task_id).await
        })?;

        response.ok_or(CryptokiError::FunctionFailed)
    }

    pub(crate) fn store_signing_response(
        &self,
        session_handle: &CK_SESSION_HANDLE,
        response: AuthResponse,
    ) -> Result<(), CryptokiError> {
        let mut sessions = SESSIONS.write()?;
        let session = sessions
            .as_mut()
            .ok_or(CryptokiError::CryptokiNotInitialized)?
            .get_session_mut(session_handle)
            .ok_or(CryptokiError::SessionHandleInvalid)?;

        session.store_signing_response(response);
        Ok(())
    }

    pub(crate) fn insert_token(&self, token: TokenStore) -> Result<CK_SLOT_ID, CryptokiError> {
        let mut slots = SLOTS.write()?;
        let slots = slots
            .as_mut()
            .ok_or(CryptokiError::CryptokiNotInitialized)?;
        Ok(slots.insert_token(token))
    }

    pub(crate) fn create_session(
        &self,
        slot_id: &CK_SLOT_ID,
    ) -> Result<CK_SESSION_HANDLE, CryptokiError> {
        let mut sessions = SESSIONS.write()?;
        let sessions = sessions
            .as_mut()
            .ok_or(CryptokiError::CryptokiNotInitialized)?;
        let slots = SLOTS.read()?;
        let token = slots
            .as_ref()
            .ok_or(CryptokiError::CryptokiNotInitialized)?
            .get_token(slot_id)
            .ok_or(CryptokiError::SlotIdInvalid)?;
        Ok(sessions.create_session(token))
    }

    pub(crate) fn close_session(
        &self,
        session_handle: &CK_SESSION_HANDLE,
    ) -> Result<(), CryptokiError> {
        let mut sessions = SESSIONS.write()?;
        let sessions = sessions
            .as_mut()
            .ok_or(CryptokiError::CryptokiNotInitialized)?;
        sessions.close_session(session_handle);
        Ok(())
    }

    pub(crate) fn create_object(
        &self,
        session_handle: &CK_SESSION_HANDLE,
        object: Arc<dyn CryptokiObject>,
    ) -> Result<CK_OBJECT_HANDLE, CryptokiError> {
        let mut sessions = SESSIONS.write()?;
        let session = sessions
            .as_mut()
            .ok_or(CryptokiError::CryptokiNotInitialized)?
            .get_session_mut(session_handle)
            .ok_or(CryptokiError::SessionHandleInvalid)?;
        Ok(session.create_object(object)?)
    }

    pub(crate) fn create_ephemeral_object(
        &self,
        session_handle: &CK_SESSION_HANDLE,
        object: Arc<dyn CryptokiObject>,
    ) -> Result<CK_OBJECT_HANDLE, CryptokiError> {
        let mut sessions = SESSIONS.write()?;
        let session = sessions
            .as_mut()
            .ok_or(CryptokiError::CryptokiNotInitialized)?
            .get_session_mut(session_handle)
            .ok_or(CryptokiError::SessionHandleInvalid)?;
        Ok(session.create_ephemeral_object(object))
    }

    pub(crate) fn destroy_object(
        &self,
        session_handle: &CK_SESSION_HANDLE,
        object_handle: &CK_OBJECT_HANDLE,
    ) -> Result<Arc<dyn CryptokiObject>, CryptokiError> {
        let mut sessions = SESSIONS.write()?;
        let session = sessions
            .as_mut()
            .ok_or(CryptokiError::CryptokiNotInitialized)?
            .get_session_mut(session_handle)
            .ok_or(CryptokiError::SessionHandleInvalid)?;
        session
            .destroy_object(object_handle)?
            .ok_or(CryptokiError::ObjectHandleInvalid)
    }

    pub(crate) fn init_object_search(
        &self,
        session_handle: &CK_SESSION_HANDLE,
        template: ObjectSearch,
    ) -> Result<(), CryptokiError> {
        let mut sessions = SESSIONS.write()?;
        let session = sessions
            .as_mut()
            .ok_or(CryptokiError::CryptokiNotInitialized)?
            .get_session_mut(session_handle)
            .ok_or(CryptokiError::SessionHandleInvalid)?;
        session.init_object_search(template);
        Ok(())
    }
    pub(crate) fn reset_object_search(
        &self,
        session_handle: &CK_SESSION_HANDLE,
    ) -> Result<(), CryptokiError> {
        let mut sessions = SESSIONS.write()?;
        let session = sessions
            .as_mut()
            .ok_or(CryptokiError::CryptokiNotInitialized)?
            .get_session_mut(session_handle)
            .ok_or(CryptokiError::SessionHandleInvalid)?;
        session.reset_object_search();
        Ok(())
    }

    pub(crate) fn get_keypair(
        &self,
        session_handle: &CK_SESSION_HANDLE,
    ) -> Result<(CK_OBJECT_HANDLE, CK_OBJECT_HANDLE), CryptokiError> {
        let mut sessions = SESSIONS.write()?;
        let session = sessions
            .as_mut()
            .ok_or(CryptokiError::CryptokiNotInitialized)?
            .get_session_mut(session_handle)
            .ok_or(CryptokiError::SessionHandleInvalid)?;
        Ok(session.get_keypair())
    }
    pub(crate) fn get_filtered_handles(
        &self,
        session_handle: &CK_SESSION_HANDLE,
        count: usize,
    ) -> Result<Vec<CK_OBJECT_HANDLE>, CryptokiError> {
        let mut sessions = SESSIONS.write()?;
        let session = sessions
            .as_mut()
            .ok_or(CryptokiError::CryptokiNotInitialized)?
            .get_session_mut(session_handle)
            .ok_or(CryptokiError::SessionHandleInvalid)?;
        session.get_filtered_handles(count)
    }

    pub(crate) fn set_signer(
        &self,
        session_handle: &CK_SESSION_HANDLE,
        signer: Signer,
    ) -> Result<(), CryptokiError> {
        let mut sessions = SESSIONS.write()?;
        let session = sessions
            .as_mut()
            .ok_or(CryptokiError::CryptokiNotInitialized)?
            .get_session_mut(session_handle)
            .ok_or(CryptokiError::SessionHandleInvalid)?;
        session.set_signer(signer);
        Ok(())
    }

    pub(crate) fn get_signer(
        &self,
        session_handle: &CK_SESSION_HANDLE,
    ) -> Result<Signer, CryptokiError> {
        let sessions = SESSIONS.read()?;
        let session = sessions
            .as_ref()
            .ok_or(CryptokiError::CryptokiNotInitialized)?
            .get_session(session_handle)
            .ok_or(CryptokiError::SessionHandleInvalid)?;
        let signer = session
            .get_signer()
            .ok_or(CryptokiError::FunctionNotSupported)?;
        Ok(signer)
    }

    #[cfg(not(feature = "mocked_ecdsa_communicator"))]
    fn get_communicator(
        &self,
        configuration: &Arc<dyn ConfigurationProvider>,
        runtime: &Runtime,
    ) -> Result<Box<dyn Communicator>, CryptokiError> {
        let configuration = configuration.get_interface_configuration().map_err(|err|{
            eprintln!("Couldn't get interface configuration. Either launch bridge controller, or provide appropriate ENV varriables.");
            eprintln!("In case bridge controller is running, make sure the interface is configured.");
            err
        })?;
        let hostname = configuration.get_communicator_hostname().into();
        let certificate_path = configuration.get_communicator_certificate_path();
        let certificate = std::fs::read(certificate_path)?;
        let cert = Certificate::from_pem(certificate);

        let meesign = runtime.block_on(async move { Meesign::new(hostname, 1337, cert).await })?;
        Ok(Box::new(meesign))
    }

    #[cfg(feature = "mocked_ecdsa_communicator")]
    fn get_communicator(
        &self,
        _configuration: &Arc<dyn ConfigurationProvider>,
        _runtime: &Runtime,
    ) -> Result<Box<dyn Communicator>, CryptokiError> {
        use crate::communicator::mocked_ecdsa_communicator::MockedEcdsaMeesign;
        let meesign = MockedEcdsaMeesign::new("testgrp".into());
        Ok(Box::new(meesign))
    }
}

fn ensure_file_structure() -> Result<(), CryptokiError> {
    let cryptoki_directory_path = get_cryptoki_path();
    fs::create_dir_all(cryptoki_directory_path).unwrap();

    Ok(())
}

fn get_cryptoki_path() -> PathBuf {
    let Some(home_directory) = home_dir() else {
        todo!();
    };

    static CRYPTOKI_DIRECTORY_NAME: &str = ".cryptoki-bridge";
    home_directory.join(CRYPTOKI_DIRECTORY_NAME)
}
