use std::{io, sync::PoisonError};

use thiserror::Error;

use crate::{
    communicator::communicator_error::CommunicatorError,
    configuration::ConfigurationProviderError,
    cryptoki::bindings::{
        CKR_CRYPTOKI_NOT_INITIALIZED, CKR_DEVICE_ERROR, CKR_FUNCTION_FAILED,
        CKR_FUNCTION_NOT_SUPPORTED, CKR_GENERAL_ERROR, CKR_OBJECT_HANDLE_INVALID,
        CKR_OPERATION_NOT_INITIALIZED, CKR_SESSION_HANDLE_INVALID, CKR_SLOT_ID_INVALID, CK_RV,
    },
    persistence::persistence_error::PersistenceError,
};

#[derive(Debug, Error)]
pub(crate) enum CryptokiError {
    #[error("Synchronization error occurred, a thread panicked while holding a lock")]
    SynchronizationElementPoisoned,
    #[error("Cryptoki not initialized")]
    CryptokiNotInitialized,
    #[error("Session handle is invalid")]
    SessionHandleInvalid,
    #[error("Function is not supported")]
    FunctionNotSupported,
    #[error("Operation is not initialized")]
    OperationNotInitialized,
    #[error("Object handle is invalid")]
    ObjectHandleInvalid,
    #[error("Function failed")]
    FunctionFailed,
    #[error("Transport error occurred")]
    TransportError,
    #[error("Slot ID is not valid")]
    SlotIdInvalid,
    #[error("General device error")]
    DeviceError,
}

impl CryptokiError {
    pub(crate) fn into_ck_rv(self) -> CK_RV {
        match self {
            Self::SynchronizationElementPoisoned => CKR_GENERAL_ERROR as CK_RV,
            Self::CryptokiNotInitialized => CKR_CRYPTOKI_NOT_INITIALIZED as CK_RV,
            Self::SessionHandleInvalid => CKR_SESSION_HANDLE_INVALID as CK_RV,
            Self::FunctionNotSupported => CKR_FUNCTION_NOT_SUPPORTED as CK_RV,
            Self::OperationNotInitialized => CKR_OPERATION_NOT_INITIALIZED as CK_RV,
            Self::ObjectHandleInvalid => CKR_OBJECT_HANDLE_INVALID as CK_RV,
            Self::FunctionFailed => CKR_FUNCTION_FAILED as CK_RV,
            Self::TransportError => CKR_GENERAL_ERROR as CK_RV,
            Self::SlotIdInvalid => CKR_SLOT_ID_INVALID as CK_RV,
            Self::DeviceError => CKR_DEVICE_ERROR as CK_RV,
        }
    }
}

impl<S> From<PoisonError<S>> for CryptokiError {
    fn from(_value: PoisonError<S>) -> Self {
        Self::SynchronizationElementPoisoned
    }
}

impl From<CommunicatorError> for CryptokiError {
    fn from(value: CommunicatorError) -> Self {
        match value {
            #[cfg(feature = "mocked_ecdsa_communicator")]
            CommunicatorError::CryptographicError(_) => Self::FunctionFailed,
            CommunicatorError::Transport(_) => Self::TransportError,
            CommunicatorError::InvalidConfiguration(_) => Self::FunctionFailed,
            CommunicatorError::TaskFailed => Self::FunctionFailed,
            CommunicatorError::TaskTimedOut(_) => Self::FunctionFailed,
            CommunicatorError::InvalidStatus(_) => Self::TransportError,
            CommunicatorError::Io(_) => Self::DeviceError,
        }
    }
}

impl From<PersistenceError> for CryptokiError {
    fn from(_value: PersistenceError) -> Self {
        Self::DeviceError
    }
}

impl From<ConfigurationProviderError> for CryptokiError {
    fn from(_value: ConfigurationProviderError) -> Self {
        Self::DeviceError
    }
}

impl From<io::Error> for CryptokiError {
    fn from(_value: io::Error) -> Self {
        Self::DeviceError
    }
}
