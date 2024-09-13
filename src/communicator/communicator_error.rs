use thiserror::Error;
use tonic::codegen::http::uri::InvalidUri;

type WaitingTimeSeconds = u64;

#[derive(Debug, Error)]
pub(crate) enum CommunicatorError {
    #[error("Communicator interaction failed: {0}")]
    Transport(#[from] tonic::transport::Error),
    #[error("Communicator responded with an invalid status: {0}")]
    InvalidStatus(#[from] tonic::Status),
    #[error("Invalid configuration")]
    InvalidConfiguration(#[from] InvalidUri),
    #[error("Task failed remotely")]
    TaskFailed,
    #[error("Task timed out after {0} seconds")]
    TaskTimedOut(WaitingTimeSeconds),
    #[error("I/O error occurred: {0}")]
    Io(#[from] std::io::Error),
    #[cfg(feature = "mocked_ecdsa_communicator")]
    #[error("Cryptographic operation failed")]
    CryptographicError(#[from] p256::ecdsa::Error),
}
