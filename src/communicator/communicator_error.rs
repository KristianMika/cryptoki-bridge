use thiserror::Error;
use tonic::codegen::http::uri::InvalidUri;

type WaitingTimeSeconds = u64;

#[derive(Debug, Error)]
pub(crate) enum CommunicatorError {
    #[error("Communicator interaction failed: {0}")]
    TransportError(#[from] tonic::transport::Error),
    #[error("Communicator responded with an invalid status: {0}")]
    InvalidStatusError(#[from] tonic::Status),
    #[error("Invalid configuration")]
    InvalidConfigurationError(#[from] InvalidUri),
    #[error("Task failed remotely")]
    TaskFailedError,
    #[error("Task timed out after {0} seconds")]
    TaskTimedOutError(WaitingTimeSeconds),
    #[error("I/O error occurred: {0}")]
    IoError(#[from] std::io::Error),
    #[cfg(feature = "mocked_communicator")]
    #[error("Cryptographic operation failed")]
    CryptographicError(#[from] p256::ecdsa::Error),
}
