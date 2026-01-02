use thiserror::Error;

#[derive(Error, Debug)]
pub enum ProcessVisionError {
    #[error("Failed to enumerate processes: {0}")]
    ProcessEnumerationError(u32),

    #[error("Failed to open process (PID: {0}): {1}")]
    ProcessOpenError(u32, u32),

    #[error("Failed to read memory from process (PID: {0}, Address: {1:X}): {2}")]
    MemoryReadError(u32, usize, u32),

    #[error("Failed to query memory region (PID: {0}, Address: {1:X}): {2}")]
    MemoryQueryError(u32, usize, u32),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("Unknown error occurred")]
    Unknown,
}

pub type Result<T> = std::result::Result<T, ProcessVisionError>;
