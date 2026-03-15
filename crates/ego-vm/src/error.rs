use std::fmt;

#[derive(Debug)]
pub enum VmError {
    CompileError(String),
    InstantiationError(String),
    ExecutionError(String),
    FuelExhausted,
    MemoryLimit,
    InvalidAbi(String),
    StorageError(String),
    HostCallError(String),
    Unauthorized(String),
}

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VmError::CompileError(s)       => write!(f, "Compile error: {}", s),
            VmError::InstantiationError(s) => write!(f, "Instantiation error: {}", s),
            VmError::ExecutionError(s)     => write!(f, "Execution error: {}", s),
            VmError::FuelExhausted         => write!(f, "Fuel exhausted (RU limit reached)"),
            VmError::MemoryLimit           => write!(f, "Memory limit exceeded"),
            VmError::InvalidAbi(s)         => write!(f, "Invalid ABI: {}", s),
            VmError::StorageError(s)       => write!(f, "Storage error: {}", s),
            VmError::HostCallError(s)      => write!(f, "Host call error: {}", s),
            VmError::Unauthorized(s)       => write!(f, "Unauthorized: {}", s),
        }
    }
}

impl std::error::Error for VmError {}

impl From<anyhow::Error> for VmError {
    fn from(e: anyhow::Error) -> Self {
        VmError::ExecutionError(e.to_string())
    }
}
