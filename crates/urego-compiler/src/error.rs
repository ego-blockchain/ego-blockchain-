use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum CompileError {
    #[error("Lex error at line {line}: {msg}")]
    LexError { line: usize, msg: String },

    #[error("Parse error at line {line}: {msg}")]
    ParseError { line: usize, msg: String },

    #[error("Type error: {0}")]
    TypeError(String),

    #[error("Codegen error: {0}")]
    CodegenError(String),

    #[error("WAT assembly error: {0}")]
    WatError(String),
}

pub type Result<T> = std::result::Result<T, CompileError>;
