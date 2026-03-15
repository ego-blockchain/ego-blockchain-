//! Urego smart contract compiler.
//!
//! Compiles Urego source code to WebAssembly bytecode (.wasm) compatible
//! with the ego-vm Wasmtime executor.
//!
//! # Example
//! ```rust
//! let wasm = urego_compiler::compile(r#"
//!     contract Counter {
//!         fn init(start: u64) {
//!             storage.set("count", start);
//!         }
//!         fn increment() {
//!             let v: u64 = storage.get_u64("count");
//!             storage.set("count", v + 1);
//!         }
//!         fn get() -> u64 {
//!             return storage.get_u64("count");
//!         }
//!     }
//! "#).unwrap();
//! assert!(!wasm.is_empty());
//! ```

pub mod ast;
pub mod codegen;
pub mod error;
pub mod lexer;
pub mod parser;

use codegen::Codegen;
use error::Result;
use lexer::lex;
use parser::Parser;

/// Compile Urego source to WASM bytes.
pub fn compile(source: &str) -> Result<Vec<u8>> {
    let tokens   = lex(source)?;
    let mut p    = Parser::new(tokens);
    let contract = p.parse_contract()?;
    let mut cg   = Codegen::new();
    let wat      = cg.generate(&contract)?;
    wat::parse_str(&wat).map_err(|e| error::CompileError::WatError(e.to_string()))
}

/// Compile to WAT text (useful for debugging).
pub fn compile_to_wat(source: &str) -> Result<String> {
    let tokens   = lex(source)?;
    let mut p    = Parser::new(tokens);
    let contract = p.parse_contract()?;
    let mut cg   = Codegen::new();
    cg.generate(&contract)
}

#[cfg(test)]
mod tests {
    use super::*;

    const COUNTER: &str = r#"
        contract Counter {
            fn init(start: u64) {
                storage.set("count", start);
            }
            fn increment() {
                let v: u64 = storage.get_u64("count");
                storage.set("count", v + 1);
            }
            fn get() -> u64 {
                return storage.get_u64("count");
            }
        }
    "#;

    const TOKEN: &str = r#"
        contract Token {
            fn init(supply: u64) {
                storage.set("supply", supply);
                storage.set("minted", 0);
            }
            fn mint(amount: u64) {
                let minted: u64 = storage.get_u64("minted");
                let supply: u64 = storage.get_u64("supply");
                assert(minted + amount <= supply, "exceeds supply");
                storage.set("minted", minted + amount);
                events.emit("minted", amount);
            }
            fn total_supply() -> u64 {
                return storage.get_u64("supply");
            }
        }
    "#;

    #[test]
    fn test_counter_compiles() {
        let wasm = compile(COUNTER).expect("counter should compile");
        assert!(!wasm.is_empty());
        // WASM magic bytes
        assert_eq!(&wasm[0..4], b"\0asm");
    }

    #[test]
    fn test_token_compiles() {
        let wasm = compile(TOKEN).expect("token should compile");
        assert!(!wasm.is_empty());
        assert_eq!(&wasm[0..4], b"\0asm");
    }

    #[test]
    fn test_wat_output() {
        let wat = compile_to_wat(COUNTER).expect("should produce WAT");
        assert!(wat.contains("(func $init"));
        assert!(wat.contains("(func $increment"));
        assert!(wat.contains("(func $get"));
        assert!(wat.contains("storage_get"));
        assert!(wat.contains("storage_set"));
    }

    #[test]
    fn test_lex_error() {
        let result = compile("contract Foo { fn bad() { @invalid } }");
        assert!(result.is_err());
    }
}
