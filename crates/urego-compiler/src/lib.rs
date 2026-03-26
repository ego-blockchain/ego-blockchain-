pub mod ast;
pub mod codegen;
pub mod error;
pub mod lexer;
pub mod parser;

use codegen::Codegen;
use error::Result;
use lexer::lex;
use parser::Parser;

pub fn compile(source: &str) -> Result<Vec<u8>> {
    let tokens   = lex(source)?;
    let mut p    = Parser::new(tokens);
    let contract = p.parse_contract()?;
    let mut cg   = Codegen::new();
    let wat      = cg.generate(&contract)?;
    wat::parse_str(&wat).map_err(|e| error::CompileError::WatError(e.to_string()))
}

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

    const FOR_LOOP: &str = r#"
        contract Loops {
            fn sum_range(n: u64) -> u64 {
                let acc: u64 = 0;
                for i in 0..n {
                    acc += i;
                }
                return acc;
            }
        }
    "#;

    const STRUCT_CONTRACT: &str = r#"
        contract Structs {
            struct Point {
                x: u64,
                y: u64,
            }
            fn make_point(a: u64, b: u64) -> u64 {
                let p = Point { x: a, y: b };
                return a + b;
            }
        }
    "#;

    const MATCH_CONTRACT: &str = r#"
        contract Matcher {
            fn classify(n: u64) -> u64 {
                match n {
                    0 => { return 0; }
                    1 => { return 1; }
                    _ => { return 2; }
                }
            }
        }
    "#;

    const EMIT_CONTRACT: &str = r#"
        contract Emitter {
            fn transfer(amount: u64) {
                emit Transfer { amount: amount };
            }
        }
    "#;

    const ARRAY_CONTRACT: &str = r#"
        contract Arrays {
            fn first(a: u64, b: u64, c: u64) -> u64 {
                let arr = [a, b, c];
                return arr[0];
            }
        }
    "#;

    const NEW_TYPES: &str = r#"
        contract Types {
            fn cast_it(x: u64) -> u64 {
                let small: u8 = x as u8;
                let wide: u128 = x as u128;
                return wide as u64;
            }
        }
    "#;

    #[test]
    fn test_for_loop_compiles() {
        let wat = compile_to_wat(FOR_LOOP).expect("for loop should compile");
        assert!(wat.contains("$for_break"));
        assert!(wat.contains("$for_continue"));
    }

    #[test]
    fn test_struct_compiles() {
        let wasm = compile(STRUCT_CONTRACT).expect("struct contract should compile");
        assert!(!wasm.is_empty());
    }

    #[test]
    fn test_match_compiles() {
        let wat = compile_to_wat(MATCH_CONTRACT).expect("match should compile");
        assert!(wat.contains("$__match_val"));
    }

    #[test]
    fn test_emit_compiles() {
        let wat = compile_to_wat(EMIT_CONTRACT).expect("emit should compile");
        assert!(wat.contains("events_emit"));
    }

    #[test]
    fn test_array_compiles() {
        let wasm = compile(ARRAY_CONTRACT).expect("array contract should compile");
        assert!(!wasm.is_empty());
    }

    #[test]
    fn test_new_integer_types_compile() {
        let wasm = compile(NEW_TYPES).expect("u8/u128 cast should compile");
        assert!(!wasm.is_empty());
    }
}
