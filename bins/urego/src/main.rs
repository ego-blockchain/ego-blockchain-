use std::{fs, path::PathBuf, process};

fn usage() -> ! {
    eprintln!("urego — Urego smart contract compiler\n");
    eprintln!("USAGE:");
    eprintln!("  urego build  <file.uro>          Compile to <file.wasm>");
    eprintln!("  urego check  <file.uro>          Type-check without emitting output");
    eprintln!("  urego wat    <file.uro>          Print WAT (text format) to stdout");
    eprintln!("  urego new    <ContractName>      Scaffold a new contract file");
    process::exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        usage();
    }

    match args[1].as_str() {
        "build" => {
            let src_path = PathBuf::from(&args[2]);
            let source = fs::read_to_string(&src_path).unwrap_or_else(|e| {
                eprintln!("error: cannot read {}: {e}", src_path.display());
                process::exit(1);
            });
            match urego_compiler::compile(&source) {
                Ok(wasm) => {
                    let out = src_path.with_extension("wasm");
                    fs::write(&out, &wasm).unwrap_or_else(|e| {
                        eprintln!("error: cannot write {}: {e}", out.display());
                        process::exit(1);
                    });
                    println!("compiled {} → {} ({} bytes)", src_path.display(), out.display(), wasm.len());
                }
                Err(e) => {
                    eprintln!("compile error: {e}");
                    process::exit(1);
                }
            }
        }

        "check" => {
            let src_path = PathBuf::from(&args[2]);
            let source = fs::read_to_string(&src_path).unwrap_or_else(|e| {
                eprintln!("error: cannot read {}: {e}", src_path.display());
                process::exit(1);
            });
            match urego_compiler::compile(&source) {
                Ok(_)  => println!("ok — no errors"),
                Err(e) => { eprintln!("error: {e}"); process::exit(1); }
            }
        }

        "wat" => {
            let src_path = PathBuf::from(&args[2]);
            let source = fs::read_to_string(&src_path).unwrap_or_else(|e| {
                eprintln!("error: cannot read {}: {e}", src_path.display());
                process::exit(1);
            });
            match urego_compiler::compile_to_wat(&source) {
                Ok(wat) => print!("{wat}"),
                Err(e)  => { eprintln!("error: {e}"); process::exit(1); }
            }
        }

        "new" => {
            let name = &args[2];
            let file = format!("{}.uro", name.to_lowercase());
            if PathBuf::from(&file).exists() {
                eprintln!("error: {file} already exists");
                process::exit(1);
            }
            let template = format!(
r#"contract {name} {{
    fn init() {{
        // Called once when the contract is deployed.
        storage.set("owner", sys.caller());
    }}

    fn get_owner() -> Address {{
        return storage.get_address("owner");
    }}
}}
"#
            );
            fs::write(&file, template).unwrap_or_else(|e| {
                eprintln!("error: cannot write {file}: {e}");
                process::exit(1);
            });
            println!("created {file}");
        }

        _ => usage(),
    }
}
