use anyhow::{Context, Result, anyhow};
use clap::{Parser, Subcommand};
use colored::Colorize;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "ego",
    about = "Ego Blockchain developer CLI — compile, deploy, call, test",
    version = "0.1.0",
    long_about = None,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {

    Compile {

        file: PathBuf,
    },

    Deploy {

        file: PathBuf,

        #[arg(long, default_value = "http://localhost:8545")]
        node: String,

        #[arg(long)]
        key: Option<String>,
    },

    Call {

        address: String,

        function: String,

        args: Vec<String>,

        #[arg(long, default_value = "http://localhost:8545")]
        node: String,

        #[arg(long)]
        key: Option<String>,
    },

    Balance {

        address: String,

        #[arg(long, default_value = "http://localhost:8545")]
        node: String,
    },

    Faucet {

        address: String,

        #[arg(long, default_value = "http://localhost:8545")]
        node: String,
    },

    Tx {

        hash: String,

        #[arg(long, default_value = "http://localhost:8545")]
        node: String,
    },

    Node {
        #[command(subcommand)]
        subcommand: NodeCommands,
    },

    Keygen,

    Init {

        #[arg(long, default_value = "my-contract")]
        name: String,
    },
}

#[derive(Subcommand)]
enum NodeCommands {

    Status {

        #[arg(long, default_value = "http://localhost:8545")]
        node: String,
    },
}

fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Compile { file } => cmd_compile(file),
        Commands::Deploy { file, node, key } => cmd_deploy(file, &node, key.as_deref()),
        Commands::Call { address, function, args, node, key } => {
            cmd_call(&address, &function, &args, &node, key.as_deref())
        }
        Commands::Balance { address, node } => cmd_balance(&address, &node),
        Commands::Faucet { address, node } => cmd_faucet(&address, &node),
        Commands::Tx { hash, node } => cmd_tx(&hash, &node),
        Commands::Node { subcommand } => match subcommand {
            NodeCommands::Status { node } => cmd_node_status(&node),
        },
        Commands::Keygen => cmd_keygen(),
        Commands::Init { name } => cmd_init(&name),
    };

    if let Err(e) = result {
        eprintln!("{} {}", "✗".red().bold(), e.to_string().red());
        std::process::exit(1);
    }
}

fn cmd_compile(file: PathBuf) -> Result<()> {
    let source = std::fs::read_to_string(&file)
        .with_context(|| format!("Failed to read '{}'", file.display()))?;

    let wasm_bytes = urego_compiler::compile(&source)
        .map_err(|e| anyhow!("Compilation failed: {}", e))?;

    let stem = file
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("output");
    let out_path = file.with_file_name(format!("{}.wasm", stem));

    std::fs::write(&out_path, &wasm_bytes)
        .with_context(|| format!("Failed to write '{}'", out_path.display()))?;

    println!(
        "{} Compiled to {} ({} bytes)",
        "✓".green().bold(),
        out_path.display().to_string().cyan(),
        wasm_bytes.len().to_string().yellow()
    );

    Ok(())
}

fn cmd_deploy(file: PathBuf, node: &str, key_hex: Option<&str>) -> Result<()> {
    let wasm_bytes = std::fs::read(&file)
        .with_context(|| format!("Failed to read '{}'", file.display()))?;

    let keypair = resolve_keypair(key_hex)?;

    let nonce = fetch_nonce(node, &keypair).unwrap_or(0);

    let address = keypair
        .derive_bech32_address(1, ego_core::AddressType::EOA, "egot")
        .map_err(|e| anyhow!("Address derivation failed: {}", e))?;

    let contract_address = derive_contract_address(&address, nonce);

    let tx = serde_json::json!({
        "kind": "deploy",
        "from": address,
        "nonce": nonce,
        "data": hex::encode(&wasm_bytes),
        "contract_address": contract_address,
    });

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(format!("{}/tx/submit", node))
        .json(&serde_json::json!({ "tx": tx }))
        .send()
        .with_context(|| format!("Failed to connect to node at '{}'", node))?;

    if resp.status().is_success() {
        println!(
            "{} Deployed at {}",
            "✓".green().bold(),
            contract_address.cyan().bold()
        );
    } else {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(anyhow!("Node rejected deploy (HTTP {}): {}", status, body));
    }

    Ok(())
}

fn cmd_call(
    address: &str,
    function: &str,
    args: &[String],
    node: &str,
    key_hex: Option<&str>,
) -> Result<()> {
    let calldata = serde_json::json!({
        "function": function,
        "args": args,
    });

    let from_address = if let Some(kh) = key_hex {
        let kp = resolve_keypair(Some(kh))?;
        kp.derive_bech32_address(1, ego_core::AddressType::EOA, "egot")
            .map_err(|e| anyhow!("Address derivation failed: {}", e))?
    } else {
        "anonymous".to_string()
    };

    let tx = serde_json::json!({
        "kind": "call",
        "from": from_address,
        "to": address,
        "data": calldata.to_string(),
        "nonce": 0,
    });

    let client = reqwest::blocking::Client::new();
    let resp = client
        .post(format!("{}/tx/submit", node))
        .json(&serde_json::json!({ "tx": tx }))
        .send()
        .with_context(|| format!("Failed to connect to node at '{}'", node))?;

    if resp.status().is_success() {
        let body: serde_json::Value = resp.json().unwrap_or(serde_json::Value::Null);
        println!("{} Call submitted", "✓".green().bold());
        if body != serde_json::Value::Null {
            println!("  Result: {}", serde_json::to_string_pretty(&body)?.cyan());
        }
    } else {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(anyhow!("Node rejected call (HTTP {}): {}", status, body));
    }

    Ok(())
}

fn cmd_balance(address: &str, node: &str) -> Result<()> {
    let client = reqwest::blocking::Client::new();
    let resp = client
        .get(format!("{}/balance/{}", node, address))
        .send()
        .with_context(|| format!("Failed to connect to node at '{}'", node))?;

    if resp.status().is_success() {
        let body: serde_json::Value = resp
            .json()
            .with_context(|| "Failed to parse balance response")?;

        let balance_egoc = body
            .get("balance_egoc")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);

        println!(
            "Balance: {} EGOC",
            format!("{:.6}", balance_egoc).yellow().bold()
        );
    } else {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(anyhow!("Node error (HTTP {}): {}", status, body));
    }

    Ok(())
}

fn cmd_faucet(address: &str, node: &str) -> Result<()> {
    let client = reqwest::blocking::Client::new();
    let resp = client
        .get(format!("{}/faucet?to={}", node, address))
        .send()
        .with_context(|| format!("Failed to connect to node at '{}'", node))?;

    if resp.status().is_success() {
        let body: serde_json::Value = resp
            .json()
            .with_context(|| "Failed to parse faucet response")?;

        let success = body.get("success").and_then(|v| v.as_bool()).unwrap_or(false);
        let amount = body
            .get("amount_egoc")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let tx_hash = body
            .get("tx_hash")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)");

        if success {
            println!(
                "{} Faucet sent {} EGOC to {}",
                "✓".green().bold(),
                format!("{:.2}", amount).yellow().bold(),
                address.cyan()
            );
            println!("  TX: {}", tx_hash.dimmed());
        } else {
            let cooldown = body
                .get("cooldown_secs")
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            println!(
                "{} Faucet on cooldown for this address. Try again in {} seconds.",
                "✗".red().bold(),
                cooldown.to_string().yellow()
            );
        }
    } else {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(anyhow!("Faucet error (HTTP {}): {}", status, body));
    }

    Ok(())
}

fn cmd_tx(hash: &str, node: &str) -> Result<()> {

    let client = reqwest::blocking::Client::new();
    let resp = client
        .get(format!("{}/chain/transactions", node))
        .send()
        .with_context(|| format!("Failed to connect to node at '{}'", node))?;

    if resp.status().is_success() {
        let txs: serde_json::Value = resp
            .json()
            .with_context(|| "Failed to parse transactions response")?;

        let found = txs.as_array().and_then(|arr| {
            arr.iter().find(|tx| {
                tx.get("hash")
                    .and_then(|h| h.as_str())
                    .map(|h| h == hash || h.starts_with(hash))
                    .unwrap_or(false)
            })
        });

        if let Some(tx) = found {
            println!("{} Transaction found:", "✓".green().bold());
            println!("{}", serde_json::to_string_pretty(tx)?.cyan());
        } else {
            println!(
                "{} Transaction {} not found in pending pool (may be confirmed or invalid)",
                "~".yellow().bold(),
                hash.cyan()
            );
        }
    } else {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(anyhow!("Node error (HTTP {}): {}", status, body));
    }

    Ok(())
}

fn cmd_node_status(node: &str) -> Result<()> {
    let client = reqwest::blocking::Client::new();
    let resp = client
        .get(format!("{}/health", node))
        .send()
        .with_context(|| format!("Failed to connect to node at '{}'. Is it running?", node))?;

    if resp.status().is_success() {
        let body: serde_json::Value = resp
            .json()
            .with_context(|| "Failed to parse health response")?;

        let status = body
            .get("status")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        let height = body
            .get("block_height")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);
        let peer_id = body
            .get("peer_id")
            .and_then(|v| v.as_str())
            .unwrap_or("(unknown)");
        let uptime = body
            .get("uptime_secs")
            .and_then(|v| v.as_u64())
            .unwrap_or(0);

        let status_colored = if status == "ok" || status == "healthy" {
            status.green().bold().to_string()
        } else {
            status.yellow().bold().to_string()
        };

        println!("{} Node status", "✓".green().bold());
        println!("  ┌─────────────────────────────────────────");
        println!("  │  Node URL    : {}", node.cyan());
        println!("  │  Status      : {}", status_colored);
        println!("  │  Block height: {}", height.to_string().yellow());
        println!("  │  Uptime      : {}s", uptime.to_string().yellow());
        println!("  │  Peer ID     : {}", peer_id.dimmed());
        println!("  └─────────────────────────────────────────");

        if let Ok(stats_resp) = client.get(format!("{}/node/stats", node)).send() {
            if stats_resp.status().is_success() {
                if let Ok(stats) = stats_resp.json::<serde_json::Value>() {
                    let pending = stats
                        .get("pending_tx_count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let peers = stats
                        .get("peer_connections_established")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);
                    let shards = stats
                        .get("shard_count")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(0);

                    println!("  ┌─────────────────────────────────────────");
                    println!("  │  Pending TXs  : {}", pending.to_string().yellow());
                    println!("  │  Peer conns   : {}", peers.to_string().yellow());
                    println!("  │  Shards       : {}", shards.to_string().yellow());
                    println!("  └─────────────────────────────────────────");
                }
            }
        }
    } else {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        return Err(anyhow!("Node returned error (HTTP {}): {}", status, body));
    }

    Ok(())
}

fn cmd_keygen() -> Result<()> {
    let keypair = ego_core::KeyPair::generate();

    let address = keypair
        .derive_bech32_address(1, ego_core::AddressType::EOA, "egot")
        .map_err(|e| anyhow!("Address derivation failed: {}", e))?;

    let ed25519_pk = keypair.ed25519_public_key();
    let ed25519_pk_hex = hex::encode(ed25519_pk.as_bytes());

    let exported = keypair.export_keys_hex();
    let seed_hex = &exported.seed;

    println!("{} New keypair generated", "✓".green().bold());
    println!();
    println!("  Address         : {}", address.cyan().bold());
    println!("  Public key      : 0x{}", ed25519_pk_hex.green());
    println!(
        "  Private key (seed): {}  {} keep secret {}",
        format!("0x{}", seed_hex).yellow(),
        "←".red(),
        "←".red()
    );
    println!();
    println!(
        "  {} Never share your private key. Store it in a secure location.",
        "!".red().bold()
    );

    Ok(())
}

fn cmd_init(name: &str) -> Result<()> {
    let project_dir = PathBuf::from(name);

    if project_dir.exists() {
        return Err(anyhow!(
            "Directory '{}' already exists",
            project_dir.display()
        ));
    }

    let src_dir = project_dir.join("src");
    std::fs::create_dir_all(&src_dir)
        .with_context(|| format!("Failed to create directory '{}'", src_dir.display()))?;

    let main_urego = r#"// Hello World contract on Ego Blockchain
contract HelloWorld {
    pub fn greet(name: String) -> String {
        return concat("Hello, ", name);
    }

    pub fn set_message(msg: String) {
        storage_set_str("message", msg);
    }

    pub fn get_message() -> String {
        return storage_get_str("message");
    }
}
"#;
    let main_path = src_dir.join("main.urego");
    std::fs::write(&main_path, main_urego)
        .with_context(|| format!("Failed to write '{}'", main_path.display()))?;

    let ego_toml = format!(
        r#"[project]
name = "{}"
version = "0.1.0"

[network]
testnet = "http://localhost:8545"
mainnet = "https://rpc.ego-blockchain.io"
"#,
        name
    );
    let toml_path = project_dir.join("ego.toml");
    std::fs::write(&toml_path, &ego_toml)
        .with_context(|| format!("Failed to write '{}'", toml_path.display()))?;

    println!(
        "{} Project {} created.",
        "✓".green().bold(),
        name.cyan().bold()
    );
    println!(
        "  Run: {} && {}",
        format!("cd {}", name).yellow(),
        "ego compile src/main.urego".yellow()
    );

    Ok(())
}

fn resolve_keypair(key_hex: Option<&str>) -> Result<ego_core::KeyPair> {
    if let Some(hex_str) = key_hex {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let bytes = hex::decode(hex_str)
            .with_context(|| "Invalid hex string for --key")?;
        if bytes.len() != 32 {
            return Err(anyhow!(
                "--key must be a 32-byte (64 hex char) seed; got {} bytes",
                bytes.len()
            ));
        }
        let mut seed = [0u8; 32];
        seed.copy_from_slice(&bytes);
        ego_core::KeyPair::from_bytes(&seed)
            .map_err(|e| anyhow!("Failed to build keypair from seed: {}", e))
    } else {
        eprintln!(
            "  {} No --key provided, generating a temporary keypair (not persisted).",
            "!".yellow()
        );
        Ok(ego_core::KeyPair::generate())
    }
}

fn fetch_nonce(node: &str, keypair: &ego_core::KeyPair) -> Result<u64> {
    let address = keypair
        .derive_bech32_address(1, ego_core::AddressType::EOA, "egot")
        .map_err(|e| anyhow!("{}", e))?;

    let client = reqwest::blocking::Client::new();
    let resp = client
        .get(format!("{}/balance/{}", node, address))
        .send()?;

    if resp.status().is_success() {
        let body: serde_json::Value = resp.json()?;
        Ok(body.get("nonce").and_then(|v| v.as_u64()).unwrap_or(0))
    } else {
        Ok(0)
    }
}

fn derive_contract_address(deployer_address: &str, nonce: u64) -> String {
    use blake2::{Blake2s256, Digest};

    let mut hasher = Blake2s256::new();
    hasher.update(deployer_address.as_bytes());
    hasher.update(nonce.to_le_bytes());
    let digest = hasher.finalize();

    format!("0x{}", hex::encode(&digest[..20]))
}
