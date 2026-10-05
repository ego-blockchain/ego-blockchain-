use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use litesvm::LiteSVM;
use serde_json::{json, Value};
use solana_address::Address;
use solana_transaction::Transaction;
use std::collections::HashMap;

struct Status {
    slot: u64,
    err: Value,
}

struct Node {
    svm: LiteSVM,
    slot: u64,
    statuses: HashMap<String, Status>,
    history: HashMap<String, Vec<String>>,
}

fn rpc_error(code: i64, message: String, logs: Vec<String>) -> Value {
    json!({ "code": code, "message": message, "data": { "logs": logs } })
}

fn custom_code(debug: &str) -> Option<(String, u32)> {
    let at = debug.find("InstructionError(")?;
    let rest = &debug[at + 17..];
    let index: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
    let c = rest.find("Custom(")?;
    let code: String = rest[c + 7..].chars().take_while(|c| c.is_ascii_digit()).collect();
    Some((index, code.parse().ok()?))
}

impl Node {
    fn record(&mut self, signature: String, keys: Vec<String>, err: Value) {
        self.slot += 1;
        self.statuses.insert(signature.clone(), Status { slot: self.slot, err });
        for k in keys {
            self.history.entry(k).or_default().insert(0, signature.clone());
        }
        self.svm.expire_blockhash();
    }

    fn handle(&mut self, method: &str, params: &Value) -> Result<Value, Value> {
        let ctx = json!({ "slot": self.slot });
        match method {
            "getHealth" => Ok(json!("ok")),
            "getLatestBlockhash" => Ok(json!({
                "context": ctx,
                "value": { "blockhash": self.svm.latest_blockhash().to_string(), "lastValidBlockHeight": self.slot + 150 },
            })),
            "getMinimumBalanceForRentExemption" => {
                let len = params[0].as_u64().unwrap_or(0) as usize;
                Ok(json!(self.svm.minimum_balance_for_rent_exemption(len)))
            }
            "getBalance" => {
                let a = address(&params[0])?;
                Ok(json!({ "context": ctx, "value": self.svm.get_account(&a).map(|x| x.lamports).unwrap_or(0) }))
            }
            "getAccountInfo" => {
                let a = address(&params[0])?;
                let value = match self.svm.get_account(&a) {
                    Some(acc) if acc.lamports > 0 => json!({
                        "data": [B64.encode(&acc.data), "base64"],
                        "lamports": acc.lamports,
                        "owner": acc.owner.to_string(),
                        "executable": acc.executable,
                        "rentEpoch": 0,
                        "space": acc.data.len(),
                    }),
                    _ => Value::Null,
                };
                Ok(json!({ "context": ctx, "value": value }))
            }
            "requestAirdrop" => {
                let a = address(&params[0])?;
                let lamports = params[1].as_u64().unwrap_or(0);
                match self.svm.airdrop(&a, lamports) {
                    Ok(meta) => {
                        let sig = meta.signature.to_string();
                        self.record(sig.clone(), vec![a.to_string()], Value::Null);
                        Ok(json!(sig))
                    }
                    Err(e) => Err(rpc_error(-32603, format!("airdrop failed: {:?}", e.err), e.meta.logs)),
                }
            }
            "sendTransaction" => {
                let raw = B64
                    .decode(params[0].as_str().unwrap_or(""))
                    .map_err(|e| rpc_error(-32602, format!("invalid base64: {e}"), vec![]))?;
                let tx: Transaction =
                    bincode::deserialize(&raw).map_err(|e| rpc_error(-32602, format!("invalid transaction: {e}"), vec![]))?;
                let sig = tx.signatures.first().map(|s| s.to_string()).unwrap_or_default();
                let keys: Vec<String> = tx.message.account_keys.iter().map(|k| k.to_string()).collect();
                match self.svm.send_transaction(tx) {
                    Ok(_) => {
                        self.record(sig.clone(), keys, Value::Null);
                        Ok(json!(sig))
                    }
                    Err(e) => {
                        let debug = format!("{:?}", e.err);
                        let message = match custom_code(&debug) {
                            Some((index, code)) => format!(
                                "Transaction simulation failed: Error processing Instruction {index}: custom program error: 0x{code:x}"
                            ),
                            None => format!("Transaction simulation failed: {debug}"),
                        };
                        Err(rpc_error(-32002, message, e.meta.logs))
                    }
                }
            }
            "getSignatureStatuses" => {
                let list: Vec<Value> = params[0]
                    .as_array()
                    .cloned()
                    .unwrap_or_default()
                    .iter()
                    .map(|s| match self.statuses.get(s.as_str().unwrap_or("")) {
                        Some(st) => json!({ "slot": st.slot, "confirmations": null, "err": st.err, "confirmationStatus": "finalized" }),
                        None => Value::Null,
                    })
                    .collect();
                Ok(json!({ "context": ctx, "value": list }))
            }
            "getSignaturesForAddress" => {
                let key = params[0].as_str().unwrap_or("").to_string();
                let limit = params[1]["limit"].as_u64().unwrap_or(1000) as usize;
                let list: Vec<Value> = self
                    .history
                    .get(&key)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .take(limit)
                    .map(|s| {
                        let slot = self.statuses.get(&s).map(|x| x.slot).unwrap_or(0);
                        json!({ "signature": s, "slot": slot, "err": null, "memo": null, "blockTime": null, "confirmationStatus": "finalized" })
                    })
                    .collect();
                Ok(json!(list))
            }
            other => Err(rpc_error(-32601, format!("method {other} is not served by this test node"), vec![])),
        }
    }
}

fn address(v: &Value) -> Result<Address, Value> {
    v.as_str()
        .and_then(|s| s.parse::<Address>().ok())
        .ok_or_else(|| rpc_error(-32602, format!("invalid address {v}"), vec![]))
}

fn main() {
    let program: Address = std::env::var("EGO_SOL_PROGRAM").expect("EGO_SOL_PROGRAM").parse().expect("a base58 program id");
    let so = std::env::var("EGO_ESCROW_SO").expect("EGO_ESCROW_SO");
    let port = std::env::var("EGO_SVM_PORT").unwrap_or_else(|_| "8899".into());
    let mut svm = LiteSVM::new();
    svm.add_program(program, &std::fs::read(so).expect("the program file")).expect("load the program");
    let mut node = Node { svm, slot: 1, statuses: HashMap::new(), history: HashMap::new() };
    let server = tiny_http::Server::http(format!("127.0.0.1:{port}")).expect("bind");
    println!("svm rpc listening on 127.0.0.1:{port}");
    for mut req in server.incoming_requests() {
        let mut body = String::new();
        let _ = req.as_reader().read_to_string(&mut body);
        let call: Value = serde_json::from_str(&body).unwrap_or(Value::Null);
        let id = call["id"].clone();
        let reply = match node.handle(call["method"].as_str().unwrap_or(""), &call["params"]) {
            Ok(result) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
            Err(error) => json!({ "jsonrpc": "2.0", "id": id, "error": error }),
        };
        let header = tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..]).unwrap();
        let _ = req.respond(tiny_http::Response::from_string(reply.to_string()).with_header(header));
    }
}
