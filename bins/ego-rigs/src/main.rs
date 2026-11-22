use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_RPC: &str = "http://127.0.0.1:47395";
const HOUR: i64 = 3_600;
const DAY: i64 = 24 * HOUR;
const WEEK: i64 = 7 * DAY;
const FIRST_PAGE: u64 = 5_000;
const MAX_PAGE: u64 = 1_000_000;
const PARALLEL: usize = 8;
const BEHIND_BLOCKS: u64 = 30;

#[derive(Parser)]
#[command(name = "ego-rigs", version, about = "See the EGOC earned by all your Ego Desktop computers as one")]
struct Cli {
    #[arg(long, env = "EGO_RPC", default_value = DEFAULT_RPC, global = true, help = "The Ego node to read from")]
    rpc: String,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    #[command(about = "Add a computer by a name you choose and its wallet address")]
    Add { name: String, address: String },
    #[command(about = "Remove a computer")]
    Remove { name: String },
    #[command(about = "List the saved computers")]
    List,
    #[command(about = "Show every computer's balance and rewards, and the total (the default)")]
    Show {
        #[arg(long, help = "Print JSON instead of a table")]
        json: bool,
    },
    #[command(about = "Show the table and keep it up to date")]
    Watch {
        #[arg(long, default_value_t = 60, help = "Seconds between refreshes")]
        every: u64,
    },
    #[command(about = "Print this computer's Ego Desktop wallet address, to add it on your main computer")]
    Here,
}

#[derive(Serialize, Deserialize, Default)]
struct Store {
    rigs: Vec<Rig>,
}

#[derive(Serialize, Deserialize, Clone)]
struct Rig {
    name: String,
    address: String,
}

#[derive(Serialize, Clone)]
struct Report {
    name: String,
    address: String,
    balance_uegoc: u64,
    rewards_24h_uegoc: u64,
    rewards_7d_uegoc: u64,
    last_reward_at: Option<i64>,
    status: &'static str,
    error: Option<String>,
}

#[derive(Serialize, Default)]
struct Totals {
    computers: usize,
    earning: usize,
    balance_uegoc: u64,
    rewards_24h_uegoc: u64,
    rewards_7d_uegoc: u64,
}

struct Health {
    height: u64,
    tip: u64,
}

#[derive(Default, Debug, PartialEq)]
struct Sums {
    day: u64,
    week: u64,
    last: Option<i64>,
    oldest: Option<i64>,
}

struct Node {
    http: reqwest::blocking::Client,
    url: String,
}

fn home() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

fn env_dir(name: &str) -> Option<PathBuf> {
    std::env::var_os(name).filter(|v| !v.is_empty()).map(PathBuf::from)
}

fn config_dir() -> PathBuf {
    if cfg!(windows) {
        if let Some(d) = env_dir("APPDATA") {
            return d;
        }
    }
    if cfg!(target_os = "macos") {
        return home().join("Library").join("Application Support");
    }
    env_dir("XDG_CONFIG_HOME").unwrap_or_else(|| home().join(".config"))
}

fn ego_desktop_dir() -> PathBuf {
    if let Some(d) = env_dir("EGO_DATA_DIR") {
        return d;
    }
    let base = if cfg!(windows) {
        env_dir("APPDATA").unwrap_or_else(home)
    } else if cfg!(target_os = "macos") {
        home().join("Library").join("Application Support")
    } else {
        env_dir("XDG_DATA_HOME").unwrap_or_else(|| home().join(".local").join("share"))
    };
    base.join("EgoDesktop")
}

impl Store {
    fn path() -> PathBuf {
        env_dir("EGO_RIGS_FILE").unwrap_or_else(|| config_dir().join("ego-rigs").join("rigs.json"))
    }

    fn load() -> Result<Self> {
        let p = Self::path();
        match fs::read_to_string(&p) {
            Ok(s) => serde_json::from_str(&s).with_context(|| format!("{} is not a valid list of computers", p.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("cannot read {}", p.display())),
        }
    }

    fn save(&self) -> Result<()> {
        let p = Self::path();
        if let Some(d) = p.parent() {
            fs::create_dir_all(d).with_context(|| format!("cannot create {}", d.display()))?;
        }
        let tmp = p.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_string_pretty(self)?).with_context(|| format!("cannot write {}", tmp.display()))?;
        fs::rename(&tmp, &p).with_context(|| format!("cannot write {}", p.display()))?;
        Ok(())
    }
}

impl Node {
    fn new(url: &str) -> Result<Self> {
        let http = reqwest::blocking::Client::builder().timeout(Duration::from_secs(60)).build()?;
        Ok(Self { http, url: url.trim_end_matches('/').to_string() })
    }

    fn unreachable(&self) -> String {
        format!(
            "no Ego node answered at {}. Start Ego Desktop on this computer, or point --rpc at a node you run",
            self.url
        )
    }

    fn call(&self, method: &str, params: Value) -> Result<Value> {
        let body = json!({ "jsonrpc": "2.0", "id": 1, "method": method, "params": params });
        let resp: Value = self
            .http
            .post(format!("{}/", self.url))
            .json(&body)
            .send()
            .with_context(|| self.unreachable())?
            .error_for_status()?
            .json()
            .context("the node's answer was not JSON")?;
        if let Some(e) = resp.get("error").filter(|e| !e.is_null()) {
            bail!("{} failed: {}", method, e["message"].as_str().unwrap_or("unknown error"));
        }
        Ok(resp.get("result").cloned().unwrap_or(Value::Null))
    }

    fn health(&self) -> Result<Health> {
        let v: Value = self
            .http
            .get(format!("{}/health", self.url))
            .send()
            .with_context(|| self.unreachable())?
            .error_for_status()?
            .json()
            .context("the node's answer was not JSON")?;
        let height = v["block_height"].as_u64().unwrap_or(0);
        Ok(Health { height, tip: v["chain_tip"].as_u64().unwrap_or(height) })
    }
}

fn now() -> i64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0)
}

fn seconds(t: i64) -> i64 {
    if t > 100_000_000_000 {
        t / 1_000
    } else {
        t
    }
}

fn valid_address(a: &str) -> bool {
    let Some((hrp, data)) = a.split_once('1') else { return false };
    matches!(hrp, "egot" | "ego") && data.len() >= 20 && data.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
}

fn sum_rewards(txs: &[Value], address: &str, now: i64) -> Sums {
    let mut s = Sums::default();
    for tx in txs {
        let ts = seconds(tx["timestamp"].as_i64().unwrap_or(0));
        s.oldest = Some(s.oldest.map_or(ts, |o| o.min(ts)));
        if tx["to"].as_str() != Some(address) || tx["from"].as_str() == Some(address) {
            continue;
        }
        let amount = tx["amount"].as_u64().unwrap_or(0);
        s.last = Some(s.last.map_or(ts, |l| l.max(ts)));
        let age = now - ts;
        if age < DAY {
            s.day += amount;
        }
        if age < WEEK {
            s.week += amount;
        }
    }
    s
}

fn rewards(node: &Node, address: &str, now: i64) -> Result<Sums> {
    let mut limit = FIRST_PAGE;
    loop {
        let list = node.call(
            "wallet.getTransactionHistory",
            json!({ "address": address, "kind": "rewards", "limit": limit }),
        )?;
        let txs = list.as_array().map(Vec::as_slice).unwrap_or(&[]);
        let sums = sum_rewards(txs, address, now);
        let complete = (txs.len() as u64) < limit || sums.oldest.is_some_and(|o| o <= now - WEEK) || limit >= MAX_PAGE;
        if complete {
            return Ok(sums);
        }
        limit = (limit * 4).min(MAX_PAGE);
    }
}

fn status_of(last: Option<i64>, now: i64) -> &'static str {
    match last.map(|t| now - t) {
        None => "no rewards yet",
        Some(a) if a < 2 * HOUR => "earning",
        Some(a) if a < DAY => "quiet",
        Some(_) => "stopped",
    }
}

fn report(node: &Node, rig: &Rig, now: i64) -> Report {
    let mut r = Report {
        name: rig.name.clone(),
        address: rig.address.clone(),
        balance_uegoc: 0,
        rewards_24h_uegoc: 0,
        rewards_7d_uegoc: 0,
        last_reward_at: None,
        status: "error",
        error: None,
    };
    let balance = node.call("wallet.getBalance", json!({ "address": rig.address }));
    let sums = rewards(node, &rig.address, now);
    match (balance, sums) {
        (Ok(b), Ok(s)) => {
            r.balance_uegoc = b["uegoc"].as_u64().unwrap_or(0);
            r.rewards_24h_uegoc = s.day;
            r.rewards_7d_uegoc = s.week;
            r.last_reward_at = s.last;
            r.status = status_of(s.last, now);
        }
        (Err(e), _) | (_, Err(e)) => r.error = Some(format!("{e:#}")),
    }
    r
}

fn fetch_all(node: &Node, rigs: &[Rig], now: i64) -> Vec<Report> {
    let mut out = Vec::with_capacity(rigs.len());
    for chunk in rigs.chunks(PARALLEL) {
        std::thread::scope(|s| {
            let handles: Vec<_> = chunk.iter().map(|rig| s.spawn(move || report(node, rig, now))).collect();
            for (rig, h) in chunk.iter().zip(handles) {
                out.push(h.join().unwrap_or_else(|_| Report {
                    name: rig.name.clone(),
                    address: rig.address.clone(),
                    balance_uegoc: 0,
                    rewards_24h_uegoc: 0,
                    rewards_7d_uegoc: 0,
                    last_reward_at: None,
                    status: "error",
                    error: Some("the lookup crashed".into()),
                }));
            }
        });
    }
    out
}

fn totals(reports: &[Report]) -> Totals {
    let mut t = Totals { computers: reports.len(), ..Totals::default() };
    for r in reports {
        t.balance_uegoc += r.balance_uegoc;
        t.rewards_24h_uegoc += r.rewards_24h_uegoc;
        t.rewards_7d_uegoc += r.rewards_7d_uegoc;
        if r.status == "earning" {
            t.earning += 1;
        }
    }
    t
}

fn group(n: u64) -> String {
    let s = n.to_string();
    let mut out = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn egoc(uegoc: u64) -> String {
    format!("{}.{:02}", group(uegoc / 1_000_000), (uegoc % 1_000_000) / 10_000)
}

fn ago(last: Option<i64>, now: i64) -> String {
    let Some(t) = last else { return "never".into() };
    let a = (now - t).max(0);
    if a < 60 {
        "just now".into()
    } else if a < HOUR {
        format!("{} min ago", a / 60)
    } else if a < DAY {
        format!("{} h ago", a / HOUR)
    } else {
        format!("{} days ago", a / DAY)
    }
}

fn short(a: &str) -> String {
    if a.len() <= 20 {
        a.to_string()
    } else {
        format!("{}...{}", &a[..10], &a[a.len() - 6..])
    }
}

fn paint(status: &str, text: &str) -> String {
    match status {
        "earning" => text.green().to_string(),
        "quiet" => text.yellow().to_string(),
        "stopped" | "error" => text.red().to_string(),
        _ => text.dimmed().to_string(),
    }
}

fn render(node: &Node, rigs: &[Rig]) -> Result<String> {
    let health = node.health()?;
    let now = now();
    let reports = fetch_all(node, rigs, now);
    let t = totals(&reports);

    let head: [String; 7] = ["Computer", "Address", "Balance", "Last 24 h", "Last 7 days", "Last reward", "Status"].map(String::from);
    let rows: Vec<[String; 7]> = reports
        .iter()
        .map(|r| {
            [
                r.name.clone(),
                short(&r.address),
                egoc(r.balance_uegoc),
                egoc(r.rewards_24h_uegoc),
                egoc(r.rewards_7d_uegoc),
                ago(r.last_reward_at, now),
                r.status.to_string(),
            ]
        })
        .collect();
    let total: [String; 7] = [
        "All computers".into(),
        computers(t.computers),
        egoc(t.balance_uegoc),
        egoc(t.rewards_24h_uegoc),
        egoc(t.rewards_7d_uegoc),
        String::new(),
        format!("{} earning", t.earning),
    ];

    let mut w = [0usize; 7];
    for row in std::iter::once(&head).chain(rows.iter()).chain(std::iter::once(&total)) {
        for (i, c) in row.iter().enumerate() {
            w[i] = w[i].max(c.chars().count());
        }
    }
    let right = [false, false, true, true, true, false, false];
    let cells = |row: &[String; 7]| -> Vec<String> {
        row.iter()
            .enumerate()
            .map(|(i, c)| if right[i] { format!("{:>1$}", c, w[i]) } else { format!("{:<1$}", c, w[i]) })
            .collect()
    };

    let mut out = String::new();
    out.push_str(&format!("{}\n", cells(&head).join("  ").trim_end().bold()));
    for (r, row) in reports.iter().zip(&rows) {
        let mut c = cells(row);
        c[6] = paint(r.status, &c[6]);
        out.push_str(&format!("{}\n", c.join("  ").trim_end()));
        if let Some(e) = &r.error {
            out.push_str(&format!("  {}\n", e.red()));
        }
    }
    out.push_str(&format!("{}\n", "-".repeat(w.iter().sum::<usize>() + 2 * (w.len() - 1))));
    out.push_str(&format!("{}\n\n", cells(&total).join("  ").trim_end().bold()));
    out.push_str(&format!("Amounts are in EGOC. Average over the last 7 days: {} EGOC a day.\n", egoc(t.rewards_7d_uegoc / 7)));
    out.push_str(&format!("Read from the Ego node at {} (block {}).\n", node.url, group(health.height)));
    if health.tip > health.height + BEHIND_BLOCKS {
        out.push_str(&format!(
            "{}\n",
            format!("That node is still catching up ({} blocks behind), so recent rewards may be missing.", health.tip - health.height).yellow()
        ));
    }
    Ok(out)
}

fn hostname() -> String {
    let raw = std::env::var("COMPUTERNAME")
        .or_else(|_| std::env::var("HOSTNAME"))
        .ok()
        .or_else(|| fs::read_to_string("/etc/hostname").ok())
        .unwrap_or_default();
    let name: String = raw.trim().chars().map(|c| if c.is_whitespace() { '-' } else { c }).collect();
    if name.is_empty() {
        "rig".into()
    } else {
        name.to_lowercase()
    }
}

fn here() -> Result<()> {
    let dir = ego_desktop_dir();
    let mut wallets: Vec<(String, String, bool)> = Vec::new();
    if let Ok(s) = fs::read_to_string(dir.join("wallets.json")) {
        let v: Value = serde_json::from_str(&s).with_context(|| format!("{} is not valid JSON", dir.join("wallets.json").display()))?;
        let active = v["active_id"].as_str().unwrap_or("wallet_0").to_string();
        for w in v["wallets"].as_array().into_iter().flatten() {
            let addr = w["address"].as_str().unwrap_or_default();
            if addr.is_empty() {
                continue;
            }
            wallets.push((w["name"].as_str().unwrap_or_default().to_string(), addr.to_string(), w["id"].as_str() == Some(active.as_str())));
        }
    }
    if wallets.is_empty() {
        if let Ok(s) = fs::read_to_string(dir.join("wallet_0").join("ledger.json")) {
            let v: Value = serde_json::from_str(&s).unwrap_or(Value::Null);
            if let Some(a) = v["address"].as_str().filter(|a| !a.is_empty()) {
                wallets.push((String::new(), a.to_string(), true));
            }
        }
    }
    if wallets.is_empty() {
        bail!("no Ego Desktop wallet found in {}. Open Ego Desktop on this computer and create a wallet first", dir.display());
    }
    for (name, addr, active) in &wallets {
        let label = if *active { " (in use)" } else { "" };
        println!("{addr}{label}  {name}");
    }
    let pick = wallets.iter().find(|w| w.2).unwrap_or(&wallets[0]);
    println!("\nOn your main computer, run:\n  ego-rigs add {} {}", hostname(), pick.1);
    Ok(())
}

fn computers(n: usize) -> String {
    if n == 1 {
        "1 computer".into()
    } else {
        format!("{n} computers")
    }
}

fn no_rigs() {
    println!("No computers saved yet.");
    println!("On each computer run `ego-rigs here`, then on this one run `ego-rigs add <name> <address>`.");
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd.unwrap_or(Cmd::Show { json: false }) {
        Cmd::Add { name, address } => {
            let name = name.trim().to_string();
            let address = address.trim().to_string();
            if name.is_empty() {
                bail!("give the computer a name");
            }
            if !valid_address(&address) {
                bail!("{address} does not look like an Ego wallet address (they start with egot1)");
            }
            let mut store = Store::load()?;
            if let Some(r) = store.rigs.iter().find(|r| r.address == address && !r.name.eq_ignore_ascii_case(&name)) {
                bail!("that address is already saved as {}", r.name);
            }
            match store.rigs.iter_mut().find(|r| r.name.eq_ignore_ascii_case(&name)) {
                Some(r) => {
                    r.address = address;
                    println!("Updated {name}.");
                }
                None => {
                    store.rigs.push(Rig { name: name.clone(), address });
                    println!("Added {name}. {} saved.", computers(store.rigs.len()));
                }
            }
            store.save()?;
        }
        Cmd::Remove { name } => {
            let mut store = Store::load()?;
            let before = store.rigs.len();
            store.rigs.retain(|r| !r.name.eq_ignore_ascii_case(name.trim()));
            if store.rigs.len() == before {
                bail!("no computer called {name}");
            }
            store.save()?;
            println!("Removed {name}. {} saved.", computers(store.rigs.len()));
        }
        Cmd::List => {
            let store = Store::load()?;
            if store.rigs.is_empty() {
                no_rigs();
            }
            for r in &store.rigs {
                println!("{}  {}", r.name, r.address);
            }
            println!("Saved in {}", Store::path().display());
        }
        Cmd::Show { json } => {
            let store = Store::load()?;
            let node = Node::new(&cli.rpc)?;
            if json {
                let health = node.health()?;
                let now = now();
                let reports = fetch_all(&node, &store.rigs, now);
                let t = totals(&reports);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "node": node.url,
                        "block": health.height,
                        "checked_at": now,
                        "computers": reports,
                        "total": t,
                    }))?
                );
            } else if store.rigs.is_empty() {
                no_rigs();
            } else {
                print!("{}", render(&node, &store.rigs)?);
            }
        }
        Cmd::Watch { every } => {
            let store = Store::load()?;
            if store.rigs.is_empty() {
                no_rigs();
                return Ok(());
            }
            let node = Node::new(&cli.rpc)?;
            let every = every.max(10);
            loop {
                let screen = render(&node, &store.rigs).unwrap_or_else(|e| format!("{}\n", format!("{e:#}").red()));
                print!("\x1b[2J\x1b[H{screen}Refreshing every {every} s. Press Ctrl+C to stop.\n");
                std::thread::sleep(Duration::from_secs(every));
            }
        }
        Cmd::Here => here()?,
    }
    Ok(())
}

fn main() {
    #[cfg(windows)]
    let _ = colored::control::set_virtual_terminal(true);
    if let Err(e) = run() {
        eprintln!("{} {e:#}", "error:".red().bold());
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ME: &str = "egot1qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqq";

    #[test]
    fn amounts_print_as_egoc_with_thousands() {
        assert_eq!(egoc(0), "0.00");
        assert_eq!(egoc(45_231), "0.04");
        assert_eq!(egoc(109_122_675), "109.12");
        assert_eq!(egoc(1_234_567_890_000), "1,234,567.89");
    }

    #[test]
    fn rewards_split_into_the_last_day_and_week() {
        let now = 1_800_000_000;
        let txs = vec![
            json!({ "to": ME, "from": "", "amount": 1_000_000, "timestamp": now - 60 }),
            json!({ "to": ME, "from": "", "amount": 2_000_000, "timestamp": (now - 2 * DAY) * 1_000 }),
            json!({ "to": ME, "from": "", "amount": 4_000_000, "timestamp": now - 8 * DAY }),
            json!({ "to": "egot1someoneelse000000000000", "from": ME, "amount": 9_000_000, "timestamp": now - 30 }),
        ];
        let s = sum_rewards(&txs, ME, now);
        assert_eq!(s.day, 1_000_000);
        assert_eq!(s.week, 3_000_000);
        assert_eq!(s.last, Some(now - 60));
        assert_eq!(s.oldest, Some(now - 8 * DAY));
    }

    #[test]
    fn status_follows_the_time_since_the_last_reward() {
        let now = 1_800_000_000;
        assert_eq!(status_of(None, now), "no rewards yet");
        assert_eq!(status_of(Some(now - 300), now), "earning");
        assert_eq!(status_of(Some(now - 5 * HOUR), now), "quiet");
        assert_eq!(status_of(Some(now - 2 * DAY), now), "stopped");
    }

    #[test]
    fn only_ego_addresses_are_accepted() {
        assert!(valid_address("egot1yq346p0gusvabcdefghjklmnpqrstuvwxyz02"));
        assert!(!valid_address("egot1short"));
        assert!(!valid_address("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"));
        assert!(!valid_address("EGOT1YQ346P0GUSVABCDEFGHJKLMNPQRSTUVWXYZ02"));
    }

    #[test]
    fn totals_add_up_every_computer() {
        let r = |b, d, w, s| Report {
            name: "a".into(),
            address: ME.into(),
            balance_uegoc: b,
            rewards_24h_uegoc: d,
            rewards_7d_uegoc: w,
            last_reward_at: None,
            status: s,
            error: None,
        };
        let t = totals(&[r(1, 2, 3, "earning"), r(10, 20, 30, "stopped")]);
        assert_eq!((t.computers, t.earning, t.balance_uegoc, t.rewards_24h_uegoc, t.rewards_7d_uegoc), (2, 1, 11, 22, 33));
    }
}
