use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use colored::Colorize;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const DEFAULT_RPC: &str = "http://127.0.0.1:47395";
const HOUR: i64 = 3_600;
const DAY: i64 = 24 * HOUR;
const WEEK: i64 = 7 * DAY;
const ONLINE_SECS: i64 = 15 * 60;
const FIRST_PAGE: u64 = 5_000;
const MAX_PAGE: u64 = 1_000_000;
const PARALLEL: usize = 8;
const BEHIND_BLOCKS: u64 = 30;
const RESTART_EXIT_CODE: i32 = 75;

#[derive(Parser)]
#[command(name = "ego-rigs", version, about = "Run Ego nodes on servers and other computers, and see what all of them earn as one")]
struct Cli {
    #[arg(long, env = "EGO_RPC", default_value = DEFAULT_RPC, global = true, help = "The Ego node to read from")]
    rpc: String,
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    #[command(about = "Run the Ego node on this computer in server mode, and start it again if it stops to restart")]
    Start {
        #[arg(long, env = "EGO_DESKTOP_APP", help = "Path to Ego Desktop (the .exe, the app's binary or the .AppImage)")]
        app: Option<PathBuf>,
    },
    #[command(about = "Show the 24 words that restore this computer's wallet")]
    Phrase {
        #[arg(long, env = "EGO_DESKTOP_APP", help = "Path to Ego Desktop (the .exe, the app's binary or the .AppImage)")]
        app: Option<PathBuf>,
    },
    #[command(about = "Print this computer's Ego Desktop wallet address, to add it on your main computer")]
    Here,
    #[command(about = "Add a computer by a name you choose and its wallet address")]
    Add { name: String, address: String },
    #[command(about = "Remove a computer")]
    Remove { name: String },
    #[command(about = "List the saved computers")]
    List,
    #[command(about = "Show every computer's balance, rewards and state, and the total (the default)")]
    Show {
        #[arg(long, help = "Print JSON instead of a table")]
        json: bool,
    },
    #[command(about = "Show the table and keep it up to date")]
    Watch {
        #[arg(long, default_value_t = 60, help = "Seconds between refreshes")]
        every: u64,
    },
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
    last_seen_at: Option<i64>,
    version: Option<String>,
    status: &'static str,
    error: Option<String>,
}

#[derive(Serialize, Default)]
struct Totals {
    computers: usize,
    online: usize,
    earning: usize,
    balance_uegoc: u64,
    rewards_24h_uegoc: u64,
    rewards_7d_uegoc: u64,
}

struct Health {
    height: u64,
    tip: u64,
    version: Option<String>,
}

#[derive(Default, Debug, PartialEq)]
struct Sums {
    day: u64,
    week: u64,
    last: Option<i64>,
    oldest: Option<i64>,
}

#[derive(Clone, Default)]
struct Seen {
    at: Option<i64>,
    version: Option<String>,
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
            "no Ego node answered at {}. Start Ego Desktop on this computer (or `ego-rigs start`), or point --rpc at a node you run",
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
        Ok(Health {
            height,
            tip: v["chain_tip"].as_u64().unwrap_or(height),
            version: v["version"].as_str().map(String::from),
        })
    }

    fn seen(&self, rigs: &[Rig]) -> Option<HashMap<String, Seen>> {
        let addresses: Vec<&str> = rigs.iter().map(|r| r.address.as_str()).collect();
        let list = self.call("node.seen", json!({ "addresses": addresses })).ok()?;
        let mut out = HashMap::new();
        for item in list.as_array()? {
            let Some(address) = item["address"].as_str() else { continue };
            out.insert(
                address.to_string(),
                Seen { at: item["last_seen"].as_i64().map(seconds), version: item["version"].as_str().map(String::from) },
            );
        }
        Some(out)
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

fn version_parts(v: &str) -> Vec<u64> {
    v.trim_start_matches('v').split('.').map(|p| p.parse().unwrap_or(0)).collect()
}

fn older_than(v: &str, reference: &str) -> bool {
    version_parts(v) < version_parts(reference)
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

fn status_of(last_reward: Option<i64>, seen: Option<&Seen>, now: i64) -> &'static str {
    let rewarded = last_reward.map(|t| now - t);
    if rewarded.is_some_and(|a| a < 2 * HOUR) {
        return "earning";
    }
    if let Some(seen) = seen {
        let online = seen.at.is_some_and(|t| now - t < ONLINE_SECS);
        return match (online, last_reward) {
            (true, None) => "online, no rewards yet",
            (true, Some(_)) => "online, not earning",
            (false, _) => "offline",
        };
    }
    match rewarded {
        None => "no rewards yet",
        Some(a) if a < DAY => "quiet",
        Some(_) => "stopped",
    }
}

fn blank_report(rig: &Rig) -> Report {
    Report {
        name: rig.name.clone(),
        address: rig.address.clone(),
        balance_uegoc: 0,
        rewards_24h_uegoc: 0,
        rewards_7d_uegoc: 0,
        last_reward_at: None,
        last_seen_at: None,
        version: None,
        status: "error",
        error: None,
    }
}

fn report(node: &Node, rig: &Rig, seen: Option<&Seen>, now: i64) -> Report {
    let mut r = blank_report(rig);
    r.last_seen_at = seen.and_then(|s| s.at);
    r.version = seen.and_then(|s| s.version.clone());
    let balance = node.call("wallet.getBalance", json!({ "address": rig.address }));
    let sums = rewards(node, &rig.address, now);
    match (balance, sums) {
        (Ok(b), Ok(s)) => {
            r.balance_uegoc = b["uegoc"].as_u64().unwrap_or(0);
            r.rewards_24h_uegoc = s.day;
            r.rewards_7d_uegoc = s.week;
            r.last_reward_at = s.last;
            r.status = status_of(s.last, seen, now);
        }
        (Err(e), _) | (_, Err(e)) => r.error = Some(format!("{e:#}")),
    }
    r
}

fn fetch_all(node: &Node, rigs: &[Rig], now: i64) -> (Vec<Report>, bool) {
    let seen = node.seen(rigs);
    let known = seen.is_some();
    let seen = seen.unwrap_or_default();
    let mut out = Vec::with_capacity(rigs.len());
    for chunk in rigs.chunks(PARALLEL) {
        std::thread::scope(|s| {
            let handles: Vec<_> = chunk
                .iter()
                .map(|rig| {
                    let entry = if known { Some(seen.get(&rig.address).cloned().unwrap_or_default()) } else { None };
                    s.spawn(move || report(node, rig, entry.as_ref(), now))
                })
                .collect();
            for (rig, h) in chunk.iter().zip(handles) {
                out.push(h.join().unwrap_or_else(|_| {
                    let mut r = blank_report(rig);
                    r.error = Some("the lookup crashed".into());
                    r
                }));
            }
        });
    }
    (out, known)
}

fn totals(reports: &[Report], now: i64) -> Totals {
    let mut t = Totals { computers: reports.len(), ..Totals::default() };
    for r in reports {
        t.balance_uegoc += r.balance_uegoc;
        t.rewards_24h_uegoc += r.rewards_24h_uegoc;
        t.rewards_7d_uegoc += r.rewards_7d_uegoc;
        if r.status == "earning" {
            t.earning += 1;
        }
        if r.last_seen_at.is_some_and(|at| now - at < ONLINE_SECS) {
            t.online += 1;
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

fn ago(at: Option<i64>, now: i64) -> String {
    let Some(t) = at else { return "never".into() };
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

fn computers(n: usize) -> String {
    if n == 1 {
        "1 computer".into()
    } else {
        format!("{n} computers")
    }
}

fn paint(status: &str, text: &str) -> String {
    match status {
        "earning" => text.green().to_string(),
        "online, no rewards yet" | "online, not earning" => text.cyan().to_string(),
        "quiet" => text.yellow().to_string(),
        "stopped" | "offline" | "error" => text.red().to_string(),
        _ => text.dimmed().to_string(),
    }
}

const COLUMNS: usize = 9;

fn render(node: &Node, rigs: &[Rig]) -> Result<String> {
    let health = node.health()?;
    let now = now();
    let (reports, seen_known) = fetch_all(node, rigs, now);
    let t = totals(&reports, now);

    let head: [String; COLUMNS] =
        ["Computer", "Address", "Balance", "Last 24 h", "Last 7 days", "Last reward", "Seen", "Version", "Status"].map(String::from);
    let rows: Vec<[String; COLUMNS]> = reports
        .iter()
        .map(|r| {
            [
                r.name.clone(),
                short(&r.address),
                egoc(r.balance_uegoc),
                egoc(r.rewards_24h_uegoc),
                egoc(r.rewards_7d_uegoc),
                ago(r.last_reward_at, now),
                if seen_known { ago(r.last_seen_at, now) } else { "-".into() },
                r.version.clone().unwrap_or_else(|| "-".into()),
                r.status.to_string(),
            ]
        })
        .collect();
    let total: [String; COLUMNS] = [
        "All computers".into(),
        computers(t.computers),
        egoc(t.balance_uegoc),
        egoc(t.rewards_24h_uegoc),
        egoc(t.rewards_7d_uegoc),
        String::new(),
        if seen_known { format!("{} online", t.online) } else { String::new() },
        String::new(),
        format!("{} earning", t.earning),
    ];

    let mut w = [0usize; COLUMNS];
    for row in std::iter::once(&head).chain(rows.iter()).chain(std::iter::once(&total)) {
        for (i, c) in row.iter().enumerate() {
            w[i] = w[i].max(c.chars().count());
        }
    }
    let right = [false, false, true, true, true, false, false, false, false];
    let cells = |row: &[String; COLUMNS]| -> Vec<String> {
        row.iter()
            .enumerate()
            .map(|(i, c)| if right[i] { format!("{:>1$}", c, w[i]) } else { format!("{:<1$}", c, w[i]) })
            .collect()
    };

    let mut out = String::new();
    out.push_str(&format!("{}\n", cells(&head).join("  ").trim_end().bold()));
    for (r, row) in reports.iter().zip(&rows) {
        let mut c = cells(row);
        if let (Some(v), Some(main)) = (&r.version, &health.version) {
            if older_than(v, main) {
                c[7] = c[7].yellow().to_string();
            }
        }
        c[8] = paint(r.status, &c[8]);
        out.push_str(&format!("{}\n", c.join("  ").trim_end()));
        if let Some(e) = &r.error {
            out.push_str(&format!("  {}\n", e.red()));
        }
    }
    out.push_str(&format!("{}\n", "-".repeat(w.iter().sum::<usize>() + 2 * (COLUMNS - 1))));
    out.push_str(&format!("{}\n\n", cells(&total).join("  ").trim_end().bold()));
    out.push_str(&format!("Amounts are in EGOC. Average over the last 7 days: {} EGOC a day.\n", egoc(t.rewards_7d_uegoc / 7)));
    let version = health.version.as_deref().map(|v| format!(", Ego Desktop {v}")).unwrap_or_default();
    out.push_str(&format!("Read from the Ego node at {} (block {}{}).\n", node.url, group(health.height), version));
    if !seen_known {
        out.push_str(&format!(
            "{}\n",
            "That node runs an older Ego Desktop, so Seen and Version stay empty until it is updated.".dimmed()
        ));
    }
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
        bail!(
            "no Ego Desktop wallet found in {}. Run `ego-rigs start` once (or open Ego Desktop) to create one",
            dir.display()
        );
    }
    for (name, addr, active) in &wallets {
        let label = if *active { " (in use)" } else { "" };
        println!("{addr}{label}  {name}");
    }
    let pick = wallets.iter().find(|w| w.2).unwrap_or(&wallets[0]);
    println!("\nOn your main computer, run:\n  ego-rigs add {} {}", hostname(), pick.1);
    Ok(())
}

fn app_candidates() -> Vec<PathBuf> {
    let mut out = Vec::new();
    if cfg!(windows) {
        for base in ["ProgramFiles", "ProgramW6432", "LOCALAPPDATA"].iter().filter_map(|v| env_dir(v)) {
            out.push(base.join("Ego Desktop").join("Ego Desktop.exe"));
            out.push(base.join("Programs").join("Ego Desktop").join("Ego Desktop.exe"));
        }
    } else if cfg!(target_os = "macos") {
        for base in [PathBuf::from("/Applications"), home().join("Applications")] {
            out.push(base.join("Ego Desktop.app").join("Contents").join("MacOS").join("Ego Desktop"));
            out.push(base.join("Ego Desktop.app").join("Contents").join("MacOS").join("ego-desktop"));
        }
    } else {
        let dirs = [std::env::current_dir().unwrap_or_default(), home().join("Applications"), home().join("Downloads"), home(), PathBuf::from("/opt/ego")];
        let mut found: Vec<(SystemTime, PathBuf)> = Vec::new();
        for d in dirs {
            let Ok(entries) = fs::read_dir(&d) else { continue };
            for e in entries.flatten() {
                let name = e.file_name().to_string_lossy().to_lowercase();
                if name.contains("ego") && name.ends_with(".appimage") {
                    let modified = e.metadata().and_then(|m| m.modified()).unwrap_or(UNIX_EPOCH);
                    found.push((modified, e.path()));
                }
            }
        }
        found.sort_by(|a, b| b.0.cmp(&a.0));
        out.extend(found.into_iter().map(|(_, p)| p));
        out.push(PathBuf::from("/usr/bin/ego-desktop"));
    }
    out
}

fn find_app(given: Option<PathBuf>) -> Result<PathBuf> {
    if let Some(p) = given {
        if p.is_file() {
            return Ok(p);
        }
        bail!("{} is not a file", p.display());
    }
    app_candidates().into_iter().find(|p| p.is_file()).context(
        "Ego Desktop was not found on this computer. Install it from egoblockchain.com/download, or pass its path with --app (on Linux, the .AppImage)",
    )
}

fn app_command(app: &Path) -> Command {
    let mut cmd = Command::new(app);
    if app.extension().is_some_and(|e| e.eq_ignore_ascii_case("appimage")) {
        cmd.env("APPIMAGE_EXTRACT_AND_RUN", "1");
    }
    cmd
}

fn start(app: Option<PathBuf>) -> Result<()> {
    let app = find_app(app)?;
    println!("Starting {} in server mode. Press Ctrl+C to stop.", app.display());
    loop {
        let status = app_command(&app)
            .arg("--server")
            .env("EGO_HEADLESS", "1")
            .status()
            .with_context(|| format!("cannot start {}", app.display()))?;
        if status.code() == Some(RESTART_EXIT_CODE) {
            println!("The node asked to restart. Starting it again in 3 seconds.");
            std::thread::sleep(Duration::from_secs(3));
            continue;
        }
        if status.success() {
            return Ok(());
        }
        bail!("the node stopped ({status})");
    }
}

fn phrase(app: Option<PathBuf>) -> Result<()> {
    let app = find_app(app)?;
    let status = app_command(&app).arg("--recovery-phrase").status().with_context(|| format!("cannot start {}", app.display()))?;
    if !status.success() {
        bail!("Ego Desktop could not show the recovery phrase ({status}). Update Ego Desktop and try again");
    }
    Ok(())
}

fn no_rigs() {
    println!("No computers saved yet.");
    println!("On each computer run `ego-rigs here`, then on this one run `ego-rigs add <name> <address>`.");
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd.unwrap_or(Cmd::Show { json: false }) {
        Cmd::Start { app } => start(app)?,
        Cmd::Phrase { app } => phrase(app)?,
        Cmd::Here => here()?,
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
                let (reports, _) = fetch_all(&node, &store.rigs, now);
                let t = totals(&reports, now);
                println!(
                    "{}",
                    serde_json::to_string_pretty(&json!({
                        "node": node.url,
                        "block": health.height,
                        "node_version": health.version,
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
    fn without_node_sightings_the_status_follows_the_last_reward() {
        let now = 1_800_000_000;
        assert_eq!(status_of(None, None, now), "no rewards yet");
        assert_eq!(status_of(Some(now - 300), None, now), "earning");
        assert_eq!(status_of(Some(now - 5 * HOUR), None, now), "quiet");
        assert_eq!(status_of(Some(now - 2 * DAY), None, now), "stopped");
    }

    #[test]
    fn with_node_sightings_online_and_offline_are_told_apart() {
        let now = 1_800_000_000;
        let online = Seen { at: Some(now - 120), version: Some("0.3.701".into()) };
        let gone = Seen { at: Some(now - 2 * HOUR), version: Some("0.3.700".into()) };
        let never = Seen::default();
        assert_eq!(status_of(Some(now - 300), Some(&gone), now), "earning");
        assert_eq!(status_of(None, Some(&online), now), "online, no rewards yet");
        assert_eq!(status_of(Some(now - 5 * HOUR), Some(&online), now), "online, not earning");
        assert_eq!(status_of(Some(now - 5 * HOUR), Some(&gone), now), "offline");
        assert_eq!(status_of(None, Some(&never), now), "offline");
    }

    #[test]
    fn versions_compare_as_numbers() {
        assert!(older_than("0.3.699", "0.3.701"));
        assert!(older_than("0.3.99", "0.3.621"));
        assert!(!older_than("0.3.701", "0.3.701"));
        assert!(!older_than("0.4.0", "0.3.999"));
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
        let now = 1_800_000_000;
        let r = |b, d, w, s, seen: Option<i64>| Report {
            name: "a".into(),
            address: ME.into(),
            balance_uegoc: b,
            rewards_24h_uegoc: d,
            rewards_7d_uegoc: w,
            last_reward_at: None,
            last_seen_at: seen,
            version: None,
            status: s,
            error: None,
        };
        let t = totals(&[r(1, 2, 3, "earning", Some(now - 60)), r(10, 20, 30, "offline", Some(now - DAY))], now);
        assert_eq!(
            (t.computers, t.online, t.earning, t.balance_uegoc, t.rewards_24h_uegoc, t.rewards_7d_uegoc),
            (2, 1, 1, 11, 22, 33)
        );
    }
}
