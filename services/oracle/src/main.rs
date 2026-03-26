use axum::{
    extract::{Path, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use chrono::Utc;
use once_cell::sync::Lazy;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::Arc,
    time::Duration,
};
use tokio::sync::RwLock;
use tower_http::cors::{Any, CorsLayer};
use tracing::{error, info, warn};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PriceEntry {
    pub usd: f64,
    pub updated_at: i64,

    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub stale: bool,
}

type PriceMap = HashMap<String, PriceEntry>;

#[derive(Clone)]
pub struct AppState {
    pub prices: Arc<RwLock<PriceMap>>,
    pub client: Client,
}

const EGOC_USD: f64 = 0.01;
const EGOC_SUPPLY: u64 = 1_000_000_000;
const EGOC_MARKET_CAP: f64 = EGOC_USD * EGOC_SUPPLY as f64;

#[allow(dead_code)]
static COINGECKO_IDS: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("BTC", "bitcoin");
    m.insert("ETH", "ethereum");
    m.insert("SOL", "solana");
    m.insert("BNB", "binancecoin");
    m.insert("MATIC", "matic-network");
    m
});

static BINANCE_SYMBOLS: Lazy<HashMap<&'static str, &'static str>> = Lazy::new(|| {
    let mut m = HashMap::new();
    m.insert("BTC", "BTCUSDT");
    m.insert("ETH", "ETHUSDT");
    m.insert("SOL", "SOLUSDT");
    m.insert("BNB", "BNBUSDT");
    m.insert("MATIC", "MATICUSDT");
    m
});

async fn fetch_coingecko(client: &Client) -> anyhow::Result<HashMap<String, f64>> {
    let url = "https://api.coingecko.com/api/v3/simple/price\
               ?ids=ethereum,bitcoin,solana,binancecoin,matic-network\
               &vs_currencies=usd";

    let resp: Value = client
        .get(url)
        .timeout(Duration::from_secs(10))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let mut out = HashMap::new();
    let pairs: &[(&str, &str)] = &[
        ("bitcoin", "BTC"),
        ("ethereum", "ETH"),
        ("solana", "SOL"),
        ("binancecoin", "BNB"),
        ("matic-network", "MATIC"),
    ];
    for (id, sym) in pairs {
        if let Some(price) = resp[id]["usd"].as_f64() {
            out.insert(sym.to_string(), price);
        }
    }
    Ok(out)
}

async fn fetch_binance(client: &Client) -> anyhow::Result<HashMap<String, f64>> {
    #[derive(Deserialize)]
    struct Ticker {
        symbol: String,
        price: String,
    }

    let tickers: Vec<Ticker> = client
        .get("https://api.binance.com/api/v3/ticker/price")
        .timeout(Duration::from_secs(10))
        .send()
        .await?
        .error_for_status()?
        .json()
        .await?;

    let reverse: HashMap<&str, &str> = BINANCE_SYMBOLS
        .iter()
        .map(|(sym, ticker)| (*ticker, *sym))
        .collect();

    let mut out = HashMap::new();
    for t in &tickers {
        if let Some(&sym) = reverse.get(t.symbol.as_str()) {
            if let Ok(price) = t.price.parse::<f64>() {
                out.insert(sym.to_string(), price);
            }
        }
    }
    Ok(out)
}

fn average_maps(
    a: HashMap<String, f64>,
    b: HashMap<String, f64>,
) -> HashMap<String, f64> {
    let mut result = HashMap::new();
    let all_keys: std::collections::HashSet<String> = a.keys().chain(b.keys()).cloned().collect();
    for key in all_keys {
        let price = match (a.get(&key), b.get(&key)) {
            (Some(&pa), Some(&pb)) => (pa + pb) / 2.0,
            (Some(&pa), None) => pa,
            (None, Some(&pb)) => pb,
            (None, None) => continue,
        };
        result.insert(key, price);
    }
    result
}

async fn refresh_prices(state: AppState) {
    let now = Utc::now().timestamp();

    let cg_result = fetch_coingecko(&state.client).await;
    let bn_result = fetch_binance(&state.client).await;

    let (merged, stale) = match (cg_result, bn_result) {
        (Ok(cg), Ok(bn)) => {
            info!("Fetched prices from CoinGecko and Binance");
            (average_maps(cg, bn), false)
        }
        (Ok(cg), Err(e)) => {
            warn!("Binance failed ({}), using CoinGecko only", e);
            (cg, false)
        }
        (Err(e), Ok(bn)) => {
            warn!("CoinGecko failed ({}), using Binance only", e);
            (bn, false)
        }
        (Err(e1), Err(e2)) => {
            error!("Both price sources failed: CoinGecko={} Binance={}", e1, e2);

            (HashMap::new(), true)
        }
    };

    let mut prices = state.prices.write().await;

    if stale {

        for entry in prices.values_mut() {
            entry.stale = true;
        }
        return;
    }

    for (sym, usd) in merged {
        prices.insert(
            sym,
            PriceEntry {
                usd,
                updated_at: now,
                stale: false,
            },
        );
    }

    prices.insert(
        "EGOC".to_string(),
        PriceEntry {
            usd: EGOC_USD,
            updated_at: now,
            stale: false,
        },
    );
}

async fn price_refresh_task(state: AppState) {

    loop {
        refresh_prices(state.clone()).await;
        tokio::time::sleep(Duration::from_secs(30)).await;
    }
}

async fn handle_prices(State(state): State<AppState>) -> impl IntoResponse {
    let prices = state.prices.read().await;
    Json(prices.clone())
}

async fn handle_price(
    State(state): State<AppState>,
    Path(symbol): Path<String>,
) -> impl IntoResponse {
    let sym = symbol.to_uppercase();
    let prices = state.prices.read().await;

    if let Some(entry) = prices.get(&sym) {
        let body = json!({
            "symbol": sym,
            "usd": entry.usd,
            "updated_at": entry.updated_at,
            "stale": entry.stale,
        });
        (StatusCode::OK, Json(body))
    } else {
        let body = json!({ "error": format!("symbol '{}' not found", sym) });
        (StatusCode::NOT_FOUND, Json(body))
    }
}

async fn handle_health(State(state): State<AppState>) -> impl IntoResponse {
    let prices = state.prices.read().await;
    let last_update = prices
        .values()
        .map(|e| e.updated_at)
        .max()
        .unwrap_or(0);
    Json(json!({
        "status": "ok",
        "prices_count": prices.len(),
        "last_update": last_update,
    }))
}

async fn handle_egoc(State(state): State<AppState>) -> impl IntoResponse {
    let prices = state.prices.read().await;
    let updated_at = prices
        .get("EGOC")
        .map(|e| e.updated_at)
        .unwrap_or_else(|| Utc::now().timestamp());

    Json(json!({
        "symbol":      "EGOC",
        "usd":         EGOC_USD,
        "market_cap":  EGOC_MARKET_CAP,
        "supply":      EGOC_SUPPLY,
        "updated_at":  updated_at,
    }))
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "ego_oracle=info,tower_http=warn".parse().unwrap()),
        )
        .init();

    info!("Ego Oracle starting on port 8547");

    let client = Client::builder()
        .user_agent("ego-oracle/1.0")
        .build()
        .expect("failed to build HTTP client");

    let prices: PriceMap = HashMap::new();
    let state = AppState {
        prices: Arc::new(RwLock::new(prices)),
        client,
    };

    {
        let mut p = state.prices.write().await;
        p.insert(
            "EGOC".to_string(),
            PriceEntry {
                usd: EGOC_USD,
                updated_at: Utc::now().timestamp(),
                stale: false,
            },
        );
    }

    tokio::spawn(price_refresh_task(state.clone()));

    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods(Any)
        .allow_headers(Any);

    let app = Router::new()
        .route("/prices", get(handle_prices))
        .route("/price/:symbol", get(handle_price))
        .route("/health", get(handle_health))
        .route("/egoc", get(handle_egoc))
        .layer(cors)
        .with_state(state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8547")
        .await
        .expect("failed to bind port 8547");

    info!("Listening on http://0.0.0.0:8547");
    axum::serve(listener, app)
        .await
        .expect("server error");
}
