// Ego Presale Proxy — keeps the Stripe secret key server-side.
// Deploy to any Node.js host (Railway, Render, Fly.io, VPS…).
// Set env vars: STRIPE_SECRET_KEY, PRESALE_ORIGIN (optional CORS whitelist)

const https = require('https');
const http  = require('http');
const qs    = require('querystring');

const STRIPE_KEY     = process.env.STRIPE_SECRET_KEY || '';
const CHANGENOW_KEY  = process.env.CHANGENOW_API_KEY || '';
const PORT           = parseInt(process.env.PORT || '3031', 10);
// SINGLE SOURCE OF TRUTH for the pre-sale price.
//
// This value alone decides both what the app quotes to a buyer and what the
// IOU is written for. They used to be separate numbers in separate places and
// drifted apart — the app advertised $0.50/EGOC while allocations were
// computed at $2.00, so buyers received a quarter of what they were shown.
// Nothing may hardcode a price again: the app reads it from /presale/config.
const EGOC_PRICE_USD = parseFloat(process.env.EGOC_PRICE_USD || '0.50');

// Advancing a tier is a restart of this service, not an app release.
const PRESALE_TIER_INDEX = parseInt(process.env.PRESALE_TIER_INDEX || '0', 10);
const PRESALE_LAUNCH_USD = parseFloat(process.env.PRESALE_LAUNCH_USD || '2.00');
const PRESALE_TIERS = [
  { label: 'Early Bird', price: 0.50, cap: 20_000_000 },
  { label: 'Pre-Sale A', price: 1.00, cap: 50_000_000 },
  { label: 'Pre-Sale B', price: 1.50, cap: 100_000_000 },
];
// These must match the routes the website actually serves — /success and
// /cancel in src/App.js. A URL with no matching route renders a blank SPA
// shell, which looks exactly like a broken payment to the buyer.
const SUCCESS_URL    = withSessionPlaceholder(
  process.env.SUCCESS_URL || 'https://egoblockchain.com/success'
);
const CANCEL_URL     = process.env.CANCEL_URL  || 'https://egoblockchain.com/cancel';

// The success page reads ?session_id= to verify the payment, and Stripe only
// substitutes {CHECKOUT_SESSION_ID} if we ask for it. Append it when an
// override forgets, so the page always has something to verify with.
function withSessionPlaceholder(url) {
  if (url.includes('{CHECKOUT_SESSION_ID}')) return url;
  return url + (url.includes('?') ? '&' : '?') + 'session_id={CHECKOUT_SESSION_ID}';
}
// Comma-separated allowlist of browser origins permitted to call this proxy.
// Empty/unset → '*' is sent but a warning is logged (set this before launch).
const ALLOWED_ORIGINS = (process.env.PRESALE_ORIGIN || '')
  .split(',').map(s => s.trim()).filter(Boolean);
const MAX_USD = parseFloat(process.env.PRESALE_MAX_USD || '50000');

if (!STRIPE_KEY) { console.error('ERROR: STRIPE_SECRET_KEY not set'); process.exit(1); }
if (!CHANGENOW_KEY) {
  console.warn('WARNING: CHANGENOW_API_KEY not set — /swap/* will return 503.');
}
if (ALLOWED_ORIGINS.length === 0) {
  console.warn('WARNING: PRESALE_ORIGIN not set — CORS is open to all origins. Set it before public launch.');
}

// ── minimal Stripe helper ───────────────────────────────────────────────────
function stripeRequest(method, path, data) {
  return new Promise((resolve, reject) => {
    const body   = data ? qs.stringify(data) : '';
    const auth   = Buffer.from(STRIPE_KEY + ':').toString('base64');
    const opts   = {
      hostname: 'api.stripe.com',
      path,
      method,
      headers: {
        'Authorization': `Basic ${auth}`,
        'Content-Type':  'application/x-www-form-urlencoded',
        'Content-Length': Buffer.byteLength(body),
      },
    };
    const req = https.request(opts, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => { try { resolve(JSON.parse(raw)); } catch { reject(new Error('Bad JSON')); } });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

// ── Fiat on/off-ramp ────────────────────────────────────────────────────────
// The desktop app never learns which provider is in use: it posts the asset,
// destination address and amount, and gets back a URL to open. Switching
// provider, or adding a second one, is a change here plus a restart — no app
// release, no new binary for users to install.
//
// URL shapes below follow each provider's hosted-widget docs. VERIFY against
// current docs when you activate an account — query parameter names do change,
// and a wrong one silently drops the value rather than erroring.
const RAMP_PROVIDER = (process.env.RAMP_PROVIDER || 'onramper').toLowerCase();
const RAMP_API_KEY  = process.env.RAMP_API_KEY  || '';
// Staging keys are issued on signup; production keys need business
// verification. RAMP_ENV=staging lets the whole flow be tested with test cards
// before that clears. Anything other than "staging" means real money.
const RAMP_STAGING  = (process.env.RAMP_ENV || 'production').toLowerCase() === 'staging';
// MoonPay only: HMAC secret used to sign widget URLs. Never ships in the app.
const MOONPAY_SECRET = process.env.MOONPAY_SECRET_KEY || '';

// MoonPay identifies assets by its own codes, and chain-qualifies anything that
// exists on more than one network. A plain lowercase of the ticker is wrong for
// those: BNB on BSC is "bnb_bsc", not "bnb" (which is BNB Beacon Chain — a
// different address format entirely). Verify each against MoonPay's
// /v3/currencies list before going live.
const MOONPAY_CODES = {
  BTC:  'btc',
  ETH:  'eth',
  BNB:  'bnb_bsc',
  SOL:  'sol',
  ADA:  'ada',
  XRP:  'xrp',
  TRX:  'trx',
  LTC:  'ltc',
  DOGE: 'doge',
  // Our USDT/USDC are ERC-20 on Ethereum — MoonPay's bare codes mean exactly
  // that, with other chains carrying a suffix (usdt_trx, usdc_polygon).
  USDT: 'usdt',
  USDC: 'usdc',
};

function moonpayCurrencyCode(asset, network) {
  const known = MOONPAY_CODES[String(asset).toUpperCase()];
  if (known) return known;
  const net = String(network || '').toLowerCase();
  return net && net !== 'mainnet'
    ? `${String(asset).toLowerCase()}_${net}`
    : String(asset).toLowerCase();
}

const RAMP_BUILDERS = {
  onramper({ side, asset, address, amount, fiat }) {
    const p = new URLSearchParams({
      apiKey: RAMP_API_KEY,
      mode: side,
      defaultCrypto: asset,
      defaultFiat: fiat,
    });
    if (amount) p.set('defaultAmount', String(amount));
    // Onramper takes wallets as ASSET:address pairs and locks the field so the
    // user cannot be talked into changing the destination.
    if (address) {
      p.set('wallets', `${asset}:${address}`);
      p.set('walletAddressLocked', 'true');
    }
    const host = RAMP_STAGING ? 'buy.onramper.dev' : 'buy.onramper.com';
    return `https://${host}/?${p.toString()}`;
  },

  ramp({ side, asset, network, address, amount, fiat }) {
    // Ramp names assets CHAIN_SYMBOL, e.g. ETH_USDT / BTC_BTC.
    const chainPrefix = (network || asset).toUpperCase()
      .replace('ETHEREUM', 'ETH').replace('MAINNET', 'BTC')
      .replace('SOLANA', 'SOL').replace('BSC', 'BSC');
    const swapAsset = asset === chainPrefix ? `${chainPrefix}_${asset}` : `${chainPrefix}_${asset}`;
    const p = new URLSearchParams({
      hostApiKey: RAMP_API_KEY,
      hostAppName: 'Ego Desktop',
      swapAsset,
      fiatCurrency: fiat,
      enabledFlows: side === 'sell' ? 'OFFRAMP' : 'ONRAMP',
      defaultFlow: side === 'sell' ? 'OFFRAMP' : 'ONRAMP',
    });
    if (amount) p.set('fiatValue', String(amount));
    if (address) p.set('userAddress', address);
    const host = RAMP_STAGING ? 'app.demo.ramp.network' : 'buy.ramp.network';
    return `https://${host}/?${p.toString()}`;
  },

  moonpay({ side, asset, network, address, amount, fiat }) {
    const base = side === 'sell'
      ? (RAMP_STAGING ? 'sell-sandbox.moonpay.com' : 'sell.moonpay.com')
      : (RAMP_STAGING ? 'buy-sandbox.moonpay.com'  : 'buy.moonpay.com');

    const code = moonpayCurrencyCode(asset, network);
    let p;

    if (side === 'sell') {
      // Sell inverts the meaning of the parameters: baseCurrency is the CRYPTO
      // being sold and the amount is denominated in crypto, not fiat. Our UI
      // collects a USD figure, so no amount is sent — the user enters the
      // quantity in MoonPay. Passing the USD number here would read as
      // "sell 100 BTC" instead of "sell $100 of BTC".
      p = new URLSearchParams({
        apiKey: RAMP_API_KEY,
        baseCurrencyCode:  code,
        quoteCurrencyCode: fiat.toLowerCase(),
      });
      if (address) p.set('refundWalletAddress', address);
    } else {
      p = new URLSearchParams({
        apiKey: RAMP_API_KEY,
        currencyCode:     code,
        baseCurrencyCode: fiat.toLowerCase(),
      });
      if (amount) p.set('baseCurrencyAmount', String(amount));
      if (address) p.set('walletAddress', address);
    }

    const query = `?${p.toString()}`;
    // MoonPay rejects unsigned URLs in production. The signing secret is the
    // reason this belongs on a server — it must never reach the desktop app.
    if (MOONPAY_SECRET) {
      const sig = require('crypto')
        .createHmac('sha256', MOONPAY_SECRET)
        .update(query)
        .digest('base64');
      return `https://${base}${query}&signature=${encodeURIComponent(sig)}`;
    }
    return `https://${base}${query}`;
  },

  transak({ side, asset, network, address, amount, fiat }) {
    const p = new URLSearchParams({
      apiKey: RAMP_API_KEY,
      productsAvailed: side === 'sell' ? 'SELL' : 'BUY',
      cryptoCurrencyCode: asset,
      fiatCurrency: fiat,
      disableWalletAddressForm: 'true',
    });
    if (network) p.set('network', network);
    if (amount) p.set('fiatAmount', String(amount));
    if (address) p.set('walletAddress', address);
    const host = RAMP_STAGING ? 'global-stg.transak.com' : 'global.transak.com';
    return `https://${host}/?${p.toString()}`;
  },
};

// ── ChangeNow helper ────────────────────────────────────────────────────────
function changenowRequest(method, path, data) {
  return new Promise((resolve, reject) => {
    const body = data ? JSON.stringify(data) : '';
    const opts = {
      hostname: 'api.changenow.io',
      path,
      method,
      headers: {
        'x-changenow-api-key': CHANGENOW_KEY,
        'Content-Type': 'application/json',
        ...(body ? { 'Content-Length': Buffer.byteLength(body) } : {}),
      },
    };
    const req = https.request(opts, res => {
      let raw = '';
      res.on('data', c => raw += c);
      res.on('end', () => { try { resolve(JSON.parse(raw)); } catch { reject(new Error('Bad JSON')); } });
    });
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

// Symbol → ChangeNow network. Kept here rather than in the client so adding a
// coin doesn't require shipping a new app build.
const CN_NETWORKS = {
  btc: 'btc',   eth: 'eth',   bnb: 'bsc',   sol: 'sol',   ada: 'ada',
  xrp: 'xrp',   trx: 'trx',   dot: 'dot',   ltc: 'ltc',   doge: 'doge',
  matic: 'matic', avax: 'avaxc', usdt: 'eth', usdc: 'eth',
};
function cnNetwork(sym) {
  return CN_NETWORKS[String(sym).toLowerCase()] || String(sym).toLowerCase();
}

// ── request router ──────────────────────────────────────────────────────────
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', c => raw += c);
    req.on('end', () => { try { resolve(JSON.parse(raw || '{}')); } catch { reject(new Error('Bad JSON')); } });
  });
}

const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.length === 0) {
    res.setHeader('Access-Control-Allow-Origin', '*');
  } else if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Vary', 'Origin');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Content-Type', 'application/json');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const url = req.url.replace(/\?.*/, '');
  console.log(req.method, url);

  try {
    // POST /presale/checkout
    if (req.method === 'POST' && url === '/presale/checkout') {
      const body = await parseBody(req);
      // SECURITY: the EGOC amount is ALWAYS derived server-side from the USD
      // paid at the fixed price. Any client-supplied egoc_amount is ignored —
      // otherwise a buyer could pay $10 and claim arbitrary EGOC.
      const usd_amount = Number(body.usd_amount);
      if (!Number.isFinite(usd_amount) || usd_amount < 10) {
        res.writeHead(400); res.end(JSON.stringify({ error: 'Invalid amount (minimum $10)' })); return;
      }
      if (usd_amount > MAX_USD) {
        res.writeHead(400); res.end(JSON.stringify({ error: `Amount exceeds maximum ($${MAX_USD})` })); return;
      }
      const egoc_amount = usd_amount / EGOC_PRICE_USD;
      const cents = Math.max(Math.round(usd_amount * 100), 50);
      const session = await stripeRequest('POST', '/v1/checkout/sessions', {
        'mode':                                             'payment',
        'line_items[0][price_data][currency]':             'usd',
        'line_items[0][price_data][product_data][name]':   `EGOC Seed Round — ${Math.floor(egoc_amount)} EGOC @ $${EGOC_PRICE_USD}`,
        'line_items[0][price_data][unit_amount]':          cents,
        'line_items[0][quantity]':                         '1',
        'payment_method_types[0]':                         'card',
        'success_url':                                     SUCCESS_URL,
        'cancel_url':                                      CANCEL_URL,
        'metadata[egoc_amount]':                           String(egoc_amount),
        'metadata[egoc_price_usd]':                        String(EGOC_PRICE_USD),
        'metadata[round]':                                 'ego-presale-seed-round',
      });
      if (session.error) { res.writeHead(400); res.end(JSON.stringify({ error: session.error.message })); return; }
      res.writeHead(200);
      res.end(JSON.stringify({ session_id: session.id, checkout_url: session.url, egoc_amount, usd_amount }));
      return;
    }

    // GET /presale/verify/:session_id
    const verifyMatch = url.match(/^\/presale\/verify\/(.+)$/);
    if (req.method === 'GET' && verifyMatch) {
      const session_id = verifyMatch[1];
      const session = await stripeRequest('GET', `/v1/checkout/sessions/${session_id}`, null);
      if (session.error) { res.writeHead(400); res.end(JSON.stringify({ error: session.error.message })); return; }
      const paid = session.payment_status === 'paid';
      // Derive EGOC from the amount Stripe actually collected at the locked price,
      // not from client input — and only release a non-zero figure once paid.
      const priceUsd = parseFloat(session.metadata?.egoc_price_usd || String(EGOC_PRICE_USD)) || EGOC_PRICE_USD;
      const usdPaid  = (session.amount_total || 0) / 100;
      const egoc_amount = paid ? usdPaid / priceUsd : 0;
      res.writeHead(200);
      res.end(JSON.stringify({
        paid,
        status:       session.payment_status,
        amount_total: session.amount_total,
        egoc_amount,
      }));
      return;
    }

    // GET /presale/config — the price the app must quote and allocate at.
    // Served from the same constant /presale/checkout prices against, so the
    // two cannot disagree.
    if (req.method === 'GET' && url === '/presale/config') {
      const idx  = Math.min(Math.max(PRESALE_TIER_INDEX, 0), PRESALE_TIERS.length - 1);
      const tier = PRESALE_TIERS[idx];
      // The env price wins over the tier table — the checkout endpoint uses it,
      // so reporting anything else here would recreate the mismatch.
      const price = EGOC_PRICE_USD;
      res.writeHead(200);
      res.end(JSON.stringify({
        price_usd:    price,
        launch_usd:   PRESALE_LAUNCH_USD,
        discount_pct: PRESALE_LAUNCH_USD > 0
          ? Math.round((1 - price / PRESALE_LAUNCH_USD) * 100)
          : 0,
        tier_label:   tier.label,
        tier_index:   idx,
        tier_count:   PRESALE_TIERS.length,
        tiers:        PRESALE_TIERS,
      }));
      return;
    }

    // POST /ramp/session — returns a hosted-widget URL to open in the browser
    if (req.method === 'POST' && url === '/ramp/session') {
      const body    = await parseBody(req);
      const side    = body.side === 'sell' ? 'sell' : 'buy';
      const asset   = String(body.asset || '').toUpperCase();
      const network = String(body.network || '');
      const address = String(body.address || '');
      const fiat    = String(body.fiat || 'USD').toUpperCase();
      const amount  = body.amount == null ? null : Number(body.amount);

      if (!RAMP_API_KEY) {
        res.writeHead(503);
        res.end(JSON.stringify({ error: 'Buy/Sell is not configured yet — no ramp provider account is connected.' }));
        return;
      }
      if (!asset || !/^[A-Z0-9]{2,10}$/.test(asset)) {
        res.writeHead(400); res.end(JSON.stringify({ error: 'Invalid asset' })); return;
      }
      // Buying needs somewhere to deliver to. Selling doesn't — the provider
      // gives the user a deposit address instead.
      if (side === 'buy' && !address) {
        res.writeHead(400); res.end(JSON.stringify({ error: 'Missing destination address' })); return;
      }
      if (amount != null && (!Number.isFinite(amount) || amount <= 0)) {
        res.writeHead(400); res.end(JSON.stringify({ error: 'Invalid amount' })); return;
      }

      const build = RAMP_BUILDERS[RAMP_PROVIDER];
      if (!build) {
        res.writeHead(500);
        res.end(JSON.stringify({ error: `Unknown RAMP_PROVIDER "${RAMP_PROVIDER}"` }));
        return;
      }

      res.writeHead(200);
      res.end(JSON.stringify({
        url:      build({ side, asset, network, address, amount, fiat }),
        provider: RAMP_PROVIDER,
      }));
      return;
    }

    // ── ChangeNow passthrough ────────────────────────────────────────────
    // The app used to call ChangeNow directly with the key compiled into the
    // binary, where `strings` could recover it. The key lives here now and the
    // app sends only the swap parameters.
    if (url.startsWith('/swap/')) {
      if (!CHANGENOW_KEY) {
        res.writeHead(503); res.end(JSON.stringify({ error: 'Swap service not configured' })); return;
      }

      if (req.method === 'GET' && url === '/swap/estimate') {
        const q = qs.parse(req.url.split('?')[1] || '');
        const from = String(q.from || '').toLowerCase();
        const to   = String(q.to   || '').toLowerCase();
        const amt  = Number(q.amount);
        if (!from || !to || !Number.isFinite(amt) || amt <= 0) {
          res.writeHead(400); res.end(JSON.stringify({ error: 'Invalid swap parameters' })); return;
        }
        const common = `fromCurrency=${from}&toCurrency=${to}` +
          `&fromNetwork=${cnNetwork(from)}&toNetwork=${cnNetwork(to)}&flow=standard`;
        const [min, est] = await Promise.all([
          changenowRequest('GET', `/v2/exchange/min-amount?${common}`).catch(() => ({})),
          changenowRequest('GET', `/v2/exchange/estimated-amount?${common}&fromAmount=${amt}&type=direct`),
        ]);
        if (est.error) {
          res.writeHead(400); res.end(JSON.stringify({ error: est.message || est.error })); return;
        }
        res.writeHead(200);
        res.end(JSON.stringify({
          to_amount:       est.toAmount,
          min_amount:      min.minAmount || 0,
          network_fee:     est.networkFee || 0,
          network_fee_usd: est.networkFeeUSD || 0,
        }));
        return;
      }

      if (req.method === 'POST' && url === '/swap/create') {
        const body = await parseBody(req);
        const from = String(body.from || '').toLowerCase();
        const to   = String(body.to   || '').toLowerCase();
        const amt  = Number(body.amount);
        const dest = String(body.to_address || '');
        if (!from || !to || !dest || !Number.isFinite(amt) || amt <= 0) {
          res.writeHead(400); res.end(JSON.stringify({ error: 'Invalid swap parameters' })); return;
        }
        const created = await changenowRequest('POST', '/v2/exchange', {
          fromCurrency: from,
          toCurrency:   to,
          fromAmount:   String(amt),
          toAddress:    dest,
          fromNetwork:  cnNetwork(from),
          toNetwork:    cnNetwork(to),
          flow:         'standard',
          type:         'direct',
        });
        if (created.error) {
          res.writeHead(400); res.end(JSON.stringify({ error: created.message || created.error })); return;
        }
        res.writeHead(200);
        res.end(JSON.stringify({
          id:               created.id || '',
          deposit_address:  created.payinAddress || '',
          deposit_extra_id: created.payinExtraId || null,
          to_amount:        created.toAmount || 0,
        }));
        return;
      }

      const statusMatch = url.match(/^\/swap\/status\/(.+)$/);
      if (req.method === 'GET' && statusMatch) {
        const st = await changenowRequest('GET', `/v2/exchange/by-id?id=${encodeURIComponent(statusMatch[1])}`);
        if (st.error) {
          res.writeHead(400); res.end(JSON.stringify({ error: st.message || st.error })); return;
        }
        res.writeHead(200);
        res.end(JSON.stringify({
          status:    st.status || 'unknown',
          to_amount: st.amountTo ?? null,
          hash_out:  st.payoutHash ?? null,
        }));
        return;
      }
    }

    res.writeHead(404); res.end(JSON.stringify({ error: 'Not found' }));
  } catch (e) {
    res.writeHead(500); res.end(JSON.stringify({ error: e.message }));
  }
});

// Bind to loopback by default: behind nginx there is no reason to expose this
// port publicly. Set HOST=0.0.0.0 only when nothing is fronting it.
const HOST = process.env.HOST || '127.0.0.1';
server.listen(PORT, HOST, () => console.log(`Ego payments proxy listening on ${HOST}:${PORT}`));
