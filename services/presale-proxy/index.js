// Ego Presale Proxy — keeps the Stripe secret key server-side.
// Deploy to any Node.js host (Railway, Render, Fly.io, VPS…).
// Set env vars: STRIPE_SECRET_KEY, PRESALE_ORIGIN (optional CORS whitelist)

const https = require('https');
const http  = require('http');
const qs    = require('querystring');

const STRIPE_KEY     = process.env.STRIPE_SECRET_KEY || '';
const CHANGENOW_KEY  = process.env.CHANGENOW_API_KEY || '';
const PORT           = parseInt(process.env.PORT || '3031', 10);
const EGOC_PRICE_USD = parseFloat(process.env.EGOC_PRICE_USD || '2.00');
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
