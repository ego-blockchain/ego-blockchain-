// Ego Presale Proxy — keeps the Stripe secret key server-side.
// Deploy to any Node.js host (Railway, Render, Fly.io, VPS…).
// Set env vars: STRIPE_SECRET_KEY, PRESALE_ORIGIN (optional CORS whitelist)

const https = require('https');
const http  = require('http');
const qs    = require('querystring');

const STRIPE_KEY     = process.env.STRIPE_SECRET_KEY || '';
const PORT           = parseInt(process.env.PORT || '3031', 10);
const EGOC_PRICE_USD = 2.00;
const SUCCESS_URL    = process.env.SUCCESS_URL || 'https://egoblockchain.com/presale/success';
const CANCEL_URL     = process.env.CANCEL_URL  || 'https://egoblockchain.com/presale/cancel';

if (!STRIPE_KEY) { console.error('ERROR: STRIPE_SECRET_KEY not set'); process.exit(1); }

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

// ── request router ──────────────────────────────────────────────────────────
function parseBody(req) {
  return new Promise((resolve, reject) => {
    let raw = '';
    req.on('data', c => raw += c);
    req.on('end', () => { try { resolve(JSON.parse(raw || '{}')); } catch { reject(new Error('Bad JSON')); } });
  });
}

const server = http.createServer(async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Content-Type', 'application/json');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  const url = req.url.replace(/\?.*/, '');
  console.log(req.method, url);

  try {
    // POST /presale/checkout
    if (req.method === 'POST' && url === '/presale/checkout') {
      const { egoc_amount, usd_amount } = await parseBody(req);
      if (!egoc_amount || !usd_amount || usd_amount < 10) {
        res.writeHead(400); res.end(JSON.stringify({ error: 'Invalid amount (minimum $10)' })); return;
      }
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
      res.writeHead(200);
      res.end(JSON.stringify({
        paid:         session.payment_status === 'paid',
        status:       session.payment_status,
        amount_total: session.amount_total,
        egoc_amount:  parseFloat(session.metadata?.egoc_amount || '0'),
      }));
      return;
    }

    res.writeHead(404); res.end(JSON.stringify({ error: 'Not found' }));
  } catch (e) {
    res.writeHead(500); res.end(JSON.stringify({ error: e.message }));
  }
});

server.listen(PORT, () => console.log(`Ego presale proxy listening on :${PORT}`));
