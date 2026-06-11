import { secp256k1 } from '@noble/curves/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { sha512 } from '@noble/hashes/sha512';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { keccak_256 } from '@noble/hashes/sha3';
import { hmac } from '@noble/hashes/hmac';
import { bech32, bech32m } from 'bech32';

// ── Key derivation (matches Ego Desktop multichain.rs) ────────────────────────
// privkey = HMAC-SHA512(key = seed, msg = path)[..32]

const PATHS = {
  BTC: 'ego:bitcoin:0',
  ETH: 'ego:ethereum:0',
  BNB: 'ego:bnb:0',
} as const;

export type SignableChain = keyof typeof PATHS;

export function isSignableChain(chain: string): chain is SignableChain {
  return chain in PATHS;
}

function derivePrivkey(seed: Uint8Array, chain: SignableChain): Uint8Array {
  return hmac(sha512, seed, new TextEncoder().encode(PATHS[chain])).slice(0, 32);
}

function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

function sha256d(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

function bytesToHex(b: Uint8Array): string {
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

function hexToBytes(hex: string): Uint8Array {
  const h = hex.replace(/^0x/, '');
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function concat(...arrs: Uint8Array[]): Uint8Array {
  const len = arrs.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(len);
  let off = 0;
  for (const a of arrs) { out.set(a, off); off += a.length; }
  return out;
}

export function parseUnits(amount: string, decimals: number): bigint {
  const s = amount.trim();
  if (!/^\d+(\.\d+)?$/.test(s)) throw new Error('Invalid amount');
  const [whole, frac = ''] = s.split('.');
  if (frac.length > decimals) throw new Error(`Too many decimal places (max ${decimals})`);
  return BigInt(whole) * 10n ** BigInt(decimals) + BigInt(frac.padEnd(decimals, '0') || '0');
}

// ── Addresses ─────────────────────────────────────────────────────────────────

function eip55(addr20: Uint8Array): string {
  const hexLower = bytesToHex(addr20);
  const hash = bytesToHex(keccak_256(new TextEncoder().encode(hexLower)));
  let out = '0x';
  for (let i = 0; i < hexLower.length; i++) {
    const c = hexLower[i];
    out += /[a-f]/.test(c) && parseInt(hash[i], 16) >= 8 ? c.toUpperCase() : c;
  }
  return out;
}

export function deriveAddress(seed: Uint8Array, chain: SignableChain): string {
  const priv = derivePrivkey(seed, chain);
  if (chain === 'BTC') {
    const pub = secp256k1.getPublicKey(priv, true);
    const h = hash160(pub);
    return bech32.encode('bc', [0, ...bech32.toWords(h)]);
  }
  const pub = secp256k1.getPublicKey(priv, false);
  return eip55(keccak_256(pub.slice(1)).slice(12));
}

// ── EVM (ETH / BNB) ───────────────────────────────────────────────────────────

const EVM = {
  ETH: { rpc: 'https://eth.llamarpc.com',         chainId: 1n,  explorer: 'https://etherscan.io/tx/' },
  BNB: { rpc: 'https://bsc-dataseed.binance.org', chainId: 56n, explorer: 'https://bscscan.com/tx/' },
} as const;

async function evmRpc(rpc: string, method: string, params: unknown[]): Promise<string> {
  const res = await fetch(rpc, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method, params }),
  });
  const j = await res.json();
  if (j.error) throw new Error(j.error.message ?? 'RPC error');
  return j.result as string;
}

function bigintToMinimal(n: bigint): Uint8Array {
  if (n === 0n) return new Uint8Array(0);
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  return hexToBytes(hex);
}

type RlpItem = Uint8Array | RlpItem[];

function rlpEncode(item: RlpItem): Uint8Array {
  if (item instanceof Uint8Array) {
    if (item.length === 1 && item[0] < 0x80) return item;
    return concat(rlpLength(item.length, 0x80), item);
  }
  const body = concat(...item.map(rlpEncode));
  return concat(rlpLength(body.length, 0xc0), body);
}

function rlpLength(len: number, offset: number): Uint8Array {
  if (len < 56) return new Uint8Array([offset + len]);
  const lenBytes = bigintToMinimal(BigInt(len));
  return concat(new Uint8Array([offset + 55 + lenBytes.length]), lenBytes);
}

export async function sendEvm(
  seed: Uint8Array,
  chain: 'ETH' | 'BNB',
  to: string,
  amount: string,
  token?: { contract: string; decimals: number },
): Promise<{ txid: string; explorer_url: string }> {
  if (!/^0x[0-9a-fA-F]{40}$/.test(to)) throw new Error('Invalid recipient address');
  const cfg = EVM[chain];
  const priv = derivePrivkey(seed, chain);
  const from = deriveAddress(seed, chain);

  let txTo: string;
  let value: bigint;
  let data: Uint8Array;

  if (token) {
    const units = parseUnits(amount, token.decimals);
    txTo = token.contract;
    value = 0n;
    data = hexToBytes(
      'a9059cbb' +
      to.replace(/^0x/, '').toLowerCase().padStart(64, '0') +
      units.toString(16).padStart(64, '0'),
    );
  } else {
    txTo = to;
    value = parseUnits(amount, 18);
    data = new Uint8Array(0);
  }

  const [nonceHex, gasPriceHex] = await Promise.all([
    evmRpc(cfg.rpc, 'eth_getTransactionCount', [from, 'pending']),
    evmRpc(cfg.rpc, 'eth_gasPrice', []),
  ]);
  const nonce = BigInt(nonceHex);
  const gasPrice = BigInt(gasPriceHex) * 110n / 100n;

  let gasLimit = 21000n;
  if (token) {
    try {
      const est = await evmRpc(cfg.rpc, 'eth_estimateGas', [{
        from, to: txTo, data: '0x' + bytesToHex(data),
      }]);
      gasLimit = BigInt(est) * 120n / 100n;
    } catch {
      gasLimit = 100000n;
    }
  }

  const toBytes = hexToBytes(txTo);
  const fields: RlpItem[] = [
    bigintToMinimal(nonce),
    bigintToMinimal(gasPrice),
    bigintToMinimal(gasLimit),
    toBytes,
    bigintToMinimal(value),
    data,
  ];

  // EIP-155 signing hash
  const sigHash = keccak_256(rlpEncode([
    ...fields,
    bigintToMinimal(cfg.chainId),
    new Uint8Array(0),
    new Uint8Array(0),
  ]));

  const sig = secp256k1.sign(sigHash, priv);
  const v = cfg.chainId * 2n + 35n + BigInt(sig.recovery);

  const raw = rlpEncode([
    ...fields,
    bigintToMinimal(v),
    bigintToMinimal(sig.r),
    bigintToMinimal(sig.s),
  ]);

  const txid = await evmRpc(cfg.rpc, 'eth_sendRawTransaction', ['0x' + bytesToHex(raw)]);
  return { txid, explorer_url: cfg.explorer + txid };
}

// ── Bitcoin (P2WPKH, BIP-143) ─────────────────────────────────────────────────

const BTC_API = 'https://blockstream.info/api';
const DUST_SATS = 546n;

interface Utxo { txid: string; vout: number; value: number }

function varint(n: number): Uint8Array {
  if (n < 0xfd) return new Uint8Array([n]);
  if (n <= 0xffff) return new Uint8Array([0xfd, n & 0xff, n >> 8]);
  throw new Error('Too many items');
}

function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}

function u64le(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, true);
  return b;
}

function txidLe(txid: string): Uint8Array {
  return hexToBytes(txid).reverse();
}

const B58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';

function base58Decode(s: string): Uint8Array {
  let n = 0n;
  for (const c of s) {
    const i = B58_ALPHABET.indexOf(c);
    if (i < 0) throw new Error('Invalid base58 character');
    n = n * 58n + BigInt(i);
  }
  let hex = n.toString(16);
  if (hex.length % 2) hex = '0' + hex;
  let bytes = hexToBytes(hex);
  let zeros = 0;
  for (const c of s) { if (c === '1') zeros++; else break; }
  if (zeros) bytes = concat(new Uint8Array(zeros), bytes);
  return bytes;
}

function btcOutputScript(address: string): Uint8Array {
  const addr = address.trim();
  if (addr.toLowerCase().startsWith('bc1')) {
    const lower = addr.toLowerCase();
    let decoded: { words: number[] };
    try {
      decoded = lower.startsWith('bc1p') ? bech32m.decode(lower) : bech32.decode(lower);
    } catch {
      throw new Error('Invalid bech32 address');
    }
    const version = decoded.words[0];
    const program = new Uint8Array(bech32.fromWords(decoded.words.slice(1)));
    if (version === 0 && program.length !== 20 && program.length !== 32) throw new Error('Invalid witness program');
    const opVersion = version === 0 ? 0x00 : 0x50 + version;
    return concat(new Uint8Array([opVersion, program.length]), program);
  }
  const payload = base58Decode(addr);
  if (payload.length !== 25) throw new Error('Invalid address');
  const checksum = sha256d(payload.slice(0, 21)).slice(0, 4);
  if (bytesToHex(checksum) !== bytesToHex(payload.slice(21))) throw new Error('Bad address checksum');
  const version = payload[0];
  const h = payload.slice(1, 21);
  if (version === 0x00) {
    // P2PKH
    return concat(hexToBytes('76a914'), h, hexToBytes('88ac'));
  }
  if (version === 0x05) {
    // P2SH
    return concat(hexToBytes('a914'), h, hexToBytes('87'));
  }
  throw new Error('Unsupported address version');
}

function serializeOutput(value: bigint, script: Uint8Array): Uint8Array {
  return concat(u64le(value), varint(script.length), script);
}

export async function sendBtc(
  seed: Uint8Array,
  to: string,
  amount: string,
): Promise<{ txid: string; explorer_url: string }> {
  const priv = derivePrivkey(seed, 'BTC');
  const pub = secp256k1.getPublicKey(priv, true);
  const myH160 = hash160(pub);
  const myAddress = deriveAddress(seed, 'BTC');
  const amountSats = parseUnits(amount, 8);
  if (amountSats < DUST_SATS) throw new Error('Amount below dust limit (0.00000546 BTC)');

  const toScript = btcOutputScript(to);

  const utxoRes = await fetch(`${BTC_API}/address/${myAddress}/utxo`);
  if (!utxoRes.ok) throw new Error(`UTXO fetch failed: HTTP ${utxoRes.status}`);
  const utxos: Utxo[] = await utxoRes.json();
  if (!utxos.length) throw new Error('No spendable balance');
  utxos.sort((a, b) => b.value - a.value);

  let feeRate = 5;
  try {
    const fees = await (await fetch(`${BTC_API}/fee-estimates`)).json();
    feeRate = Math.max(1, Math.ceil(fees['3'] ?? fees['6'] ?? 5));
  } catch { /* default */ }

  // Select inputs
  const selected: Utxo[] = [];
  let inputSats = 0n;
  let fee = 0n;
  for (const u of utxos) {
    selected.push(u);
    inputSats += BigInt(u.value);
    const vsize = 11 + 68 * selected.length + 31 * 2;
    fee = BigInt(vsize * feeRate);
    if (inputSats >= amountSats + fee) break;
  }
  if (inputSats < amountSats + fee) throw new Error('Insufficient balance (including network fee)');

  const change = inputSats - amountSats - fee;
  const myScript = concat(new Uint8Array([0x00, 0x14]), myH160);

  const outputs: Uint8Array[] = [serializeOutput(amountSats, toScript)];
  if (change > DUST_SATS) outputs.push(serializeOutput(change, myScript));

  const version = u32le(2);
  const locktime = u32le(0);
  const sequence = u32le(0xfffffffd);

  // BIP-143 shared hashes
  const prevoutsBlob = concat(...selected.map(u => concat(txidLe(u.txid), u32le(u.vout))));
  const hashPrevouts = sha256d(prevoutsBlob);
  const hashSequence = sha256d(concat(...selected.map(() => sequence)));
  const outputsBlob = concat(...outputs);
  const hashOutputs = sha256d(outputsBlob);

  const scriptCode = concat(hexToBytes('1976a914'), myH160, hexToBytes('88ac'));

  const witnesses: Uint8Array[] = [];
  for (const u of selected) {
    const preimage = concat(
      version,
      hashPrevouts,
      hashSequence,
      txidLe(u.txid), u32le(u.vout),
      scriptCode,
      u64le(BigInt(u.value)),
      sequence,
      hashOutputs,
      locktime,
      u32le(1), // SIGHASH_ALL
    );
    const sigHash = sha256d(preimage);
    const sig = secp256k1.sign(sigHash, priv, { lowS: true });
    const der = concat(sig.toDERRawBytes(), new Uint8Array([0x01]));
    witnesses.push(concat(
      varint(2),
      varint(der.length), der,
      varint(pub.length), pub,
    ));
  }

  // Serialize segwit transaction
  const vin = concat(
    varint(selected.length),
    ...selected.map(u => concat(txidLe(u.txid), u32le(u.vout), varint(0), sequence)),
  );
  const vout = concat(varint(outputs.length), outputsBlob);
  const rawTx = concat(
    version,
    new Uint8Array([0x00, 0x01]), // marker + flag
    vin,
    vout,
    ...witnesses,
    locktime,
  );

  const broadcast = await fetch(`${BTC_API}/tx`, { method: 'POST', body: bytesToHex(rawTx) });
  const text = await broadcast.text();
  if (!broadcast.ok) throw new Error(`Broadcast rejected: ${text.slice(0, 140)}`);
  return { txid: text.trim(), explorer_url: `https://blockstream.info/tx/${text.trim()}` };
}
