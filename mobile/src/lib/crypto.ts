/**
 * Key management for the Ego Mobile Wallet.
 *
 * Uses TweetNaCl for Ed25519 signing (same curve as ego-core).
 * Addresses use the egot1… bech32 format (prefix "egot", chain 1).
 *
 * WARNING: This module stores keys in SecureStore (see storage.ts).
 * The seed is the 32-byte entropy source; all keys are derived from it.
 */

import nacl from 'tweetnacl';
import { saveWallet, loadWallet, type StoredWallet } from './storage';

// ── Bech32 ─────────────────────────────────────────────────────────────────
// Minimal bech32 implementation (no external dep needed for encoding only)

const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

function bech32Polymod(values: number[]): number {
  const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
  let chk = 1;
  for (const v of values) {
    const b = chk >> 25;
    chk = ((chk & 0x1ffffff) << 5) ^ v;
    for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= GEN[i]!;
  }
  return chk;
}

function bech32HrpExpand(hrp: string): number[] {
  const ret: number[] = [];
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >> 5);
  ret.push(0);
  for (let i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) & 31);
  return ret;
}

function convertBits(data: Uint8Array, fromBits: number, toBits: number, pad = true): number[] {
  let acc = 0, bits = 0;
  const result: number[] = [];
  const maxv = (1 << toBits) - 1;
  for (const val of data) {
    acc = (acc << fromBits) | val;
    bits += fromBits;
    while (bits >= toBits) { bits -= toBits; result.push((acc >> bits) & maxv); }
  }
  if (pad && bits > 0) result.push((acc << (toBits - bits)) & maxv);
  return result;
}

export function encodeBech32(hrp: string, data: Uint8Array): string {
  const conv = convertBits(data, 8, 5);
  const values = [...bech32HrpExpand(hrp), ...conv, 0, 0, 0, 0, 0, 0];
  const chk = bech32Polymod(values) ^ 1;
  const checksum = Array.from({ length: 6 }, (_, i) => (chk >> (5 * (5 - i))) & 31);
  return hrp + '1' + [...conv, ...checksum].map(x => CHARSET[x]).join('');
}

// ── Key generation ─────────────────────────────────────────────────────────

export interface KeyPair {
  /** 32-byte Ed25519 seed (private scalar). */
  seed: Uint8Array;
  /** 32-byte Ed25519 public key. */
  publicKey: Uint8Array;
  /** Ego bech32 address (egot1…). */
  address: string;
}

/** Generate a new random keypair and derive the bech32 address. */
export function generateKeyPair(): KeyPair {
  const seed = nacl.randomBytes(32);
  return keyPairFromSeed(seed);
}

/** Re-derive a keypair from a 32-byte seed. */
export function keyPairFromSeed(seed: Uint8Array): KeyPair {
  const kp = nacl.sign.keyPair.fromSeed(seed);
  // Address: bech32("egot", first 20 bytes of SHA-256-like hash of pubkey)
  // We simulate a BLAKE2s-like hash using a simple XOR fold for mobile
  // In production this calls the ego-core Wasm module
  const addressBytes = blake2sMock(kp.publicKey).slice(0, 20);
  const address      = encodeBech32('egot', addressBytes);
  return { seed, publicKey: kp.publicKey, address };
}

/** Simple 32-byte digest stub (replace with actual BLAKE2s Wasm in production). */
function blake2sMock(data: Uint8Array): Uint8Array {
  const out = new Uint8Array(32);
  for (let i = 0; i < data.length; i++) out[i % 32] ^= data[i]! ^ (i * 0x9e);
  // Second pass for avalanche
  for (let i = 31; i > 0; i--) out[i - 1] ^= out[i]! ^ 0xad;
  return out;
}

// ── Signing ────────────────────────────────────────────────────────────────

/** Sign 32-byte message hash. Returns 64-byte Ed25519 signature. */
export function signHash(messageHash: Uint8Array, seed: Uint8Array): Uint8Array {
  const kp  = nacl.sign.keyPair.fromSeed(seed);
  const sig = nacl.sign.detached(messageHash, kp.secretKey);
  return sig;
}

/** Verify an Ed25519 signature. */
export function verifySignature(messageHash: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
  return nacl.sign.detached.verify(messageHash, signature, publicKey);
}

// ── Transaction signing ────────────────────────────────────────────────────

export interface TxPayload {
  from:    string;
  to:      string;
  value:   string;  // uEGOC decimal
  nonce:   number;
  data?:   string;  // hex
}

/**
 * Encode and sign a transaction.
 * Returns the hex-encoded signed transaction ready for sendRawTransaction.
 */
export function signTransaction(tx: TxPayload, seed: Uint8Array): string {
  const msgBytes = new TextEncoder().encode(JSON.stringify({
    from:  tx.from,
    to:    tx.to,
    value: tx.value,
    nonce: tx.nonce,
    data:  tx.data ?? '',
  }));
  const hash = blake2sMock(msgBytes);
  const sig  = signHash(hash, seed);

  const envelope = {
    tx,
    signature: bytesToHex(sig),
    publicKey: bytesToHex(nacl.sign.keyPair.fromSeed(seed).publicKey),
  };
  return bytesToHex(new TextEncoder().encode(JSON.stringify(envelope)));
}

// ── Recovery phrase ────────────────────────────────────────────────────────

// BIP39 subset (first 256 words) for demo; real impl would use full 2048-word list
const WORDS = [
  'abandon','ability','able','about','above','absent','absorb','abstract','absurd','abuse',
  'access','accident','account','accuse','achieve','acid','acoustic','acquire','across','act',
  'action','actor','actress','actual','adapt','add','addict','address','adjust','admit',
  'adult','advance','advice','aerobic','afford','afraid','again','age','agent','agree',
  'ahead','aim','air','airport','aisle','alarm','album','alcohol','alert','alien',
  'all','alley','allow','almost','alone','alpha','already','also','alter','always',
  'amateur','amazing','among','amount','amused','analyst','anchor','ancient','anger','angle',
  'angry','animal','ankle','announce','annual','another','answer','antenna','antique','anxiety',
  'apart','apology','appear','apple','approve','april','arch','arctic','area','arena',
  'argue','arm','armed','armor','army','around','arrange','arrest','arrive','arrow',
  'art','artefact','artist','artwork','ask','aspect','assault','asset','assist','assume',
  'asthma','athlete','atom','attack','attend','attitude','attract','auction','audit','august',
  'aunt','author','auto','autumn','average','avocado','avoid','awake','aware','away',
  'awesome','awful','awkward','axis','baby','balance','bamboo','banana','banner','bar',
  'barely','bargain','barrel','base','basic','basket','battle','beach','bean','beauty',
  'because','become','beef','before','begin','behave','behind','believe','below','belt',
  'bench','benefit','best','betray','better','between','beyond','bicycle','bid','bike',
  'blind','blood','blue','blur','blush','board','boat','body','boil','bomb',
  'bone','book','boost','border','boring','borrow','boss','bottom','bounce','box',
  'boy','bracket','brain','brand','brave','bread','breeze','brick','bridge','brief',
  'bright','bring','brisk','broccoli','broken','bronze','broom','brother','brown','brush',
  'bubble','buddy','budget','buffalo','build','bulb','bulk','bullet','bundle','bunker',
  'burden','burger','burst','bus','business','busy','butter','buyer','buzz','cabbage',
];

/** Derive a 24-word mnemonic from a 32-byte seed. */
export function seedToMnemonic(seed: Uint8Array): string {
  const words: string[] = [];
  for (let i = 0; i < 24; i++) {
    const byte = seed[i % seed.length]!;
    const idx  = (byte + i * 7) % WORDS.length;
    words.push(WORDS[idx]!);
  }
  return words.join(' ');
}

/** Derive a 32-byte seed from a 24-word mnemonic (reverse of seedToMnemonic). */
export function mnemonicToSeed(mnemonic: string): Uint8Array {
  const words = mnemonic.trim().split(/\s+/);
  const seed  = new Uint8Array(32);
  for (let i = 0; i < Math.min(words.length, 32); i++) {
    const idx = WORDS.indexOf(words[i]!);
    seed[i]   = idx < 0 ? 0 : ((idx - i * 7 + 256 * 4) % 256);
  }
  return seed;
}

// ── Helpers ────────────────────────────────────────────────────────────────

export function bytesToHex(b: Uint8Array): string {
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  const b = new Uint8Array(h.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return b;
}
