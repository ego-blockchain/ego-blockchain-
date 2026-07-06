import nacl from 'tweetnacl';
import { blake2s } from 'blakejs';
import { bech32m } from 'bech32';

import { WORDLIST } from './wordlist';

export function generateSeed(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

// Encodes seed exactly like Ego Desktop's generate_recovery_phrase():
// buf = seed(32) || blake2s256(seed)[0], split into 24 x 11-bit indices.
export async function seedToMnemonic(seed: Uint8Array): Promise<string[]> {
  const checksum = blake2s(seed, undefined, 32)[0];

  const data = new Uint8Array(33);
  data.set(seed);
  data[32] = checksum;

  const words: string[] = [];
  for (let i = 0; i < 24; i++) {
    const bitOffset = i * 11;
    const byteIdx = Math.floor(bitOffset / 8);
    const bitShift = bitOffset % 8;

    const b0 = data[byteIdx] ?? 0;
    const b1 = data[byteIdx + 1] ?? 0;
    const b2 = data[byteIdx + 2] ?? 0;

    const raw = (b0 << 16) | (b1 << 8) | b2;
    const index = ((raw >> (13 - bitShift)) & 0x7ff) % WORDLIST.length;
    words.push(WORDLIST[index]);
  }
  return words;
}

// Decodes an Ego Desktop recovery phrase. The desktop wordlist contains a
// few duplicated words, so every occurrence position is tried as a candidate
// and the blake2s checksum picks the correct combination.
export function mnemonicToSeed(words: string[]): Uint8Array | null {
  if (words.length !== 24) return null;

  const positions = new Map<string, number[]>();
  WORDLIST.forEach((w, i) => {
    const list = positions.get(w);
    if (list) list.push(i); else positions.set(w, [i]);
  });

  const candidates: number[][] = [];
  for (const raw of words) {
    const found = positions.get(raw.toLowerCase().trim());
    if (!found) return null;
    candidates.push(found);
  }

  const totalCombos = candidates.reduce((n, c) => n * c.length, 1);
  if (totalCombos > 256) return null;

  const tryCombo = (indices: number[]): Uint8Array | null => {
    const buf = new Uint8Array(33);
    for (let i = 0; i < 24; i++) {
      const bitOffset = i * 11;
      const byteIdx = Math.floor(bitOffset / 8);
      const bitShift = bitOffset % 8;
      const raw = (indices[i] & 0x7ff) << (13 - bitShift);
      buf[byteIdx] |= (raw >> 16) & 0xff;
      if (byteIdx + 1 < 33) buf[byteIdx + 1] |= (raw >> 8) & 0xff;
      if (byteIdx + 2 < 33) buf[byteIdx + 2] |= raw & 0xff;
    }
    const seed = buf.slice(0, 32);
    if (blake2s(seed, undefined, 32)[0] !== buf[32]) return null;
    return seed;
  };

  const combo = new Array<number>(24);
  const search = (pos: number): Uint8Array | null => {
    if (pos === 24) return tryCombo(combo);
    for (const idx of candidates[pos]) {
      combo[pos] = idx;
      const result = search(pos + 1);
      if (result) return result;
    }
    return null;
  };

  return search(0);
}

export function hexToSeed(hex: string): Uint8Array | null {
  const clean = hex.replace(/\s/g, '').toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(clean)) return null;
  const bytes = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    bytes[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export function seedToHex(seed: Uint8Array): string {
  return Array.from(seed).map(b => b.toString(16).padStart(2, '0')).join('');
}

export function seedToKeypair(seed: Uint8Array): { privateKey: Uint8Array; publicKey: Uint8Array } {

  const keypair = nacl.sign.keyPair.fromSeed(seed);
  return {
    privateKey: keypair.secretKey.slice(0, 32),
    publicKey: keypair.publicKey,
  };
}

// Mirrors ego-core EgoAddress::from_public_key_bytes(pk, 1, EOA).to_bech32("egot"):
// blake2s256("ego/addr/v1" || chain_id_le || pubkey)[..20], version byte, bech32m.
export function publicKeyToAddress(pubkey: Uint8Array): string {
  const domainTag = new TextEncoder().encode('ego/addr/v1');
  const input = new Uint8Array(domainTag.length + 4 + pubkey.length);
  input.set(domainTag, 0);
  input.set(new Uint8Array([1, 0, 0, 0]), domainTag.length); // chain_id = 1u32 LE (testnet)
  input.set(pubkey, domainTag.length + 4);
  const digest = blake2s(input, undefined, 32);

  const ADDRESS_VERSION = 0b001;
  const EOA = 0;
  const payload = new Uint8Array(21);
  payload[0] = (ADDRESS_VERSION << 5) | EOA;
  payload.set(digest.slice(0, 20), 1);
  return bech32m.encode('egot', bech32m.toWords(payload));
}

function u64le(n: bigint): Uint8Array {
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, n, true);
  return b;
}

function toHex(b: Uint8Array): string {
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

// Byte-identical mirror of Ego Desktop's ledger::tx_signing_bytes_v2:
// "ego/tx/v2:" chain_id ':' from ':' to ':' amount_u64le ':' nonce_u64le ':'
// timestamp_i64le ':' memo_len_u32le memo
export function txSigningBytesV2(
  from: string,
  to: string,
  amountUegoc: bigint,
  nonce: bigint,
  timestamp: bigint,
  chainId: number,
  memo: string,
): Uint8Array {
  const enc = new TextEncoder();
  const memoBytes = enc.encode(memo.slice(0, 256));
  const colon = new Uint8Array([0x3a]);
  const memoLen = new Uint8Array(4);
  new DataView(memoLen.buffer).setUint32(0, memoBytes.length, true);

  const parts = [
    enc.encode('ego/tx/v2:'),
    new Uint8Array([chainId]), colon,
    enc.encode(from), colon,
    enc.encode(to), colon,
    u64le(amountUegoc), colon,
    u64le(nonce), colon,
    u64le(BigInt.asUintN(64, timestamp)), colon,
    memoLen, memoBytes,
  ];
  const total = parts.reduce((s, a) => s + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of parts) { out.set(a, off); off += a.length; }
  return out;
}

export interface SignedEgoTx {
  hash: string;
  from: string;
  to: string;
  amount: number;
  memo: string | null;
  timestamp: number;
  signature: string;
  status: string;
  nonce: number;
  public_key_ed25519: string;
  fee_uegoc: number;
  tx_type: string;
  tx_version: number;
  chain_id: number;
}

// Builds a fully-formed, chain-valid transfer exactly like Ego Desktop's
// send_transaction: v2 signing bytes, Ed25519 signature, and the tx hash
// bound to blake2s(sign_bytes) — the node verifies all three.
export function buildSignedEgoTx(
  seed: Uint8Array,
  from: string,
  to: string,
  amountUegoc: number,
  nonce: number,
  feeUegoc: number,
  memo: string,
): SignedEgoTx {
  const chainId = 1;
  const timestamp = Math.floor(Date.now() / 1000);
  const signBytes = txSigningBytesV2(
    from, to, BigInt(amountUegoc), BigInt(nonce), BigInt(timestamp), chainId, memo,
  );
  const keypair = nacl.sign.keyPair.fromSeed(seed);
  const sig = nacl.sign.detached(signBytes, keypair.secretKey);
  const hash = '0x' + toHex(blake2s(signBytes, undefined, 32));

  return {
    hash,
    from,
    to,
    amount: amountUegoc,
    memo: memo || null,
    timestamp,
    signature: toHex(sig),
    status: 'Pending',
    nonce,
    public_key_ed25519: toHex(keypair.publicKey),
    fee_uegoc: feeUegoc,
    tx_type: 'transfer',
    tx_version: 2,
    chain_id: chainId,
  };
}

export function signMessage(message: Uint8Array, privateKey: Uint8Array): string {
  const keypair = nacl.sign.keyPair.fromSeed(privateKey);
  const sig = nacl.sign.detached(message, keypair.secretKey);
  return Array.from(sig).map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function encryptSeed(seed: Uint8Array, password: string): Promise<string> {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(password),
    'PBKDF2',
    false,
    ['deriveKey'],
  );
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 200_000, hash: 'SHA-256' },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt'],
  );
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, seed as BufferSource);

  const packed = new Uint8Array(16 + 12 + ciphertext.byteLength);
  packed.set(salt, 0);
  packed.set(iv, 16);
  packed.set(new Uint8Array(ciphertext), 28);

  return btoa(String.fromCharCode(...packed));
}

export async function decryptSeed(encrypted: string, password: string): Promise<Uint8Array | null> {
  try {
    const packed = Uint8Array.from(atob(encrypted), c => c.charCodeAt(0));
    const salt = packed.slice(0, 16);
    const iv = packed.slice(16, 28);
    const ciphertext = packed.slice(28);

    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      enc.encode(password),
      'PBKDF2',
      false,
      ['deriveKey'],
    );
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations: 200_000, hash: 'SHA-256' },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['decrypt'],
    );
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
    return new Uint8Array(plaintext);
  } catch {
    return null;
  }
}
