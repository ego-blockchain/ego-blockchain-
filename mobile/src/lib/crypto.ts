import nacl from 'tweetnacl';
import { blake2s } from 'blakejs';
import { bech32m } from 'bech32';
import { WORDLIST } from './wordlist';

export interface KeyPair {
  seed: Uint8Array;
  publicKey: Uint8Array;
  address: string;
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

export function generateKeyPair(): KeyPair {
  const seed = nacl.randomBytes(32);
  return keyPairFromSeed(seed);
}

export function keyPairFromSeed(seed: Uint8Array): KeyPair {
  const kp = nacl.sign.keyPair.fromSeed(seed);
  const address = publicKeyToAddress(kp.publicKey);
  return { seed, publicKey: kp.publicKey, address };
}

export function signHash(messageHash: Uint8Array, seed: Uint8Array): Uint8Array {
  const kp  = nacl.sign.keyPair.fromSeed(seed);
  const sig = nacl.sign.detached(messageHash, kp.secretKey);
  return sig;
}

export function verifySignature(messageHash: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean {
  return nacl.sign.detached.verify(messageHash, signature, publicKey);
}

export interface TxPayload {
  from:    string;
  to:      string;
  value:   string;
  nonce:   number;
  data?:   string;
}

export function signTransaction(tx: TxPayload, seed: Uint8Array): string {
  const msgBytes = new TextEncoder().encode(JSON.stringify({
    from:  tx.from,
    to:    tx.to,
    value: tx.value,
    nonce: tx.nonce,
    data:  tx.data ?? '',
  }));
  const hash = blake2s(msgBytes, undefined, 32);
  const sig  = signHash(hash, seed);

  const envelope = {
    tx,
    signature: bytesToHex(sig),
    publicKey: bytesToHex(nacl.sign.keyPair.fromSeed(seed).publicKey),
  };
  return bytesToHex(new TextEncoder().encode(JSON.stringify(envelope)));
}

// Encodes seed exactly like Ego Desktop's generate_recovery_phrase():
// buf = seed(32) || blake2s256(seed)[0], split into 24 x 11-bit indices.
export function seedToMnemonic(seed: Uint8Array): string {
  const checksum = blake2s(seed, undefined, 32)[0]!;

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
    words.push(WORDLIST[index]!);
  }
  return words.join(' ');
}

// Decodes an Ego Desktop recovery phrase. The desktop wordlist contains a few
// duplicated words, so every occurrence position is tried as a candidate and
// the blake2s checksum picks the correct combination. Returns null if invalid.
export function mnemonicToSeed(mnemonic: string): Uint8Array | null {
  const words = mnemonic.trim().toLowerCase().split(/\s+/);
  if (words.length !== 24) return null;

  const positions = new Map<string, number[]>();
  WORDLIST.forEach((w, i) => {
    const list = positions.get(w);
    if (list) list.push(i); else positions.set(w, [i]);
  });

  const candidates: number[][] = [];
  for (const raw of words) {
    const found = positions.get(raw);
    if (!found) return null;
    candidates.push(found);
  }

  const tryCombo = (indices: number[]): Uint8Array | null => {
    const buf = new Uint8Array(33);
    for (let i = 0; i < 24; i++) {
      const bitOffset = i * 11;
      const byteIdx = Math.floor(bitOffset / 8);
      const bitShift = bitOffset % 8;
      const raw = (indices[i]! & 0x7ff) << (13 - bitShift);
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
    for (const idx of candidates[pos]!) {
      combo[pos] = idx;
      const result = search(pos + 1);
      if (result) return result;
    }
    return null;
  };

  return search(0);
}

export function bytesToHex(b: Uint8Array): string {
  return Array.from(b).map(x => x.toString(16).padStart(2, '0')).join('');
}

export function hexToBytes(hex: string): Uint8Array {
  const h = hex.startsWith('0x') ? hex.slice(2) : hex;
  const b = new Uint8Array(h.length / 2);
  for (let i = 0; i < b.length; i++) b[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  return b;
}
