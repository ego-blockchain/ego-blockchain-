import nacl from 'tweetnacl';

const WORDLIST: string[] = [
  'abandon','ability','able','about','above','absent','absorb','abstract',
  'absurd','abuse','access','accident','account','accuse','achieve','acid',
  'acoustic','acquire','across','action','actor','actress','actual','adapt',
  'add','addict','address','adjust','admit','adult','advance','advice',
  'aerobic','afford','afraid','again','agent','agree','ahead','aim',
  'air','airport','aisle','alarm','album','alcohol','alert','alien',
  'alley','allow','almost','alone','alpha','already','also','alter',
  'always','amateur','amazing','among','amount','amused','analyst','anchor',
  'ancient','anger','angle','angry','animal','ankle','announce','annual',
  'another','answer','antenna','antique','anxiety','any','apart','apology',
  'appear','apple','approve','april','arch','arctic','area','arena',
  'argue','arm','armor','army','around','arrange','arrest','arrive',
  'arrow','art','artefact','artist','artwork','ask','aspect','assault',
  'asset','assist','assume','asthma','athlete','atom','attack','attend',
  'attitude','attract','auction','audit','august','aunt','author','auto',
  'autumn','average','avocado','avoid','awake','aware','away','awesome',
  'awful','awkward','axis','baby','balance','bamboo','banana','banner',
  'bar','barely','bargain','barrel','base','basic','basket','battle',
  'beach','beauty','because','become','beef','before','begin','behave',
  'behind','believe','below','belt','bench','benefit','best','betray',
  'better','between','beyond','bicycle','bid','bike','bind','biology',
  'bird','birth','bitter','black','blade','blame','blanket','blast',
  'bleak','bless','blind','blood','blossom','blouse','blue','blur',
  'blush','board','boat','body','boil','bomb','bone','book',
  'boost','border','boring','borrow','boss','bottom','bounce','box',
  'boy','bracket','brain','brand','brave','bread','breeze','brick',
  'bridge','brief','bright','bring','brisk','broccoli','broken','bronze',
  'broom','brother','brown','brush','bubble','buddy','budget','buffalo',
  'build','bulb','bulk','bullet','bundle','bunker','burden','burger',
];

export function generateSeed(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

export async function seedToMnemonic(seed: Uint8Array): Promise<string[]> {

  const hashBuf = await crypto.subtle.digest('SHA-256', seed);
  const checksum = new Uint8Array(hashBuf)[0];

  const data = new Uint8Array(33);
  data.set(seed);
  data[32] = checksum;

  const words: string[] = [];
  for (let i = 0; i < 24; i++) {
    const bitStart = i * 11;
    const byteStart = Math.floor(bitStart / 8);
    const bitOffset = bitStart % 8;

    const b0 = data[byteStart] ?? 0;
    const b1 = data[byteStart + 1] ?? 0;
    const b2 = data[byteStart + 2] ?? 0;

    const val24 = (b0 << 16) | (b1 << 8) | b2;
    const index = (val24 >> (13 - bitOffset)) & 0x7ff;

    words.push(WORDLIST[index % WORDLIST.length]);
  }
  return words;
}

export function mnemonicToSeed(words: string[]): Uint8Array | null {
  if (words.length !== 24) return null;

  const data = new Uint8Array(33);

  for (let i = 0; i < 24; i++) {
    const idx = WORDLIST.indexOf(words[i].toLowerCase().trim());
    if (idx === -1) return null;

    const bitStart = i * 11;
    const byteStart = Math.floor(bitStart / 8);
    const bitOffset = bitStart % 8;

    const val = idx & 0x7ff;

    const bitsInFirst = 8 - bitOffset;

    if (bitsInFirst >= 11) {
      data[byteStart] |= (val << (bitsInFirst - 11)) & 0xff;
    } else {
      const bitsInSecond = 11 - bitsInFirst;
      if (bitsInSecond <= 8) {
        data[byteStart] |= (val >> bitsInSecond) & 0xff;
        data[byteStart + 1] |= (val << (8 - bitsInSecond)) & 0xff;
      } else {
        const bitsInThird = bitsInSecond - 8;
        data[byteStart] |= (val >> bitsInSecond) & 0xff;
        data[byteStart + 1] |= (val >> bitsInThird) & 0xff;
        data[byteStart + 2] |= (val << (8 - bitsInThird)) & 0xff;
      }
    }
  }

  return data.slice(0, 32);
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

export async function publicKeyToAddress(pubkey: Uint8Array): Promise<string> {
  const hashBuf = await crypto.subtle.digest('SHA-256', pubkey);
  const hashBytes = new Uint8Array(hashBuf);
  const last20 = hashBytes.slice(12);
  return '0x' + Array.from(last20).map(b => b.toString(16).padStart(2, '0')).join('');
}

export interface TxPayload {
  from: string;
  to: string;
  amount_uegoc: number;
  nonce: number;
  memo?: string;
  timestamp: number;
}

export function signTransaction(tx: TxPayload, privateKey: Uint8Array): {
  tx: TxPayload;
  signature: string;
  public_key_hex: string;
} {

  const keypair = nacl.sign.keyPair.fromSeed(privateKey);
  const message = new TextEncoder().encode(JSON.stringify(tx));
  const sig = nacl.sign.detached(message, keypair.secretKey);
  return {
    tx,
    signature: Array.from(sig).map(b => b.toString(16).padStart(2, '0')).join(''),
    public_key_hex: Array.from(keypair.publicKey).map(b => b.toString(16).padStart(2, '0')).join(''),
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
  const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, seed);

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
