import { readFile, writeFile, mkdir, access } from 'fs/promises';
import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'crypto';
import { homedir } from 'os';
import { dirname, join } from 'path';

const args = process.argv.slice(2);
const flag = (name) => {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
};
const manifestPath = args.find((a, i) => !a.startsWith('--') && !['--key'].includes(args[i - 1]));
const keyPath = flag('--key') ?? join(homedir(), '.ego-signing', 'version-json-key.pem');
const newKey = args.includes('--new-key');

const exists = (p) => access(p).then(() => true, () => false);

const publicHex = (privateKey) =>
  createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');

if (newKey) {
  if (await exists(keyPath)) {
    console.error(`a key already exists at ${keyPath}; refusing to overwrite it`);
    process.exit(1);
  }
  const { privateKey } = generateKeyPairSync('ed25519');
  await mkdir(dirname(keyPath), { recursive: true });
  await writeFile(keyPath, privateKey.export({ format: 'pem', type: 'pkcs8' }), { mode: 0o600 });
  console.log(`key written to ${keyPath}`);
  console.log(`public key: ${publicHex(privateKey)}`);
  process.exit(0);
}

if (!manifestPath) {
  console.error('usage: node scripts/sign-version-json.mjs <path to version.json> [--key <pem>]');
  console.error('       node scripts/sign-version-json.mjs --new-key [--key <pem>]');
  process.exit(1);
}

const count = (v) => (Number.isInteger(v) && v >= 0 ? v : 0);
const text = (v) => (typeof v === 'string' ? v.trim().toLowerCase() : '');

const message = (m) => {
  const cert = m.state_cert ?? {};
  const anchor = m.chain_anchor ?? {};
  return [
    'ego-version-manifest-v1',
    `state_cert:${count(cert.index)}:${count(cert.height)}:${text(cert.hash)}`,
    `chain_anchor:${count(anchor.height)}:${text(anchor.hash).replace(/^(0x)+/, '')}`,
  ].join('|');
};

const manifest = JSON.parse(await readFile(manifestPath, 'utf8'));
const privateKey = createPrivateKey(await readFile(keyPath, 'utf8'));
const msg = Buffer.from(message(manifest));
const signature = sign(null, msg, privateKey);
if (!verify(null, msg, createPublicKey(privateKey), signature)) {
  console.error('the signature did not verify; nothing was written');
  process.exit(1);
}
manifest.signature = signature.toString('hex');
await writeFile(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
console.log(`signed ${manifestPath}`);
console.log(`message: ${msg.toString()}`);
console.log(`public key: ${publicHex(privateKey)}`);
