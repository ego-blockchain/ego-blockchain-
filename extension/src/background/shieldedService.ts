import { bech32m } from 'bech32';
import nacl from 'tweetnacl';
import { buildSignedEgoTx } from '../shared/crypto';
import {
  checkShielded,
  exportWalletNotes,
  getNonceInfo,
  getShieldedLeaves,
  getShieldedState,
  submitTx,
  type ShieldedCheck,
  type ShieldedState,
} from '../shared/rpc';
import {
  DENOMINATIONS_UEGOC,
  MAX_SPENDS,
  NOTE_DOMAINS,
  POOL_ADDRESS,
  PROOF_SYSTEM,
  RECOVERY_GAP,
  SYNC_LAG_TOLERANCE,
  TX_SHIELD,
  TX_UNSHIELD,
  denominate,
  depositAbandoned,
  feeShares,
  fromHex,
  noteSecrets,
  noteStatus,
  notesExportMessage,
  notesKeyBytes,
  recipientDigest,
  secretsOf,
  shieldMemo,
  toHex,
  unshieldBodyJson,
  unshieldHash,
  withdrawalAbandoned,
  type ChainView,
  type DesktopStoredNote,
  type NoteDomain,
  type NoteStatus,
  type NoteView,
  type StoredNote,
  type TxCheck,
} from '../shared/shielded';
import { appendCached, cachedLeaves, clearCached, leafHexAt } from './leafCache';
import { appendLeaves, deriveNotes, proveSpends, resetTree, treeSummary, type TreeSummary } from './stark';

export interface ShieldedContext {
  seed: Uint8Array;
  address: string;
  rpcUrl: string;
}

export interface ShieldedStatusView {
  enabled: boolean;
  active: boolean;
  pool_address: string;
  pool_balance_uegoc: number;
  leaf_count: number;
  denominations_uegoc: number[];
  min_fee_uegoc: number;
  current_fee_uegoc: number;
  deposit_fee_uegoc: number;
  spendable_uegoc: number;
  max_spends: number;
  proof_system: string;
  behind: boolean;
  notes: NoteView[];
  ready_balance_uegoc: number;
  pending_balance_uegoc: number;
}

export interface ShieldResult {
  tx_hashes: string[];
  notes: number[];
  shielded_uegoc: number;
  remainder_uegoc: number;
  fee_total_uegoc: number;
}

export interface UnshieldResult {
  hash: string;
  amount_uegoc: number;
  fee_uegoc: number;
  payout_uegoc: number;
  recipient: string;
}

interface PoolSync {
  leafCount: number;
  root: string;
  bytes: Uint8Array;
}

const LEAF_PAGE = 16_384;
const CHECK_BATCH = 1_024;
const RECOVERY_BATCH = 50;
const LEAF_BYTES = 32;
const RESEND_EVERY_MS = 15_000;
const DESKTOP_SYNC_EVERY_MS = 60_000;

type PendingTxs = Record<string, object>;

const lastResent = new Map<string, number>();
const lastDesktopSync = new Map<string, number>();

let queue: Promise<unknown> = Promise.resolve();
let cacheEpoch = 0;
let treeEpoch = -1;
let scanEpoch = -1;
let scannedUpTo = 0;

function exclusive<T>(fn: () => Promise<T>): Promise<T> {
  const run = queue.then(fn, fn);
  queue = run.catch(() => undefined);
  return run;
}

function now(): number {
  return Math.floor(Date.now() / 1000);
}

function egoc(uegoc: number): string {
  return (uegoc / 1_000_000).toLocaleString(undefined, { maximumFractionDigits: 6 });
}

function storageGet<T>(key: string): Promise<T | undefined> {
  return new Promise(resolve => {
    chrome.storage.local.get([key], r => resolve(r[key] as T | undefined));
  });
}

function storageSet(items: Record<string, unknown>): Promise<void> {
  return new Promise((resolve, reject) => {
    chrome.storage.local.set(items, () => {
      const err = chrome.runtime.lastError;
      if (err) reject(new Error(err.message));
      else resolve();
    });
  });
}

const notesKeyName = (address: string) => `shieldedNotes:${address}`;
const nextKeyName = (address: string) => `shieldedNext:${address}`;
const scannedKeyName = (address: string) => `shieldedScanned:${address}`;
const pendingKeyName = (address: string) => `shieldedPending:${address}`;

function b64encode(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return btoa(s);
}

function b64decode(s: string): Uint8Array {
  const bin = atob(s);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

async function notesKey(seed: Uint8Array): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', new Uint8Array(notesKeyBytes(seed)), 'AES-GCM', false, ['encrypt', 'decrypt']);
}

async function openSealed<T>(ctx: ShieldedContext, bytes: Uint8Array): Promise<T> {
  if (bytes.length < 28) throw new Error('The shielded notes saved in this browser are damaged.');
  let plain: ArrayBuffer;
  try {
    plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: bytes.slice(0, 12) },
      await notesKey(ctx.seed),
      bytes.slice(12),
    );
  } catch {
    throw new Error('The shielded notes saved in this browser do not open with this wallet.');
  }
  return JSON.parse(new TextDecoder().decode(plain)) as T;
}

async function loadSealed<T>(ctx: ShieldedContext, key: string, empty: T): Promise<T> {
  const blob = await storageGet<string>(key);
  if (!blob) return empty;
  return openSealed<T>(ctx, b64decode(blob));
}

async function saveSealed(ctx: ShieldedContext, key: string, value: unknown): Promise<void> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = new Uint8Array(await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    await notesKey(ctx.seed),
    new TextEncoder().encode(JSON.stringify(value)),
  ));
  const out = new Uint8Array(iv.length + ct.length);
  out.set(iv);
  out.set(ct, iv.length);
  await storageSet({ [key]: b64encode(out) });
}

function loadNotes(ctx: ShieldedContext): Promise<StoredNote[]> {
  return loadSealed<StoredNote[]>(ctx, notesKeyName(ctx.address), []);
}

function saveNotes(ctx: ShieldedContext, notes: StoredNote[]): Promise<void> {
  return saveSealed(ctx, notesKeyName(ctx.address), notes);
}

function loadPending(ctx: ShieldedContext): Promise<PendingTxs> {
  return loadSealed<PendingTxs>(ctx, pendingKeyName(ctx.address), {});
}

function savePending(ctx: ShieldedContext, pending: PendingTxs): Promise<void> {
  return saveSealed(ctx, pendingKeyName(ctx.address), pending);
}

async function forgetPending(ctx: ShieldedContext, hashes: string[]): Promise<void> {
  const pending = await loadPending(ctx);
  let changed = false;
  for (const h of hashes) {
    if (h in pending) {
      delete pending[h];
      lastResent.delete(h);
      changed = true;
    }
  }
  if (changed) await savePending(ctx, pending);
}

async function nextIndex(ctx: ShieldedContext, notes: StoredNote[]): Promise<number> {
  const stored = (await storageGet<number>(nextKeyName(ctx.address))) ?? 0;
  return Math.max(
    stored,
    notes.reduce((m, n) => (!n.secret && (n.domain ?? 'ext') === 'ext' ? Math.max(m, n.index + 1) : m), 0),
  );
}

function requireOpen(st: ShieldedState): void {
  if (!st.enabled) throw new Error('Shielded transactions are switched off on this node.');
  if (!st.active) throw new Error('This chain has not activated the shielded pool yet.');
}

function validateRecipient(address: string): void {
  let ok = false;
  try {
    ok = address === address.toLowerCase() && bech32m.decode(address, 120).prefix === 'egot';
  } catch {
    ok = false;
  }
  if (!ok) throw new Error('That is not an Ego testnet address (egot1…).');
  if (address === POOL_ADDRESS) throw new Error('Cannot send to the shielded pool itself.');
}

function isNodeRefusal(e: unknown): boolean {
  return !(e instanceof TypeError);
}

async function resetPool(): Promise<void> {
  await clearCached();
  cacheEpoch += 1;
}

async function loadProver(bytes: Uint8Array, count: number): Promise<TreeSummary> {
  let summary = await treeSummary();
  if (treeEpoch !== cacheEpoch || summary.leaf_count > count) {
    summary = await resetTree();
    treeEpoch = cacheEpoch;
  }
  if (summary.leaf_count < count) {
    summary = await appendLeaves(bytes.subarray(summary.leaf_count * LEAF_BYTES, count * LEAF_BYTES));
  }
  return summary;
}

async function syncPool(rpcUrl: string, st: ShieldedState, retry = true): Promise<PoolSync> {
  let { count } = await cachedLeaves();
  if (count > st.leaf_count) {
    await resetPool();
    count = 0;
  }
  while (count < st.leaf_count) {
    const page = await getShieldedLeaves(count, Math.min(LEAF_PAGE, st.leaf_count - count), rpcUrl);
    if (page.leaves.length === 0) break;
    const raw = new Uint8Array(page.leaves.length * LEAF_BYTES);
    page.leaves.forEach((leaf, i) => raw.set(fromHex(leaf), i * LEAF_BYTES));
    count = await appendCached(count, raw);
  }
  const { bytes } = await cachedLeaves();
  const summary = await loadProver(bytes, count);
  if (!st.recent_roots.includes(summary.root)) {
    if (retry) {
      await resetPool();
      return syncPool(rpcUrl, st, false);
    }
    throw new Error('The pool this node served does not add up to its own root. Try again in a moment.');
  }
  return { leafCount: count, root: summary.root, bytes };
}

function resolveLeafIndices(notes: StoredNote[], pool: PoolSync): boolean {
  let changed = false;
  if (scanEpoch !== cacheEpoch || scannedUpTo > pool.leafCount) {
    scanEpoch = cacheEpoch;
    scannedUpTo = 0;
  }
  for (const n of notes) {
    if (n.leaf_index != null && (n.leaf_index >= pool.leafCount || leafHexAt(pool.bytes, n.leaf_index) !== n.leaf)) {
      n.leaf_index = null;
      scannedUpTo = 0;
      changed = true;
    }
  }
  const wanted = new Map<string, StoredNote>();
  for (const n of notes) if (n.leaf_index == null) wanted.set(n.leaf, n);
  if (wanted.size > 0) {
    for (let i = scannedUpTo; i < pool.leafCount; i++) {
      const n = wanted.get(leafHexAt(pool.bytes, i));
      if (n) {
        n.leaf_index = i;
        changed = true;
      }
    }
  }
  scannedUpTo = pool.leafCount;
  return changed;
}

async function checkAll(rpcUrl: string, nullifiers: string[], txs: string[]): Promise<ShieldedCheck> {
  const out: ShieldedCheck = { nullifiers: [], txs: [], local_height: 0, network_tip: 0, finalized_height: 0 };
  let first = true;
  for (let i = 0; first || i < Math.max(nullifiers.length, txs.length); i += CHECK_BATCH) {
    const part = await checkShielded(nullifiers.slice(i, i + CHECK_BATCH), txs.slice(i, i + CHECK_BATCH), rpcUrl);
    out.nullifiers.push(...part.nullifiers);
    out.txs.push(...part.txs);
    out.local_height = part.local_height;
    out.network_tip = part.network_tip;
    out.finalized_height = part.finalized_height;
    first = false;
  }
  return out;
}

async function chainView(rpcUrl: string, notes: StoredNote[]): Promise<{ view: ChainView; lag: number }> {
  const nullifiers = [...new Set(notes.map(n => n.nullifier))];
  const txs = [...new Set(notes.flatMap(n => [n.deposit_tx, n.spent_tx ?? '']).filter(Boolean))];
  const chk = await checkAll(rpcUrl, nullifiers, txs);
  const spent = new Map(nullifiers.map((n, i) => [n, chk.nullifiers[i] ?? false]));
  const byHash = new Map<string, TxCheck>(chk.txs.map(t => [t.hash, t]));
  return {
    view: {
      now: now(),
      behind: chk.network_tip > chk.local_height,
      nullifierSpent: n => spent.get(n) ?? false,
      tx: h => byHash.get(h),
    },
    lag: Math.max(0, chk.network_tip - chk.local_height),
  };
}

function leafPositions(pool: PoolSync, wanted: Set<string>): Map<string, number> {
  const hits = new Map<string, number>();
  if (wanted.size === 0) return hits;
  for (let i = 0; i < pool.leafCount; i++) {
    const leaf = leafHexAt(pool.bytes, i);
    if (wanted.has(leaf)) hits.set(leaf, i);
  }
  return hits;
}

async function recoverDomain(
  ctx: ShieldedContext,
  domain: NoteDomain,
  ceiling: number,
  known: Set<string>,
  pool: PoolSync,
): Promise<{ found: StoredNote[]; highest: number }> {
  const found: StoredNote[] = [];
  let highest = -1;
  let misses = 0;
  let start = 0;
  while (start <= ceiling || misses < RECOVERY_GAP) {
    const batch = Array.from({ length: RECOVERY_BATCH }, (_, k) => start + k);
    const derived = await deriveNotes(batch.map(j => ({ ...noteSecrets(ctx.seed, j, domain), values: DENOMINATIONS_UEGOC })));
    const hits = leafPositions(pool, new Set(derived.flatMap(d => d.leaves)));
    for (let k = 0; k < derived.length; k++) {
      const j = start + k;
      const d = derived[k];
      const v = d.leaves.findIndex(leaf => hits.has(leaf));
      if (v >= 0) {
        misses = 0;
        highest = Math.max(highest, j);
        if (!known.has(d.commitment)) {
          found.push({
            index: j,
            domain,
            source: domain === 'desktop' ? 'desktop' : 'extension',
            value_uegoc: DENOMINATIONS_UEGOC[v],
            commitment: d.commitment,
            nullifier: d.nullifier,
            leaf: d.leaves[v],
            leaf_index: hits.get(d.leaves[v]) ?? null,
            created_at: now(),
            deposit_tx: '',
            spent_tx: null,
            spent_at: null,
            cancelled_at: null,
          });
        }
      } else if (j > ceiling) {
        misses += 1;
        if (misses >= RECOVERY_GAP) break;
      }
    }
    start += RECOVERY_BATCH;
  }
  return { found, highest };
}

async function recover(ctx: ShieldedContext, notes: StoredNote[], pool: PoolSync): Promise<number> {
  const known = new Set(notes.map(n => n.commitment));
  const extCeiling = (await nextIndex(ctx, notes)) - 1;
  const found: StoredNote[] = [];
  let extHighest = -1;
  for (const domain of NOTE_DOMAINS) {
    const r = await recoverDomain(ctx, domain, domain === 'ext' ? extCeiling : -1, known, pool);
    found.push(...r.found);
    if (domain === 'ext') extHighest = r.highest;
  }
  let fresh = found;
  if (found.length > 0) {
    const chk = await checkAll(ctx.rpcUrl, found.map(n => n.nullifier), []);
    fresh = found.filter((_, i) => !chk.nullifiers[i]);
  }
  notes.push(...fresh);
  await storageSet({ [nextKeyName(ctx.address)]: Math.max(extCeiling + 1, extHighest + 1) });
  return fresh.length;
}

function bytesHex(v: unknown): string | null {
  return Array.isArray(v) && v.length === 32 && v.every(x => Number.isInteger(x) && x >= 0 && x < 256)
    ? toHex(Uint8Array.from(v as number[]))
    : null;
}

async function importDesktopNotes(
  ctx: ShieldedContext,
  notes: StoredNote[],
  pool: PoolSync | null,
  force = false,
): Promise<{ added: number; changed: boolean }> {
  const none = { added: 0, changed: false };
  const at = Date.now();
  if (!force && at - (lastDesktopSync.get(ctx.address) ?? 0) < DESKTOP_SYNC_EVERY_MS) return none;
  lastDesktopSync.set(ctx.address, at);

  const timestamp = Math.floor(at / 1000);
  const kp = nacl.sign.keyPair.fromSeed(ctx.seed);
  const signature = nacl.sign.detached(new TextEncoder().encode(notesExportMessage(ctx.address, timestamp)), kp.secretKey);
  let desktop: DesktopStoredNote[];
  try {
    const exported = await exportWalletNotes(
      { address: ctx.address, public_key: toHex(kp.publicKey), timestamp, signature: toHex(signature) },
      ctx.rpcUrl,
    );
    if (!exported.found || !exported.sealed) return none;
    desktop = await openSealed<DesktopStoredNote[]>(ctx, b64decode(exported.sealed));
  } catch {
    return none;
  }

  const byCommitment = new Map(notes.map(n => [n.commitment, n]));
  let added = 0;
  let changed = false;
  const candidates: { d: DesktopStoredNote; secret: { owner_secret: string; rho: string }; value: number }[] = [];
  for (const d of desktop) {
    const mine = byCommitment.get(d.commitment);
    if (mine) {
      if (!mine.spent_tx && d.spent_tx) {
        mine.spent_tx = d.spent_tx;
        mine.spent_at = d.spent_at ?? now();
        changed = true;
      }
      continue;
    }
    const owner = bytesHex(d.note?.inner?.owner_secret);
    const rho = bytesHex(d.note?.inner?.rho);
    const value = Number(d.note?.inner?.value_uegoc);
    if (!owner || !rho || !DENOMINATIONS_UEGOC.includes(value)) continue;
    candidates.push({ d, secret: { owner_secret: owner, rho }, value });
  }
  if (candidates.length === 0) return { added, changed };

  const derived = await deriveNotes(candidates.map(c => ({ ...c.secret, values: [c.value] })));
  const hits = pool ? leafPositions(pool, new Set(derived.map(x => x.leaves[0]))) : new Map<string, number>();
  candidates.forEach((c, i) => {
    const x = derived[i];
    if (x.commitment !== c.d.commitment || byCommitment.has(x.commitment)) return;
    const note: StoredNote = {
      index: -1,
      secret: c.secret,
      source: 'desktop',
      value_uegoc: c.value,
      commitment: x.commitment,
      nullifier: x.nullifier,
      leaf: x.leaves[0],
      leaf_index: hits.get(x.leaves[0]) ?? null,
      created_at: Number(c.d.created_at) || now(),
      deposit_tx: c.d.deposit_tx ?? '',
      spent_tx: c.d.spent_tx ?? null,
      spent_at: c.d.spent_at ?? null,
      cancelled_at: c.d.cancelled_at ?? null,
    };
    notes.push(note);
    byCommitment.set(note.commitment, note);
    added += 1;
  });
  if (added > 0) scannedUpTo = 0;
  return { added, changed: changed || added > 0 };
}

function toView(n: StoredNote, status: NoteStatus): NoteView {
  return {
    commitment: n.commitment,
    value_uegoc: n.value_uegoc,
    leaf_index: n.leaf_index,
    status,
    deposit_tx: n.deposit_tx,
    spent_tx: n.spent_tx,
    created_at: n.created_at,
    source: n.source ?? 'extension',
  };
}

async function settle(ctx: ShieldedContext, notes: StoredNote[]): Promise<{ view: ChainView; lag: number; changed: boolean }> {
  const { view, lag } = await chainView(ctx.rpcUrl, notes);
  let changed = false;
  for (const n of notes) {
    if (n.spent_tx) {
      const t = view.tx(n.spent_tx);
      const gone = t?.block_height != null || view.nullifierSpent(n.nullifier);
      if (!gone && withdrawalAbandoned(n, view)) {
        n.spent_tx = null;
        n.spent_at = null;
        changed = true;
      }
      continue;
    }
    if (n.leaf_index == null && n.cancelled_at == null && n.deposit_tx && depositAbandoned(n, view)) {
      n.cancelled_at = now();
      changed = true;
    }
  }
  await resendDropped(ctx, notes, view);
  return { view, lag, changed };
}

async function resendDropped(ctx: ShieldedContext, notes: StoredNote[], view: ChainView): Promise<void> {
  const pending = await loadPending(ctx);
  const hashes = Object.keys(pending);
  if (hashes.length === 0) return;
  const waitingOn = new Set<string>();
  for (const n of notes) {
    if (n.spent_tx) waitingOn.add(n.spent_tx);
    if (n.deposit_tx && n.leaf_index == null && n.cancelled_at == null && !n.spent_tx) waitingOn.add(n.deposit_tx);
  }
  let changed = false;
  for (const hash of hashes) {
    const t = view.tx(hash);
    if (t?.block_height != null || !waitingOn.has(hash)) {
      delete pending[hash];
      lastResent.delete(hash);
      changed = true;
      continue;
    }
    if (view.behind || t?.in_mempool) continue;
    const at = Date.now();
    if (at - (lastResent.get(hash) ?? 0) < RESEND_EVERY_MS) continue;
    lastResent.set(hash, at);
    await submitTx(pending[hash], ctx.rpcUrl).catch(() => undefined);
  }
  if (changed) await savePending(ctx, pending);
}

export function shieldedStatus(ctx: ShieldedContext): Promise<ShieldedStatusView> {
  return exclusive(async () => {
    const st = await getShieldedState(ctx.address, ctx.rpcUrl);
    const info = await getNonceInfo(ctx.address, ctx.rpcUrl);
    const notes = await loadNotes(ctx);
    let changed = false;
    if (st.enabled && st.active) {
      const pool = await syncPool(ctx.rpcUrl, st);
      if ((await importDesktopNotes(ctx, notes, pool)).changed) changed = true;
      changed = resolveLeafIndices(notes, pool) || changed;
      if (!(await storageGet<boolean>(scannedKeyName(ctx.address)))) {
        if ((await recover(ctx, notes, pool)) > 0) changed = true;
        await storageSet({ [scannedKeyName(ctx.address)]: true });
      }
    }
    const { view, lag, changed: settled } = await settle(ctx, notes);
    if (changed || settled) await saveNotes(ctx, notes);

    let ready = 0;
    let pending = 0;
    const views = notes.map(n => {
      const status = noteStatus(n, view);
      if (status === 'ready') ready += n.value_uegoc;
      if (status === 'pending') pending += n.value_uegoc;
      return toView(n, status);
    });
    views.sort((a, b) => b.created_at - a.created_at);
    return {
      enabled: st.enabled,
      active: st.active,
      pool_address: st.pool_address,
      pool_balance_uegoc: st.pool_balance_uegoc,
      leaf_count: st.leaf_count,
      denominations_uegoc: st.denominations_uegoc,
      min_fee_uegoc: st.min_fee_uegoc,
      current_fee_uegoc: st.current_fee_uegoc,
      deposit_fee_uegoc: info.fee_uegoc,
      spendable_uegoc: st.spendable_uegoc,
      max_spends: st.max_spends || MAX_SPENDS,
      proof_system: st.proof_system || PROOF_SYSTEM,
      behind: lag > SYNC_LAG_TOLERANCE,
      notes: views,
      ready_balance_uegoc: ready,
      pending_balance_uegoc: pending,
    };
  });
}

export function shieldDeposit(ctx: ShieldedContext, amountUegoc: number): Promise<ShieldResult> {
  return exclusive(async () => {
    const st = await getShieldedState(ctx.address, ctx.rpcUrl);
    requireOpen(st);
    const { notes: values, remainder } = denominate(amountUegoc);
    if (values.length === 0) {
      throw new Error(`Shield at least ${egoc(DENOMINATIONS_UEGOC[0])} EGOC; notes come in fixed sizes.`);
    }
    const info = await getNonceInfo(ctx.address, ctx.rpcUrl);
    const fee = info.fee_uegoc;
    const shielded = values.reduce((a, v) => a + v, 0);
    const feeTotal = fee * values.length;
    if (shielded + feeTotal > st.spendable_uegoc) {
      throw new Error(
        `Insufficient balance: you have ${egoc(st.spendable_uegoc)} EGOC free, this needs ${egoc(shielded + feeTotal)} ` +
        `(${egoc(shielded)} in notes + ${egoc(feeTotal)} in fees for ${values.length} deposit${values.length === 1 ? '' : 's'}).`,
      );
    }

    const notes = await loadNotes(ctx);
    const first = await nextIndex(ctx, notes);
    const derived = await deriveNotes(values.map((v, k) => ({ ...noteSecrets(ctx.seed, first + k), values: [v] })));
    const created = now();
    const txs = values.map((value, k) =>
      buildSignedEgoTx(ctx.seed, ctx.address, POOL_ADDRESS, value, info.next + k, fee, shieldMemo(derived[k].commitment), TX_SHIELD),
    );
    const fresh: StoredNote[] = values.map((value, k) => ({
      index: first + k,
      value_uegoc: value,
      commitment: derived[k].commitment,
      nullifier: derived[k].nullifier,
      leaf: derived[k].leaves[0],
      leaf_index: null,
      created_at: created,
      deposit_tx: txs[k].hash,
      spent_tx: null,
      spent_at: null,
      cancelled_at: null,
    }));
    const all = [...notes, ...fresh];
    await saveNotes(ctx, all);
    await storageSet({ [nextKeyName(ctx.address)]: first + values.length });
    const pending = await loadPending(ctx);
    for (const tx of txs) pending[tx.hash] = tx;
    await savePending(ctx, pending);

    const hashes: string[] = [];
    for (let k = 0; k < txs.length; k++) {
      try {
        const r = await submitTx(txs[k], ctx.rpcUrl);
        hashes.push(r.tx_hash ?? txs[k].hash);
      } catch (e) {
        const refused = isNodeRefusal(e);
        for (let m = k; m < fresh.length; m++) {
          if (m > k || refused) fresh[m].cancelled_at = now();
        }
        await saveNotes(ctx, all);
        await forgetPending(ctx, txs.slice(refused ? k : k + 1).map(t => t.hash));
        const why = (e as Error).message;
        throw new Error(
          hashes.length === 0
            ? `Deposit refused: ${why}`
            : `${hashes.length} of ${txs.length} deposits went out; the rest stayed in your balance: ${why}`,
        );
      }
    }
    return {
      tx_hashes: hashes,
      notes: values,
      shielded_uegoc: shielded,
      remainder_uegoc: remainder,
      fee_total_uegoc: feeTotal,
    };
  });
}

export function shieldWithdraw(ctx: ShieldedContext, commitments: string[], recipientIn: string): Promise<UnshieldResult> {
  return exclusive(async () => {
    const recipient = recipientIn.trim();
    validateRecipient(recipient);
    if (commitments.length === 0) throw new Error('Select at least one note to spend.');
    if (commitments.length > MAX_SPENDS) throw new Error(`A withdrawal can spend at most ${MAX_SPENDS} notes at once.`);
    if (new Set(commitments).size !== commitments.length) throw new Error('The same note is listed twice.');

    const st = await getShieldedState(ctx.address, ctx.rpcUrl);
    requireOpen(st);
    const pool = await syncPool(ctx.rpcUrl, st);
    const notes = await loadNotes(ctx);
    if (resolveLeafIndices(notes, pool)) await saveNotes(ctx, notes);

    const selected = commitments.map(c => {
      const n = notes.find(x => x.commitment === c);
      if (!n) throw new Error('No such note in this wallet.');
      if (n.spent_tx) throw new Error('A selected note is already being spent.');
      if (n.leaf_index == null) throw new Error("A selected note's deposit has not been confirmed yet.");
      return n;
    });
    const chk = await checkAll(ctx.rpcUrl, selected.map(n => n.nullifier), []);
    if (chk.nullifiers.some(Boolean)) throw new Error('A selected note has already been spent on-chain.');

    const totalFee = st.current_fee_uegoc;
    const shares = feeShares(totalFee, selected.length);
    selected.forEach((n, i) => {
      if (shares[i] >= n.value_uegoc) {
        throw new Error(`The fee of ${egoc(totalFee)} EGOC would consume a ${egoc(n.value_uegoc)} EGOC note.`);
      }
    });

    const proved = await proveSpends({
      leaf_count: pool.leafCount,
      recipient_digest: recipientDigest(recipient),
      spends: selected.map((n, i) => ({
        ...secretsOf(ctx.seed, n),
        value_uegoc: n.value_uegoc,
        leaf_index: n.leaf_index as number,
        fee_uegoc: shares[i],
      })),
    });
    if (!st.recent_roots.includes(proved.root)) {
      throw new Error('The pool moved while this was being prepared. Try again in a moment.');
    }

    const amount = proved.spends.reduce((a, s) => a + s.amount_uegoc, 0);
    const body = unshieldBodyJson(proved.spends, recipient, amount, totalFee);
    const hash = unshieldHash(body);
    const sentAt = now();
    const tx = {
      hash,
      from: POOL_ADDRESS,
      to: recipient,
      amount,
      memo: null,
      timestamp: sentAt,
      signature: '',
      status: 'Pending',
      block_height: null,
      nonce: 0,
      public_key_ed25519: '',
      tx_type: TX_UNSHIELD,
      fee_uegoc: totalFee,
      call_args: body,
      tx_version: 0,
      chain_id: 0,
      signed_summary:
        `Unshield ${(amount / 1_000_000).toFixed(6)} EGOC from ${selected.length} note(s)\n` +
        `  To:      ${recipient}\n` +
        `  Fee:     ${(totalFee / 1_000_000).toFixed(6)} EGOC\n` +
        `  Payout:  ${((amount - totalFee) / 1_000_000).toFixed(6)} EGOC`,
    };

    for (const n of selected) {
      n.spent_tx = hash;
      n.spent_at = sentAt;
    }
    await saveNotes(ctx, notes);
    const pending = await loadPending(ctx);
    pending[hash] = tx;
    await savePending(ctx, pending);
    try {
      await submitTx(tx, ctx.rpcUrl);
    } catch (e) {
      if (isNodeRefusal(e)) {
        for (const n of selected) {
          n.spent_tx = null;
          n.spent_at = null;
        }
        await saveNotes(ctx, notes);
        await forgetPending(ctx, [hash]);
      }
      throw new Error(`Withdrawal refused: ${(e as Error).message}`);
    }
    return { hash, amount_uegoc: amount, fee_uegoc: totalFee, payout_uegoc: amount - totalFee, recipient };
  });
}

export function cancelDeposit(ctx: ShieldedContext, commitment: string): Promise<number> {
  return exclusive(async () => {
    const st = await getShieldedState(ctx.address, ctx.rpcUrl);
    const notes = await loadNotes(ctx);
    if (st.enabled && st.active) resolveLeafIndices(notes, await syncPool(ctx.rpcUrl, st));
    const n = notes.find(x => x.commitment === commitment);
    if (!n) throw new Error('No such note in this wallet.');
    if (n.leaf_index != null) throw new Error('That deposit is already in the pool, so it cannot be cancelled. It is a note you can spend.');
    if (n.spent_tx) throw new Error('That note is already being spent. Cancel the send first.');
    if (n.cancelled_at != null) throw new Error('That deposit has already been cancelled.');
    const { view } = await chainView(ctx.rpcUrl, [n]);
    const t = view.tx(n.deposit_tx);
    if (t?.block_height != null) throw new Error('That deposit is already in a block. It joins the pool shortly.');
    if (t?.in_mempool) {
      throw new Error(
        'That deposit is still queued on your node and will most likely land in the next block. ' +
        'If it has not landed within 5 minutes it is returned to your balance automatically.',
      );
    }
    n.cancelled_at = now();
    await saveNotes(ctx, notes);
    await forgetPending(ctx, [n.deposit_tx]);
    return n.value_uegoc;
  });
}

export function cancelWithdrawal(ctx: ShieldedContext, spentTx: string): Promise<number> {
  return exclusive(async () => {
    const notes = await loadNotes(ctx);
    const waiting = notes.filter(n => n.spent_tx === spentTx);
    if (waiting.length === 0) throw new Error('No note in this wallet is waiting on that transaction.');
    const { view, lag } = await chainView(ctx.rpcUrl, waiting);
    const t = view.tx(spentTx);
    if (t?.block_height != null) throw new Error('That withdrawal is already in a block, so it cannot be cancelled.');
    if (lag > SYNC_LAG_TOLERANCE) {
      throw new Error(
        `Your node is ${lag} blocks behind the network, so it cannot yet tell whether that withdrawal was included. ` +
        'Wait for it to catch up before cancelling.',
      );
    }
    if (t?.in_mempool) {
      throw new Error(
        'That withdrawal is still queued on your node and will most likely land in the next block. ' +
        'If it is dropped, the notes become spendable again on their own.',
      );
    }
    if (waiting.some(n => view.nullifierSpent(n.nullifier))) {
      throw new Error('The chain has already recorded that note as spent, so it cannot be cancelled.');
    }
    for (const n of waiting) {
      n.spent_tx = null;
      n.spent_at = null;
    }
    await saveNotes(ctx, notes);
    await forgetPending(ctx, [spentTx]);
    return waiting.length;
  });
}

export function forgetNote(ctx: ShieldedContext, commitment: string): Promise<void> {
  return exclusive(async () => {
    const notes = await loadNotes(ctx);
    const pos = notes.findIndex(n => n.commitment === commitment);
    if (pos < 0) throw new Error('No such note in this wallet.');
    const { view } = await chainView(ctx.rpcUrl, [notes[pos]]);
    const status = noteStatus(notes[pos], view);
    if (status !== 'spent') {
      throw new Error(`This note is ${status}, not spent, so it stays in the wallet.`);
    }
    notes.splice(pos, 1);
    await saveNotes(ctx, notes);
  });
}

export function forgetSpent(ctx: ShieldedContext): Promise<number> {
  return exclusive(async () => {
    const notes = await loadNotes(ctx);
    const { view } = await chainView(ctx.rpcUrl, notes);
    const kept = notes.filter(n => noteStatus(n, view) !== 'spent');
    const removed = notes.length - kept.length;
    if (removed > 0) await saveNotes(ctx, kept);
    return removed;
  });
}

export function scanForNotes(ctx: ShieldedContext): Promise<number> {
  return exclusive(async () => {
    const st = await getShieldedState(ctx.address, ctx.rpcUrl);
    requireOpen(st);
    const pool = await syncPool(ctx.rpcUrl, st);
    const notes = await loadNotes(ctx);
    const imported = await importDesktopNotes(ctx, notes, pool, true);
    resolveLeafIndices(notes, pool);
    const added = (await recover(ctx, notes, pool)) + imported.added;
    await saveNotes(ctx, notes);
    await storageSet({ [scannedKeyName(ctx.address)]: true });
    return added;
  });
}
