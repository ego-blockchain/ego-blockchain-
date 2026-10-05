const DB_NAME = 'ego-shielded';
const DB_VERSION = 1;
const STORE = 'leaves';
const META = 'meta';
const LEAF_BYTES = 32;
const CHUNK_LEAVES = 4096;
const CHUNK_BYTES = CHUNK_LEAVES * LEAF_BYTES;

interface Meta {
  count: number;
}

let dbPromise: Promise<IDBDatabase> | null = null;
let memory: Uint8Array | null = null;
let memoryCount = 0;

function openDb(): Promise<IDBDatabase> {
  if (!dbPromise) {
    dbPromise = new Promise<IDBDatabase>((resolve, reject) => {
      const req = indexedDB.open(DB_NAME, DB_VERSION);
      req.onupgradeneeded = () => {
        if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE);
      };
      req.onsuccess = () => resolve(req.result);
      req.onerror = () => reject(req.error ?? new Error('could not open the leaf cache'));
    }).catch(e => {
      dbPromise = null;
      throw e;
    });
  }
  return dbPromise;
}

function request<T>(r: IDBRequest<T>): Promise<T> {
  return new Promise((resolve, reject) => {
    r.onsuccess = () => resolve(r.result);
    r.onerror = () => reject(r.error);
  });
}

function done(tx: IDBTransaction): Promise<void> {
  return new Promise((resolve, reject) => {
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
    tx.onabort = () => reject(tx.error ?? new Error('leaf cache write aborted'));
  });
}

function ensureCapacity(bytes: number): void {
  if (memory && memory.length >= bytes) return;
  let size = Math.max(CHUNK_BYTES, memory?.length ?? 0);
  while (size < bytes) size *= 2;
  const next = new Uint8Array(size);
  if (memory) next.set(memory.subarray(0, memoryCount * LEAF_BYTES));
  memory = next;
}

async function load(): Promise<void> {
  if (memory) return;
  const db = await openDb();
  const tx = db.transaction(STORE, 'readonly');
  const store = tx.objectStore(STORE);
  const meta = (await request(store.get(META))) as Meta | undefined;
  const count = meta?.count ?? 0;
  ensureCapacity(count * LEAF_BYTES);
  let loadedCount = 0;
  for (let chunk = 0; loadedCount < count; chunk++) {
    const part = (await request(store.get(chunk))) as Uint8Array | undefined;
    const want = Math.min(CHUNK_LEAVES, count - loadedCount);
    if (!part || part.length < want * LEAF_BYTES) break;
    memory!.set(part.subarray(0, want * LEAF_BYTES), loadedCount * LEAF_BYTES);
    loadedCount += want;
  }
  memoryCount = loadedCount;
}

export async function cachedLeaves(): Promise<{ count: number; bytes: Uint8Array }> {
  await load();
  return { count: memoryCount, bytes: memory!.subarray(0, memoryCount * LEAF_BYTES) };
}

export async function appendCached(from: number, leaves: Uint8Array): Promise<number> {
  await load();
  if (from !== memoryCount) throw new Error(`the leaf cache holds ${memoryCount} leaves, not ${from}`);
  if (leaves.length % LEAF_BYTES !== 0) throw new Error('a leaf batch must be whole leaves');
  const added = leaves.length / LEAF_BYTES;
  if (added === 0) return memoryCount;
  const total = memoryCount + added;
  ensureCapacity(total * LEAF_BYTES);
  memory!.set(leaves, memoryCount * LEAF_BYTES);

  const db = await openDb();
  const tx = db.transaction(STORE, 'readwrite');
  const store = tx.objectStore(STORE);
  const firstChunk = Math.floor(memoryCount / CHUNK_LEAVES);
  const lastChunk = Math.floor((total - 1) / CHUNK_LEAVES);
  for (let chunk = firstChunk; chunk <= lastChunk; chunk++) {
    const start = chunk * CHUNK_LEAVES;
    const end = Math.min(total, start + CHUNK_LEAVES);
    store.put(memory!.slice(start * LEAF_BYTES, end * LEAF_BYTES), chunk);
  }
  store.put({ count: total } satisfies Meta, META);
  await done(tx);
  memoryCount = total;
  return memoryCount;
}

export async function clearCached(): Promise<void> {
  memory = null;
  memoryCount = 0;
  const db = await openDb();
  const tx = db.transaction(STORE, 'readwrite');
  tx.objectStore(STORE).clear();
  await done(tx);
}

export function leafHexAt(bytes: Uint8Array, index: number): string {
  let s = '';
  const off = index * LEAF_BYTES;
  for (let i = off; i < off + LEAF_BYTES; i++) s += bytes[i].toString(16).padStart(2, '0');
  return s;
}
