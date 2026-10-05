interface StarkExports {
  memory: WebAssembly.Memory;
  ego_alloc(len: number): number;
  ego_free(ptr: number, len: number): void;
  ego_call(ptr: number, len: number): number;
  ego_tree_append(ptr: number, len: number): number;
  ego_output_ptr(): number;
  ego_output_len(): number;
}

export interface TreeSummary {
  root: string;
  leaf_count: number;
}

export interface DerivedNote {
  commitment: string;
  nullifier: string;
  leaves: string[];
}

export interface ProvedSpend {
  root: string;
  nullifier: string;
  amount_uegoc: number;
  fee_uegoc: number;
  proof: string;
}

const WASM_PATH = 'ego_stark.wasm';
const RANDOM_CHUNK = 65_536;

let loaded: Promise<StarkExports> | null = null;
let generation = 0;

async function instantiate(): Promise<StarkExports> {
  const res = await fetch(chrome.runtime.getURL(WASM_PATH));
  if (!res.ok) throw new Error('The shielded prover is missing from this build of the extension.');
  const bytes = await res.arrayBuffer();
  let memory: WebAssembly.Memory | null = null;
  const imports = {
    env: {
      ego_random(ptr: number, len: number): number {
        if (!memory) return 1;
        for (let off = 0; off < len; off += RANDOM_CHUNK) {
          crypto.getRandomValues(new Uint8Array(memory.buffer, ptr + off, Math.min(RANDOM_CHUNK, len - off)));
        }
        return 0;
      },
    },
  };
  const { instance } = await WebAssembly.instantiate(bytes, imports);
  const x = instance.exports as unknown as StarkExports;
  memory = x.memory;
  generation += 1;
  return x;
}

function stark(): Promise<StarkExports> {
  if (!loaded) {
    loaded = instantiate().catch(e => {
      loaded = null;
      throw e;
    });
  }
  return loaded;
}

export function proverGeneration(): number {
  return generation;
}

async function invoke<T>(fn: 'ego_call' | 'ego_tree_append', input: Uint8Array): Promise<T> {
  const x = await stark();
  let out: { error?: string } & Record<string, unknown>;
  let ok: number;
  try {
    const ptr = x.ego_alloc(input.length);
    if (!ptr) throw new Error('The shielded prover ran out of memory.');
    new Uint8Array(x.memory.buffer, ptr, input.length).set(input);
    ok = x[fn](ptr, input.length);
    x.ego_free(ptr, input.length);
    const raw = new Uint8Array(x.memory.buffer, x.ego_output_ptr(), x.ego_output_len());
    out = JSON.parse(new TextDecoder().decode(raw));
  } catch (e) {
    loaded = null;
    throw e instanceof WebAssembly.RuntimeError
      ? new Error(`The shielded prover stopped unexpectedly (${e.message}). Try again.`)
      : e;
  }
  if (!ok) throw new Error(out.error ?? 'The shielded prover refused the request.');
  return out as unknown as T;
}

function callJson<T>(req: object): Promise<T> {
  return invoke<T>('ego_call', new TextEncoder().encode(JSON.stringify(req)));
}

export function deriveNotes(notes: { owner_secret: string; rho: string; values: number[] }[]): Promise<DerivedNote[]> {
  return callJson<DerivedNote[]>({ op: 'notes', notes });
}

export function treeSummary(): Promise<TreeSummary> {
  return callJson<TreeSummary>({ op: 'tree' });
}

export function resetTree(): Promise<TreeSummary> {
  return callJson<TreeSummary>({ op: 'reset' });
}

export function appendLeaves(raw: Uint8Array): Promise<TreeSummary> {
  return invoke<TreeSummary>('ego_tree_append', raw);
}

export function proveSpends(req: {
  leaf_count: number;
  recipient_digest: string;
  spends: { owner_secret: string; rho: string; value_uegoc: number; leaf_index: number; fee_uegoc: number }[];
}): Promise<TreeSummary & { spends: ProvedSpend[] }> {
  return callJson({ op: 'prove', ...req });
}
