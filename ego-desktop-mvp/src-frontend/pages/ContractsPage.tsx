import React, { useState, useEffect, useCallback, useRef } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { useLocation } from 'react-router-dom';
import { useWallet } from '../App';

interface ContractInfo {
  address:     string;
  name:        string;
  deployer:    string;
  deployed_at: number;
  code_hash:   string;
  abi:         string[];
}

interface DeployResult {
  contract_address: string;
  code_hash:        string;
  ru_used:          number;
}

interface CallResult {
  success:    boolean;
  return_val: number[];
  ru_used:    number;
  events:     { contract: string; topic: string; payload: number[]; height: number; timestamp: number }[];
  error:      string | null;
}

interface StoredEvent {
  topic:        string;
  payload_hex:  string;
  timestamp:    number;
  block_height: number;
  entrypoint:   string;
}

function fmtDate(ts: number): string {
  return new Date(ts * 1000).toLocaleDateString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
  });
}

function truncAddr(addr: string): string {
  if (addr.length <= 18) return addr;
  return addr.slice(0, 10) + '…' + addr.slice(-6);
}

function bytesToHex(bytes: number[]): string {
  return bytes.map(b => b.toString(16).padStart(2, '0')).join('');
}

function textToHex(s: string): string {
  const enc = new TextEncoder();
  return bytesToHex(Array.from(enc.encode(s)));
}

function hexToDisplay(hex: string): string {
  if (!hex) return '';
  try {
    const bytes = hex.match(/.{1,2}/g)!.map(b => parseInt(b, 16));
    const text  = new TextDecoder().decode(new Uint8Array(bytes));
    const printable = text.replace(/[^\x20-\x7e]/g, '').length;
    return printable / Math.max(1, text.length) > 0.8 ? text : hex;
  } catch {
    return hex;
  }
}

function detectContractType(abi: string[]): { label: string; color: string } | null {
  const names = abi.map(s => s.split('(')[0].toLowerCase());
  if (names.includes('transfer') && (names.includes('total_supply') || names.includes('balance_of'))) {
    return { label: 'EGO-20', color: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30' };
  }
  if (names.includes('vote_yes') || names.includes('vote') || names.includes('propose')) {
    return { label: 'DAO', color: 'bg-violet-500/20 text-violet-300 border-violet-500/30' };
  }
  if (names.includes('mint') && names.includes('burn') && names.includes('total_supply')) {
    return { label: 'Token', color: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30' };
  }
  if (names.includes('release') || names.includes('refund')) {
    return { label: 'Escrow', color: 'bg-teal-500/20 text-teal-300 border-teal-500/30' };
  }
  if (abi.length > 0) {
    return { label: 'Custom', color: 'bg-blue-500/20 text-blue-300 border-blue-500/30' };
  }
  return null;
}

const DeployTab: React.FC<{ onDeployed: () => void }> = ({ onDeployed }) => {
  const fileRef     = useRef<HTMLInputElement>(null);
  const [wasmHex,   setWasmHex]   = useState('');
  const [fileName,  setFileName]  = useState('');
  const [initArgs,  setInitArgs]  = useState('');
  const [rawHex,    setRawHex]    = useState(false);
  const [busy,      setBusy]      = useState(false);
  const [result,    setResult]    = useState<DeployResult | null>(null);
  const [error,     setError]     = useState('');

  function handleFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = ev => {
      const bytes = new Uint8Array(ev.target!.result as ArrayBuffer);
      setWasmHex(bytesToHex(Array.from(bytes)));
    };
    reader.readAsArrayBuffer(file);
  }

  async function handleDeploy() {
    if (!wasmHex) { setError('Select a .wasm file first.'); return; }
    setBusy(true);
    setError('');
    setResult(null);
    try {
      const argsHex = rawHex ? initArgs : (initArgs ? textToHex(initArgs) : '');
      const res = await invoke<DeployResult>('deploy_contract', {
        args: { wasm_hex: wasmHex, init_args_hex: argsHex },
      });
      setResult(res);
      onDeployed();
    } catch (e: any) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  if (result) {
    return (
      <div className="space-y-4 max-w-lg">
        <div className="bg-green-500/10 border border-green-500/30 rounded-2xl p-6 space-y-3">
          <div className="text-lg font-bold text-green-400">Contract Deployed</div>
          <div className="space-y-2 text-sm">
            <div>
              <span className="text-gray-400">Contract address</span>
              <div className="font-mono text-xs text-white break-all mt-0.5 bg-gray-900 rounded-xl px-3 py-2 select-all">
                {result.contract_address}
              </div>
            </div>
            <div className="flex gap-6">
              <div>
                <span className="text-gray-400">Code hash</span>
                <div className="font-mono text-xs text-gray-300 mt-0.5">{result.code_hash.slice(0, 24)}…</div>
              </div>
              <div>
                <span className="text-gray-400">RU used</span>
                <div className="text-yellow-400 font-mono text-xs mt-0.5">{result.ru_used.toLocaleString()}</div>
              </div>
            </div>
          </div>
        </div>
        <button
          onClick={() => { setResult(null); setWasmHex(''); setFileName(''); setInitArgs(''); if (fileRef.current) fileRef.current.value = ''; }}
          className="bg-gray-700 hover:bg-gray-600 px-5 py-2.5 rounded-xl text-sm font-semibold transition"
        >
          Deploy Another
        </button>
      </div>
    );
  }

  return (
    <div className="space-y-5 max-w-lg">
      {}
      <div>
        <label className="text-xs text-gray-400 block mb-1.5">WASM Bytecode (.wasm file)</label>
        <div
          onClick={() => fileRef.current?.click()}
          className="border-2 border-dashed border-gray-600 hover:border-blue-500 rounded-xl px-5 py-8 text-center cursor-pointer transition-colors"
        >
          {fileName ? (
            <div className="space-y-1">
              <div className="text-2xl">📦</div>
              <div className="text-sm text-white font-medium">{fileName}</div>
              <div className="text-xs text-gray-400">{(wasmHex.length / 2).toLocaleString()} bytes</div>
            </div>
          ) : (
            <div className="space-y-2 text-gray-400">
              <div className="text-3xl">⬆️</div>
              <div className="text-sm">Click to select a compiled .wasm contract</div>
              <div className="text-xs">Compiled from Urego source</div>
            </div>
          )}
        </div>
        <input ref={fileRef} type="file" accept=".wasm" className="hidden" onChange={handleFile} />
      </div>

      {}
      <div>
        <div className="flex items-center justify-between mb-1.5">
          <label className="text-xs text-gray-400">Init Arguments (optional)</label>
          <button
            onClick={() => setRawHex(r => !r)}
            className="text-xs text-blue-400 hover:text-blue-300"
          >
            {rawHex ? 'Switch to text' : 'Switch to hex'}
          </button>
        </div>
        <input
          type="text"
          value={initArgs}
          onChange={e => setInitArgs(e.target.value)}
          placeholder={rawHex ? 'hex-encoded ABI arguments' : 'plain text (auto-encoded to hex)'}
          className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none font-mono transition"
        />
        {!rawHex && initArgs && (
          <div className="text-xs text-gray-500 mt-1 font-mono">hex: {textToHex(initArgs)}</div>
        )}
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      <button
        onClick={handleDeploy}
        disabled={!wasmHex || busy}
        className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-40 py-3 rounded-xl font-semibold transition"
      >
        {busy ? '⏳ Deploying…' : '🚀 Deploy Contract'}
      </button>

      <p className="text-xs text-gray-500">
        Deployment broadcasts a Deploy TX to all network peers. The contract state persists locally and is replicated when peers sync blocks.
      </p>
    </div>
  );
};

const GENESIS_CONTRACTS = [
  { name: 'EgoDAO',        address: 'egot1qdao000000000000000000000000000000001', standard: 'EGO-8',  icon: '🗳️' },
  { name: 'EgoPriceFeed',  address: 'egot1qoracle00000000000000000000000000001', standard: 'EGO-9',  icon: '📊' },
  { name: 'EgoBridge',     address: 'egot1qbridge00000000000000000000000000001', standard: 'EGO-10', icon: '🌉' },
  { name: 'EGUSD',         address: 'egot1qegusd000000000000000000000000000001', standard: 'EGO-11', icon: '💵' },
];

const InteractTab: React.FC<{ contracts: ContractInfo[]; initialAddr?: string }> = ({ contracts, initialAddr }) => {
  const [addr,       setAddr]       = useState(initialAddr ?? '');
  const [entrypoint, setEntrypoint] = useState('');
  const [callArgs,   setCallArgs]   = useState('');
  const [rawHex,     setRawHex]     = useState(false);
  const [busy,       setBusy]       = useState(false);
  const [result,     setResult]     = useState<CallResult | null>(null);
  const [error,      setError]      = useState('');

  const selectedAbi = contracts.find(c => c.address === addr)?.abi ?? [];

  const callableFns = selectedAbi.filter(s => !s.startsWith('init'));

  async function handleCall() {
    if (!addr)       { setError('Enter a contract address.'); return; }
    if (!entrypoint) { setError('Enter an entrypoint function name.'); return; }
    setBusy(true);
    setError('');
    setResult(null);
    try {
      const argsHex = rawHex ? callArgs : (callArgs ? textToHex(callArgs) : '');
      const res = await invoke<CallResult>('call_contract', {
        args: { contract_addr: addr, entrypoint, args_hex: argsHex },
      });
      setResult(res);
    } catch (e: any) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-5 max-w-lg">
      {}
      <div>
        <div className="text-xs text-gray-500 font-medium mb-2">Genesis Contracts</div>
        <div className="grid grid-cols-2 gap-2">
          {GENESIS_CONTRACTS.map(gc => (
            <button
              key={gc.address}
              onClick={() => setAddr(gc.address)}
              className={`flex items-center gap-2 px-3 py-2 rounded-xl border text-left transition text-xs ${
                addr === gc.address
                  ? 'bg-blue-600/20 border-blue-500/50 text-blue-300'
                  : 'bg-gray-800 border-gray-700 text-gray-300 hover:border-gray-500'
              }`}
            >
              <span>{gc.icon}</span>
              <div className="min-w-0">
                <div className="font-medium truncate">{gc.name}</div>
                <div className="text-gray-500">{gc.standard}</div>
              </div>
            </button>
          ))}
        </div>
      </div>

      {}
      <div>
        <label className="text-xs text-gray-400 block mb-1.5">Contract Address</label>
        <input
          type="text"
          value={addr}
          onChange={e => setAddr(e.target.value.trim())}
          placeholder="egot1…"
          className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none font-mono transition"
        />
        {}
        {contracts.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {contracts.map(c => (
              <button
                key={c.address}
                onClick={() => setAddr(c.address)}
                className={`text-xs px-2.5 py-1 rounded-lg transition ${
                  addr === c.address
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                }`}
              >
                {c.name || truncAddr(c.address)}
              </button>
            ))}
          </div>
        )}
      </div>

      {}
      {callableFns.length > 0 && (
        <div>
          <div className="text-xs text-gray-500 font-medium mb-2">Contract Functions</div>
          <div className="flex flex-wrap gap-1.5">
            {callableFns.map((sig, i) => {
              const name = sig.split('(')[0];
              return (
                <button
                  key={i}
                  onClick={() => setEntrypoint(name)}
                  title={sig}
                  className={`text-xs px-2.5 py-1 rounded-lg font-mono transition border ${
                    entrypoint === name
                      ? 'bg-purple-600 text-white border-purple-500'
                      : 'bg-gray-800 text-gray-300 border-gray-700 hover:border-purple-500 hover:text-purple-300'
                  }`}
                >
                  {sig}
                </button>
              );
            })}
          </div>
        </div>
      )}

      {}
      <div>
        <label className="text-xs text-gray-400 block mb-1.5">Entrypoint</label>
        <input
          type="text"
          value={entrypoint}
          onChange={e => setEntrypoint(e.target.value.trim())}
          placeholder="e.g. transfer, mint, get_balance"
          className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none font-mono transition"
        />
      </div>

      {}
      <div>
        <div className="flex items-center justify-between mb-1.5">
          <label className="text-xs text-gray-400">Arguments (optional)</label>
          <button
            onClick={() => setRawHex(r => !r)}
            className="text-xs text-blue-400 hover:text-blue-300"
          >
            {rawHex ? 'Switch to text' : 'Switch to hex'}
          </button>
        </div>
        <input
          type="text"
          value={callArgs}
          onChange={e => setCallArgs(e.target.value)}
          placeholder={rawHex ? 'hex-encoded ABI arguments' : 'plain text (auto-encoded to hex)'}
          className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none font-mono transition"
        />
        {!rawHex && callArgs && (
          <div className="text-xs text-gray-500 mt-1 font-mono">hex: {textToHex(callArgs)}</div>
        )}
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      <button
        onClick={handleCall}
        disabled={!addr || !entrypoint || busy}
        className="w-full bg-purple-600 hover:bg-purple-500 disabled:opacity-40 py-3 rounded-xl font-semibold transition"
      >
        {busy ? '⏳ Calling…' : '⚡ Call Contract'}
      </button>

      {}
      {result && (
        <div className={`rounded-2xl border p-5 space-y-3 text-sm ${
          result.success
            ? 'bg-green-500/10 border-green-500/30'
            : 'bg-red-500/10 border-red-500/30'
        }`}>
          <div className={`font-bold text-base ${result.success ? 'text-green-400' : 'text-red-400'}`}>
            {result.success ? '✅ Call succeeded' : '❌ Call failed'}
          </div>
          {result.error && (
            <div className="text-red-300 text-xs">{result.error}</div>
          )}
          <div className="flex gap-6">
            <div>
              <div className="text-xs text-gray-400">Return value</div>
              <div className="font-mono text-xs text-white mt-0.5 break-all">
                {(result.return_val?.length ?? 0) > 0
                  ? hexToDisplay(bytesToHex(result.return_val))
                  : '(empty)'}
              </div>
            </div>
            <div>
              <div className="text-xs text-gray-400">RU used</div>
              <div className="text-yellow-400 font-mono text-xs mt-0.5">{result.ru_used.toLocaleString()}</div>
            </div>
          </div>
          {(result.events?.length ?? 0) > 0 && (
            <div>
              <div className="text-xs text-gray-400 mb-1.5">Events ({result.events.length})</div>
              <div className="space-y-1.5">
                {result.events.map((ev, i) => (
                  <div key={i} className="bg-gray-900/60 rounded-xl px-3 py-2 text-xs font-mono">
                    <span className="text-blue-400">{ev.topic}</span>
                    {(ev.payload?.length ?? 0) > 0 && (
                      <span className="text-gray-300 ml-2">{hexToDisplay(bytesToHex(ev.payload))}</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

const StateTab: React.FC<{ contracts: ContractInfo[] }> = ({ contracts }) => {
  const [addr,   setAddr]   = useState('');
  const [prefix, setPrefix] = useState('');
  const [key,    setKey]    = useState('');
  const [busy,   setBusy]   = useState(false);
  const [value,  setValue]  = useState<string | null | undefined>(undefined);
  const [error,  setError]  = useState('');

  async function handleQuery() {
    if (!addr) { setError('Enter a contract address.'); return; }
    setBusy(true);
    setError('');
    setValue(undefined);
    try {
      const res = await invoke<string | null>('get_contract_state', {
        contractAddr: addr,
        prefix,
        key,
      });
      setValue(res);
    } catch (e: any) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-5 max-w-lg">
      {}
      <div>
        <label className="text-xs text-gray-400 block mb-1.5">Contract Address</label>
        <input
          type="text"
          value={addr}
          onChange={e => setAddr(e.target.value.trim())}
          placeholder="egot1…"
          className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none font-mono transition"
        />
        {contracts.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {contracts.map(c => (
              <button
                key={c.address}
                onClick={() => setAddr(c.address)}
                className={`text-xs px-2.5 py-1 rounded-lg transition ${
                  addr === c.address
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                }`}
              >
                {c.name || truncAddr(c.address)}
              </button>
            ))}
          </div>
        )}
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div>
          <label className="text-xs text-gray-400 block mb-1.5">Namespace / Prefix</label>
          <input
            type="text"
            value={prefix}
            onChange={e => setPrefix(e.target.value)}
            placeholder="e.g. balances"
            className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none font-mono transition"
          />
        </div>
        <div>
          <label className="text-xs text-gray-400 block mb-1.5">Key</label>
          <input
            type="text"
            value={key}
            onChange={e => setKey(e.target.value)}
            placeholder="e.g. egot1abc…"
            className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none font-mono transition"
          />
        </div>
      </div>

      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-xl px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      <button
        onClick={handleQuery}
        disabled={!addr || busy}
        className="w-full bg-cyan-600 hover:bg-cyan-500 disabled:opacity-40 py-3 rounded-xl font-semibold transition"
      >
        {busy ? '⏳ Querying…' : '🔎 Read State'}
      </button>

      {value !== undefined && (
        <div className="bg-gray-800 border border-gray-700 rounded-2xl p-5 text-sm space-y-2">
          <div className="text-xs text-gray-400 font-medium">Result</div>
          {value === null ? (
            <div className="text-gray-500 italic">Key not found</div>
          ) : (
            <div className="space-y-1">
              <div className="font-mono text-white break-all">{hexToDisplay(value)}</div>
              <div className="text-xs text-gray-500 font-mono">raw hex: {value}</div>
            </div>
          )}
        </div>
      )}
    </div>
  );
};

const EventsTab: React.FC<{ contracts: ContractInfo[] }> = ({ contracts }) => {
  const [addr,   setAddr]   = useState('');
  const [events, setEvents] = useState<StoredEvent[]>([]);
  const [busy,   setBusy]   = useState(false);

  const loadEvents = useCallback(async (a: string) => {
    if (!a) return;
    setBusy(true);
    try {
      const res = await invoke<StoredEvent[]>('get_contract_events', {
        contractAddr: a,
        limit: 50,
      });
      setEvents(res);
    } catch {
      setEvents([]);
    } finally {
      setBusy(false);
    }
  }, []);

  useEffect(() => { loadEvents(addr); }, [addr, loadEvents]);

  return (
    <div className="space-y-5 max-w-lg">
      <div>
        <label className="text-xs text-gray-400 block mb-1.5">Contract Address</label>
        <input
          type="text"
          value={addr}
          onChange={e => setAddr(e.target.value.trim())}
          placeholder="egot1… or hex address"
          className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none font-mono transition"
        />
        {contracts.length > 0 && (
          <div className="mt-2 flex flex-wrap gap-1.5">
            {contracts.map(c => (
              <button
                key={c.address}
                onClick={() => setAddr(c.address)}
                className={`text-xs px-2.5 py-1 rounded-lg transition ${
                  addr === c.address
                    ? 'bg-blue-600 text-white'
                    : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
                }`}
              >
                {c.name || truncAddr(c.address)}
              </button>
            ))}
          </div>
        )}
      </div>

      {!addr ? (
        <div className="text-center py-10 text-gray-500">
          <div className="text-4xl mb-3">📋</div>
          <div className="text-sm">Select a contract to view its event log</div>
        </div>
      ) : busy ? (
        <div className="text-center py-8 text-gray-500 animate-pulse text-sm">Loading events…</div>
      ) : events.length === 0 ? (
        <div className="text-center py-10 text-gray-500">
          <div className="text-3xl mb-2">🔇</div>
          <div className="text-sm">No events recorded yet</div>
          <div className="text-xs mt-1">Events are captured when you call contract functions</div>
        </div>
      ) : (
        <div className="space-y-2">
          <div className="text-xs text-gray-500 font-medium">{events.length} event{events.length !== 1 ? 's' : ''} (newest first)</div>
          {events.map((ev, i) => (
            <div key={i} className="bg-gray-800 border border-gray-700 rounded-xl px-4 py-3 text-xs">
              <div className="flex items-center justify-between mb-1.5">
                <span className="text-blue-400 font-mono font-semibold">{ev.topic}</span>
                <span className="text-gray-500">{new Date(ev.timestamp * 1000).toLocaleTimeString()}</span>
              </div>
              <div className="text-gray-400 mb-1">
                via <span className="text-purple-400 font-mono">{ev.entrypoint}()</span>
                {' · '}block <span className="text-gray-300">{ev.block_height}</span>
              </div>
              {ev.payload_hex && (
                <div className="font-mono text-gray-300 break-all bg-gray-900/60 rounded-lg px-2 py-1 mt-1">
                  {hexToDisplay(ev.payload_hex)}
                  {hexToDisplay(ev.payload_hex) !== ev.payload_hex && (
                    <span className="text-gray-600 ml-2">(hex: {ev.payload_hex})</span>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

const EXAMPLES = [
  {
    icon: '🪙',
    title: 'EGO-20 Token',
    color: 'from-yellow-500/20 to-orange-500/10 border-yellow-500/30',
    badge: 'bg-yellow-500/20 text-yellow-300',
    badgeLabel: 'EGO-20',
    description: 'Issue your own fungible token with fixed supply, transfers, and allowances. The Ego standard for all fungible assets.',
    entrypoints: ['init(name, symbol, supply)', 'transfer(to, amount)', 'approve(spender, amount)', 'balance_of(addr)'],
    useCases: ['Community currencies', 'In-app credits', 'Governance tokens'],
  },
  {
    icon: '💱',
    title: 'DEX / AMM Pool',
    color: 'from-blue-500/20 to-cyan-500/10 border-blue-500/30',
    badge: 'bg-blue-500/20 text-blue-300',
    badgeLabel: 'EGO-4',
    description: 'Automated market maker using x×y=k constant product formula. Add liquidity, swap tokens, earn fees. Feeless for stakers.',
    entrypoints: ['add_liquidity(token_a, token_b, amount_a, amount_b)', 'swap_exact_in(token_in, amount_in, min_out)', 'remove_liquidity(lp_amount)'],
    useCases: ['Token swaps', 'Liquidity provision', 'LP yield farming'],
  },
  {
    icon: '🏦',
    title: 'Lending Pool',
    color: 'from-green-500/20 to-teal-500/10 border-green-500/30',
    badge: 'bg-green-500/20 text-green-300',
    badgeLabel: 'EGO-13',
    description: 'Overcollateralised lending. Suppliers earn yield. Borrowers post collateral. Health factor < 1.0 triggers liquidation.',
    entrypoints: ['supply(asset, amount)', 'borrow(asset, amount)', 'repay(asset, amount)', 'get_health_factor(user)'],
    useCases: ['Yield on idle tokens', 'Leverage trading', 'Stablecoin borrowing'],
  },
  {
    icon: '🌾',
    title: 'Yield Farm',
    color: 'from-lime-500/20 to-green-500/10 border-lime-500/30',
    badge: 'bg-lime-500/20 text-lime-300',
    badgeLabel: 'EGO-19',
    description: 'MasterChef-style liquidity mining. Stake LP tokens, earn EGOC rewards per block. Multiple pools with allocation points.',
    entrypoints: ['add_pool(staking_token, alloc_points)', 'deposit(pool_id, amount)', 'harvest(pool_id)', 'pending_reward(pool_id, user)'],
    useCases: ['Incentivize DEX pools', 'Protocol-owned liquidity', 'Bootstrap token distribution'],
  },
  {
    icon: '🚀',
    title: 'IDO Launchpad',
    color: 'from-orange-500/20 to-red-500/10 border-orange-500/30',
    badge: 'bg-orange-500/20 text-orange-300',
    badgeLabel: 'EGO-22',
    description: 'Token sale with soft cap / hard cap, pro-rata allocation if oversubscribed. Refunds if soft cap not met. 3% platform fee.',
    entrypoints: ['create_sale(token, raise_token, price, soft_cap, hard_cap, start, end, supply)', 'participate(sale_id, amount)', 'claim_tokens(sale_id)', 'claim_refund(sale_id)'],
    useCases: ['Project fundraising', 'Fair token launches', 'Community rounds'],
  },
  {
    icon: '🗳️',
    title: 'DAO Governance',
    color: 'from-violet-500/20 to-purple-500/10 border-violet-500/30',
    badge: 'bg-violet-500/20 text-violet-300',
    badgeLabel: 'EGO-8',
    description: 'Full on-chain DAO with dual voting (staking + knowledge weight), quorum thresholds per category, and time-locked execution.',
    entrypoints: ['propose(title, category, calldata)', 'vote(proposal_id, support)', 'queue(proposal_id)', 'execute(proposal_id)'],
    useCases: ['Protocol upgrades', 'Treasury management', 'Parameter changes'],
  },
  {
    icon: '🏛️',
    title: 'Government Services',
    color: 'from-slate-500/20 to-gray-500/10 border-slate-500/30',
    badge: 'bg-slate-500/20 text-slate-300',
    badgeLabel: 'EGO-15',
    description: 'First L1-native government module: tax collection, public tenders, sovereign bonds, loan programs, and social grants.',
    entrypoints: ['pay_tax(tax_id, period, amount)', 'publish_tender(title, budget, deadline)', 'participate_sale(sale_id, amount)', 'claim(program_id)'],
    useCases: ['Tax payments', 'Public procurement', 'Citizen grants', 'Sovereign bonds'],
  },
  {
    icon: '🏠',
    title: 'Real Estate Token',
    color: 'from-amber-500/20 to-yellow-500/10 border-amber-500/30',
    badge: 'bg-amber-500/20 text-amber-300',
    badgeLabel: 'EGO-3',
    description: 'Tokenise real-world property as a deed + 1,000,000 fractional EGO-20 shares. KYC-gated transfers, rental income distribution.',
    entrypoints: ['register_property(jurisdiction, cadastral_id, valuation)', 'transfer_shares(to, amount)', 'distribute_rental(amount)', 'set_kyc(addr, approved)'],
    useCases: ['Property fractionalisation', 'REIT on-chain', 'Cross-border real estate'],
  },
  {
    icon: '🤝',
    title: 'Escrow',
    color: 'from-teal-500/20 to-cyan-500/10 border-teal-500/30',
    badge: 'bg-teal-500/20 text-teal-300',
    badgeLabel: 'Payments',
    description: 'Lock EGOC between two parties. Funds release automatically when both confirm delivery, or refund after a deadline.',
    entrypoints: ['create(buyer, seller, amount, deadline)', 'confirm(escrow_id)', 'refund(escrow_id)'],
    useCases: ['P2P trades', 'Freelance payments', 'Marketplace deals'],
  },
];

const ExamplesSection: React.FC = () => {
  const [expanded, setExpanded] = useState<number | null>(null);

  return (
    <div className="mt-6">
      <div className="flex items-center gap-2 mb-4">
        <div className="h-px flex-1 bg-gray-700" />
        <span className="text-xs text-gray-500 font-medium px-2">What can you build?</span>
        <div className="h-px flex-1 bg-gray-700" />
      </div>
      <div className="grid grid-cols-2 gap-3 max-h-[520px] overflow-y-auto pr-1">
        {EXAMPLES.map((ex, i) => (
          <div
            key={i}
            className={`bg-gradient-to-br ${ex.color} border rounded-2xl p-4 cursor-pointer transition-all`}
            onClick={() => setExpanded(expanded === i ? null : i)}
          >
            <div className="flex items-start justify-between gap-2 mb-2">
              <div className="flex items-center gap-2">
                <span className="text-2xl">{ex.icon}</span>
                <div>
                  <div className="font-semibold text-white text-sm leading-tight">{ex.title}</div>
                  <span className={`text-xs px-1.5 py-0.5 rounded-md font-medium ${ex.badge}`}>{ex.badgeLabel}</span>
                </div>
              </div>
              <span className="text-gray-500 text-xs shrink-0 mt-1">{expanded === i ? '▲' : '▼'}</span>
            </div>
            <p className="text-xs text-gray-300 leading-relaxed">{ex.description}</p>

            {expanded === i && (
              <div className="mt-3 space-y-2.5">
                <div>
                  <div className="text-xs text-gray-400 mb-1.5 font-medium">Entrypoints</div>
                  <div className="space-y-1">
                    {ex.entrypoints.map((ep, j) => (
                      <div key={j} className="font-mono text-xs text-gray-200 bg-black/30 rounded-lg px-3 py-1.5">{ep}</div>
                    ))}
                  </div>
                </div>
                <div>
                  <div className="text-xs text-gray-400 mb-1.5 font-medium">Use cases</div>
                  <div className="flex flex-wrap gap-1.5">
                    {ex.useCases.map((uc, j) => (
                      <span key={j} className="text-xs bg-black/20 text-gray-300 rounded-lg px-2 py-1">{uc}</span>
                    ))}
                  </div>
                </div>
              </div>
            )}
          </div>
        ))}
      </div>
      <p className="text-xs text-gray-500 mt-3 text-center">
        10 standards built-in — write contracts in Urego (compiles to WASM) or deploy Solidity via EVM compatibility (EGO-12).
      </p>
    </div>
  );
};

const ContractsList: React.FC<{ contracts: ContractInfo[]; loading: boolean }> = ({ contracts, loading }) => {
  if (loading) {
    return (
      <div className="text-center py-12 text-gray-500">
        <div className="text-3xl animate-pulse mb-3">🔄</div>
        <div className="text-sm">Loading contracts…</div>
      </div>
    );
  }
  return (
    <div>
      {contracts.length === 0 ? (
        <div className="text-center py-10 text-gray-500">
          <div className="text-5xl mb-4">📜</div>
          <div className="text-sm font-medium">No contracts deployed yet</div>
          <div className="text-xs mt-1">Use the dApp IDE to write, compile, and deploy a Urego contract</div>
        </div>
      ) : (
        <div className="space-y-3">
          {contracts.map(c => {
            const contractType = detectContractType(c.abi);
            return (
              <div key={c.address} className="bg-gray-800 border border-gray-700 rounded-2xl p-5">
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span className="text-base">📜</span>
                      <span className="font-semibold text-white">{c.name || 'Unnamed Contract'}</span>
                      {contractType && (
                        <span className={`text-xs px-2 py-0.5 rounded-lg border font-medium ${contractType.color}`}>
                          {contractType.label}
                        </span>
                      )}
                    </div>
                    <div className="font-mono text-xs text-gray-400 break-all">{c.address}</div>
                  </div>
                  <div className="text-xs text-gray-500 shrink-0">{fmtDate(c.deployed_at)}</div>
                </div>
                <div className="mt-3 grid grid-cols-2 gap-3 text-xs">
                  <div>
                    <div className="text-gray-500 mb-0.5">Deployer</div>
                    <div className="font-mono text-gray-300">{truncAddr(c.deployer)}</div>
                  </div>
                  <div>
                    <div className="text-gray-500 mb-0.5">Code hash</div>
                    <div className="font-mono text-gray-300">{c.code_hash.slice(0, 20)}…</div>
                  </div>
                </div>
                {}
                {c.abi.length > 0 && (
                  <div className="mt-3">
                    <div className="text-gray-500 text-xs mb-1.5">Functions ({c.abi.length})</div>
                    <div className="flex flex-wrap gap-1">
                      {c.abi.filter(s => !s.startsWith('init')).map((sig, i) => (
                        <span key={i} className="font-mono text-xs bg-gray-900 text-gray-300 rounded px-2 py-0.5">
                          {sig.split('(')[0]}()
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
      <ExamplesSection />
    </div>
  );
};

interface RollupStatus {
  shard_count:         number;
  pending_txs:         number;
  submitted_total:     number;
  confirmed_total:     number;
  batch_interval_ms:   number;
  batch_size:          number;
  total_blocks:        number;
  total_txs:           number;
  latest_block_height: number;
  shard_sizes:         number[];
  theoretical_tps:     number;
  last_batch_tps:      number;
}

const RollupBar: React.FC = () => {
  const [status, setStatus] = useState<RollupStatus | null>(null);

  useEffect(() => {
    const fetch = () => invoke<RollupStatus>('get_rollup_status').then(setStatus).catch(() => {});
    fetch();
    const t = setInterval(fetch, 2_000);
    return () => clearInterval(t);
  }, []);

  if (!status) return null;

  const maxShard   = Math.max(...status.shard_sizes, 1);
  const totalPct   = Math.min(100, (status.pending_txs / (status.shard_count * status.batch_size)) * 100);
  const tpsDisplay = status.last_batch_tps > 0
    ? status.last_batch_tps.toLocaleString()
    : '—';

  return (
    <div className="bg-gray-800/80 border border-gray-700 rounded-2xl px-5 py-4">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-2">
          <span className="text-sm font-semibold text-white">⚡ Rollup Engine</span>
          <span className="text-xs bg-blue-600/30 text-blue-300 px-2 py-0.5 rounded-lg">
            {status.shard_count} shards · {status.batch_interval_ms}ms batches
          </span>
        </div>
        <div className="flex items-center gap-4 text-xs">
          <div className="text-right">
            <div className="text-gray-400">Last batch</div>
            <div className="text-green-400 font-mono font-bold">{tpsDisplay} TPS</div>
          </div>
          <div className="text-right">
            <div className="text-gray-400">Peak capacity</div>
            <div className="text-blue-400 font-mono font-bold">{status.theoretical_tps.toLocaleString()} TPS</div>
          </div>
          <div className="text-right">
            <div className="text-gray-400">Pending</div>
            <div className="text-yellow-400 font-mono font-bold">{status.pending_txs.toLocaleString()}</div>
          </div>
          <div className="text-right">
            <div className="text-gray-400">Confirmed</div>
            <div className="text-purple-400 font-mono font-bold">{status.confirmed_total.toLocaleString()}</div>
          </div>
        </div>
      </div>

      {}
      <div className="space-y-1">
        <div className="text-xs text-gray-500 mb-1.5">Shard load ({status.shard_count} shards)</div>
        <div className="grid gap-1" style={{ gridTemplateColumns: `repeat(${status.shard_count}, 1fr)` }}>
          {status.shard_sizes.map((sz, i) => {
            const pct = (sz / maxShard) * 100;
            const color = pct > 80 ? 'bg-red-500' : pct > 50 ? 'bg-yellow-500' : 'bg-blue-500';
            return (
              <div key={i} title={`Shard ${i}: ${sz} pending`} className="flex flex-col items-center gap-0.5">
                <div className="w-full h-6 bg-gray-700 rounded overflow-hidden flex items-end">
                  <div className={`w-full ${color} transition-all`} style={{ height: `${Math.max(2, pct)}%` }} />
                </div>
                <span className="text-gray-600 font-mono" style={{ fontSize: '8px' }}>{i}</span>
              </div>
            );
          })}
        </div>
      </div>

      {}
      <div className="mt-2">
        <div className="h-1 bg-gray-700 rounded-full overflow-hidden">
          <div className="h-full bg-gradient-to-r from-blue-500 to-purple-500 transition-all"
               style={{ width: `${totalPct}%` }} />
        </div>
        <div className="flex justify-between text-xs text-gray-500 mt-0.5">
          <span>Mempool {totalPct.toFixed(1)}% full</span>
          <span>Block #{status.latest_block_height.toLocaleString()} · {status.total_txs.toLocaleString()} total TXs</span>
        </div>
      </div>
    </div>
  );
};

type Tab = 'contracts' | 'deploy' | 'interact' | 'state' | 'events';

const ContractsPage: React.FC = () => {
  const { wallet }                     = useWallet();
  const location                       = useLocation();
  const fromIDE                        = location.state as { address?: string; abi?: string[] } | null;
  const [tab,       setTab]            = useState<Tab>(fromIDE?.address ? 'interact' : 'contracts');
  const [contracts, setContracts]      = useState<ContractInfo[]>([]);
  const [loadingList, setLoadingList]  = useState(true);

  const loadContracts = useCallback(async () => {
    setLoadingList(true);
    try {
      const list = await invoke<ContractInfo[]>('list_deployed_contracts');
      setContracts(list);
    } catch {}
    finally { setLoadingList(false); }
  }, []);

  useEffect(() => { loadContracts(); }, [loadContracts, wallet?.address]);

  const TABS: { id: Tab; label: string; icon: string }[] = [
    { id: 'contracts', label: 'Contracts',  icon: '📜' },
    { id: 'deploy',    label: 'Deploy',     icon: '🚀' },
    { id: 'interact',  label: 'Interact',   icon: '⚡' },
    { id: 'state',     label: 'Read State', icon: '🔎' },
    { id: 'events',    label: 'Events',     icon: '📋' },
  ];

  return (
    <div className="p-6 space-y-5 max-w-4xl mx-auto">
      {}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Smart Contracts</h1>
          <p className="text-xs text-gray-400 mt-0.5">Deploy and interact with Urego contracts on the Ego network</p>
        </div>
        <div className="flex items-center gap-2 bg-gray-800 border border-gray-700 rounded-xl px-4 py-2 text-xs text-gray-400">
          <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse"></span>
          {contracts.length} contract{contracts.length !== 1 ? 's' : ''} deployed
        </div>
      </div>

      {}
      <RollupBar />

      {}
      <div className="flex gap-1 bg-gray-800 border border-gray-700 rounded-2xl p-1">
        {TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            className={`flex-1 flex items-center justify-center gap-1.5 py-2.5 rounded-xl text-xs font-medium transition ${
              tab === t.id
                ? 'bg-blue-600 text-white shadow'
                : 'text-gray-400 hover:text-white hover:bg-gray-700'
            }`}
          >
            <span>{t.icon}</span>
            <span>{t.label}</span>
          </button>
        ))}
      </div>

      {}
      {tab === 'contracts' && (
        <ContractsList contracts={contracts} loading={loadingList} />
      )}
      {tab === 'deploy' && (
        <DeployTab onDeployed={() => { loadContracts(); setTab('contracts'); }} />
      )}
      {tab === 'interact' && (
        <InteractTab contracts={contracts} initialAddr={fromIDE?.address} />
      )}
      {tab === 'state' && (
        <StateTab contracts={contracts} />
      )}
      {tab === 'events' && (
        <EventsTab contracts={contracts} />
      )}
    </div>
  );
};

export default ContractsPage;
