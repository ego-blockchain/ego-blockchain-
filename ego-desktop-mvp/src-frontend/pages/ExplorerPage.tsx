import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';

// Matches src/ledger.rs LedgerBlock
interface LedgerBlock {
  height: number;
  hash: string;
  prev_hash: string;
  timestamp: number;
  tx_count: number;
  size_bytes: number;
  miner: string;
  reward: number;
}

// Matches src/ledger.rs LedgerTx
interface LedgerTx {
  hash: string;
  from: string;
  to: string;
  amount: number;
  memo?: string;
  timestamp: number;
  signature: string;
  status: string;
  block_height?: number;
  nonce: number;
}

// Matches src/commands/explorer.rs FileEvent
interface FileEvent {
  cid: string;
  owner: string;
  event_type: string;  // "Stored" | "Received"
  original_size: number;
  encrypted_size: number;
  timestamp: number;
  expiry: number;
  status: string;
}

// Matches src/commands/explorer.rs NetworkStats
interface NetworkStats {
  latest_block: number;
  total_transactions: number;
  total_files_stored: number;
  node_count: number;
  network: string;
}

function shortHash(h: string) { return h.length > 18 ? h.slice(0, 10) + '…' + h.slice(-8) : h; }
function shortAddr(a: string) { return a.length > 16 ? a.slice(0, 10) + '…' + a.slice(-4) : a; }
function shortCid(cid: string) {
  // Show egocid1 prefix + first 6 chars of hash + … + last 6
  const body = cid.slice(7); // strip "egocid1"
  return body.length > 16 ? `egocid1${body.slice(0, 6)}…${body.slice(-6)}` : cid;
}
function fmtBytes(b: number) {
  if (b === 0) return '—';
  if (b >= 1e9) return (b / 1e9).toFixed(2) + ' GB';
  if (b >= 1e6) return (b / 1e6).toFixed(2) + ' MB';
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB';
  return b + ' B';
}
function timeAgo(ts: number) {
  const diff = Math.floor(Date.now() / 1000 - ts);
  if (diff < 60)    return `${diff}s ago`;
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

interface Tokenomics {
  total_supply_egoc:  number;
  circulating_egoc:   number;
  circulating_pct:    number;
  emission_pools: {
    genesis:       { cap_uegoc: number; pct: number };
    block_rewards: { cap_uegoc: number; pct: number };
    storage:       { cap_uegoc: number; pct: number };
    coverage:      { cap_uegoc: number; pct: number };
    ecosystem:     { cap_uegoc: number; pct: number };
  };
  block_rewards_issued_uegoc: number;
  halving: {
    era:                    number;
    interval_blocks:        number;
    current_reward_egoc:    number;
    blocks_to_next_halving: number;
    next_halving_at_block:  number;
    max_block_height:       number;
  };
  staking: {
    total_staked_egoc: number;
    active_stakers:    number;
    min_stake_egoc:    number;
  };
  drs: {
    min_drs_to_mine: number;
    weights: { poc: number; post: number; stake: number };
  };
}

type Tab = 'blocks' | 'txs' | 'files' | 'tokenomics';

const ExplorerPage: React.FC = () => {
  const [tab, setTab] = useState<Tab>('blocks');
  const [blocks, setBlocks] = useState<LedgerBlock[]>([]);
  const [txs, setTxs] = useState<LedgerTx[]>([]);
  const [fileEvents, setFileEvents] = useState<FileEvent[]>([]);
  const [netStats, setNetStats] = useState<NetworkStats | null>(null);
  const [tokenomics, setTokenomics] = useState<Tokenomics | null>(null);
  const [selectedBlock, setSelectedBlock] = useState<LedgerBlock | null>(null);
  const [selectedTx, setSelectedTx] = useState<LedgerTx | null>(null);
  const [selectedFile, setSelectedFile] = useState<FileEvent | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadData();
    const unsub = listen('ego://chain-updated', () => { loadData(); });
    return () => { unsub.then(fn => fn()); };
  }, []);

  async function loadData() {
    setLoading(true);
    try {
      const [b, t, n, fe] = await Promise.all([
        invoke<LedgerBlock[]>('get_blocks'),
        invoke<LedgerTx[]>('get_all_transactions'),
        invoke<NetworkStats>('get_network_stats'),
        invoke<FileEvent[]>('get_file_events'),
      ]);
      setBlocks(b);
      setTxs(t);
      setNetStats(n);
      setFileEvents(fe);
    } catch (e) {
      console.error('Explorer load failed:', e);
    } finally {
      setLoading(false);
    }
    invoke<Tokenomics>('get_tokenomics').then(setTokenomics).catch(() => {});
  }

  async function handleSearch() {
    const q = searchQuery.trim();
    if (!q) return;
    // CID search
    if (q.startsWith('egocid1')) {
      const ev = fileEvents.find(e => e.cid.startsWith(q));
      if (ev) { setSelectedFile(ev); setTab('files'); return; }
    }
    try {
      if (q.match(/^\d+$/)) {
        const block = await invoke<LedgerBlock>('get_block_info', { height: parseInt(q) });
        setSelectedBlock(block); setTab('blocks');
      } else {
        const tx = await invoke<LedgerTx>('get_transaction_info', { hash: q });
        setSelectedTx(tx); setTab('txs');
      }
    } catch {
      alert('Not found: ' + q);
    }
  }

  const tabs: { key: Tab; label: string; count: number }[] = [
    { key: 'blocks',     label: '🧱 Blocks',       count: blocks.length      },
    { key: 'txs',        label: '↔️ Transactions', count: txs.length         },
    { key: 'files',      label: '📁 Files',         count: fileEvents.length  },
    { key: 'tokenomics', label: '💰 Tokenomics',    count: 0                  },
  ];

  const statsCards = [
    { label: 'Latest Block',   val: netStats ? `#${netStats.latest_block.toLocaleString()}` : '—' },
    { label: 'Transactions',   val: netStats ? netStats.total_transactions.toString() : '—' },
    { label: 'Files Stored',   val: netStats ? netStats.total_files_stored.toString() : '—' },
    { label: 'Active Nodes',   val: netStats ? netStats.node_count.toString() : '—', highlight: true },
    { label: 'Network',        val: netStats?.network ?? 'Testnet' },
  ];

  return (
    <div className="p-6 space-y-5 max-w-5xl mx-auto">
      {/* Network stats */}
      <div className="grid grid-cols-5 gap-3">
        {statsCards.map(c => (
          <div key={c.label} className={`rounded-xl p-4 border ${'highlight' in c && c.highlight ? 'bg-green-500/10 border-green-500/30' : 'bg-gray-800 border-gray-700'}`}>
            <div className="text-xs text-gray-400 mb-1">{c.label}</div>
            <div className={`font-bold text-sm ${'highlight' in c && c.highlight ? 'text-green-400' : ''}`}>{c.val}</div>
          </div>
        ))}
      </div>

      {/* Search */}
      <div className="flex gap-3">
        <input
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleSearch()}
          className="flex-1 bg-gray-800 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none transition"
          placeholder="Search by block height, tx hash, or file CID (egocid1…)…"
        />
        <button
          onClick={handleSearch}
          className="bg-blue-600 hover:bg-blue-500 transition px-5 py-3 rounded-xl font-semibold text-sm"
        >
          🔍 Search
        </button>
        <button
          onClick={loadData}
          className="bg-gray-700 hover:bg-gray-600 transition px-4 py-3 rounded-xl text-sm"
          title="Refresh"
        >
          ↻
        </button>
      </div>

      {/* Tabs + table */}
      <div className="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
        <div className="flex border-b border-gray-700">
          {tabs.map(t => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`flex-1 py-3.5 text-sm font-medium transition flex items-center justify-center gap-2 ${
                tab === t.key ? 'text-white border-b-2 border-blue-500 bg-blue-500/5' : 'text-gray-400 hover:text-gray-200'
              }`}
            >
              {t.label}
              {t.count > 0 && (
                <span className="text-xs bg-gray-700 rounded-full px-1.5 py-0.5 text-gray-300">{t.count}</span>
              )}
            </button>
          ))}
        </div>

        {loading ? (
          <div className="py-16 text-center text-gray-500">
            <div className="text-3xl mb-3 animate-spin">⏳</div>
            <div className="text-sm">Loading chain data…</div>
          </div>

        ) : tab === 'blocks' ? (
          blocks.length === 0 ? (
            <div className="py-16 text-center text-gray-500">
              <div className="text-4xl mb-3">🧱</div>
              <div className="text-sm">No blocks yet</div>
              <div className="text-xs mt-1 text-gray-600">Send a transaction to mine the first block</div>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-700 text-xs text-gray-400">
                    <th className="px-5 py-3 text-left">Block</th>
                    <th className="px-5 py-3 text-left">Hash</th>
                    <th className="px-5 py-3 text-left">Miner</th>
                    <th className="px-5 py-3 text-right">Txs</th>
                    <th className="px-5 py-3 text-right">Reward</th>
                    <th className="px-5 py-3 text-right">Age</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700/50">
                  {blocks.map(block => (
                    <tr
                      key={block.height}
                      onClick={() => setSelectedBlock(block)}
                      className="hover:bg-gray-700/40 cursor-pointer transition"
                    >
                      <td className="px-5 py-3 font-mono text-blue-400">#{block.height.toLocaleString()}</td>
                      <td className="px-5 py-3 font-mono text-xs text-gray-300">{shortHash(block.hash)}</td>
                      <td className="px-5 py-3 font-mono text-xs text-gray-400">{shortAddr(block.miner)}</td>
                      <td className="px-5 py-3 text-right text-gray-300">{block.tx_count}</td>
                      <td className="px-5 py-3 text-right text-green-400">{(block.reward / 1_000_000).toFixed(0)} EGOC</td>
                      <td className="px-5 py-3 text-right text-gray-500 text-xs">{timeAgo(block.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )

        ) : tab === 'txs' ? (
          txs.length === 0 ? (
            <div className="py-16 text-center text-gray-500">
              <div className="text-4xl mb-3">↔️</div>
              <div className="text-sm">No transactions yet</div>
              <div className="text-xs mt-1 text-gray-600">Use the Wallet tab to send EGOC</div>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-700 text-xs text-gray-400">
                    <th className="px-5 py-3 text-left">Hash</th>
                    <th className="px-5 py-3 text-left">Block</th>
                    <th className="px-5 py-3 text-left">From</th>
                    <th className="px-5 py-3 text-left">To</th>
                    <th className="px-5 py-3 text-right">Amount</th>
                    <th className="px-5 py-3 text-right">Status</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700/50">
                  {txs.map(tx => (
                    <tr
                      key={tx.hash}
                      onClick={() => setSelectedTx(tx)}
                      className="hover:bg-gray-700/40 cursor-pointer transition"
                    >
                      <td className="px-5 py-3 font-mono text-xs text-blue-400">{shortHash(tx.hash)}</td>
                      <td className="px-5 py-3 font-mono text-xs text-gray-400">
                        {tx.block_height != null ? `#${tx.block_height.toLocaleString()}` : '—'}
                      </td>
                      <td className="px-5 py-3 font-mono text-xs text-gray-400">{shortAddr(tx.from)}</td>
                      <td className="px-5 py-3 font-mono text-xs text-gray-400">{shortAddr(tx.to)}</td>
                      <td className="px-5 py-3 text-right text-gray-200">{(tx.amount / 1_000_000).toFixed(2)} EGOC</td>
                      <td className="px-5 py-3 text-right">
                        <span className={`text-xs px-2 py-0.5 rounded-full ${
                          tx.status === 'Confirmed' ? 'bg-green-500/20 text-green-400' :
                          tx.status === 'Pending'   ? 'bg-yellow-500/20 text-yellow-400' :
                                                      'bg-red-500/20 text-red-400'
                        }`}>{tx.status}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )

        ) : tab === 'tokenomics' ? (
          /* ── Tokenomics tab ── */
          !tokenomics ? (
            <div className="py-16 text-center text-gray-500">
              <div className="text-3xl mb-3 animate-pulse">💰</div>
              <div className="text-sm">Loading tokenomics from relay…</div>
              <div className="text-xs mt-1 text-gray-600">Relay must be reachable</div>
            </div>
          ) : (
            <div className="p-5 space-y-5">
              {/* Supply overview */}
              <div className="grid grid-cols-3 gap-3">
                {[
                  { label: 'Total Supply',   val: `${tokenomics.total_supply_egoc.toLocaleString()} EGOC`, color: 'text-white' },
                  { label: 'Circulating',    val: `${tokenomics.circulating_egoc.toLocaleString(undefined,{maximumFractionDigits:0})} EGOC`, color: 'text-green-400' },
                  { label: 'Circulating %',  val: `${tokenomics.circulating_pct}%`, color: 'text-blue-400' },
                ].map(c => (
                  <div key={c.label} className="bg-gray-900 rounded-xl p-4 border border-gray-700/50">
                    <div className="text-xs text-gray-400 mb-1">{c.label}</div>
                    <div className={`text-lg font-bold ${c.color}`}>{c.val}</div>
                  </div>
                ))}
              </div>

              {/* Emission pools */}
              <div>
                <div className="text-xs text-gray-400 mb-3 font-semibold uppercase tracking-wide">Emission Pools</div>
                <div className="space-y-2">
                  {Object.entries({
                    'Genesis Allocation': { ...tokenomics.emission_pools.genesis,       color: 'bg-purple-500' },
                    'Block Rewards':      { ...tokenomics.emission_pools.block_rewards,  color: 'bg-blue-500'   },
                    'Storage (PoST)':     { ...tokenomics.emission_pools.storage,        color: 'bg-green-500'  },
                    'Coverage (PoC)':     { ...tokenomics.emission_pools.coverage,       color: 'bg-yellow-500' },
                    'Ecosystem':          { ...tokenomics.emission_pools.ecosystem,      color: 'bg-orange-500' },
                  }).map(([name, pool]) => (
                    <div key={name} className="flex items-center gap-3">
                      <div className="w-32 text-xs text-gray-400 shrink-0">{name}</div>
                      <div className="flex-1 h-2 bg-gray-700 rounded-full overflow-hidden">
                        <div className={`h-full ${pool.color} rounded-full`} style={{ width: `${pool.pct}%` }} />
                      </div>
                      <div className="text-xs text-gray-300 w-10 text-right">{pool.pct}%</div>
                      <div className="text-xs text-gray-500 w-40 text-right font-mono">
                        {(pool.cap_uegoc / 1_000_000).toLocaleString(undefined,{maximumFractionDigits:0})} EGOC cap
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* Halving schedule */}
              <div className="bg-gray-900 rounded-xl p-4 border border-gray-700/50">
                <div className="text-xs font-semibold text-gray-300 mb-3">Halving Schedule</div>
                <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
                  {[
                    { label: 'Current Era',          val: `Era ${tokenomics.halving.era}` },
                    { label: 'Current Block Reward',  val: `${tokenomics.halving.current_reward_egoc} EGOC` },
                    { label: 'Halving Interval',      val: `${tokenomics.halving.interval_blocks.toLocaleString()} blocks` },
                    { label: 'Next Halving At',       val: `Block #${tokenomics.halving.next_halving_at_block.toLocaleString()}` },
                    { label: 'Blocks to Halving',     val: tokenomics.halving.blocks_to_next_halving.toLocaleString() },
                    { label: 'Current Height',        val: `#${tokenomics.halving.max_block_height.toLocaleString()}` },
                  ].map(r => (
                    <div key={r.label} className="flex justify-between gap-2">
                      <span className="text-gray-400">{r.label}</span>
                      <span className="font-mono text-xs">{r.val}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Staking + DRS */}
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-gray-900 rounded-xl p-4 border border-gray-700/50">
                  <div className="text-xs font-semibold text-gray-300 mb-3">Network Staking</div>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between"><span className="text-gray-400">Total Staked</span><span className="text-orange-400 font-mono">{tokenomics.staking.total_staked_egoc.toLocaleString(undefined,{maximumFractionDigits:0})} EGOC</span></div>
                    <div className="flex justify-between"><span className="text-gray-400">Active Stakers</span><span className="font-mono">{tokenomics.staking.active_stakers}</span></div>
                    <div className="flex justify-between"><span className="text-gray-400">Min to Mine</span><span className="font-mono">{tokenomics.staking.min_stake_egoc.toLocaleString()} EGOC</span></div>
                  </div>
                </div>
                <div className="bg-gray-900 rounded-xl p-4 border border-gray-700/50">
                  <div className="text-xs font-semibold text-gray-300 mb-3">DRS Validator Gate</div>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between"><span className="text-gray-400">Min DRS to Mine</span><span className="font-mono">{tokenomics.drs.min_drs_to_mine}</span></div>
                    <div className="flex justify-between"><span className="text-gray-400">PoC Weight</span><span className="text-blue-400 font-mono">{(tokenomics.drs.weights.poc * 100).toFixed(0)}%</span></div>
                    <div className="flex justify-between"><span className="text-gray-400">PoST Weight</span><span className="text-purple-400 font-mono">{(tokenomics.drs.weights.post * 100).toFixed(0)}%</span></div>
                    <div className="flex justify-between"><span className="text-gray-400">Stake Weight</span><span className="text-orange-400 font-mono">{(tokenomics.drs.weights.stake * 100).toFixed(0)}%</span></div>
                  </div>
                </div>
              </div>
            </div>
          )

        ) : (
          /* ── Files tab ── */
          fileEvents.length === 0 ? (
            <div className="py-16 text-center text-gray-500">
              <div className="text-4xl mb-3">📁</div>
              <div className="text-sm">No file events yet</div>
              <div className="text-xs mt-1 text-gray-600">Store a file in the Storage tab to see it here</div>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-700 text-xs text-gray-400">
                    <th className="px-5 py-3 text-left">CID Hash</th>
                    <th className="px-5 py-3 text-left">Type</th>
                    <th className="px-5 py-3 text-left">Owner</th>
                    <th className="px-5 py-3 text-right">Size</th>
                    <th className="px-5 py-3 text-right">Status</th>
                    <th className="px-5 py-3 text-right">Age</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700/50">
                  {fileEvents.map(ev => (
                    <tr
                      key={ev.cid}
                      onClick={() => setSelectedFile(ev)}
                      className="hover:bg-gray-700/40 cursor-pointer transition"
                    >
                      <td className="px-5 py-3 font-mono text-xs text-blue-400">{shortCid(ev.cid)}</td>
                      <td className="px-5 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                          ev.event_type === 'Stored'   ? 'bg-purple-500/20 text-purple-400' :
                                                         'bg-blue-500/20 text-blue-400'
                        }`}>{ev.event_type}</span>
                      </td>
                      <td className="px-5 py-3 font-mono text-xs text-gray-400">{shortAddr(ev.owner)}</td>
                      <td className="px-5 py-3 text-right text-gray-300 text-xs">{fmtBytes(ev.original_size)}</td>
                      <td className="px-5 py-3 text-right">
                        <span className={`text-xs px-2 py-0.5 rounded-full ${
                          ev.status === 'Active'   ? 'bg-green-500/20 text-green-400' :
                          ev.status === 'Received' ? 'bg-blue-500/20 text-blue-400' :
                                                     'bg-red-500/20 text-red-400'
                        }`}>{ev.status}</span>
                      </td>
                      <td className="px-5 py-3 text-right text-gray-500 text-xs">{timeAgo(ev.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )
        )}
      </div>

      {/* Block detail modal */}
      {selectedBlock && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-lg border border-gray-700 shadow-2xl">
            <div className="flex justify-between items-center mb-5">
              <h3 className="text-lg font-bold">Block #{selectedBlock.height.toLocaleString()}</h3>
              <button onClick={() => setSelectedBlock(null)} className="text-gray-400 hover:text-white text-xl">✕</button>
            </div>
            <div className="space-y-3 text-sm">
              {[
                { label: 'Height',       val: `#${selectedBlock.height.toLocaleString()}` },
                { label: 'Hash',         val: selectedBlock.hash,      mono: true },
                { label: 'Prev Hash',    val: selectedBlock.prev_hash, mono: true },
                { label: 'Timestamp',    val: new Date(selectedBlock.timestamp * 1000).toLocaleString() },
                { label: 'Miner',        val: selectedBlock.miner,     mono: true },
                { label: 'Reward',       val: `${(selectedBlock.reward / 1_000_000).toFixed(2)} EGOC` },
                { label: 'Transactions', val: String(selectedBlock.tx_count) },
                { label: 'Size',         val: `${(selectedBlock.size_bytes / 1024).toFixed(1)} KB` },
                { label: 'Finality',     val: 'Dilithium QC verified ✓' },
              ].map(({ label, val, mono }) => (
                <div key={label} className="flex justify-between items-start gap-4 py-1.5 border-b border-gray-700/50 last:border-0">
                  <span className="text-gray-400 shrink-0">{label}</span>
                  <span className={`text-right break-all ${mono ? 'font-mono text-xs text-gray-300' : ''}`}>{val}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* TX detail modal */}
      {selectedTx && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-lg border border-gray-700 shadow-2xl">
            <div className="flex justify-between items-center mb-5">
              <h3 className="text-lg font-bold">Transaction</h3>
              <button onClick={() => setSelectedTx(null)} className="text-gray-400 hover:text-white text-xl">✕</button>
            </div>
            <div className={`rounded-xl p-4 text-center mb-5 ${
              selectedTx.status === 'Confirmed' ? 'bg-green-500/10 border border-green-500/20' :
              selectedTx.status === 'Pending'   ? 'bg-yellow-500/10 border border-yellow-500/20' :
                                                  'bg-red-500/10 border border-red-500/20'
            }`}>
              <div className="text-3xl mb-1">
                {selectedTx.status === 'Confirmed' ? '✅' : selectedTx.status === 'Pending' ? '⏳' : '❌'}
              </div>
              <div className="text-2xl font-black text-white">
                {(selectedTx.amount / 1_000_000).toFixed(6)} EGOC
              </div>
              <div className={`text-sm ${
                selectedTx.status === 'Confirmed' ? 'text-green-400' :
                selectedTx.status === 'Pending'   ? 'text-yellow-400' : 'text-red-400'
              }`}>{selectedTx.status}</div>
            </div>
            <div className="space-y-3 text-sm">
              {[
                { label: 'Hash',      val: selectedTx.hash,                    mono: true },
                { label: 'Block',     val: selectedTx.block_height != null ? `#${selectedTx.block_height.toLocaleString()}` : 'Unconfirmed' },
                { label: 'From',      val: selectedTx.from,                    mono: true },
                { label: 'To',        val: selectedTx.to,                      mono: true },
                { label: 'Amount',    val: `${(selectedTx.amount / 1_000_000).toFixed(6)} EGOC` },
                { label: 'Fee',       val: 'Free (wallet-to-wallet)' },
                { label: 'Nonce',     val: String(selectedTx.nonce) },
                { label: 'Timestamp', val: new Date(selectedTx.timestamp * 1000).toLocaleString() },
                { label: 'Signature', val: selectedTx.signature.slice(0, 32) + '…', mono: true },
                ...(selectedTx.memo ? [{ label: 'Memo', val: selectedTx.memo }] : []),
              ].map(({ label, val, mono }) => (
                <div key={label} className="flex justify-between items-start gap-4 py-1.5 border-b border-gray-700/50 last:border-0">
                  <span className="text-gray-400 shrink-0">{label}</span>
                  <span className={`text-right break-all ${mono ? 'font-mono text-xs text-gray-300' : ''}`}>{val}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* File event detail modal */}
      {selectedFile && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-lg border border-gray-700 shadow-2xl">
            <div className="flex justify-between items-center mb-5">
              <h3 className="text-lg font-bold">File Event</h3>
              <button onClick={() => setSelectedFile(null)} className="text-gray-400 hover:text-white text-xl">✕</button>
            </div>

            <div className={`rounded-xl p-4 text-center mb-5 ${
              selectedFile.event_type === 'Received'
                ? 'bg-blue-500/10 border border-blue-500/20'
                : 'bg-purple-500/10 border border-purple-500/20'
            }`}>
              <div className="text-3xl mb-1">{selectedFile.event_type === 'Received' ? '📥' : '📤'}</div>
              <div className={`text-lg font-bold ${selectedFile.event_type === 'Received' ? 'text-blue-400' : 'text-purple-400'}`}>
                {selectedFile.event_type === 'Received' ? 'File Received' : 'File Stored'}
              </div>
              <div className="text-xs text-gray-400 mt-1">
                {selectedFile.event_type === 'Received'
                  ? 'Shared by another Ego user'
                  : 'Encrypted and committed to ledger'}
              </div>
            </div>

            <div className="space-y-3 text-sm">
              {[
                { label: 'CID (hash)',      val: selectedFile.cid,                                          mono: true },
                { label: 'Owner',           val: selectedFile.owner,                                        mono: true },
                { label: 'Type',            val: selectedFile.event_type },
                { label: 'Original size',   val: fmtBytes(selectedFile.original_size) },
                { label: 'Encrypted size',  val: fmtBytes(selectedFile.encrypted_size) },
                { label: 'Stored at',       val: new Date(selectedFile.timestamp * 1000).toLocaleString() },
                { label: 'Expires',         val: new Date(selectedFile.expiry * 1000).toLocaleDateString() },
                { label: 'Status',          val: selectedFile.status },
                { label: 'Encryption',      val: 'AES-256-GCM' },
                { label: 'Hash function',   val: 'BLAKE2s-256' },
              ].map(({ label, val, mono }) => (
                <div key={label} className="flex justify-between items-start gap-4 py-1.5 border-b border-gray-700/50 last:border-0">
                  <span className="text-gray-400 shrink-0">{label}</span>
                  <span className={`text-right break-all ${mono ? 'font-mono text-xs text-gray-300' : ''}`}>{val}</span>
                </div>
              ))}
            </div>

            <div className="mt-4 bg-gray-900/60 rounded-lg px-4 py-3 text-xs text-gray-500">
              🔒 File name and decryption key are private — they are never stored on-chain or visible to network nodes.
              Only the CID (content hash) is public.
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default ExplorerPage;
