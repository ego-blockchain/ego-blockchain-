import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';
import Pagination from '../components/Pagination';
import { txDisplayAmount } from '../constants';
import { open as openUrl } from '@tauri-apps/api/shell';
import { txUrl, blockUrl, addressUrl, searchUrl } from '../config';

type DetailRow = { label: string; val: string; mono?: boolean; href?: string };

function openOnWeb(url: string) {
  return (e?: React.MouseEvent) => {
    e?.stopPropagation();
    openUrl(url).catch(() => {});
  };
}

function DetailValue({ val, mono, href }: { val: string; mono?: boolean; href?: string }) {
  if (!href) return <span className={`text-right break-all ${mono ? 'font-mono text-xs text-gray-300' : ''}`}>{val}</span>;
  return (
    <button
      onClick={openOnWeb(href)}
      title="Open on egoblockchain.com"
      className={`text-right break-all text-blue-400 hover:text-blue-300 hover:underline ${mono ? 'font-mono text-xs' : ''}`}
    >
      {val}
    </button>
  );
}

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
  tx_type?: string;
  cid?: string;
  fee_uegoc?: number;
  priority_fee_uegoc?: number;
  is_private?: boolean;
}

interface FileEvent {
  cid: string;
  owner: string;
  event_type: string;
  original_size: number;
  encrypted_size: number;
  timestamp: number;
  expiry: number;
  status: string;
}

interface NetworkStats {
  latest_block: number;
  total_transactions: number;
  total_files_stored: number;
  local_blocks: number;
  local_transactions: number;
  node_count: number;
  network: string;
}

function shortHash(h: string) { return h.length > 18 ? h.slice(0, 10) + '…' + h.slice(-8) : h; }
function shortAddr(a: string) { return a.length > 16 ? a.slice(0, 10) + '…' + a.slice(-4) : a; }
function shortCid(cid: string) {

  const body = cid.slice(7);
  return body.length > 16 ? `egocid1${body.slice(0, 6)}…${body.slice(-6)}` : cid;
}
function fmtBytes(b: number) {
  if (b === 0) return '—';
  if (b >= 1e9) return (b / 1e9).toFixed(2) + ' GB';
  if (b >= 1e6) return (b / 1e6).toFixed(2) + ' MB';
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB';
  return b + ' B';
}
// A block stamped in the future (its producer's clock was wrong) can't have been made
// after the blocks that follow it, or after now. Such blocks are placed between the last
// block with a believable time and the next one, in height order, so every viewer sees a
// past time that fits the chain.
function shownTimes(list: { height: number; timestamp: number }[]): Map<number, number> {
  const now = Math.floor(Date.now() / 1000);
  const asc = [...list].sort((a, b) => a.height - b.height);
  const out = new Map<number, number>();
  let anchor: { height: number; ts: number } | null = null;
  let pending: number[] = [];
  const settle = (end: { height: number; ts: number }) => {
    const start = anchor ?? { height: end.height - pending.length - 1, ts: end.ts - (pending.length + 1) * 10 };
    const span = Math.max(1, end.height - start.height);
    for (const h of pending) {
      out.set(h, Math.round(start.ts + ((end.ts - start.ts) * (h - start.height)) / span));
    }
    pending = [];
  };
  for (const b of asc) {
    if (b.timestamp <= now && (!anchor || b.timestamp >= anchor.ts)) {
      settle({ height: b.height, ts: b.timestamp });
      out.set(b.height, b.timestamp);
      anchor = { height: b.height, ts: b.timestamp };
    } else {
      pending.push(b.height);
    }
  }
  if (pending.length) settle({ height: pending[pending.length - 1] + 1, ts: now });
  return out;
}

function timeAgo(ts: number) {
  const diff = Math.floor(Date.now() / 1000 - ts);
  if (diff < 5)     return 'just now';
  if (diff < 60)    return `${diff}s ago`;
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

// Absolute block/tx times are shown in San Francisco time (US Pacific) so the
// chain has one canonical clock regardless of the viewer's location.
// timeZoneName:'short' appends PST/PDT so users know the zone.
function sfTime(ts: number) {
  if (!ts) return '—';
  try {
    return new Date(ts * 1000).toLocaleString('en-US', {
      timeZone: 'America/Los_Angeles',
      year: 'numeric', month: 'short', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit',
      timeZoneName: 'short',
    });
  } catch {
    return new Date(ts * 1000).toLocaleString();
  }
}

interface EmissionPool { cap_uegoc: number; pct: number; }
interface Tokenomics {
  total_supply_egoc:          number;
  is_testnet:                 boolean;
  circulating_egoc:           number;
  circulating_pct:            number;
  block_rewards_issued_uegoc: number;
  emission_pools: {
    node_rewards:  EmissionPool;
    block_rewards: EmissionPool;
    ecosystem:     EmissionPool;
    foundation:    EmissionPool;
    staking:       EmissionPool;
  };
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
  };
  drs: {
    min_drs_to_mine: number;
    weights: { poc: number; post: number; stake: number };
  };
}

interface HolderRow { address: string; balance_uegoc: number; label: string | null; }
interface HolderGroup { min_egoc: number; max_egoc: number | null; wallets: number; total_uegoc: number; }
interface Holders {
  height: number;
  total_uegoc: number;
  wallets: number;
  wallet_total_uegoc: number;
  shielded_uegoc: number;
  groups: HolderGroup[];
  top: HolderRow[];
}

const egoc = (u: number) => (u / 1_000_000).toLocaleString('en-US', { maximumFractionDigits: 2 });
const groupName = (g: HolderGroup) =>
  g.max_egoc == null ? `${g.min_egoc.toLocaleString('en-US')}+ EGOC` : `${g.min_egoc.toLocaleString('en-US')} to ${g.max_egoc.toLocaleString('en-US')} EGOC`;

function HoldersView({ data }: { data: Holders | null }) {
  const [showAll, setShowAll] = useState(false);
  if (!data) {
    return (
      <div className="py-16 text-center text-gray-500">
        <div className="text-3xl mb-3 animate-pulse">👥</div>
        <div className="text-sm">Reading balances from this node…</div>
      </div>
    );
  }
  const share = (u: number) => {
    const pct = data.total_uegoc ? (u / data.total_uegoc) * 100 : 0;
    return pct >= 0.01 ? `${pct.toFixed(2)}%` : '< 0.01%';
  };
  const groups = data.groups.filter(g => g.wallets > 0);
  const maxWallets = Math.max(1, ...groups.map(g => g.wallets));
  const rows = showAll ? data.top : data.top.slice(0, 25);
  return (
    <div className="p-5 space-y-5">
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: 'Wallets holding EGOC', val: data.wallets.toLocaleString('en-US'), sub: 'not counting the pools' },
          { label: 'Held by those wallets', val: `${egoc(data.wallet_total_uegoc)} EGOC`, sub: 'all of them together' },
          { label: 'Shielded', val: `${egoc(data.shielded_uegoc)} EGOC`, sub: 'one total, owners stay hidden' },
        ].map(c => (
          <div key={c.label} className="bg-gray-900 rounded-xl p-4 border border-gray-700/50">
            <div className="text-xs text-gray-400 mb-1">{c.label}</div>
            <div className="text-lg font-bold text-white">{c.val}</div>
            <div className="text-xs text-gray-500 mt-0.5">{c.sub}</div>
          </div>
        ))}
      </div>

      {groups.length > 0 && (
        <div>
          <div className="text-xs text-gray-400 mb-3 font-semibold uppercase tracking-wide">Wallets by size</div>
          <div className="space-y-2">
            {groups.map(g => (
              <div key={g.min_egoc} className="flex items-center gap-3" title={`${groupName(g)}: ${g.wallets} wallets holding ${egoc(g.total_uegoc)} EGOC together`}>
                <div className="w-40 text-xs text-gray-300 shrink-0">{groupName(g)}</div>
                <div className="flex-1 h-2 bg-gray-700 rounded-full overflow-hidden">
                  <div className="h-full bg-blue-500 rounded-full" style={{ width: `${Math.max(2, (g.wallets / maxWallets) * 100)}%` }} />
                </div>
                <div className="text-xs w-56 text-right whitespace-nowrap">
                  <span className="text-white font-semibold">{g.wallets.toLocaleString('en-US')}</span>
                  <span className="text-gray-400"> wallets · {egoc(g.total_uegoc)} EGOC</span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div>
        <div className="text-xs text-gray-400 mb-3 font-semibold uppercase tracking-wide">Largest holders</div>
        <div className="overflow-x-auto border border-gray-700/50 rounded-xl">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700 text-xs text-gray-400">
                <th className="px-4 py-3 text-left">#</th>
                <th className="px-4 py-3 text-left">Holder</th>
                <th className="px-4 py-3 text-right">Balance (EGOC)</th>
                <th className="px-4 py-3 text-right">Share of all coins</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((h, i) => (
                <tr key={h.address} className="border-b border-gray-700/40 last:border-0 hover:bg-gray-700/20">
                  <td className="px-4 py-2.5 text-gray-500">{i + 1}</td>
                  <td className="px-4 py-2.5">
                    {h.label && <span className="text-xs bg-gray-700 text-gray-200 rounded-full px-2 py-0.5 mr-2">{h.label}</span>}
                    <button onClick={openOnWeb(addressUrl(h.address))} title={h.address} className="font-mono text-xs text-blue-400 hover:text-blue-300 hover:underline">
                      {h.address.length > 24 ? `${h.address.slice(0, 14)}…${h.address.slice(-6)}` : h.address}
                    </button>
                  </td>
                  <td className="px-4 py-2.5 text-right font-semibold whitespace-nowrap">{egoc(h.balance_uegoc)}</td>
                  <td className="px-4 py-2.5 text-right text-gray-400">{share(h.balance_uegoc)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {data.top.length > 25 && (
          <button onClick={() => setShowAll(v => !v)} className="mt-3 text-xs bg-gray-700 hover:bg-gray-600 transition rounded-lg px-3 py-1.5">
            {showAll ? 'Show fewer' : `Show top ${data.top.length}`}
          </button>
        )}
      </div>

      <div className="text-xs text-gray-500 leading-relaxed">
        Read from this node's own copy of the chain at block #{data.height.toLocaleString('en-US')}. Public balances are visible to everyone, as on any blockchain. Coins in the shielded pool appear only as one total, and their owners stay hidden.
      </div>
    </div>
  );
}

type Tab = 'blocks' | 'txs' | 'holders' | 'files' | 'tokenomics';

const ExplorerPage: React.FC = () => {
  const [tab, setTab] = useState<Tab>('blocks');
  const [blocks, setBlocks] = useState<LedgerBlock[]>([]);
  const [txs, setTxs] = useState<LedgerTx[]>([]);
  const [fileEvents, setFileEvents] = useState<FileEvent[]>([]);
  const [netStats, setNetStats] = useState<NetworkStats | null>(null);
  const [tokenomics, setTokenomics] = useState<Tokenomics | null>(null);
  const [holders, setHolders] = useState<Holders | null>(null);
  const [selectedBlock, setSelectedBlock] = useState<LedgerBlock | null>(null);
  const blockTimes = shownTimes(blocks);
  const [selectedTx, setSelectedTx] = useState<LedgerTx | null>(null);
  const [selectedFile, setSelectedFile] = useState<FileEvent | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [loading, setLoading] = useState(true);
  const refreshTimer = React.useRef<ReturnType<typeof setTimeout> | null>(null);

  const [blockPage, setBlockPage] = useState(1);
  const [txPage, setTxPage] = useState(1);
  const [filePage, setFilePage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [txView, setTxView] = useState<'transfers' | 'all'>('transfers');
  const [activity, setActivity] = useState<LedgerTx[]>([]);
  const [activityCursors, setActivityCursors] = useState<(number | null)[]>([null]);
  const [activityNext, setActivityNext] = useState<number | null>(null);

  useEffect(() => {
    if (tab !== 'txs' || txView !== 'all') return;
    const before = activityCursors[activityCursors.length - 1];
    invoke<{ txs: LedgerTx[]; next_before: number | null }>('get_activity', { before, limit: pageSize })
      .then(p => { setActivity(p.txs); setActivityNext(p.next_before); })
      .catch(() => {});
  }, [tab, txView, activityCursors, pageSize]);

  useEffect(() => { setBlockPage(1); setTxPage(1); setFilePage(1); }, [tab]);

  useEffect(() => {
    if (!netStats) return;
    const offset = (blockPage - 1) * pageSize;
    invoke<LedgerBlock[]>('get_blocks', { offset, limit: pageSize }).then(setBlocks).catch(() => {});
  }, [blockPage, pageSize, netStats]);

  useEffect(() => {
    if (!netStats) return;
    const offset = (txPage - 1) * pageSize;
    invoke<LedgerTx[]>('get_all_transactions', { offset, limit: pageSize }).then(setTxs).catch(() => {});
  }, [txPage, pageSize, netStats]);

  useEffect(() => {
    loadData(false);
    const unsub = listen('ego://chain-updated', () => {
      if (refreshTimer.current) clearTimeout(refreshTimer.current);
      refreshTimer.current = setTimeout(() => loadData(true), 2_000);
    });
    const pollId = setInterval(() => loadData(true), 30_000);
    return () => {
      unsub.then(fn => fn());
      if (refreshTimer.current) clearTimeout(refreshTimer.current);
      clearInterval(pollId);
    };
  }, []);

  async function loadData(silent: boolean) {
    if (!silent) setLoading(true);

    const withTimeout = <T,>(p: Promise<T>, fallback: T, ms = 8_000): Promise<T> =>
      Promise.race([p, new Promise<T>(resolve => setTimeout(() => resolve(fallback), ms))]);

    try {
      const [n, fe] = await Promise.all([
        withTimeout(invoke<NetworkStats>('get_network_stats').catch(() => null), null),
        withTimeout(invoke<FileEvent[]>('get_file_events').catch(() => [] as FileEvent[]), [] as FileEvent[]),
      ]);

      if (fe) {
        // Ensure file events are displayed from newest to oldest
        const sortedFiles = [...fe].sort((a, b) => b.timestamp - a.timestamp);
        setFileEvents(sortedFiles);
      }

      if (n) setNetStats(n);
      invoke<Tokenomics>('get_tokenomics').then(setTokenomics).catch(() => {});
      invoke<Holders>('get_holders').then(setHolders).catch(() => {});
    } finally {
      setLoading(false);
    }
  }

  async function handleSearch() {
    const q = searchQuery.trim();
    if (!q) return;

    if (q.startsWith('egocid1')) {
      const ev = fileEvents.find(e => e.cid.startsWith(q));
      if (ev) { setSelectedFile(ev); setTab('files'); return; }
    }
    if (/^ego[a-z0-9]*1[a-z0-9]+$/i.test(q)) {
      openUrl(addressUrl(q)).catch(() => {});
      return;
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
      openUrl(searchUrl(q)).catch(() => {});
    }
  }

  const totalBlocks = netStats?.latest_block ?? blocks.length;
  const totalTxs    = netStats?.total_transactions ?? txs.length;
  const localBlocks = netStats?.local_blocks ?? blocks.length;
  const localTxs    = netStats?.local_transactions ?? txs.length;

  const tabs: { key: Tab; label: string; count: number }[] = [
    { key: 'blocks',     label: '🧱 Blocks',       count: totalBlocks        },
    { key: 'txs',        label: '↔️ Transactions', count: totalTxs           },
    { key: 'holders',    label: '👥 Holders',       count: holders?.wallets ?? 0 },
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
      {}
      <div className="grid grid-cols-5 gap-3">
        {statsCards.map(c => (
          <div key={c.label} className={`rounded-xl p-4 border ${'highlight' in c && c.highlight ? 'bg-green-500/10 border-green-500/30' : 'bg-gray-800 border-gray-700'}`}>
            <div className="text-xs text-gray-400 mb-1">{c.label}</div>
            <div className={`font-bold text-sm ${'highlight' in c && c.highlight ? 'text-green-400' : ''}`}>{c.val}</div>
          </div>
        ))}
      </div>

      {}
      <div className="flex gap-3">
        <input
          value={searchQuery}
          onChange={e => setSearchQuery(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && handleSearch()}
          className="flex-1 bg-gray-800 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none transition"
          placeholder="Search by block height, block hash, tx hash, address or file CID (egocid1…)"
        />
        <button
          onClick={handleSearch}
          className="bg-blue-600 hover:bg-blue-500 transition px-5 py-3 rounded-xl font-semibold text-sm"
        >
          🔍 Search
        </button>
        <button
          onClick={() => loadData(false)}
          className="bg-gray-700 hover:bg-gray-600 transition px-4 py-3 rounded-xl text-sm"
          title="Refresh"
        >
          ↻
        </button>
      </div>

      <div className="flex items-start gap-2.5 bg-blue-500/5 border border-blue-500/20 rounded-xl px-4 py-3 text-xs text-gray-400 leading-relaxed">
        <span className="text-blue-400 text-sm leading-none mt-0.5">ℹ️</span>
        <span>
          Ego Desktop is a full <span className="text-gray-200 font-medium">miner, validator, and storage/compute node</span> — it keeps the complete account state and the recent blocks it needs to produce and verify blocks, but not the entire historical archive. Storing every past block on every device won&apos;t scale as the chain grows — <span className="text-gray-200 font-medium">sharding</span> will distribute archival history across the network. So this Explorer shows recent activity this node has synced; the counters above are <span className="text-gray-200 font-medium">network-wide totals</span> and can exceed the rows listed. For complete history, open <span className="text-gray-200 font-medium">EgoScan</span> (the web explorer) at egoblockchain.com.
        </span>
      </div>

      {}
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
          totalBlocks === 0 ? (
            <div className="py-16 text-center text-gray-500">
              <div className="text-4xl mb-3">🧱</div>
              <div className="text-sm">No blocks yet</div>
              <div className="text-xs mt-1 text-gray-600">Send a transaction to mine the first block</div>
            </div>
          ) : (
            <>
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
                    {blocks.length === 0 ? (
                      <tr>
                        <td colSpan={6} className="py-12 text-center text-gray-500">No blocks on this page</td>
                      </tr>
                    ) : (
                      blocks.map(block => (
                        <tr
                          key={block.height}
                          onClick={() => setSelectedBlock(block)}
                          className="hover:bg-gray-700/40 cursor-pointer transition"
                        >
                          <td className="px-5 py-3 font-mono text-blue-400">#{block.height.toLocaleString()}</td>
                          <td className="px-5 py-3 font-mono text-xs text-gray-300">
                            <button onClick={openOnWeb(blockUrl(block.height))} title="Open on egoblockchain.com" className="hover:text-blue-400 hover:underline">{shortHash(block.hash)}</button>
                          </td>
                          <td className="px-5 py-3 font-mono text-xs text-gray-400">{shortAddr(block.miner)}</td>
                          <td className="px-5 py-3 text-right text-gray-300">{block.tx_count}</td>
                          <td className="px-5 py-3 text-right text-green-400">{(block.reward / 1_000_000).toFixed(3)} EGOC</td>
                          <td className="px-5 py-3 text-right text-gray-500 text-xs">{timeAgo(blockTimes.get(block.height) ?? block.timestamp)}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
              <Pagination total={localBlocks} page={blockPage} pageSize={pageSize} onPage={setBlockPage} onPageSize={ps => { setPageSize(ps); setBlockPage(1); }} />
            </>
          )

        ) : tab === 'txs' ? (
          <>
          <div className="flex gap-2 px-5 pt-4">
            {(['transfers', 'all'] as const).map(v => (
              <button
                key={v}
                onClick={() => { setTxView(v); setActivityCursors([null]); }}
                className={`text-xs px-3 py-1.5 rounded-lg transition ${txView === v ? 'bg-blue-600 text-white' : 'bg-gray-700 text-gray-300 hover:bg-gray-600'}`}
              >
                {v === 'transfers' ? 'Transfers' : 'All activity'}
              </button>
            ))}
          </div>
          {totalTxs === 0 && txView === 'transfers' ? (
            <div className="py-16 text-center text-gray-500">
              <div className="text-4xl mb-3">↔️</div>
              <div className="text-sm">No transactions yet</div>
              <div className="text-xs mt-1 text-gray-600">Use the Wallet tab to send EGOC</div>
            </div>
          ) : (
            <>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-700 text-xs text-gray-400">
                      <th className="px-5 py-3 text-left">Hash</th>
                      <th className="px-5 py-3 text-left">Type</th>
                      <th className="px-5 py-3 text-left">Block</th>
                      <th className="px-5 py-3 text-left">From</th>
                      <th className="px-5 py-3 text-left">To</th>
                      <th className="px-5 py-3 text-right">Amount</th>
                      <th className="px-5 py-3 text-right">Status</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-700/50">
                    {(txView === 'all' ? activity : txs).length === 0 ? (
                      <tr>
                        <td colSpan={7} className="py-12 text-center text-gray-500">No transactions on this page</td>
                      </tr>
                    ) : (
                      (txView === 'all' ? activity : txs).map(tx => {
                        const txTypeLabel = tx.is_private                  ? '🛡 Hidden'
                                          : tx.tx_type === 'reward'        ? '🏆 Reward'
                                          : tx.tx_type === 'store_data'    ? '📦 Store'
                                          : tx.tx_type === 'store_file'    ? '📦 Store'
                                          : tx.tx_type === 'retrieve_file' ? '📥 Retrieve'
                                          : tx.tx_type === 'slash_storage' ? '⚡ Slash'
                                          : tx.tx_type === 'transfer'      ? '↔️ Transfer'
                                          : tx.tx_type === 'faucet'        ? '🚰 Test Coins'
                                          : tx.tx_type                     ? tx.tx_type
                                          : tx.from.startsWith('egot1faucet') ? '🚰 Test Coins'
                                          : '↔️ Transfer';
                        const fromLabel = tx.from.startsWith('egot1rewards') ? 'Rewards Pool'
                                        : tx.from.startsWith('egot1faucet')  ? 'Test Coins Faucet'
                                        : shortAddr(tx.from);
                        const fromFinal = tx.from === 'Shielded' ? <span className="text-yellow-500/70">🛡 Hidden</span> : fromLabel;
                        const toFinal   = tx.to   === 'Shielded' ? <span className="text-yellow-500/70">🛡 Hidden</span> : shortAddr(tx.to);
                        return (
                        <tr
                          key={`${tx.block_height ?? ''}-${tx.hash}`}
                          onClick={() => setSelectedTx(tx)}
                          className="hover:bg-gray-700/40 cursor-pointer transition"
                        >
                          <td className="px-5 py-3 font-mono text-xs text-blue-400">
                            <button onClick={openOnWeb(txUrl(tx.hash, tx.block_height))} title="Open on egoblockchain.com" className="hover:underline">{shortHash(tx.hash)}</button>
                          </td>
                          <td className="px-5 py-3 text-xs text-gray-300">
                            <span className={tx.is_private ? 'text-yellow-400 font-bold' : ''}>{txTypeLabel}</span>
                          </td>
                          <td className="px-5 py-3 font-mono text-xs text-gray-400">
                            {tx.block_height != null ? `#${tx.block_height.toLocaleString()}` : '—'}
                          </td>
                          <td className="px-5 py-3 font-mono text-xs text-gray-400">{fromFinal}</td>
                          <td className="px-5 py-3 font-mono text-xs text-gray-400">{toFinal}</td>
                          <td className="px-5 py-3 text-right text-gray-200">{txDisplayAmount(tx, 2)}</td>
                          <td className="px-5 py-3 text-right">
                            <span className={`text-xs px-2 py-0.5 rounded-full ${
                              tx.status === 'Confirmed' ? 'bg-green-500/20 text-green-400' :
                              (tx.status === 'Pending' || tx.status.startsWith('Confirming')) ? 'bg-yellow-500/20 text-yellow-400' :
                                                          'bg-red-500/20 text-red-400'
                            }`}>{tx.status}</span>
                          </td>
                        </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>
              {txView === 'all' ? (
                <div className="flex items-center justify-between px-5 py-3 border-t border-gray-700 text-xs text-gray-400">
                  <button
                    disabled={activityCursors.length <= 1}
                    onClick={() => setActivityCursors(c => c.slice(0, -1))}
                    className="px-3 py-1.5 rounded-lg bg-gray-700 hover:bg-gray-600 disabled:opacity-40 transition"
                  >
                    ‹ Newer
                  </button>
                  <span>Page {activityCursors.length}</span>
                  <button
                    disabled={activityNext == null}
                    onClick={() => activityNext != null && setActivityCursors(c => [...c, activityNext])}
                    className="px-3 py-1.5 rounded-lg bg-gray-700 hover:bg-gray-600 disabled:opacity-40 transition"
                  >
                    Older ›
                  </button>
                </div>
              ) : (
                <Pagination total={localTxs} page={txPage} pageSize={pageSize} onPage={setTxPage} onPageSize={ps => { setPageSize(ps); setTxPage(1); }} />
              )}
            </>
          )}
          </>

        ) : tab === 'holders' ? (

          <HoldersView data={holders} />

        ) : tab === 'tokenomics' ? (

          !tokenomics ? (
            <div className="py-16 text-center text-gray-500">
              <div className="text-3xl mb-3 animate-pulse">💰</div>
              <div className="text-sm">Loading tokenomics from relay…</div>
              <div className="text-xs mt-1 text-gray-600">Relay must be reachable</div>
            </div>
          ) : (
            <div className="p-5 space-y-5">
              {}
              <div className={`grid gap-3 ${tokenomics.is_testnet ? 'grid-cols-1' : 'grid-cols-3'}`}>
                {[
                  { label: 'Total Supply',   val: `${tokenomics.total_supply_egoc.toLocaleString()} EGOC`, color: 'text-white' },
                  ...(tokenomics.is_testnet ? [] : [
                  { label: 'Circulating',    val: `${tokenomics.circulating_egoc.toLocaleString(undefined,{maximumFractionDigits:0})} EGOC`, color: 'text-green-400' },
                  { label: 'Circulating %',  val: `${tokenomics.circulating_pct}%`, color: 'text-blue-400' },
                  ]),
                ].map(c => (
                  <div key={c.label} className="bg-gray-900 rounded-xl p-4 border border-gray-700/50">
                    <div className="text-xs text-gray-400 mb-1">{c.label}</div>
                    <div className={`text-lg font-bold ${c.color}`}>{c.val}</div>
                  </div>
                ))}
              </div>

              {}
              <div>
                <div className="text-xs text-gray-400 mb-3 font-semibold uppercase tracking-wide">Emission Pools</div>
                <div className="space-y-2">
                  {Object.entries({
                    'Node Rewards':    { ...tokenomics.emission_pools.node_rewards,  color: 'bg-green-500'  },
                    'Block Emissions': { ...tokenomics.emission_pools.block_rewards, color: 'bg-blue-500'   },
                    'Ecosystem':       { ...tokenomics.emission_pools.ecosystem,    color: 'bg-purple-500' },
                    'Foundation':      { ...tokenomics.emission_pools.foundation,   color: 'bg-yellow-500' },
                    'Staking Rewards': { ...tokenomics.emission_pools.staking,      color: 'bg-pink-500'   },
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

              {}
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

              {}
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-gray-900 rounded-xl p-4 border border-gray-700/50">
                  <div className="text-xs font-semibold text-gray-300 mb-3">Network Staking</div>
                  <div className="space-y-2 text-sm">
                    <div className="flex justify-between"><span className="text-gray-400">Total Staked</span><span className="text-orange-400 font-mono">{tokenomics.staking.total_staked_egoc.toLocaleString(undefined,{maximumFractionDigits:0})} EGOC</span></div>
                    <div className="flex justify-between"><span className="text-gray-400">Active Stakers</span><span className="font-mono">{tokenomics.staking.active_stakers}</span></div>
                    <div className="flex justify-between text-xs"><span className="text-gray-500">Staking boosts DRS (optional)</span></div>
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

          fileEvents.length === 0 ? (
            <div className="py-16 text-center text-gray-500">
              <div className="text-4xl mb-3">📁</div>
              <div className="text-sm">No file events yet</div>
              <div className="text-xs mt-1 text-gray-600">Store a file in the Storage tab to see it here</div>
            </div>
          ) : (
            <>
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
                    {fileEvents.slice((filePage - 1) * pageSize, filePage * pageSize).length === 0 ? (
                      <tr>
                        <td colSpan={6} className="py-12 text-center text-gray-500">No files on this page</td>
                      </tr>
                    ) : (
                      fileEvents.slice((filePage - 1) * pageSize, filePage * pageSize).map(ev => (
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
                      ))
                    )}
                  </tbody>
                </table>
              </div>
              <Pagination total={fileEvents.length} page={filePage} pageSize={pageSize} onPage={setFilePage} onPageSize={ps => { setPageSize(ps); setFilePage(1); }} />
            </>
          )
        )}
      </div>

      {}
      {selectedBlock && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-lg border border-gray-700 shadow-2xl">
            <div className="flex justify-between items-center mb-5">
              <h3 className="text-lg font-bold">Block #{selectedBlock.height.toLocaleString()}</h3>
              <button onClick={() => setSelectedBlock(null)} className="text-gray-400 hover:text-white text-xl">✕</button>
            </div>
            <div className="space-y-3 text-sm">
              {([
                { label: 'Height',       val: `#${selectedBlock.height.toLocaleString()}`, href: blockUrl(selectedBlock.height) },
                { label: 'Hash',         val: selectedBlock.hash,      mono: true, href: blockUrl(selectedBlock.height) },
                { label: 'Prev Hash',    val: selectedBlock.prev_hash, mono: true, href: selectedBlock.height > 0 ? blockUrl(selectedBlock.height - 1) : undefined },
                { label: 'Timestamp',    val: sfTime(blockTimes.get(selectedBlock.height) ?? Math.min(selectedBlock.timestamp, Math.floor(Date.now() / 1000))) },
                { label: 'Miner',        val: selectedBlock.miner,     mono: true, href: selectedBlock.miner ? addressUrl(selectedBlock.miner) : undefined },
                { label: 'Reward',       val: `${(selectedBlock.reward / 1_000_000).toFixed(3)} EGOC` },
                { label: 'Transactions', val: String(selectedBlock.tx_count) },
                { label: 'Size',         val: `${(selectedBlock.size_bytes / 1024).toFixed(1)} KB` },
                { label: 'Finality',     val: 'Dilithium QC verified ✓' },
              ] as DetailRow[]).map(({ label, val, mono, href }) => (
                <div key={label} className="flex justify-between items-start gap-4 py-1.5 border-b border-gray-700/50 last:border-0">
                  <span className="text-gray-400 shrink-0">{label}</span>
                  <DetailValue val={val} mono={mono} href={href} />
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {}
      {selectedTx && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-lg border border-gray-700 shadow-2xl">
            <div className="flex justify-between items-center mb-5">
              <h3 className="text-lg font-bold">Transaction</h3>
              <button onClick={() => setSelectedTx(null)} className="text-gray-400 hover:text-white text-xl">✕</button>
            </div>
            <div className={`rounded-xl p-4 text-center mb-5 ${
              selectedTx.status === 'Confirmed' ? 'bg-green-500/10 border border-green-500/20' :
              (selectedTx.status === 'Pending' || selectedTx.status.startsWith('Confirming')) ? 'bg-yellow-500/10 border border-yellow-500/20' :
                                                  'bg-red-500/10 border border-red-500/20'
            }`}>
              <div className="text-3xl mb-1">
                {selectedTx.status === 'Confirmed' ? '✅' : (selectedTx.status === 'Pending' || selectedTx.status.startsWith('Confirming')) ? '⏳' : '❌'}
              </div>
              <div className="text-2xl font-black text-white">
                {txDisplayAmount(selectedTx)}
              </div>
              <div className={`text-sm ${
                selectedTx.status === 'Confirmed' ? 'text-green-400' :
                (selectedTx.status === 'Pending' || selectedTx.status.startsWith('Confirming')) ? 'text-yellow-400' : 'text-red-400'
              }`}>{selectedTx.status}</div>
            </div>
            <div className="space-y-3 text-sm">
              {([
                { label: 'Hash',      val: selectedTx.hash,                    mono: true, href: txUrl(selectedTx.hash, selectedTx.block_height) },
                { label: 'Block',     val: selectedTx.block_height != null ? `#${selectedTx.block_height.toLocaleString()}` : 'Unconfirmed', href: selectedTx.block_height != null ? blockUrl(selectedTx.block_height) : undefined },
                { label: 'From',      val: selectedTx.from,                    mono: true, href: /^ego[a-z0-9]*1/.test(selectedTx.from) ? addressUrl(selectedTx.from) : undefined },
                { label: 'To',        val: selectedTx.to,                      mono: true, href: /^ego[a-z0-9]*1/.test(selectedTx.to) ? addressUrl(selectedTx.to) : undefined },
                { label: 'Amount',    val: txDisplayAmount(selectedTx) },
                { label: 'Fee',       val: selectedTx.fee_uegoc && selectedTx.fee_uegoc > 0 ? `${(selectedTx.fee_uegoc / 1_000_000).toFixed(6)} EGOC` : '0 EGOC' },
                { label: 'Nonce',     val: String(selectedTx.nonce) },
                { label: 'Timestamp', val: sfTime(selectedTx.timestamp) },
                { label: 'Signature', val: selectedTx.signature.slice(0, 32) + '…', mono: true },
                ...(selectedTx.memo ? [{ label: 'Memo', val: selectedTx.memo }] : []),
              ] as DetailRow[]).map(({ label, val, mono, href }) => (
                <div key={label} className="flex justify-between items-start gap-4 py-1.5 border-b border-gray-700/50 last:border-0">
                  <span className="text-gray-400 shrink-0">{label}</span>
                  <DetailValue val={val} mono={mono} href={href} />
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {}
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
