import React, { useState, useRef, useEffect } from 'react';
import { Outlet, NavLink } from 'react-router-dom';
import { invoke } from '@tauri-apps/api/tauri';
import { useWallet, useTheme } from '../App';
import TitleBar from './TitleBar';

const NAV_ITEMS = [
  { path: '/wallet',    label: 'Wallet',    icon: '💰', desc: 'Send & receive' },
  { path: '/storage',   label: 'Storage',   icon: '🗄️', desc: 'Decentralized files' },
  { path: '/earnings',  label: 'Earn',      icon: '📈', desc: 'Rewards & DRS' },
  { path: '/staking',   label: 'Stake',     icon: '🔒', desc: 'Lock & earn' },
  { path: '/coverage',  label: 'Coverage',  icon: '📡', desc: 'PoC network' },
  { path: '/egosafe',   label: 'EgoSafe',   icon: '🔐', desc: 'Encrypted sharing' },
  { path: '/messenger', label: 'Messages',  icon: '💬', desc: 'P2P encrypted chat' },
  { path: '/explorer',  label: 'Explorer',  icon: '🔍', desc: 'Blocks & txs' },
  { path: '/contracts', label: 'Contracts', icon: '📜', desc: 'Deploy & interact' },
  { path: '/ide',       label: 'dApp IDE',  icon: '🧑‍💻', desc: 'Write & deploy contracts' },
  { path: '/settings',  label: 'Settings',  icon: '⚙️',  desc: 'Preferences' },
];

function truncAddr(addr: string): string {
  if (addr.length <= 14) return addr;
  return addr.slice(0, 8) + '…' + addr.slice(-4);
}

const WalletSwitcher: React.FC = () => {
  const { wallet, registry, reload, reloadRegistry } = useWallet();
  const [open, setOpen]         = useState(false);
  const [creating, setCreating] = useState(false);
  const [newName, setNewName]   = useState('');
  const [busy, setBusy]         = useState(false);
  const [error, setError]       = useState('');
  const dropRef = useRef<HTMLDivElement>(null);

  // Close dropdown when clicking outside
  useEffect(() => {
    if (!open) return;
    function handle(e: MouseEvent) {
      if (dropRef.current && !dropRef.current.contains(e.target as Node)) {
        setOpen(false);
        setCreating(false);
        setError('');
      }
    }
    document.addEventListener('mousedown', handle);
    return () => document.removeEventListener('mousedown', handle);
  }, [open]);

  const activeWallet = registry?.wallets.find(w => w.id === registry.active_id);
  const walletCount  = registry?.wallets.length ?? 0;
  const displayName  = activeWallet?.name ?? 'Wallet';
  const displayAddr  = wallet?.address ?? '';

  async function switchTo(id: string) {
    if (id === registry?.active_id) { setOpen(false); return; }
    setBusy(true);
    setError('');
    try {
      await invoke('switch_wallet', { walletId: id });
      await reload();
      await reloadRegistry();
      setOpen(false);
    } catch (e: any) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function deleteWallet(id: string) {
    if (id === registry?.active_id) {
      setError('Switch to a different wallet before deleting this one.');
      return;
    }
    if (walletCount <= 1) {
      setError('Cannot delete the last wallet.');
      return;
    }
    setBusy(true);
    setError('');
    try {
      await invoke('delete_wallet', { walletId: id });
      await reloadRegistry();
    } catch (e: any) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  async function createWallet() {
    const name = newName.trim() || `Wallet ${walletCount + 1}`;
    setBusy(true);
    setError('');
    try {
      await invoke('create_wallet', { name });
      await reloadRegistry();
      setCreating(false);
      setNewName('');
    } catch (e: any) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="relative px-3 py-2 border-b border-gray-700" ref={dropRef}>
      {/* Trigger button */}
      <button
        onClick={() => { setOpen(o => !o); setCreating(false); setError(''); }}
        className="w-full flex items-center gap-2.5 px-2 py-2 rounded-xl hover:bg-gray-700 transition-colors text-left group"
      >
        <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-purple-500 to-pink-600 flex items-center justify-center text-xs font-bold shrink-0">
          {displayName.charAt(0).toUpperCase()}
        </div>
        <div className="min-w-0 flex-1">
          <div className="text-xs font-semibold text-white leading-tight truncate">{displayName}</div>
          <div className="text-xs text-gray-500 font-mono leading-tight">{truncAddr(displayAddr)}</div>
        </div>
        <span className="text-gray-500 text-xs">{open ? '▲' : '▼'}</span>
      </button>

      {/* Dropdown */}
      {open && (
        <div className="absolute left-2 right-2 top-full mt-1 bg-gray-800 border border-gray-600 rounded-xl shadow-2xl z-50 overflow-hidden">
          {/* Header */}
          <div className="px-3 py-2 border-b border-gray-700 flex items-center justify-between">
            <span className="text-xs text-gray-400 font-medium">{walletCount} / 6 wallets</span>
            {walletCount < 6 && (
              <button
                onClick={() => { setCreating(c => !c); setError(''); }}
                className="text-xs text-blue-400 hover:text-blue-300 font-medium"
              >
                {creating ? 'Cancel' : '+ New'}
              </button>
            )}
          </div>

          {/* Create form */}
          {creating && (
            <div className="px-3 py-2 border-b border-gray-700 space-y-2">
              <input
                autoFocus
                value={newName}
                onChange={e => setNewName(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter') createWallet(); if (e.key === 'Escape') { setCreating(false); setError(''); } }}
                placeholder={`Wallet ${walletCount + 1}`}
                className="w-full bg-gray-900 border border-gray-600 rounded-lg px-2 py-1.5 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
              />
              <button
                onClick={createWallet}
                disabled={busy}
                className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white text-xs font-semibold py-1.5 rounded-lg transition-colors"
              >
                {busy ? 'Creating…' : 'Create Wallet'}
              </button>
            </div>
          )}

          {/* Wallet list */}
          <div className="max-h-56 overflow-y-auto">
            {registry?.wallets.map(w => {
              const isActive = w.id === registry.active_id;
              return (
                <div
                  key={w.id}
                  className={`flex items-center gap-2 px-3 py-2.5 group hover:bg-gray-700/50 transition-colors ${isActive ? 'bg-blue-600/10' : ''}`}
                >
                  {/* Switch on row click */}
                  <button
                    className="flex items-center gap-2 flex-1 min-w-0 text-left"
                    onClick={() => switchTo(w.id)}
                    disabled={busy}
                  >
                    <div className={`w-5 h-5 rounded-md flex items-center justify-center text-xs font-bold shrink-0 ${isActive ? 'bg-blue-500' : 'bg-gray-600'}`}>
                      {w.name.charAt(0).toUpperCase()}
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className={`text-xs font-medium leading-tight truncate ${isActive ? 'text-blue-300' : 'text-gray-200'}`}>{w.name}</div>
                      <div className="text-xs text-gray-500 font-mono leading-tight">{truncAddr(w.address)}</div>
                    </div>
                    {isActive && <span className="text-blue-400 text-xs shrink-0">✓</span>}
                  </button>

                  {/* Delete (only for non-active) */}
                  {!isActive && walletCount > 1 && (
                    <button
                      onClick={() => deleteWallet(w.id)}
                      disabled={busy}
                      className="opacity-0 group-hover:opacity-100 text-gray-500 hover:text-red-400 transition-all text-xs px-1"
                      title="Delete wallet"
                    >
                      ✕
                    </button>
                  )}
                </div>
              );
            })}
          </div>

          {/* Error */}
          {error && (
            <div className="px-3 py-2 border-t border-gray-700 text-xs text-red-400 bg-red-500/10">
              {error}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

const Layout: React.FC = () => {
  const { theme, toggleTheme } = useTheme();
  const [chainStats, setChainStats] = useState<{ latest_block: number; total_transactions: number } | null>(null);

  useEffect(() => {
    const fetch = () => {
      invoke<{ latest_block: number; total_transactions: number }>('get_network_stats')
        .then(s => setChainStats(s))
        .catch(() => {});
    };
    fetch();
    const t = setInterval(fetch, 15_000);
    return () => clearInterval(t);
  }, []);

  return (
    <div className="flex flex-col h-screen bg-gray-900 text-white overflow-hidden">
      <TitleBar />
      <div className="flex flex-1 min-h-0">
      {/* Sidebar */}
      <aside className="w-52 bg-gray-800 border-r border-gray-700 flex flex-col shrink-0">
        {/* Logo */}
        <div className="p-4 border-b border-gray-700">
          <div className="flex items-center gap-2.5">
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-sm font-black">
              E
            </div>
            <div>
              <div className="font-bold text-sm leading-tight">Ego Wallet</div>
              <div className="text-xs text-gray-400">Testnet v0.1.0</div>
            </div>
          </div>
        </div>

        {/* Wallet switcher */}
        <WalletSwitcher />

        {/* Nav */}
        <nav className="flex-1 p-2 space-y-0.5 overflow-y-auto">
          {NAV_ITEMS.map(item => (
            <NavLink
              key={item.path}
              to={item.path}
              className={({ isActive }) =>
                `flex items-center gap-3 px-3 py-2.5 rounded-xl text-sm transition-all duration-150 group ${
                  isActive
                    ? 'bg-blue-600 text-white shadow-lg shadow-blue-600/20'
                    : 'text-gray-400 hover:bg-gray-700 hover:text-white'
                }`
              }
            >
              <span className="text-base w-5 text-center">{item.icon}</span>
              <div className="min-w-0">
                <div className="font-medium leading-tight">{item.label}</div>
              </div>
            </NavLink>
          ))}
        </nav>

        {/* Status bar */}
        <div className="p-3 border-t border-gray-700 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse"></span>
              <span className="text-xs text-gray-400">Testnet • Synced</span>
            </div>
            {/* Theme toggle */}
            <button
              onClick={toggleTheme}
              title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
              className={`w-10 h-5 rounded-full transition-colors relative shrink-0 ${theme === 'light' ? 'bg-blue-500' : 'bg-gray-600'}`}
            >
              <div className={`w-4 h-4 bg-white rounded-full shadow absolute top-0.5 transition-all ${theme === 'light' ? 'left-5' : 'left-0.5'}`} />
            </button>
          </div>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-gray-500">Block</span>
              <span className="text-xs text-gray-300 font-mono">
                #{chainStats ? chainStats.latest_block.toLocaleString() : '—'}
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-xs text-gray-500">Txs</span>
              <span className="text-xs text-blue-400 font-mono">
                {chainStats ? chainStats.total_transactions.toLocaleString() : '—'}
              </span>
            </div>
          </div>
        </div>
      </aside>

      {/* Main content */}
      <main className="flex-1 overflow-auto min-w-0">
        <Outlet />
      </main>
      </div>
    </div>
  );
};

export default Layout;
