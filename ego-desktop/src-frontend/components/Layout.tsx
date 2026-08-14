import React, { useState, useRef, useEffect } from 'react';
import { Outlet, NavLink, useNavigate } from 'react-router-dom';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';
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
  { path: '/market',      label: 'Market',      icon: '📊', desc: 'Prices & charts' },
  { path: '/hosting',     label: 'Hosting',     icon: '🌐', desc: 'Web3 sites' },
  { path: '/compute',     label: 'Compute',     icon: '🖥️', desc: 'Rent · CPU/GPU/RAM' },
  { path: '/governance',  label: 'Governance',  icon: '🗳️', desc: 'DAO voting' },
  { path: '/settings',    label: 'Settings',    icon: '⚙️',  desc: 'Preferences' },
];

function truncAddr(addr: string): string {
  if (addr.length <= 14) return addr;
  return addr.slice(0, 8) + '…' + addr.slice(-4);
}

const SunIcon = () => (
  <svg width="14" height="14" viewBox="0 0 24 24" fill="none"
    stroke="#b8860b" strokeWidth="2.5" strokeLinecap="round">
    <circle cx="12" cy="12" r="4" />
    <line x1="12" y1="2"  x2="12" y2="5" />
    <line x1="12" y1="19" x2="12" y2="22" />
    <line x1="4.22"  y1="4.22"  x2="6.34"  y2="6.34" />
    <line x1="17.66" y1="17.66" x2="19.78" y2="19.78" />
    <line x1="2"  y1="12" x2="5"  y2="12" />
    <line x1="19" y1="12" x2="22" y2="12" />
    <line x1="4.22"  y1="19.78" x2="6.34"  y2="17.66" />
    <line x1="17.66" y1="6.34"  x2="19.78" y2="4.22" />
  </svg>
);

const MoonIcon = () => (
  <svg width="12" height="12" viewBox="0 0 24 24" fill="none"
    stroke="#534AB7" strokeWidth="2.5" strokeLinecap="round">
    <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z" />
  </svg>
);

const themeStyles = {
  track: (dark: boolean): React.CSSProperties => ({
    width: 72, height: 36, borderRadius: 18, border: "none", cursor: "pointer",
    padding: 0, position: "relative",
    background: dark ? "#2d2a4a" : "#e9e4f0", transition: "background 0.3s",
  }),
  thumb: (dark: boolean): React.CSSProperties => ({
    position: "absolute", top: 5, left: 5, width: 26, height: 26,
    borderRadius: "50%",
    background: dark ? "#e8e8f0" : "#f5c842",
    display: "flex", alignItems: "center", justifyContent: "center",
    transform: dark ? "translateX(36px)" : "translateX(0)",
    transition: "transform 0.35s cubic-bezier(.34,1.3,.64,1), background 0.3s",
    pointerEvents: "none",
  }),
  icon: (visible: boolean): React.CSSProperties => ({
    position: "absolute",
    opacity: visible ? 1 : 0,
    transform: visible ? "scale(1)" : "scale(0.6)",
    transition: "opacity 0.2s, transform 0.2s",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
  }),
};

const WalletSwitcher: React.FC = () => {
  const { wallet, registry, reload, reloadRegistry } = useWallet();
  const [open, setOpen]         = useState(false);
  const [creating, setCreating] = useState(false);
  const [importing, setImporting] = useState(false);
  const [importName, setImportName]     = useState('');
  const [importMethod, setImportMethod] = useState<'phrase' | 'seed'>('phrase');
  const [importValue, setImportValue]   = useState('');
  const [newName, setNewName]   = useState('');
  const [busy, setBusy]         = useState(false);
  const [error, setError]       = useState('');
  const dropRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    function handle(e: MouseEvent) {
      if (dropRef.current && !dropRef.current.contains(e.target as Node)) {
        setOpen(false); setCreating(false); setImporting(false);
        setImportValue(''); setImportName(''); setError('');
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
    setBusy(true); setError('');
    try {
      await invoke('create_wallet', { name });
      await reloadRegistry();
      setCreating(false); setNewName('');
    } catch (e: any) { setError(String(e)); }
    finally { setBusy(false); }
  }

  async function importWallet() {
    const v = importValue.trim();
    if (!v) { setError('Please enter your recovery phrase or seed hex.'); return; }
    const name = importName.trim() || `Wallet ${walletCount + 1}`;
    setBusy(true); setError('');
    try {
      await invoke('import_wallet', { name, method: importMethod, value: v });
      await reload();
      await reloadRegistry();
      setImporting(false); setImportValue(''); setImportName(''); setOpen(false);
    } catch (e: any) { setError(String(e)); }
    finally { setBusy(false); }
  }

  return (
    <div className="relative px-3 py-2 border-b border-gray-700" ref={dropRef}>
      {}
      <button
        onClick={() => { setOpen(o => !o); setCreating(false); setError(''); }}
        className="w-full flex items-center gap-2.5 px-2 py-2 rounded-xl hover:bg-gray-700 transition-colors text-left group"
      >
        <div className="w-7 h-7 rounded-lg bg-gradient-to-br from-purple-500 to-pink-600 flex items-center justify-center text-xs font-bold shrink-0">
          {displayName.charAt(0).toUpperCase()}
        </div>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-1.5">
            <span className="text-xs font-semibold text-white leading-tight truncate">{displayName}</span>
          </div>
          <div className="text-xs text-gray-500 font-mono leading-tight">{truncAddr(displayAddr)}</div>
        </div>
        <span className="text-gray-500 text-xs">{open ? '▲' : '▼'}</span>
      </button>

      {}
      {open && (
        <div className="absolute left-2 right-2 top-full mt-1 bg-gray-800 border border-gray-600 rounded-xl shadow-2xl z-50 overflow-hidden">
          {}
          <div className="px-3 py-2 border-b border-gray-700 flex items-center justify-between">
            <span className="text-xs text-gray-400 font-medium">{walletCount} / 6 wallets</span>
            {walletCount < 6 && (
              <div className="flex items-center gap-2">
                <button
                  onClick={() => { setImporting(i => !i); setCreating(false); setError(''); }}
                  className="text-xs text-purple-400 hover:text-purple-300 font-medium"
                >
                  {importing ? 'Cancel' : '↓ Import'}
                </button>
                <button
                  onClick={() => { setCreating(c => !c); setImporting(false); setError(''); }}
                  className="text-xs text-blue-400 hover:text-blue-300 font-medium"
                >
                  {creating ? 'Cancel' : '+ New'}
                </button>
              </div>
            )}
          </div>

          {}
          {importing && (
            <div className="px-3 py-2 border-b border-gray-700 space-y-2">
              <div className="flex rounded-lg overflow-hidden border border-gray-600 text-xs">
                <button
                  onClick={() => setImportMethod('phrase')}
                  className={`flex-1 py-1.5 font-medium transition-colors ${importMethod === 'phrase' ? 'bg-purple-600 text-white' : 'bg-gray-700 text-gray-400 hover:text-white'}`}
                >
                  24-Word Phrase
                </button>
                <button
                  onClick={() => setImportMethod('seed')}
                  className={`flex-1 py-1.5 font-medium transition-colors ${importMethod === 'seed' ? 'bg-purple-600 text-white' : 'bg-gray-700 text-gray-400 hover:text-white'}`}
                >
                  Seed Hex
                </button>
              </div>
              <input
                value={importName}
                onChange={e => setImportName(e.target.value)}
                placeholder={`Wallet ${walletCount + 1}`}
                className="w-full bg-gray-900 border border-gray-600 rounded-lg px-2 py-1.5 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-purple-500"
              />
              <textarea
                autoFocus
                value={importValue}
                onChange={e => setImportValue(e.target.value)}
                placeholder={importMethod === 'phrase'
                  ? 'Enter your 24 words separated by spaces…'
                  : 'Enter 64-character hex seed…'}
                rows={importMethod === 'phrase' ? 3 : 2}
                className="w-full bg-gray-900 border border-gray-600 rounded-lg px-2 py-1.5 text-xs text-white placeholder-gray-500 focus:outline-none focus:border-purple-500 resize-none font-mono"
              />
              <button
                onClick={importWallet}
                disabled={busy}
                className="w-full bg-purple-600 hover:bg-purple-500 disabled:opacity-50 text-white text-xs font-semibold py-1.5 rounded-lg transition-colors"
              >
                {busy ? 'Importing…' : 'Import Wallet'}
              </button>
            </div>
          )}

          {}
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

          {}
          <div className="max-h-56 overflow-y-auto">
            {registry?.wallets.map(w => {
              const isActive = w.id === registry.active_id;
              return (
                <div
                  key={w.id}
                  className={`flex items-center gap-2 px-3 py-2.5 group hover:bg-gray-700/50 transition-colors ${isActive ? 'bg-blue-600/10' : ''}`}
                >
                  {}
                  <button
                    className="flex items-center gap-2 flex-1 min-w-0 text-left"
                    onClick={() => switchTo(w.id)}
                    disabled={busy}
                  >
                    <div className={`w-5 h-5 rounded-md flex items-center justify-center text-xs font-bold shrink-0 ${isActive ? 'bg-blue-500' : 'bg-gray-600'}`}>
                      {w.name.charAt(0).toUpperCase()}
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-1.5">
                        <span className={`text-xs font-medium leading-tight truncate ${isActive ? 'text-blue-300' : 'text-gray-200'}`}>{w.name}</span>
                      </div>
                      <div className="text-xs text-gray-500 font-mono leading-tight">{truncAddr(w.address)}</div>
                    </div>
                    {isActive && <span className="text-blue-400 text-xs shrink-0">✓</span>}
                  </button>

                  {}
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

          {}
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
  const navigate = useNavigate();
  const [unreadCount, setUnreadCount] = useState(0);

  // Global handler: notification click → navigate to Messenger and open that chat
  useEffect(() => {
    const unlisten = listen<{ address: string }>('ego://open-chat', (event) => {
      navigate('/messenger', { state: { openChat: event.payload.address } });
    });
    return () => { unlisten.then(fn => fn()); };
  }, [navigate]);

  useEffect(() => {
    const refresh = () => {
      invoke<number>('get_unread_count').then(setUnreadCount).catch(() => {});
    };
    refresh();
    const unlisten = listen('ego://message-received', refresh);
    return () => { unlisten.then(fn => fn()); };
  }, []);

  return (
    <div className="flex flex-col h-screen bg-gray-900 text-white overflow-hidden">
      <TitleBar />
      <div className="flex flex-1 min-h-0">
      {}
      <aside className="w-52 bg-gray-800 border-r border-gray-700 flex flex-col shrink-0">
        {}
        <div className="p-4 border-b border-gray-700">
          <div className="flex items-center gap-2.5">
            <img src="/ego_logo.png" alt="Ego" className="w-9 h-9 rounded-full object-cover" />
            <div>
              <div className="font-bold text-sm leading-tight">Ego Wallet</div>
              <div className="text-xs text-gray-400">v0.3.30</div>
            </div>
          </div>
        </div>

        {}
        <WalletSwitcher />

        {}
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
              <div className="min-w-0 flex-1 flex items-center justify-between gap-2">
                <div className="font-medium leading-tight">{item.label}</div>
                {item.path === '/messenger' && unreadCount > 0 && (
                  <span className="shrink-0 bg-red-500 text-white text-[10px] font-bold leading-none rounded-full px-1.5 py-1 min-w-[18px] text-center">
                    {unreadCount > 99 ? '99+' : unreadCount}
                  </span>
                )}
              </div>
            </NavLink>
          ))}
        </nav>

        {}
        <div className="p-3 border-t border-gray-700 space-y-2">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="w-2 h-2 rounded-full bg-green-400 animate-pulse"></span>
              <span className="text-xs text-gray-400">Synced</span>
            </div>
            {}
            <button
              style={themeStyles.track(theme === 'dark')}
              onClick={toggleTheme}
              title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
              aria-label="Toggle theme"
              aria-pressed={theme === 'dark'}
            >
              <div style={themeStyles.thumb(theme === 'dark')}>
                <span style={themeStyles.icon(theme !== 'dark')}><SunIcon /></span>
                <span style={themeStyles.icon(theme === 'dark')}><MoonIcon /></span>
              </div>
            </button>
          </div>
        </div>
      </aside>

      {}
      <main className="flex-1 overflow-auto min-w-0">
        <Outlet />
      </main>
      </div>
    </div>
  );
};

export default Layout;
