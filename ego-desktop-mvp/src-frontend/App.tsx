import React, { createContext, useContext, useEffect, useState } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { invoke } from '@tauri-apps/api/tauri';
import { open as openUrl } from '@tauri-apps/api/shell';
import { emit } from '@tauri-apps/api/event';
import Layout from './components/Layout';
import TitleBar from './components/TitleBar';
import WelcomeScreen from './pages/WelcomeScreen';
import WalletPage from './pages/WalletPage';
import EgoSafePage from './pages/EgoSafePage';
import CoveragePage from './pages/CoveragePage';
import StoragePage from './pages/StoragePage';
import EarningsPage from './pages/EarningsPage';
import StakingPage from './pages/StakingPage';
import ExplorerPage from './pages/ExplorerPage';
import SettingsPage from './pages/SettingsPage';
import MessengerPage from './pages/MessengerPage';

// ── Theme context ─────────────────────────────────────────────────────────────

type Theme = 'dark' | 'light';

interface ThemeCtx {
  theme: Theme;
  toggleTheme: () => void;
}

export const ThemeContext = createContext<ThemeCtx>({
  theme: 'dark',
  toggleTheme: () => {},
});

export function useTheme() {
  return useContext(ThemeContext);
}

// ── Wallet context ────────────────────────────────────────────────────────────

export interface WalletInfo {
  address: string;
  public_key_ed25519: string;
  public_key_dilithium: string;
  public_key_kyber: string;
  balance_uegoc: number;
  balance_formatted: string;
  is_new_wallet: boolean;
}

export interface WalletEntry {
  id: string;
  name: string;
  address: string;
  created_at: number;
}

export interface WalletRegistry {
  active_id: string;
  wallets: WalletEntry[];
}

interface WalletCtx {
  wallet: WalletInfo | null;
  registry: WalletRegistry | null;
  loading: boolean;
  reload: () => void;
  reloadRegistry: () => void;
}

export const WalletContext = createContext<WalletCtx>({
  wallet: null,
  registry: null,
  loading: true,
  reload: () => {},
  reloadRegistry: () => {},
});

export function useWallet() {
  return useContext(WalletContext);
}

// ── Terms consent gate ────────────────────────────────────────────────────────

const CONSENT_KEY = 'ego-terms-agreed-v1';

const ConsentGate: React.FC<{ onAccept: () => void }> = ({ onAccept }) => {
  const [checked, setChecked] = useState(false);

  return (
    <div className="min-h-screen bg-gray-900 flex items-center justify-center p-6">
      <div className="w-full max-w-md bg-gray-800 rounded-2xl shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="px-8 py-6 border-b border-gray-700 text-center">
          <div className="w-14 h-14 rounded-2xl bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-2xl font-black mx-auto mb-3">
            E
          </div>
          <h1 className="text-xl font-bold text-white">Welcome to Ego Desktop</h1>
          <p className="text-sm text-gray-400 mt-1">Quantum-Safe Blockchain Node</p>
        </div>

        {/* Body */}
        <div className="px-8 py-6 space-y-5">
          <p className="text-sm text-gray-300 leading-relaxed">
            Before continuing, please read and agree to the Ego Blockchain legal documents below.
            By installing and using this software you agree to be bound by these terms.
          </p>

          {/* Links */}
          <div className="space-y-2">
            <button
              onClick={() => openUrl('https://egoblockchain.com/terms')}
              className="w-full flex items-center gap-3 px-4 py-3 bg-gray-700 hover:bg-gray-600 rounded-xl transition-colors text-left group"
            >
              <span className="text-blue-400 text-lg">📄</span>
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium text-white">Terms of Service</div>
                <div className="text-xs text-blue-400 group-hover:underline truncate">
                  https://egoblockchain.com/terms
                </div>
              </div>
              <span className="text-gray-500 text-xs shrink-0">↗</span>
            </button>

            <button
              onClick={() => openUrl('https://egoblockchain.com/privacy')}
              className="w-full flex items-center gap-3 px-4 py-3 bg-gray-700 hover:bg-gray-600 rounded-xl transition-colors text-left group"
            >
              <span className="text-purple-400 text-lg">🔒</span>
              <div className="flex-1 min-w-0">
                <div className="text-sm font-medium text-white">Privacy Policy</div>
                <div className="text-xs text-blue-400 group-hover:underline truncate">
                  https://egoblockchain.com/privacy
                </div>
              </div>
              <span className="text-gray-500 text-xs shrink-0">↗</span>
            </button>
          </div>

          {/* Checkbox */}
          <label className="flex items-start gap-3 cursor-pointer group">
            <div className="relative shrink-0 mt-0.5">
              <input
                type="checkbox"
                checked={checked}
                onChange={e => setChecked(e.target.checked)}
                className="sr-only"
              />
              <div className={`w-5 h-5 rounded-md border-2 flex items-center justify-center transition-colors ${
                checked
                  ? 'bg-blue-600 border-blue-600'
                  : 'bg-gray-700 border-gray-500 group-hover:border-gray-400'
              }`}>
                {checked && (
                  <svg className="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                    <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                  </svg>
                )}
              </div>
            </div>
            <span className="text-sm text-gray-300 leading-relaxed">
              I have read and I agree to the{' '}
              <button
                onClick={e => { e.preventDefault(); openUrl('https://egoblockchain.com/terms'); }}
                className="text-blue-400 hover:underline"
              >
                Terms of Service
              </button>{' '}
              and{' '}
              <button
                onClick={e => { e.preventDefault(); openUrl('https://egoblockchain.com/privacy'); }}
                className="text-blue-400 hover:underline"
              >
                Privacy Policy
              </button>
              .
            </span>
          </label>

          {/* Accept button */}
          <button
            onClick={onAccept}
            disabled={!checked}
            className="w-full py-3 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 disabled:cursor-not-allowed rounded-xl font-semibold text-sm transition-colors"
          >
            Continue to Ego Desktop
          </button>

          <p className="text-xs text-gray-500 text-center">
            You must agree to use this software. Your acceptance is stored locally on this device.
          </p>
        </div>
      </div>
    </div>
  );
};

// ── App ───────────────────────────────────────────────────────────────────────

function App() {
  const [termsAgreed, setTermsAgreed] = useState<boolean>(
    () => localStorage.getItem(CONSENT_KEY) === 'true'
  );
  const [wallet,    setWallet]    = useState<WalletInfo | null>(null);
  const [registry,  setRegistry]  = useState<WalletRegistry | null>(null);
  const [loading,   setLoading]   = useState(true);
  const [initError, setInitError] = useState<string | null>(null);
  const [theme, setTheme] = useState<Theme>(() =>
    (localStorage.getItem('ego-theme') as Theme) ?? 'dark'
  );

  function toggleTheme() {
    setTheme(t => {
      const next = t === 'dark' ? 'light' : 'dark';
      localStorage.setItem('ego-theme', next);
      return next;
    });
  }

  async function loadRegistry() {
    try {
      const reg = await invoke<WalletRegistry>('list_wallets');
      setRegistry(reg);
    } catch (e) {
      console.error('list_wallets failed:', e);
    }
  }

  async function initWallet() {
    setLoading(true);
    setInitError(null);
    try {
      const timeout = new Promise<never>((_, reject) =>
        setTimeout(() => reject(new Error(
          'Wallet initialisation timed out after 60 s.\n' +
          'This usually means the post-quantum key generation failed on this device.\n' +
          'Please try again or reinstall the app.'
        )), 60_000)
      );
      const info = await Promise.race([invoke<WalletInfo>('init_wallet'), timeout]);
      setWallet(info);
      await loadRegistry();
    } catch (e) {
      console.error('init_wallet failed:', e);
      setInitError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    emit('frontend-ready');
    initWallet();
  }, []);

  // Show consent gate before anything else — blocks the whole app.
  if (!termsAgreed) {
    return (
      <div data-theme={theme} className="flex flex-col h-screen bg-gray-900">
        <TitleBar />
        <div className="flex-1 overflow-auto">
          <ConsentGate
            onAccept={() => {
              localStorage.setItem(CONSENT_KEY, 'true');
              setTermsAgreed(true);
            }}
          />
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div data-theme={theme} className="flex flex-col h-screen bg-gray-900">
        <TitleBar />
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center space-y-4">
            <div className="text-5xl animate-pulse">🔑</div>
            <div className="text-white font-semibold">Initialising wallet…</div>
            <div className="text-gray-400 text-sm">Generating quantum-safe keys</div>
          </div>
        </div>
      </div>
    );
  }

  if (initError) {
    return (
      <div data-theme={theme} className="flex flex-col h-screen bg-gray-900">
        <TitleBar />
        <div className="flex-1 flex items-center justify-center p-6">
          <div className="w-full max-w-md bg-gray-800 rounded-2xl border border-red-500/40 p-8 text-center space-y-5">
            <div className="text-5xl">⚠️</div>
            <div className="text-white font-bold text-lg">Wallet Initialisation Failed</div>
            <div className="text-red-400 text-sm bg-red-500/10 rounded-xl px-4 py-3 text-left whitespace-pre-wrap break-words">
              {initError}
            </div>
            <button
              onClick={initWallet}
              className="w-full py-3 bg-blue-600 hover:bg-blue-500 rounded-xl font-semibold text-sm transition-colors"
            >
              Retry
            </button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <ThemeContext.Provider value={{ theme, toggleTheme }}>
      <WalletContext.Provider
        value={{ wallet, registry, loading, reload: initWallet, reloadRegistry: loadRegistry }}
      >
        <Router>
          <div data-theme={theme} className="App min-h-screen bg-gray-900 text-white">
            <Routes>
              <Route path="/welcome" element={<WelcomeScreen />} />
              <Route path="/" element={<Layout />}>
                <Route index element={<Navigate to="/wallet" replace />} />
                <Route path="wallet"   element={<WalletPage />} />
                <Route path="egosafe"  element={<EgoSafePage />} />
                <Route path="coverage" element={<CoveragePage />} />
                <Route path="storage"  element={<StoragePage />} />
                <Route path="earnings" element={<EarningsPage />} />
                <Route path="staking"  element={<StakingPage />} />
                <Route path="explorer" element={<ExplorerPage />} />
                <Route path="settings"   element={<SettingsPage />} />
                <Route path="messenger" element={<MessengerPage />} />
              </Route>
            </Routes>
          </div>
        </Router>
      </WalletContext.Provider>
    </ThemeContext.Provider>
  );
}

export default App;
