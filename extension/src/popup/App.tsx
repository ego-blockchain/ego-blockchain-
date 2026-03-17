import React, { useCallback, useEffect, useReducer, useRef, useState } from 'react';
import qrcode from 'qrcode-generator';
import { generateSeed, seedToMnemonic } from '../shared/crypto';
import type { ExtMessage, ExtResponse, PendingConnection } from '../shared/types';

// ── Utilities ─────────────────────────────────────────────────────────────────

function sendMsg<T = unknown>(
  type: ExtMessage['type'],
  payload: Record<string, unknown> = {},
): Promise<ExtResponse<T>> {
  return new Promise(resolve => {
    chrome.runtime.sendMessage({ type, payload }, (resp: ExtResponse<T>) => {
      resolve(resp ?? { success: false, error: 'No response' });
    });
  });
}

function shortAddress(addr: string): string {
  if (!addr || addr.length < 12) return addr;
  return addr.slice(0, 8) + '…' + addr.slice(-6);
}

function cls(...args: (string | boolean | undefined | null)[]): string {
  return args.filter(Boolean).join(' ');
}

// ── Style constants ───────────────────────────────────────────────────────────

const S = {
  page: 'flex flex-col h-full bg-gray-900 text-white',
  header: 'flex items-center justify-between px-4 py-3 bg-gray-800 border-b border-gray-700',
  title: 'text-lg font-bold text-blue-400',
  btn: 'flex items-center justify-center rounded-lg font-semibold transition-colors cursor-pointer',
  btnPrimary: 'bg-blue-600 hover:bg-blue-500 text-white py-2.5 px-4',
  btnSecondary: 'bg-gray-700 hover:bg-gray-600 text-white py-2.5 px-4',
  btnDanger: 'bg-red-700 hover:bg-red-600 text-white py-2.5 px-4',
  btnGhost: 'bg-transparent hover:bg-gray-700 text-gray-300 py-2 px-3',
  input: 'w-full rounded-lg bg-gray-800 border border-gray-600 text-white placeholder-gray-400 px-3 py-2.5 outline-none focus:border-blue-500 transition-colors',
  label: 'block text-sm text-gray-400 mb-1',
  card: 'rounded-xl bg-gray-800 border border-gray-700 p-4',
  error: 'text-red-400 text-sm mt-1',
  success: 'text-green-400 text-sm mt-1',
  section: 'flex-1 overflow-y-auto px-4 py-4 flex flex-col gap-4',
};

// ── Inline styles for elements that can't use Tailwind (popup constraints) ────
// We use a single CSS string injected via <style> instead of Tailwind CDN
// to keep the extension self-contained and avoid network requests.

const STYLES = `
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; }

  .flex { display: flex; }
  .flex-col { flex-direction: column; }
  .flex-1 { flex: 1 1 0%; }
  .flex-wrap { flex-wrap: wrap; }
  .items-center { align-items: center; }
  .items-start { align-items: flex-start; }
  .justify-center { justify-content: center; }
  .justify-between { justify-content: space-between; }
  .justify-end { justify-content: flex-end; }
  .gap-1 { gap: 0.25rem; }
  .gap-2 { gap: 0.5rem; }
  .gap-3 { gap: 0.75rem; }
  .gap-4 { gap: 1rem; }
  .gap-6 { gap: 1.5rem; }
  .grid { display: grid; }
  .grid-cols-3 { grid-template-columns: repeat(3, 1fr); }
  .grid-cols-4 { grid-template-columns: repeat(4, 1fr); }
  .h-full { height: 100%; }
  .h-6 { height: 1.5rem; }
  .h-8 { height: 2rem; }
  .h-10 { height: 2.5rem; }
  .w-full { width: 100%; }
  .w-6 { width: 1.5rem; }
  .w-8 { width: 2rem; }
  .w-10 { width: 2.5rem; }
  .min-h-0 { min-height: 0; }
  .overflow-hidden { overflow: hidden; }
  .overflow-y-auto { overflow-y: auto; }
  .rounded { border-radius: 0.25rem; }
  .rounded-lg { border-radius: 0.5rem; }
  .rounded-xl { border-radius: 0.75rem; }
  .rounded-full { border-radius: 9999px; }
  .border { border-width: 1px; border-style: solid; }
  .border-b { border-bottom-width: 1px; border-bottom-style: solid; }
  .border-t { border-top-width: 1px; border-top-style: solid; }
  .border-gray-600 { border-color: #4b5563; }
  .border-gray-700 { border-color: #374151; }
  .border-blue-500 { border-color: #3b82f6; }
  .bg-gray-900 { background-color: #111827; }
  .bg-gray-800 { background-color: #1f2937; }
  .bg-gray-700 { background-color: #374151; }
  .bg-blue-600 { background-color: #2563eb; }
  .bg-blue-900 { background-color: #1e3a8a; }
  .bg-green-900 { background-color: #14532d; }
  .bg-red-700 { background-color: #b91c1c; }
  .bg-transparent { background-color: transparent; }
  .text-white { color: #ffffff; }
  .text-gray-300 { color: #d1d5db; }
  .text-gray-400 { color: #9ca3af; }
  .text-gray-500 { color: #6b7280; }
  .text-blue-400 { color: #60a5fa; }
  .text-blue-300 { color: #93c5fd; }
  .text-green-400 { color: #4ade80; }
  .text-red-400 { color: #f87171; }
  .text-yellow-400 { color: #facc15; }
  .text-xs { font-size: 0.75rem; line-height: 1rem; }
  .text-sm { font-size: 0.875rem; line-height: 1.25rem; }
  .text-base { font-size: 1rem; line-height: 1.5rem; }
  .text-lg { font-size: 1.125rem; line-height: 1.75rem; }
  .text-xl { font-size: 1.25rem; line-height: 1.75rem; }
  .text-2xl { font-size: 1.5rem; line-height: 2rem; }
  .text-3xl { font-size: 1.875rem; line-height: 2.25rem; }
  .font-medium { font-weight: 500; }
  .font-semibold { font-weight: 600; }
  .font-bold { font-weight: 700; }
  .font-mono { font-family: ui-monospace, SFMono-Regular, monospace; }
  .tracking-wide { letter-spacing: 0.025em; }
  .break-all { word-break: break-all; }
  .truncate { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .text-center { text-align: center; }
  .text-right { text-align: right; }
  .leading-relaxed { line-height: 1.625; }
  .opacity-70 { opacity: 0.7; }
  .cursor-pointer { cursor: pointer; }
  .select-none { user-select: none; }
  .select-all { user-select: all; }
  .appearance-none { appearance: none; }
  .outline-none { outline: none; }
  .transition-colors { transition: background-color 0.15s, border-color 0.15s, color 0.15s; }
  .shadow-lg { box-shadow: 0 10px 15px -3px rgba(0,0,0,0.1), 0 4px 6px -2px rgba(0,0,0,0.05); }
  .animate-spin { animation: spin 1s linear infinite; }
  @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
  .animate-pulse { animation: pulse 2s cubic-bezier(0.4,0,0.6,1) infinite; }
  @keyframes pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.5; } }

  /* Padding / margin */
  .p-1 { padding: 0.25rem; }
  .p-2 { padding: 0.5rem; }
  .p-3 { padding: 0.75rem; }
  .p-4 { padding: 1rem; }
  .p-6 { padding: 1.5rem; }
  .px-2 { padding-left: 0.5rem; padding-right: 0.5rem; }
  .px-3 { padding-left: 0.75rem; padding-right: 0.75rem; }
  .px-4 { padding-left: 1rem; padding-right: 1rem; }
  .py-1 { padding-top: 0.25rem; padding-bottom: 0.25rem; }
  .py-1\\.5 { padding-top: 0.375rem; padding-bottom: 0.375rem; }
  .py-2 { padding-top: 0.5rem; padding-bottom: 0.5rem; }
  .py-2\\.5 { padding-top: 0.625rem; padding-bottom: 0.625rem; }
  .py-3 { padding-top: 0.75rem; padding-bottom: 0.75rem; }
  .py-4 { padding-top: 1rem; padding-bottom: 1rem; }
  .pb-2 { padding-bottom: 0.5rem; }
  .pb-4 { padding-bottom: 1rem; }
  .pt-2 { padding-top: 0.5rem; }
  .mt-1 { margin-top: 0.25rem; }
  .mt-2 { margin-top: 0.5rem; }
  .mt-3 { margin-top: 0.75rem; }
  .mt-4 { margin-top: 1rem; }
  .mt-6 { margin-top: 1.5rem; }
  .mb-1 { margin-bottom: 0.25rem; }
  .mb-2 { margin-bottom: 0.5rem; }
  .mb-3 { margin-bottom: 0.75rem; }
  .mb-4 { margin-bottom: 1rem; }
  .mx-auto { margin-left: auto; margin-right: auto; }
  .mr-2 { margin-right: 0.5rem; }
  .ml-auto { margin-left: auto; }

  /* Hover states */
  .hover\\:bg-blue-500:hover { background-color: #3b82f6; }
  .hover\\:bg-gray-600:hover { background-color: #4b5563; }
  .hover\\:bg-gray-700:hover { background-color: #374151; }
  .hover\\:bg-red-600:hover { background-color: #dc2626; }
  .hover\\:text-white:hover { color: #ffffff; }
  .hover\\:border-blue-500:hover { border-color: #3b82f6; }

  /* Scrollbar */
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: #1f2937; }
  ::-webkit-scrollbar-thumb { background: #4b5563; border-radius: 2px; }

  /* Focus */
  input:focus, textarea:focus { border-color: #3b82f6 !important; }

  /* Word badge */
  .word-badge {
    display: inline-flex;
    align-items: center;
    background: #1e3a8a;
    border: 1px solid #2563eb;
    border-radius: 6px;
    padding: 4px 8px;
    font-size: 0.8rem;
    font-family: monospace;
    color: #93c5fd;
  }
  .word-badge span.num {
    color: #4b5563;
    margin-right: 4px;
    font-size: 0.7rem;
  }

  /* Navbar */
  .navbar { display: flex; background: #1f2937; border-top: 1px solid #374151; }
  .nav-btn {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    padding: 8px 4px;
    cursor: pointer;
    border: none;
    background: transparent;
    color: #9ca3af;
    font-size: 0.65rem;
    transition: color 0.15s;
    gap: 2px;
  }
  .nav-btn.active { color: #60a5fa; }
  .nav-btn:hover { color: #d1d5db; }
  .nav-btn svg { width: 20px; height: 20px; }
`;

// ── Inline style tag ──────────────────────────────────────────────────────────

function StyleTag() {
  return <style dangerouslySetInnerHTML={{ __html: STYLES }} />;
}

// ── Types ─────────────────────────────────────────────────────────────────────

type Screen =
  | 'welcome'
  | 'create'
  | 'import'
  | 'setPassword'
  | 'unlock'
  | 'home'
  | 'send'
  | 'receive'
  | 'settings'
  | 'dappConnect'
  | 'activity';

interface AppState {
  screen: Screen;
  address: string;
  balance: number;
  balanceUegoc: number;
  network: 'testnet' | 'mainnet';
  loading: boolean;
  error: string;
  pendingConnection: PendingConnection | null;
  nodeStatus: string;
  blockHeight: number;
  recentTxs: Array<{ hash: string; from?: string; to?: string; amount_egoc?: number; timestamp?: number }>;
}

type Action =
  | { type: 'SET_SCREEN'; screen: Screen }
  | { type: 'SET_WALLET'; address: string; network: 'testnet' | 'mainnet' }
  | { type: 'SET_BALANCE'; balance: number; balanceUegoc: number }
  | { type: 'SET_LOADING'; loading: boolean }
  | { type: 'SET_ERROR'; error: string }
  | { type: 'SET_NODE'; status: string; blockHeight: number }
  | { type: 'SET_TXS'; txs: AppState['recentTxs'] }
  | { type: 'SET_PENDING_CONN'; conn: PendingConnection | null };

function reducer(state: AppState, action: Action): AppState {
  switch (action.type) {
    case 'SET_SCREEN': return { ...state, screen: action.screen, error: '' };
    case 'SET_WALLET': return { ...state, address: action.address, network: action.network };
    case 'SET_BALANCE': return { ...state, balance: action.balance, balanceUegoc: action.balanceUegoc };
    case 'SET_LOADING': return { ...state, loading: action.loading };
    case 'SET_ERROR': return { ...state, error: action.error };
    case 'SET_NODE': return { ...state, nodeStatus: action.status, blockHeight: action.blockHeight };
    case 'SET_TXS': return { ...state, recentTxs: action.txs };
    case 'SET_PENDING_CONN': return { ...state, pendingConnection: action.conn };
    default: return state;
  }
}

const INIT: AppState = {
  screen: 'welcome',
  address: '',
  balance: 0,
  balanceUegoc: 0,
  network: 'testnet',
  loading: true,
  error: '',
  pendingConnection: null,
  nodeStatus: 'unknown',
  blockHeight: 0,
  recentTxs: [],
};

// ── Icons ─────────────────────────────────────────────────────────────────────

const Icons = {
  Home: () => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
    </svg>
  ),
  Send: () => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 19l9 2-9-18-9 18 9-2zm0 0v-8" />
    </svg>
  ),
  Receive: () => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
    </svg>
  ),
  Activity: () => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z" />
    </svg>
  ),
  Settings: () => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
    </svg>
  ),
  Copy: () => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} style={{ width: 14, height: 14 }}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
    </svg>
  ),
  Lock: () => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} style={{ width: 16, height: 16 }}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
    </svg>
  ),
  Back: () => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} style={{ width: 20, height: 20 }}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
    </svg>
  ),
  Spinner: () => (
    <svg className="animate-spin" viewBox="0 0 24 24" fill="none" style={{ width: 20, height: 20 }}>
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" style={{ opacity: 0.25 }} />
      <path d="M4 12a8 8 0 018-8" stroke="currentColor" strokeWidth="4" strokeLinecap="round" style={{ opacity: 0.75 }} />
    </svg>
  ),
  Faucet: () => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} style={{ width: 16, height: 16 }}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
    </svg>
  ),
};

// ── QR Code component ─────────────────────────────────────────────────────────

function QRCode({ data, size = 200 }: { data: string; size?: number }) {
  const canvasRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!canvasRef.current || !data) return;
    const qr = qrcode(0, 'M');
    qr.addData(data);
    qr.make();
    canvasRef.current.innerHTML = qr.createImgTag(4, 0);
    const img = canvasRef.current.querySelector('img');
    if (img) {
      img.style.width = `${size}px`;
      img.style.height = `${size}px`;
      img.style.imageRendering = 'pixelated';
    }
  }, [data, size]);

  return (
    <div
      ref={canvasRef}
      style={{
        background: 'white',
        padding: 8,
        borderRadius: 8,
        display: 'inline-block',
      }}
    />
  );
}

// ── Shared UI components ──────────────────────────────────────────────────────

function Input({
  label,
  type = 'text',
  value,
  onChange,
  placeholder,
  autoFocus,
  rows,
}: {
  label?: string;
  type?: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  autoFocus?: boolean;
  rows?: number;
}) {
  const shared = {
    className: S.input,
    value,
    onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => onChange(e.target.value),
    placeholder,
    autoFocus,
  };
  return (
    <div>
      {label && <label className={S.label}>{label}</label>}
      {rows ? (
        <textarea {...shared} rows={rows} style={{ resize: 'none' }} />
      ) : (
        <input {...shared} type={type} />
      )}
    </div>
  );
}

function Button({
  children,
  onClick,
  variant = 'primary',
  disabled,
  fullWidth = true,
  small,
}: {
  children: React.ReactNode;
  onClick: () => void;
  variant?: 'primary' | 'secondary' | 'danger' | 'ghost';
  disabled?: boolean;
  fullWidth?: boolean;
  small?: boolean;
}) {
  const variantCls: Record<string, string> = {
    primary: S.btnPrimary,
    secondary: S.btnSecondary,
    danger: S.btnDanger,
    ghost: S.btnGhost,
  };
  return (
    <button
      className={cls(S.btn, variantCls[variant], fullWidth && 'w-full', small && 'text-sm py-1.5 px-3')}
      onClick={onClick}
      disabled={disabled}
      style={{ opacity: disabled ? 0.5 : 1, cursor: disabled ? 'not-allowed' : 'pointer' }}
    >
      {children}
    </button>
  );
}

function Header({
  title,
  onBack,
  onLock,
}: {
  title: string;
  onBack?: () => void;
  onLock?: () => void;
}) {
  return (
    <div className="flex items-center px-4 py-3 bg-gray-800 border-b border-gray-700" style={{ minHeight: 52 }}>
      {onBack ? (
        <button className="mr-2 text-gray-400 hover:text-white transition-colors" onClick={onBack} style={{ background: 'none', border: 'none', cursor: 'pointer' }}>
          <Icons.Back />
        </button>
      ) : (
        <span
          style={{
            width: 28,
            height: 28,
            borderRadius: '50%',
            background: 'linear-gradient(135deg, #2563eb, #7c3aed)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: 14,
            fontWeight: 700,
            marginRight: 8,
          }}
        >
          E
        </span>
      )}
      <span className="text-lg font-bold text-blue-400 flex-1">{title}</span>
      {onLock && (
        <button
          onClick={onLock}
          style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#9ca3af' }}
          title="Lock wallet"
        >
          <Icons.Lock />
        </button>
      )}
    </div>
  );
}

function ErrorBox({ message }: { message: string }) {
  if (!message) return null;
  return (
    <div className="rounded-lg p-3 text-sm" style={{ background: '#450a0a', border: '1px solid #7f1d1d', color: '#fca5a5' }}>
      {message}
    </div>
  );
}

function SuccessBox({ message }: { message: string }) {
  if (!message) return null;
  return (
    <div className="rounded-lg p-3 text-sm" style={{ background: '#052e16', border: '1px solid #166534', color: '#86efac' }}>
      {message}
    </div>
  );
}

// ── Navbar ────────────────────────────────────────────────────────────────────

function Navbar({
  screen,
  onNavigate,
}: {
  screen: Screen;
  onNavigate: (s: Screen) => void;
}) {
  const tabs: { id: Screen; label: string; Icon: React.FC }[] = [
    { id: 'home', label: 'Home', Icon: Icons.Home },
    { id: 'send', label: 'Send', Icon: Icons.Send },
    { id: 'receive', label: 'Receive', Icon: Icons.Receive },
    { id: 'activity', label: 'Activity', Icon: Icons.Activity },
    { id: 'settings', label: 'Settings', Icon: Icons.Settings },
  ];

  return (
    <nav className="navbar">
      {tabs.map(({ id, label, Icon }) => (
        <button
          key={id}
          className={cls('nav-btn', screen === id && 'active')}
          onClick={() => onNavigate(id)}
        >
          <Icon />
          <span>{label}</span>
        </button>
      ))}
    </nav>
  );
}

// ── Screens ───────────────────────────────────────────────────────────────────

// Welcome
function WelcomeScreen({ onNavigate }: { onNavigate: (s: Screen) => void }) {
  return (
    <div className="flex flex-col h-full">
      <div className="flex-1 flex flex-col items-center justify-center p-6 gap-6">
        <div style={{
          width: 80,
          height: 80,
          borderRadius: '50%',
          background: 'linear-gradient(135deg, #2563eb, #7c3aed)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: 36,
          fontWeight: 900,
          boxShadow: '0 0 40px rgba(37,99,235,0.4)',
        }}>
          E
        </div>
        <div className="text-center">
          <h1 className="text-2xl font-bold text-white mb-2">Ego Wallet</h1>
          <p className="text-gray-400 text-sm leading-relaxed">
            Quantum-safe wallet for the Ego Blockchain ecosystem
          </p>
        </div>
        <div className="w-full flex flex-col gap-3 mt-4">
          <Button onClick={() => onNavigate('create')}>Create New Wallet</Button>
          <Button variant="secondary" onClick={() => onNavigate('import')}>Import Existing Wallet</Button>
        </div>
        <p className="text-xs text-gray-500 text-center">
          Ed25519 · AES-256-GCM · Ego Blockchain
        </p>
      </div>
    </div>
  );
}

// Create wallet — generate seed
function CreateScreen({
  onBack,
  onDone,
}: {
  onBack: () => void;
  onDone: (mnemonic: string[]) => void;
}) {
  const [mnemonic, setMnemonic] = useState<string[]>([]);
  const [confirmed, setConfirmed] = useState(false);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    // Generate a temporary mnemonic to display before password is set
    (async () => {
      const seed = generateSeed();
      const words = await seedToMnemonic(seed);
      setMnemonic(words);
    })();
  }, []);

  if (!mnemonic.length) {
    return (
      <div className="flex flex-col h-full">
        <Header title="Create Wallet" onBack={onBack} />
        <div className="flex-1 flex items-center justify-center">
          <Icons.Spinner />
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <Header title="Create Wallet" onBack={onBack} />
      <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-4">
        <div className="rounded-xl p-3" style={{ background: '#1e3a5f', border: '1px solid #1d4ed8' }}>
          <p className="text-sm text-blue-300 font-semibold mb-1">Your Secret Recovery Phrase</p>
          <p className="text-xs text-gray-400">Write these 24 words down and store them safely. Never share them.</p>
        </div>
        <div className="grid grid-cols-3 gap-2">
          {mnemonic.map((word, i) => (
            <div key={i} className="word-badge">
              <span className="num">{i + 1}.</span>
              {word}
            </div>
          ))}
        </div>
        <label className="flex items-start gap-2 cursor-pointer">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={e => setConfirmed(e.target.checked)}
            style={{ marginTop: 2, accentColor: '#3b82f6' }}
          />
          <span className="text-sm text-gray-300">
            I have safely backed up my recovery phrase
          </span>
        </label>
        <Button
          disabled={!confirmed || loading}
          onClick={() => onDone(mnemonic)}
        >
          {loading ? 'Generating…' : 'Continue to Set Password'}
        </Button>
      </div>
    </div>
  );
}

// Import wallet
function ImportScreen({
  onBack,
  onDone,
}: {
  onBack: () => void;
  onDone: (input: string) => void;
}) {
  const [input, setInput] = useState('');

  return (
    <div className="flex flex-col h-full">
      <Header title="Import Wallet" onBack={onBack} />
      <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-4">
        <p className="text-sm text-gray-400">
          Enter your 24-word recovery phrase (space-separated) or 64-character hex seed.
        </p>
        <Input
          label="Recovery Phrase or Hex Seed"
          value={input}
          onChange={setInput}
          placeholder="word1 word2 word3 … or 0x…"
          rows={5}
        />
        <Button disabled={input.trim().length < 10} onClick={() => onDone(input)}>
          Continue
        </Button>
      </div>
    </div>
  );
}

// Set password
function SetPasswordScreen({
  onBack,
  onDone,
  createMode,
  mnemonic,
  importInput,
}: {
  onBack: () => void;
  onDone: () => void;
  createMode: boolean;
  mnemonic?: string[];
  importInput?: string;
}) {
  const [password, setPassword] = useState('');
  const [confirm, setConfirm] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState('');

  async function handleSubmit() {
    if (password.length < 8) { setError('Password must be at least 8 characters'); return; }
    if (password !== confirm) { setError('Passwords do not match'); return; }
    setError('');
    setLoading(true);

    let resp: ExtResponse;
    if (createMode && mnemonic) {
      // Create using the displayed mnemonic words
      resp = await sendMsg('EGO_IMPORT_WALLET', { input: mnemonic.join(' '), password });
    } else if (!createMode && importInput) {
      resp = await sendMsg('EGO_IMPORT_WALLET', { input: importInput, password });
    } else {
      resp = await sendMsg('EGO_GENERATE_WALLET', { password });
    }

    setLoading(false);
    if (resp.success) {
      setSuccess('Wallet created! Redirecting…');
      setTimeout(onDone, 800);
    } else {
      setError(resp.error ?? 'Failed to create wallet');
    }
  }

  return (
    <div className="flex flex-col h-full">
      <Header title="Set Password" onBack={onBack} />
      <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-4">
        <p className="text-sm text-gray-400">
          This password encrypts your wallet locally. You will need it to unlock the extension.
        </p>
        <Input
          label="Password"
          type="password"
          value={password}
          onChange={setPassword}
          placeholder="Min 8 characters"
          autoFocus
        />
        <Input
          label="Confirm Password"
          type="password"
          value={confirm}
          onChange={setConfirm}
          placeholder="Re-enter password"
        />
        <ErrorBox message={error} />
        <SuccessBox message={success} />
        <Button disabled={!password || !confirm || loading} onClick={handleSubmit}>
          {loading ? 'Creating wallet…' : 'Create Wallet'}
        </Button>
      </div>
    </div>
  );
}

// Unlock
function UnlockScreen({ onUnlocked }: { onUnlocked: () => void }) {
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);

  async function handleUnlock() {
    if (!password) return;
    setLoading(true);
    setError('');
    const resp = await sendMsg('EGO_UNLOCK', { password });
    setLoading(false);
    if (resp.success) {
      onUnlocked();
    } else {
      setError(resp.error ?? 'Wrong password');
    }
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex-1 flex flex-col items-center justify-center p-6 gap-6">
        <div style={{
          width: 64,
          height: 64,
          borderRadius: '50%',
          background: 'linear-gradient(135deg, #2563eb, #7c3aed)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: 28,
          fontWeight: 900,
        }}>
          E
        </div>
        <h1 className="text-xl font-bold text-white">Ego Wallet</h1>
        <div className="w-full flex flex-col gap-3">
          <Input
            label="Password"
            type="password"
            value={password}
            onChange={setPassword}
            placeholder="Enter your password"
            autoFocus
          />
          <ErrorBox message={error} />
          <Button disabled={!password || loading} onClick={handleUnlock}>
            {loading ? 'Unlocking…' : 'Unlock'}
          </Button>
        </div>
      </div>
    </div>
  );
}

// Home
function HomeScreen({
  state,
  onRefresh,
  onFaucet,
}: {
  state: AppState;
  onRefresh: () => void;
  onFaucet: () => void;
}) {
  const [copied, setCopied] = useState(false);
  const [faucetMsg, setFaucetMsg] = useState('');
  const [faucetLoading, setFaucetLoading] = useState(false);

  function copyAddress() {
    navigator.clipboard.writeText(state.address);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  async function handleFaucet() {
    setFaucetLoading(true);
    setFaucetMsg('');
    const resp = await sendMsg('EGO_FAUCET', {});
    setFaucetLoading(false);
    if (resp.success) {
      setFaucetMsg('100 EGOC sent from faucet!');
      onRefresh();
    } else {
      setFaucetMsg((resp.error ?? 'Faucet unavailable'));
    }
    setTimeout(() => setFaucetMsg(''), 4000);
  }

  const networkLabel = state.network === 'testnet' ? 'Ego Testnet' : 'Ego Mainnet';
  const nodeOnline = state.nodeStatus === 'healthy' || state.nodeStatus === 'ok';

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Network badge + node status */}
      <div className="flex items-center justify-between px-4 py-2 bg-gray-800 border-b border-gray-700">
        <span className="text-xs font-medium" style={{ color: nodeOnline ? '#4ade80' : '#f87171' }}>
          {nodeOnline ? '● ' : '○ '}{networkLabel}
        </span>
        {state.blockHeight > 0 && (
          <span className="text-xs text-gray-500">Block #{state.blockHeight.toLocaleString()}</span>
        )}
      </div>

      <div className="flex-1 overflow-y-auto">
        {/* Balance card */}
        <div className="mx-4 mt-4 rounded-xl p-5 text-center" style={{
          background: 'linear-gradient(135deg, #1e3a8a, #1e1b4b)',
          border: '1px solid #2563eb',
        }}>
          <p className="text-xs text-gray-400 mb-1">Total Balance</p>
          <p className="text-3xl font-bold text-white">{state.balance.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 6 })}</p>
          <p className="text-sm text-blue-300 mt-1">EGOC</p>
          <p className="text-xs text-gray-500 mt-1">{state.balanceUegoc.toLocaleString()} uEGOC</p>
        </div>

        {/* Address */}
        <div className="mx-4 mt-3 rounded-xl p-3" style={{ background: '#1f2937', border: '1px solid #374151' }}>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs text-gray-400 mb-0.5">Address</p>
              <p className="font-mono text-sm text-gray-200">{shortAddress(state.address)}</p>
            </div>
            <button
              onClick={copyAddress}
              style={{ background: '#374151', border: 'none', cursor: 'pointer', borderRadius: 6, padding: '6px 10px', color: copied ? '#4ade80' : '#9ca3af', fontSize: 12, display: 'flex', alignItems: 'center', gap: 4 }}
            >
              <Icons.Copy />
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
        </div>

        {/* Faucet (testnet only) */}
        {state.network === 'testnet' && (
          <div className="mx-4 mt-2">
            <button
              onClick={handleFaucet}
              disabled={faucetLoading}
              style={{
                width: '100%',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: 6,
                padding: '8px 12px',
                borderRadius: 8,
                background: '#1c1917',
                border: '1px solid #44403c',
                color: '#d6d3d1',
                fontSize: 13,
                cursor: faucetLoading ? 'wait' : 'pointer',
                opacity: faucetLoading ? 0.7 : 1,
              }}
            >
              <Icons.Faucet />
              {faucetLoading ? 'Requesting…' : 'Request 100 EGOC from Faucet'}
            </button>
            {faucetMsg && (
              <p className="text-xs mt-1 text-center" style={{ color: faucetMsg.includes('sent') ? '#4ade80' : '#f87171' }}>
                {faucetMsg}
              </p>
            )}
          </div>
        )}

        {/* Recent transactions */}
        <div className="mx-4 mt-4 mb-4">
          <div className="flex items-center justify-between mb-2">
            <p className="text-sm font-semibold text-gray-300">Recent Transactions</p>
            <button
              onClick={onRefresh}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#60a5fa', fontSize: 12 }}
            >
              Refresh
            </button>
          </div>
          {state.recentTxs.length === 0 ? (
            <p className="text-xs text-gray-500 text-center py-6">No transactions yet</p>
          ) : (
            <div className="flex flex-col gap-2">
              {state.recentTxs.slice(0, 5).map((tx, i) => (
                <div key={i} className="rounded-lg p-3" style={{ background: '#1f2937', border: '1px solid #374151' }}>
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs text-gray-400">{tx.hash?.slice(0, 16)}…</span>
                    {tx.amount_egoc != null && (
                      <span className="text-sm font-semibold text-green-400">+{tx.amount_egoc} EGOC</span>
                    )}
                  </div>
                  {tx.from && (
                    <p className="text-xs text-gray-500 mt-1">From: {shortAddress(tx.from)}</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// Send
function SendScreen({
  address,
  onBack,
  network,
}: {
  address: string;
  onBack: () => void;
  network: 'testnet' | 'mainnet';
}) {
  const [to, setTo] = useState('');
  const [amount, setAmount] = useState('');
  const [memo, setMemo] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [txHash, setTxHash] = useState('');

  async function handleSend() {
    if (!to || !amount) { setError('Fill in all fields'); return; }
    const amtNum = parseFloat(amount);
    if (isNaN(amtNum) || amtNum <= 0) { setError('Invalid amount'); return; }
    if (!to.startsWith('0x') || to.length !== 42) { setError('Invalid address (must be 0x + 40 hex chars)'); return; }

    setLoading(true);
    setError('');
    const resp = await sendMsg<{ tx_hash: string }>('EGO_SEND_TX', { to, amount_egoc: amtNum, memo });
    setLoading(false);
    if (resp.success && resp.data) {
      setTxHash(resp.data.tx_hash);
    } else {
      setError(resp.error ?? 'Transaction failed');
    }
  }

  if (txHash) {
    return (
      <div className="flex flex-col h-full">
        <Header title="Send EGOC" onBack={onBack} />
        <div className="flex-1 flex flex-col items-center justify-center p-6 gap-4">
          <div style={{ fontSize: 48 }}>✓</div>
          <p className="text-xl font-bold text-green-400">Transaction Sent!</p>
          <div className="rounded-xl p-4 w-full" style={{ background: '#1f2937', border: '1px solid #374151' }}>
            <p className="text-xs text-gray-400 mb-1">Transaction Hash</p>
            <p className="font-mono text-xs text-gray-200 break-all">{txHash}</p>
          </div>
          <Button onClick={onBack}>Back to Home</Button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <Header title="Send EGOC" onBack={onBack} />
      <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-4">
        <div className="rounded-xl p-3" style={{ background: '#1f2937', border: '1px solid #374151' }}>
          <p className="text-xs text-gray-400">From</p>
          <p className="font-mono text-sm text-gray-200">{shortAddress(address)}</p>
        </div>
        <Input label="Recipient Address" value={to} onChange={setTo} placeholder="0x…" />
        <Input label="Amount (EGOC)" type="number" value={amount} onChange={setAmount} placeholder="0.00" />
        <Input label="Memo (optional)" value={memo} onChange={setMemo} placeholder="Optional note" />
        <ErrorBox message={error} />
        <Button disabled={!to || !amount || loading} onClick={handleSend}>
          {loading ? 'Sending…' : 'Send EGOC'}
        </Button>
      </div>
    </div>
  );
}

// Receive
function ReceiveScreen({ address, onBack }: { address: string; onBack: () => void }) {
  const [copied, setCopied] = useState(false);

  function copyAddress() {
    navigator.clipboard.writeText(address);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="flex flex-col h-full">
      <Header title="Receive EGOC" onBack={onBack} />
      <div className="flex-1 flex flex-col items-center p-6 gap-5">
        <p className="text-sm text-gray-400 text-center">
          Share your address to receive EGOC on the Ego Blockchain.
        </p>
        <div style={{ display: 'flex', justifyContent: 'center' }}>
          <QRCode data={address} size={180} />
        </div>
        <div className="w-full rounded-xl p-4" style={{ background: '#1f2937', border: '1px solid #374151' }}>
          <p className="text-xs text-gray-400 mb-2">Your Address</p>
          <p className="font-mono text-sm text-gray-200 break-all">{address}</p>
        </div>
        <Button onClick={copyAddress}>
          {copied ? '✓ Copied!' : 'Copy Address'}
        </Button>
      </div>
    </div>
  );
}

// Activity
function ActivityScreen({ txs, onRefresh }: { txs: AppState['recentTxs']; onRefresh: () => void }) {
  return (
    <div className="flex flex-col h-full">
      <Header title="Activity" />
      <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-3">
        <div className="flex justify-end">
          <button
            onClick={onRefresh}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#60a5fa', fontSize: 13 }}
          >
            Refresh
          </button>
        </div>
        {txs.length === 0 ? (
          <div className="flex-1 flex items-center justify-center">
            <p className="text-gray-500 text-sm">No transactions found</p>
          </div>
        ) : (
          txs.map((tx, i) => (
            <div key={i} className="rounded-xl p-4" style={{ background: '#1f2937', border: '1px solid #374151' }}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-gray-400 font-mono">{tx.hash?.slice(0, 20)}…</span>
                {tx.amount_egoc != null && (
                  <span className="text-sm font-semibold text-green-400">+{tx.amount_egoc} EGOC</span>
                )}
              </div>
              {tx.from && <p className="text-xs text-gray-500">From: {shortAddress(tx.from)}</p>}
              {tx.to && <p className="text-xs text-gray-500">To: {shortAddress(tx.to)}</p>}
              {tx.timestamp && (
                <p className="text-xs text-gray-600 mt-1">
                  {new Date(tx.timestamp).toLocaleString()}
                </p>
              )}
            </div>
          ))
        )}
      </div>
    </div>
  );
}

// Settings
function SettingsScreen({
  state,
  onLock,
  onNetworkChange,
}: {
  state: AppState;
  onLock: () => void;
  onNetworkChange: (n: 'testnet' | 'mainnet') => void;
}) {
  const [showPhrase, setShowPhrase] = useState(false);
  const [password, setPassword] = useState('');
  const [mnemonic, setMnemonic] = useState<string[]>([]);
  const [phraseError, setPhraseError] = useState('');
  const [phraseLoading, setPhraseLoading] = useState(false);
  const [copied, setCopied] = useState('');

  async function revealPhrase() {
    if (!password) return;
    setPhraseLoading(true);
    setPhraseError('');
    const resp = await sendMsg<{ mnemonic: string[] }>('EGO_GET_MNEMONIC', { password });
    setPhraseLoading(false);
    if (resp.success && resp.data) {
      setMnemonic(resp.data.mnemonic);
      setShowPhrase(true);
    } else {
      setPhraseError(resp.error ?? 'Wrong password');
    }
  }

  function copyItem(text: string, key: string) {
    navigator.clipboard.writeText(text);
    setCopied(key);
    setTimeout(() => setCopied(''), 2000);
  }

  return (
    <div className="flex flex-col h-full">
      <Header title="Settings" />
      <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-4">
        {/* Network */}
        <div className="rounded-xl p-4" style={{ background: '#1f2937', border: '1px solid #374151' }}>
          <p className="text-sm font-semibold text-gray-200 mb-3">Network</p>
          <div className="flex gap-2">
            {(['testnet', 'mainnet'] as const).map(n => (
              <button
                key={n}
                onClick={() => onNetworkChange(n)}
                style={{
                  flex: 1,
                  padding: '8px 0',
                  borderRadius: 8,
                  border: '1px solid',
                  borderColor: state.network === n ? '#3b82f6' : '#374151',
                  background: state.network === n ? '#1e3a8a' : '#374151',
                  color: state.network === n ? '#93c5fd' : '#9ca3af',
                  fontWeight: 600,
                  fontSize: 13,
                  cursor: 'pointer',
                }}
              >
                {n === 'testnet' ? 'Testnet' : 'Mainnet'}
              </button>
            ))}
          </div>
        </div>

        {/* Address */}
        <div className="rounded-xl p-4" style={{ background: '#1f2937', border: '1px solid #374151' }}>
          <div className="flex items-center justify-between mb-1">
            <p className="text-sm font-semibold text-gray-200">Your Address</p>
            <button
              onClick={() => copyItem(state.address, 'address')}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: copied === 'address' ? '#4ade80' : '#60a5fa', fontSize: 12 }}
            >
              {copied === 'address' ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <p className="font-mono text-xs text-gray-400 break-all">{state.address}</p>
        </div>

        {/* Recovery phrase */}
        <div className="rounded-xl p-4" style={{ background: '#1f2937', border: '1px solid #374151' }}>
          <p className="text-sm font-semibold text-gray-200 mb-2">Recovery Phrase</p>
          {!showPhrase ? (
            <div className="flex flex-col gap-2">
              <p className="text-xs text-gray-400">Enter your password to reveal the 24-word recovery phrase.</p>
              <Input type="password" value={password} onChange={setPassword} placeholder="Your password" />
              <ErrorBox message={phraseError} />
              <Button variant="secondary" disabled={!password || phraseLoading} onClick={revealPhrase}>
                {phraseLoading ? 'Verifying…' : 'Reveal Phrase'}
              </Button>
            </div>
          ) : (
            <div className="flex flex-col gap-2">
              <div className="grid grid-cols-3 gap-1">
                {mnemonic.map((word, i) => (
                  <div key={i} className="word-badge">
                    <span className="num">{i + 1}.</span>
                    {word}
                  </div>
                ))}
              </div>
              <button
                onClick={() => copyItem(mnemonic.join(' '), 'mnemonic')}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: copied === 'mnemonic' ? '#4ade80' : '#60a5fa', fontSize: 13, marginTop: 4 }}
              >
                {copied === 'mnemonic' ? '✓ Copied all words' : 'Copy all words'}
              </button>
              <button
                onClick={() => { setShowPhrase(false); setMnemonic([]); setPassword(''); }}
                style={{ background: 'none', border: 'none', cursor: 'pointer', color: '#9ca3af', fontSize: 12 }}
              >
                Hide phrase
              </button>
            </div>
          )}
        </div>

        {/* Lock */}
        <Button variant="danger" onClick={onLock}>
          Lock Wallet
        </Button>

        {/* Version */}
        <p className="text-xs text-gray-600 text-center">Ego Wallet v1.0.0 · MV3</p>
      </div>
    </div>
  );
}

// dApp Connect
function DAppConnectScreen({
  conn,
  onApprove,
  onReject,
}: {
  conn: PendingConnection;
  onApprove: () => void;
  onReject: () => void;
}) {
  return (
    <div className="flex flex-col h-full">
      <Header title="Connect Request" />
      <div className="flex-1 flex flex-col items-center justify-center p-6 gap-5">
        <div style={{ fontSize: 40, lineHeight: 1 }}>🔗</div>
        <div className="text-center">
          <h2 className="text-lg font-bold text-white mb-1">Connection Request</h2>
          <p className="text-sm text-gray-400">A dApp wants to connect to your wallet</p>
        </div>
        <div className="w-full rounded-xl p-4" style={{ background: '#1f2937', border: '1px solid #374151' }}>
          <p className="text-xs text-gray-400 mb-1">Origin</p>
          <p className="font-semibold text-blue-400">{conn.origin}</p>
          {conn.title && (
            <>
              <p className="text-xs text-gray-400 mb-1 mt-2">Site</p>
              <p className="text-sm text-gray-300">{conn.title}</p>
            </>
          )}
        </div>
        <p className="text-xs text-gray-500 text-center">
          This will share your address. You can revoke access in Settings.
        </p>
        <div className="flex gap-3 w-full">
          <Button variant="secondary" onClick={onReject} fullWidth>Reject</Button>
          <Button variant="primary" onClick={onApprove} fullWidth>Connect</Button>
        </div>
      </div>
    </div>
  );
}

// ── Root App ──────────────────────────────────────────────────────────────────

export default function App() {
  const [state, dispatch] = useReducer(reducer, INIT);

  // Wizard state
  const [wizardMnemonic, setWizardMnemonic] = useState<string[]>([]);
  const [importInput, setImportInput] = useState('');
  const [wizardMode, setWizardMode] = useState<'create' | 'import'>('create');

  // ── On mount: check wallet state ──────────────────────────────────────────

  const loadState = useCallback(async () => {
    const resp = await sendMsg<{
      hasWallet: boolean;
      locked: boolean;
      address?: string;
      publicKeyHex?: string;
      network?: string;
      pendingConnection?: PendingConnection;
    }>('EGO_GET_STATE');

    dispatch({ type: 'SET_LOADING', loading: false });

    if (!resp.success || !resp.data) return;
    const { hasWallet, locked, address, network, pendingConnection } = resp.data;

    if (pendingConnection) {
      dispatch({ type: 'SET_PENDING_CONN', conn: pendingConnection });
    }

    if (!hasWallet) {
      dispatch({ type: 'SET_SCREEN', screen: 'welcome' });
      return;
    }

    if (locked) {
      dispatch({ type: 'SET_SCREEN', screen: 'unlock' });
      return;
    }

    if (address) {
      dispatch({ type: 'SET_WALLET', address, network: (network ?? 'testnet') as 'testnet' | 'mainnet' });
      dispatch({ type: 'SET_SCREEN', screen: pendingConnection ? 'dappConnect' : 'home' });
      loadBalance(address, (network ?? 'testnet') as 'testnet' | 'mainnet');
      loadTxs();
      loadNodeHealth();
    }
  }, []);

  useEffect(() => { loadState(); }, [loadState]);

  // ── Data loaders ──────────────────────────────────────────────────────────

  async function loadBalance(addr?: string, net?: 'testnet' | 'mainnet') {
    const resp = await sendMsg<{ balance_egoc: number; balance_uegoc: number }>('EGO_GET_BALANCE');
    if (resp.success && resp.data) {
      dispatch({ type: 'SET_BALANCE', balance: resp.data.balance_egoc, balanceUegoc: resp.data.balance_uegoc });
    }
  }

  async function loadTxs() {
    const resp = await sendMsg<AppState['recentTxs']>('EGO_GET_TXS');
    if (resp.success && resp.data) {
      dispatch({ type: 'SET_TXS', txs: resp.data });
    }
  }

  async function loadNodeHealth() {
    const resp = await sendMsg<{ status: string; block_height: number }>('EGO_GET_HEALTH');
    if (resp.success && resp.data) {
      dispatch({ type: 'SET_NODE', status: resp.data.status, blockHeight: resp.data.block_height });
    }
  }

  function refreshAll() {
    loadBalance();
    loadTxs();
    loadNodeHealth();
  }

  // ── Navigation ────────────────────────────────────────────────────────────

  function navigate(screen: Screen) {
    dispatch({ type: 'SET_SCREEN', screen });
    if (screen === 'home') refreshAll();
  }

  // ── Lock / Unlock ─────────────────────────────────────────────────────────

  async function handleLock() {
    await sendMsg('EGO_LOCK');
    dispatch({ type: 'SET_SCREEN', screen: 'unlock' });
  }

  async function handleUnlocked() {
    await loadState();
  }

  // ── Network change ────────────────────────────────────────────────────────

  async function handleNetworkChange(network: 'testnet' | 'mainnet') {
    await sendMsg('EGO_SET_NETWORK', { network });
    dispatch({ type: 'SET_WALLET', address: state.address, network });
  }

  // ── dApp connect ──────────────────────────────────────────────────────────

  async function handleApproveConn() {
    if (!state.pendingConnection) return;
    await sendMsg('EGO_APPROVE_CONNECTION', { requestId: state.pendingConnection.requestId });
    dispatch({ type: 'SET_PENDING_CONN', conn: null });
    navigate('home');
  }

  async function handleRejectConn() {
    if (!state.pendingConnection) return;
    await sendMsg('EGO_REJECT_CONNECTION', { requestId: state.pendingConnection.requestId });
    dispatch({ type: 'SET_PENDING_CONN', conn: null });
    navigate('home');
  }

  // ── Wizard callbacks ──────────────────────────────────────────────────────

  function handleWizardDone() {
    loadState();
  }

  // ── Loading splash ────────────────────────────────────────────────────────

  if (state.loading) {
    return (
      <>
        <StyleTag />
        <div className="flex flex-col h-full bg-gray-900 items-center justify-center gap-4">
          <Icons.Spinner />
          <p className="text-sm text-gray-400">Loading…</p>
        </div>
      </>
    );
  }

  // ── Main render ───────────────────────────────────────────────────────────

  const isWalletScreen = ['home', 'send', 'receive', 'activity', 'settings', 'dappConnect'].includes(state.screen);

  return (
    <>
      <StyleTag />
      <div className="flex flex-col h-full bg-gray-900 text-white overflow-hidden">
        {/* Header for wallet screens */}
        {isWalletScreen && state.screen !== 'send' && state.screen !== 'receive' && state.screen !== 'dappConnect' && state.screen !== 'settings' && state.screen !== 'activity' && (
          <Header title="Ego Wallet" onLock={handleLock} />
        )}

        {/* Screen content */}
        <div className="flex-1 min-h-0 flex flex-col overflow-hidden">
          {state.screen === 'welcome' && (
            <WelcomeScreen onNavigate={s => dispatch({ type: 'SET_SCREEN', screen: s })} />
          )}

          {state.screen === 'create' && (
            <CreateScreen
              onBack={() => dispatch({ type: 'SET_SCREEN', screen: 'welcome' })}
              onDone={(mnemonic) => {
                setWizardMnemonic(mnemonic);
                setWizardMode('create');
                dispatch({ type: 'SET_SCREEN', screen: 'setPassword' });
              }}
            />
          )}

          {state.screen === 'import' && (
            <ImportScreen
              onBack={() => dispatch({ type: 'SET_SCREEN', screen: 'welcome' })}
              onDone={(input) => {
                setImportInput(input);
                setWizardMode('import');
                dispatch({ type: 'SET_SCREEN', screen: 'setPassword' });
              }}
            />
          )}

          {state.screen === 'setPassword' && (
            <SetPasswordScreen
              onBack={() => dispatch({ type: 'SET_SCREEN', screen: wizardMode === 'create' ? 'create' : 'import' })}
              onDone={handleWizardDone}
              createMode={wizardMode === 'create'}
              mnemonic={wizardMode === 'create' ? wizardMnemonic : undefined}
              importInput={wizardMode === 'import' ? importInput : undefined}
            />
          )}

          {state.screen === 'unlock' && (
            <UnlockScreen onUnlocked={handleUnlocked} />
          )}

          {state.screen === 'home' && (
            <HomeScreen
              state={state}
              onRefresh={refreshAll}
              onFaucet={() => {}}
            />
          )}

          {state.screen === 'send' && (
            <SendScreen
              address={state.address}
              network={state.network}
              onBack={() => navigate('home')}
            />
          )}

          {state.screen === 'receive' && (
            <ReceiveScreen address={state.address} onBack={() => navigate('home')} />
          )}

          {state.screen === 'activity' && (
            <ActivityScreen txs={state.recentTxs} onRefresh={refreshAll} />
          )}

          {state.screen === 'settings' && (
            <SettingsScreen
              state={state}
              onLock={handleLock}
              onNetworkChange={handleNetworkChange}
            />
          )}

          {state.screen === 'dappConnect' && state.pendingConnection && (
            <DAppConnectScreen
              conn={state.pendingConnection}
              onApprove={handleApproveConn}
              onReject={handleRejectConn}
            />
          )}
        </div>

        {/* Bottom navbar — only on main wallet screens */}
        {['home', 'send', 'receive', 'activity', 'settings'].includes(state.screen) && (
          <Navbar screen={state.screen} onNavigate={navigate} />
        )}
      </div>
    </>
  );
}
