import React, { useCallback, useEffect, useReducer, useRef, useState } from 'react';
import qrcode from 'qrcode-generator';
import { generateSeed, seedToMnemonic } from '../shared/crypto';
import { CHAINS, type ChainId } from '../shared/assets';
import type { ExtMessage, ExtResponse, PendingConnection, TrackedAsset, AssetBalance } from '../shared/types';

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

function timeAgo(ts: number): string {
  const ms = ts > 1e12 ? ts : ts * 1000;
  const diff = Date.now() - ms;
  if (diff < 60_000) return 'just now';
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)}h ago`;
  return new Date(ms).toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

const S = {
  input: 'ego-input',
  label: 'ego-label',
  error: 'text-red-400 text-sm mt-1',
  success: 'text-green-400 text-sm mt-1',
};

const LOGO_URL = chrome.runtime.getURL('icons/icon128.png');

const STYLES = `
  @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&display=swap');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --bg:        #07070d;
    --bg-1:      #0c0c16;
    --bg-2:      #12121f;
    --bg-3:      #1a1a2c;
    --line:      rgba(148,163,255,0.10);
    --line-2:    rgba(148,163,255,0.18);
    --txt:       #f4f5fb;
    --txt-2:     #9aa1c0;
    --txt-3:     #5d6485;
    --indigo:    #6366f1;
    --violet:    #8b5cf6;
    --blue:      #3b82f6;
    --green:     #34d399;
    --red:       #f87171;
    --amber:     #fbbf24;
    --grad:      linear-gradient(135deg, #6366f1, #8b5cf6 55%, #3b82f6);
  }

  /* ── Light theme ─────────────────────────────────────────────── */
  :root[data-theme="light"] {
    --bg:     #f6f7fb;
    --bg-1:   #ffffff;
    --bg-2:   #f0f1f8;
    --bg-3:   #e6e8f2;
    --line:   rgba(40,46,99,0.12);
    --line-2: rgba(40,46,99,0.20);
    --txt:    #15172b;
    --txt-2:  #4c5374;
    --txt-3:  #737a98;
  }
  /* Hardcoded grays that would be invisible on a light background */
  :root[data-theme="light"] .text-gray-300 { color: #2a3047; }
  :root[data-theme="light"] .text-gray-600 { color: #737a98; }
  :root[data-theme="light"] .text-blue-300 { color: #4f46e5; }
  :root[data-theme="light"] .text-blue-400 { color: #4f46e5; }
  :root[data-theme="light"] .topbar { background: rgba(255,255,255,0.85); }

  /* ── Inline text-link button ─────────────────────────────────── */
  .link-btn {
    background: none; border: none; cursor: pointer;
    color: var(--txt-3); font-size: 0.74rem; font-weight: 500;
    margin: 6px auto 0; display: block; padding: 4px;
    text-decoration: underline; text-underline-offset: 3px;
    transition: color 0.15s ease;
  }
  .link-btn:hover { color: var(--indigo); }

  body {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
    background: var(--bg);
    color: var(--txt);
    -webkit-font-smoothing: antialiased;
  }

  /* ── Utility classes ─────────────────────────────────────────── */
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
  .gap-5 { gap: 1.25rem; }
  .gap-6 { gap: 1.5rem; }
  .grid { display: grid; }
  .grid-cols-3 { grid-template-columns: repeat(3, 1fr); }
  .h-full { height: 100%; }
  .w-full { width: 100%; }
  .min-h-0 { min-height: 0; }
  .overflow-hidden { overflow: hidden; }
  .overflow-y-auto { overflow-y: auto; }
  .rounded-lg { border-radius: 0.5rem; }
  .rounded-xl { border-radius: 0.75rem; }
  .rounded-2xl { border-radius: 1rem; }
  .rounded-full { border-radius: 9999px; }
  .text-white { color: var(--txt); }
  .text-gray-300 { color: #c7cce6; }
  .text-gray-400 { color: var(--txt-2); }
  .text-gray-500 { color: var(--txt-3); }
  .text-gray-600 { color: #494f6b; }
  .text-blue-400 { color: #818cf8; }
  .text-blue-300 { color: #a5b4fc; }
  .text-green-400 { color: var(--green); }
  .text-red-400 { color: var(--red); }
  .text-xs { font-size: 0.72rem; line-height: 1rem; }
  .text-sm { font-size: 0.84rem; line-height: 1.25rem; }
  .text-base { font-size: 1rem; line-height: 1.5rem; }
  .text-lg { font-size: 1.125rem; line-height: 1.75rem; }
  .text-xl { font-size: 1.25rem; line-height: 1.75rem; }
  .text-2xl { font-size: 1.5rem; line-height: 2rem; }
  .text-3xl { font-size: 1.95rem; line-height: 2.3rem; }
  .font-medium { font-weight: 500; }
  .font-semibold { font-weight: 600; }
  .font-bold { font-weight: 700; }
  .font-extrabold { font-weight: 800; }
  .font-mono { font-family: 'SF Mono', ui-monospace, SFMono-Regular, monospace; }
  .tracking-wide { letter-spacing: 0.04em; }
  .uppercase { text-transform: uppercase; }
  .break-all { word-break: break-all; }
  .truncate { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .text-center { text-align: center; }
  .text-right { text-align: right; }
  .leading-relaxed { line-height: 1.625; }
  .cursor-pointer { cursor: pointer; }
  .p-3 { padding: 0.75rem; }
  .p-4 { padding: 1rem; }
  .p-6 { padding: 1.5rem; }
  .px-3 { padding-left: 0.75rem; padding-right: 0.75rem; }
  .px-4 { padding-left: 1rem; padding-right: 1rem; }
  .py-2 { padding-top: 0.5rem; padding-bottom: 0.5rem; }
  .py-3 { padding-top: 0.75rem; padding-bottom: 0.75rem; }
  .py-6 { padding-top: 1.5rem; padding-bottom: 1.5rem; }
  .mt-1 { margin-top: 0.25rem; }
  .mt-2 { margin-top: 0.5rem; }
  .mt-3 { margin-top: 0.75rem; }
  .mt-4 { margin-top: 1rem; }
  .mb-1 { margin-bottom: 0.25rem; }
  .mb-2 { margin-bottom: 0.5rem; }
  .mb-3 { margin-bottom: 0.75rem; }
  .mx-4 { margin-left: 1rem; margin-right: 1rem; }
  .mr-2 { margin-right: 0.5rem; }

  /* ── Animations ──────────────────────────────────────────────── */
  @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
  @keyframes fadeUp {
    from { opacity: 0; transform: translateY(8px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }
  @keyframes shimmer {
    0%   { background-position: -200% 0; }
    100% { background-position: 200% 0; }
  }
  @keyframes pulseDot {
    0%, 100% { opacity: 1; transform: scale(1); }
    50%      { opacity: 0.55; transform: scale(0.85); }
  }
  @keyframes floaty {
    0%, 100% { transform: translateY(0); }
    50%      { transform: translateY(-6px); }
  }
  @keyframes orbit { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }

  .animate-spin { animation: spin 1s linear infinite; }
  .screen-enter { animation: fadeUp 0.22s ease both; }
  .fade-in { animation: fadeIn 0.3s ease both; }

  .skeleton {
    background: linear-gradient(90deg, var(--bg-2) 25%, var(--bg-3) 50%, var(--bg-2) 75%);
    background-size: 200% 100%;
    animation: shimmer 1.4s infinite;
    border-radius: 8px;
  }

  /* ── Cards ───────────────────────────────────────────────────── */
  .card {
    background: var(--bg-2);
    border: 1px solid var(--line);
    border-radius: 14px;
    padding: 14px;
  }
  .card-hover { transition: border-color 0.15s, transform 0.15s, background 0.15s; }
  .card-hover:hover { border-color: var(--line-2); background: var(--bg-3); }

  .hero-card {
    position: relative;
    border-radius: 18px;
    padding: 22px 18px 18px;
    text-align: center;
    overflow: hidden;
    background:
      radial-gradient(120% 140% at 50% 0%, rgba(99,102,241,0.28) 0%, rgba(139,92,246,0.10) 45%, transparent 75%),
      var(--bg-2);
    border: 1px solid rgba(129,140,248,0.28);
    box-shadow: 0 12px 40px -16px rgba(99,102,241,0.45), inset 0 1px 0 rgba(255,255,255,0.06);
  }
  .hero-card::before {
    content: '';
    position: absolute;
    inset: 0;
    background: radial-gradient(60% 50% at 50% -10%, rgba(165,180,252,0.18), transparent 70%);
    pointer-events: none;
  }

  /* ── Buttons ─────────────────────────────────────────────────── */
  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    font-family: inherit;
    font-weight: 600;
    font-size: 0.875rem;
    border-radius: 12px;
    border: none;
    cursor: pointer;
    padding: 11px 16px;
    transition: transform 0.12s, box-shadow 0.15s, background 0.15s, opacity 0.15s, border-color 0.15s;
    user-select: none;
  }
  .btn:active { transform: scale(0.97); }
  .btn:disabled { opacity: 0.45; cursor: not-allowed; }

  .btn-primary {
    background: var(--grad);
    color: white;
    box-shadow: 0 6px 20px -8px rgba(99,102,241,0.7);
  }
  .btn-primary:hover:not(:disabled) { box-shadow: 0 8px 26px -8px rgba(99,102,241,0.9); filter: brightness(1.08); }

  .btn-secondary {
    background: var(--bg-3);
    color: var(--txt);
    border: 1px solid var(--line-2);
  }
  .btn-secondary:hover:not(:disabled) { background: #222238; }

  .btn-danger {
    background: rgba(248,113,113,0.12);
    color: var(--red);
    border: 1px solid rgba(248,113,113,0.35);
  }
  .btn-danger:hover:not(:disabled) { background: rgba(248,113,113,0.2); }

  .btn-ghost { background: transparent; color: var(--txt-2); padding: 8px 12px; }
  .btn-ghost:hover:not(:disabled) { color: var(--txt); background: var(--bg-3); }

  .icon-btn {
    display: flex; align-items: center; justify-content: center;
    width: 34px; height: 34px;
    border-radius: 10px;
    background: transparent;
    border: none;
    color: var(--txt-2);
    cursor: pointer;
    transition: background 0.15s, color 0.15s;
  }
  .icon-btn:hover { background: var(--bg-3); color: var(--txt); }

  /* Quick actions on home */
  .qa-btn {
    display: flex; flex-direction: column; align-items: center; gap: 6px;
    background: transparent; border: none; cursor: pointer;
    color: var(--txt-2); font-family: inherit; font-size: 0.7rem; font-weight: 600;
    flex: 1;
  }
  .qa-circle {
    width: 46px; height: 46px;
    border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    background: var(--bg-3);
    border: 1px solid var(--line-2);
    color: #a5b4fc;
    transition: transform 0.15s, box-shadow 0.2s, border-color 0.15s, background 0.15s;
  }
  .qa-btn:hover .qa-circle {
    transform: translateY(-2px);
    border-color: rgba(129,140,248,0.55);
    box-shadow: 0 8px 22px -10px rgba(99,102,241,0.8);
    background: rgba(99,102,241,0.14);
  }
  .qa-btn:hover { color: var(--txt); }
  .qa-circle svg { width: 19px; height: 19px; }

  /* ── Inputs ──────────────────────────────────────────────────── */
  .ego-label {
    display: block;
    font-size: 0.72rem;
    font-weight: 600;
    letter-spacing: 0.05em;
    text-transform: uppercase;
    color: var(--txt-3);
    margin-bottom: 6px;
  }
  .ego-input {
    width: 100%;
    border-radius: 12px;
    background: var(--bg-2);
    border: 1px solid var(--line-2);
    color: var(--txt);
    padding: 11px 13px;
    font-size: 0.875rem;
    font-family: inherit;
    outline: none;
    transition: border-color 0.15s, box-shadow 0.15s;
  }
  .ego-input::placeholder { color: var(--txt-3); }
  .ego-input:focus {
    border-color: var(--indigo);
    box-shadow: 0 0 0 3px rgba(99,102,241,0.18);
  }

  /* ── Header ──────────────────────────────────────────────────── */
  .topbar {
    display: flex; align-items: center; gap: 10px;
    padding: 12px 16px;
    background: rgba(12,12,22,0.85);
    backdrop-filter: blur(10px);
    border-bottom: 1px solid var(--line);
    min-height: 54px;
  }
  .grad-text {
    background: var(--grad);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }
  .net-pill {
    display: inline-flex; align-items: center; gap: 5px;
    font-size: 0.68rem; font-weight: 600;
    padding: 4px 9px;
    border-radius: 999px;
    border: 1px solid var(--line-2);
    background: var(--bg-2);
    color: var(--txt-2);
    white-space: nowrap;
  }
  .net-dot { width: 6px; height: 6px; border-radius: 50%; animation: pulseDot 2s ease infinite; }

  /* ── Tx rows ─────────────────────────────────────────────────── */
  .tx-row {
    display: flex; align-items: center; gap: 11px;
    padding: 11px 12px;
    border-radius: 13px;
    background: var(--bg-2);
    border: 1px solid var(--line);
    transition: border-color 0.15s, background 0.15s;
  }
  .tx-row:hover { border-color: var(--line-2); background: var(--bg-3); }
  .tx-icon {
    width: 34px; height: 34px; border-radius: 50%;
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0;
  }
  .tx-in  { background: rgba(52,211,153,0.12); color: var(--green); }
  .tx-out { background: rgba(248,113,113,0.12); color: var(--red); }
  .tx-icon svg { width: 15px; height: 15px; }

  /* ── Word badges (mnemonic) ──────────────────────────────────── */
  .word-badge {
    display: inline-flex;
    align-items: center;
    background: rgba(99,102,241,0.10);
    border: 1px solid rgba(99,102,241,0.30);
    border-radius: 8px;
    padding: 5px 8px;
    font-size: 0.76rem;
    font-family: 'SF Mono', ui-monospace, monospace;
    color: #c7d2fe;
  }
  .word-badge span.num { color: var(--txt-3); margin-right: 5px; font-size: 0.65rem; }

  /* ── Logo treatments ─────────────────────────────────────────── */
  .logo-glow { filter: drop-shadow(0 0 14px rgba(99,102,241,0.65)); }
  .logo-orbit {
    position: absolute; inset: -10px;
    border-radius: 50%;
    background: conic-gradient(from 0deg, transparent 10%, #6366f1 30%, #8b5cf6 50%, #3b82f6 70%, transparent 90%);
    animation: orbit 4s linear infinite;
    opacity: 0.7;
    -webkit-mask: radial-gradient(farthest-side, transparent calc(100% - 3px), #000 calc(100% - 2px));
    mask: radial-gradient(farthest-side, transparent calc(100% - 3px), #000 calc(100% - 2px));
  }
  .float { animation: floaty 4.5s ease-in-out infinite; }

  /* ── Navbar ──────────────────────────────────────────────────── */
  .navbar {
    display: flex;
    background: rgba(10,10,18,0.92);
    backdrop-filter: blur(12px);
    border-top: 1px solid var(--line);
    padding: 4px 6px 6px;
  }
  .nav-btn {
    flex: 1;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    gap: 3px;
    padding: 7px 2px 5px;
    cursor: pointer;
    border: none;
    background: transparent;
    color: var(--txt-3);
    font-family: inherit;
    font-size: 0.62rem;
    font-weight: 600;
    border-radius: 11px;
    transition: color 0.15s, background 0.15s;
    position: relative;
  }
  .nav-btn:hover { color: var(--txt-2); }
  .nav-btn.active { color: #a5b4fc; background: rgba(99,102,241,0.10); }
  .nav-btn.active::after {
    content: '';
    position: absolute; top: 0; left: 50%; transform: translateX(-50%);
    width: 18px; height: 2.5px; border-radius: 2px;
    background: var(--grad);
  }
  .nav-btn svg { width: 19px; height: 19px; }

  /* ── Toast ───────────────────────────────────────────────────── */
  .toast {
    position: fixed;
    bottom: 70px; left: 50%; transform: translateX(-50%);
    background: var(--bg-3);
    border: 1px solid var(--line-2);
    color: var(--txt);
    font-size: 0.78rem;
    font-weight: 500;
    border-radius: 999px;
    padding: 8px 16px;
    box-shadow: 0 10px 30px -10px rgba(0,0,0,0.8);
    animation: fadeUp 0.2s ease both;
    z-index: 9999;
    white-space: nowrap;
  }

  /* ── Misc ────────────────────────────────────────────────────── */
  ::-webkit-scrollbar { width: 4px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: #262640; border-radius: 2px; }

  .divider { height: 1px; background: var(--line); border: none; }

  .alert {
    border-radius: 12px;
    padding: 11px 13px;
    font-size: 0.8rem;
    line-height: 1.45;
    animation: fadeUp 0.18s ease both;
  }
  .alert-error   { background: rgba(248,113,113,0.10); border: 1px solid rgba(248,113,113,0.35); color: #fca5a5; }
  .alert-success { background: rgba(52,211,153,0.10);  border: 1px solid rgba(52,211,153,0.35);  color: #6ee7b7; }
  .alert-info    { background: rgba(99,102,241,0.10);  border: 1px solid rgba(99,102,241,0.35);  color: #c7d2fe; }
  .alert-warn    { background: rgba(251,191,36,0.08);  border: 1px solid rgba(251,191,36,0.30);  color: #fcd34d; }

  .checkbox-row {
    display: flex; align-items: flex-start; gap: 9px;
    cursor: pointer;
    padding: 11px 13px;
    border-radius: 12px;
    background: var(--bg-2);
    border: 1px solid var(--line);
    transition: border-color 0.15s;
  }
  .checkbox-row:hover { border-color: var(--line-2); }
`;

function StyleTag() {
  return <style dangerouslySetInnerHTML={{ __html: STYLES }} />;
}

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
  | 'activity'
  | 'addAsset'
  | 'sendAsset';

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

const Icons = {
  Home: () => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
    </svg>
  ),
  Send: () => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M7 17L17 7m0 0H9m8 0v8" />
    </svg>
  ),
  Receive: () => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M17 7L7 17m0 0h8m-8 0V9" />
    </svg>
  ),
  Activity: () => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M13 7h8m0 0v8m0-8l-8 8-4-4-6 6" />
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
  Sun: () => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} style={{ width: 16, height: 16 }}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 3v1m0 16v1m9-9h-1M4 12H3m15.364 6.364l-.707-.707M6.343 6.343l-.707-.707m12.728 0l-.707.707M6.343 17.657l-.707.707M16 12a4 4 0 11-8 0 4 4 0 018 0z" />
    </svg>
  ),
  Moon: () => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} style={{ width: 16, height: 16 }}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M20.354 15.354A9 9 0 018.646 3.646 9.003 9.003 0 0012 21a9.003 9.003 0 008.354-5.646z" />
    </svg>
  ),
  Eye: () => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} style={{ width: 17, height: 17 }}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
    </svg>
  ),
  EyeOff: () => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} style={{ width: 17, height: 17 }}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M13.875 18.825A10.05 10.05 0 0112 19c-4.478 0-8.268-2.943-9.543-7a9.97 9.97 0 011.563-3.029m5.858.908a3 3 0 114.243 4.243M9.878 9.878l4.242 4.242M9.88 9.88l-3.29-3.29m7.532 7.532l3.29 3.29M3 3l3.59 3.59m0 0A9.953 9.953 0 0112 5c4.478 0 8.268 2.943 9.542 7a10.025 10.025 0 01-4.132 5.411m0 0L21 21" />
    </svg>
  ),
  Back: () => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} style={{ width: 19, height: 19 }}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
    </svg>
  ),
  Refresh: () => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} style={{ width: 14, height: 14 }}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
    </svg>
  ),
  Spinner: () => (
    <svg className="animate-spin" viewBox="0 0 24 24" fill="none" style={{ width: 22, height: 22 }}>
      <circle cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" style={{ opacity: 0.2 }} />
      <path d="M4 12a8 8 0 018-8" stroke="currentColor" strokeWidth="4" strokeLinecap="round" style={{ opacity: 0.8 }} />
    </svg>
  ),
  Faucet: () => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M19.428 15.428a2 2 0 00-1.022-.547l-2.387-.477a6 6 0 00-3.86.517l-.318.158a6 6 0 01-3.86.517L6.05 15.21a2 2 0 00-1.806.547M8 4h8l-1 1v5.172a2 2 0 00.586 1.414l5 5c1.26 1.26.367 3.414-1.415 3.414H4.828c-1.782 0-2.674-2.154-1.414-3.414l5-5A2 2 0 009 10.172V5L8 4z" />
    </svg>
  ),
  Shield: () => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} style={{ width: 14, height: 14 }}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    </svg>
  ),
  Check: () => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5} style={{ width: 30, height: 30 }}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
    </svg>
  ),
  Link: () => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} style={{ width: 24, height: 24 }}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M13.828 10.172a4 4 0 00-5.656 0l-4 4a4 4 0 105.656 5.656l1.102-1.101m-.758-4.899a4 4 0 005.656 0l4-4a4 4 0 00-5.656-5.656l-1.1 1.1" />
    </svg>
  ),
};

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
      img.style.display = 'block';
    }
  }, [data, size]);

  return (
    <div
      ref={canvasRef}
      style={{
        background: 'white',
        padding: 10,
        borderRadius: 14,
        display: 'inline-block',
        boxShadow: '0 0 0 1px rgba(148,163,255,0.25), 0 14px 40px -14px rgba(99,102,241,0.5)',
      }}
    />
  );
}

function Input({
  label,
  type = 'text',
  value,
  onChange,
  placeholder,
  autoFocus,
  rows,
  onEnter,
}: {
  label?: string;
  type?: string;
  value: string;
  onChange: (v: string) => void;
  placeholder?: string;
  autoFocus?: boolean;
  rows?: number;
  onEnter?: () => void;
}) {
  const [show, setShow] = useState(false);
  const isPassword = type === 'password';
  const shared = {
    className: S.input,
    value,
    onChange: (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => onChange(e.target.value),
    placeholder,
    autoFocus,
    onKeyDown: (e: React.KeyboardEvent) => { if (e.key === 'Enter' && onEnter) onEnter(); },
  };
  return (
    <div>
      {label && <label className={S.label}>{label}</label>}
      {rows ? (
        <textarea {...shared} rows={rows} style={{ resize: 'none' }} />
      ) : isPassword ? (
        <div style={{ position: 'relative' }}>
          <input {...shared} type={show ? 'text' : 'password'} style={{ paddingRight: 42 }} />
          <button
            type="button"
            onClick={() => setShow((s) => !s)}
            title={show ? 'Hide password' : 'Show password'}
            aria-label={show ? 'Hide password' : 'Show password'}
            style={{
              position: 'absolute', right: 8, top: '50%', transform: 'translateY(-50%)',
              background: 'none', border: 'none', cursor: 'pointer', padding: 4,
              color: 'var(--txt-3)', display: 'flex', alignItems: 'center',
            }}
          >
            {show ? <Icons.EyeOff /> : <Icons.Eye />}
          </button>
        </div>
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
  return (
    <button
      className={cls('btn', `btn-${variant}`, fullWidth && 'w-full', small && 'text-sm')}
      onClick={onClick}
      disabled={disabled}
      style={small ? { padding: '7px 12px', fontSize: '0.78rem' } : undefined}
    >
      {children}
    </button>
  );
}

function ThemeToggle() {
  const [theme, setTheme] = useState<'dark' | 'light'>(
    () => (localStorage.getItem('ego-theme') === 'light' ? 'light' : 'dark'),
  );
  function toggle() {
    const next = theme === 'dark' ? 'light' : 'dark';
    setTheme(next);
    localStorage.setItem('ego-theme', next);
    document.documentElement.setAttribute('data-theme', next);
  }
  return (
    <button
      className="icon-btn"
      onClick={toggle}
      title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
      aria-label="Toggle theme"
    >
      {theme === 'dark' ? <Icons.Sun /> : <Icons.Moon />}
    </button>
  );
}

function Header({
  title,
  onBack,
  onLock,
  network,
  nodeOnline,
}: {
  title: string;
  onBack?: () => void;
  onLock?: () => void;
  network?: 'testnet' | 'mainnet';
  nodeOnline?: boolean;
}) {
  return (
    <div className="topbar">
      {onBack ? (
        <button className="icon-btn" onClick={onBack} aria-label="Back">
          <Icons.Back />
        </button>
      ) : (
        <img src={LOGO_URL} alt="Ego" className="logo-glow" style={{ width: 28, height: 28, borderRadius: '50%' }} />
      )}
      <span className="text-base font-bold grad-text flex-1" style={{ letterSpacing: '0.01em' }}>{title}</span>
      {network && (
        <span className="net-pill">
          <span className="net-dot" style={{ background: nodeOnline ? 'var(--green)' : 'var(--red)' }} />
          {network === 'testnet' ? 'Testnet' : 'Mainnet'}
        </span>
      )}
      <ThemeToggle />
      {onLock && (
        <button className="icon-btn" onClick={onLock} title="Lock wallet" aria-label="Lock wallet">
          <Icons.Lock />
        </button>
      )}
    </div>
  );
}

function ErrorBox({ message }: { message: string }) {
  if (!message) return null;
  return <div className="alert alert-error">{message}</div>;
}

function SuccessBox({ message }: { message: string }) {
  if (!message) return null;
  return <div className="alert alert-success">{message}</div>;
}

function Toast({ message }: { message: string }) {
  if (!message) return null;
  return <div className="toast">{message}</div>;
}

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

function WelcomeScreen({ onNavigate }: { onNavigate: (s: Screen) => void }) {
  return (
    <div className="flex flex-col h-full screen-enter">
      <div
        className="flex-1 flex flex-col items-center justify-center p-6 gap-5"
        style={{ background: 'radial-gradient(85% 55% at 50% 0%, rgba(99,102,241,0.16) 0%, transparent 70%)' }}
      >
        <div className="float" style={{ position: 'relative' }}>
          <div className="logo-orbit" />
          <img src={LOGO_URL} alt="Ego" className="logo-glow" style={{ width: 92, height: 92, borderRadius: '50%', position: 'relative', zIndex: 1 }} />
        </div>
        <div className="text-center">
          <h1 className="text-2xl font-extrabold grad-text mb-2">Ego Wallet</h1>
          <p className="text-gray-400 text-sm leading-relaxed">
            The quantum-safe wallet for the<br />Ego Blockchain
          </p>
        </div>
        <div className="w-full flex flex-col gap-3 mt-2">
          <Button onClick={() => onNavigate('create')}>Create New Wallet</Button>
          <Button variant="secondary" onClick={() => onNavigate('import')}>Import Existing Wallet</Button>
        </div>
        <div className="flex items-center gap-2 text-xs text-gray-500">
          <Icons.Shield />
          <span>Ed25519 · Dilithium-2 · AES-256-GCM</span>
        </div>
      </div>
    </div>
  );
}

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
        <div className="flex-1 flex items-center justify-center text-blue-400">
          <Icons.Spinner />
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full screen-enter">
      <Header title="Create Wallet" onBack={onBack} />
      <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-4">
        <div className="alert alert-info">
          <p className="font-semibold mb-1">Your Secret Recovery Phrase</p>
          <p className="text-xs" style={{ color: 'var(--txt-2)' }}>
            Write these 24 words down in order and store them somewhere safe. Anyone with these words controls your funds — never share them.
          </p>
        </div>
        <div className="grid grid-cols-3 gap-2">
          {mnemonic.map((word, i) => (
            <div key={i} className="word-badge">
              <span className="num">{i + 1}</span>
              {word}
            </div>
          ))}
        </div>
        <label className="checkbox-row">
          <input
            type="checkbox"
            checked={confirmed}
            onChange={e => setConfirmed(e.target.checked)}
            style={{ marginTop: 2, accentColor: '#6366f1' }}
          />
          <span className="text-sm text-gray-300">
            I have safely backed up my recovery phrase
          </span>
        </label>
        <Button
          disabled={!confirmed || loading}
          onClick={() => onDone(mnemonic)}
        >
          {loading ? 'Generating…' : 'Continue'}
        </Button>
      </div>
    </div>
  );
}

function ImportScreen({
  onBack,
  onDone,
}: {
  onBack: () => void;
  onDone: (input: string) => void;
}) {
  const [input, setInput] = useState('');

  return (
    <div className="flex flex-col h-full screen-enter">
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
          autoFocus
        />
        <Button disabled={input.trim().length < 10} onClick={() => onDone(input)}>
          Continue
        </Button>
      </div>
    </div>
  );
}

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

  const strength = password.length >= 16 ? 3 : password.length >= 12 ? 2 : password.length >= 8 ? 1 : 0;
  const strengthLabel = ['Too short', 'Okay', 'Good', 'Strong'][strength];
  const strengthColor = ['var(--red)', 'var(--amber)', '#a3e635', 'var(--green)'][strength];

  async function handleSubmit() {
    if (password.length < 8) { setError('Password must be at least 8 characters'); return; }
    if (password !== confirm) { setError('Passwords do not match'); return; }
    setError('');
    setLoading(true);

    let resp: ExtResponse;
    if (createMode && mnemonic) {
      resp = await sendMsg('EGO_IMPORT_WALLET', { input: mnemonic.join(' '), password });
    } else if (!createMode && importInput) {
      resp = await sendMsg('EGO_IMPORT_WALLET', { input: importInput, password });
    } else {
      resp = await sendMsg('EGO_GENERATE_WALLET', { password });
    }

    setLoading(false);
    if (resp.success) {
      setSuccess('Wallet ready! Redirecting…');
      setTimeout(onDone, 800);
    } else {
      setError(resp.error ?? 'Failed to create wallet');
    }
  }

  return (
    <div className="flex flex-col h-full screen-enter">
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
        {password.length > 0 && (
          <div className="flex items-center gap-2" style={{ marginTop: -8 }}>
            <div style={{ flex: 1, height: 4, borderRadius: 2, background: 'var(--bg-3)', overflow: 'hidden' }}>
              <div style={{
                width: `${Math.min(100, (strength + 1) * 25)}%`,
                height: '100%',
                background: strengthColor,
                borderRadius: 2,
                transition: 'width 0.25s, background 0.25s',
              }} />
            </div>
            <span className="text-xs" style={{ color: strengthColor, minWidth: 56, textAlign: 'right' }}>{strengthLabel}</span>
          </div>
        )}
        <Input
          label="Confirm Password"
          type="password"
          value={confirm}
          onChange={setConfirm}
          placeholder="Re-enter password"
          onEnter={handleSubmit}
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

function UnlockScreen({ onUnlocked, onForgot }: { onUnlocked: () => void; onForgot: () => void }) {
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
    <div className="flex flex-col h-full screen-enter">
      <div className="flex justify-end px-3 pt-3">
        <ThemeToggle />
      </div>
      <div
        className="flex-1 flex flex-col items-center justify-center p-6 gap-5"
        style={{ background: 'radial-gradient(85% 55% at 50% 0%, rgba(99,102,241,0.14) 0%, transparent 70%)' }}
      >
        <div className="float" style={{ position: 'relative' }}>
          <div className="logo-orbit" />
          <img src={LOGO_URL} alt="Ego" className="logo-glow" style={{ width: 72, height: 72, borderRadius: '50%', position: 'relative', zIndex: 1 }} />
        </div>
        <div className="text-center">
          <h1 className="text-xl font-extrabold grad-text mb-1">Welcome back</h1>
          <p className="text-xs text-gray-500">Enter your password to unlock Ego Wallet</p>
        </div>
        <div className="w-full flex flex-col gap-3">
          <Input
            type="password"
            value={password}
            onChange={setPassword}
            placeholder="Password"
            autoFocus
            onEnter={handleUnlock}
          />
          <ErrorBox message={error} />
          <Button disabled={!password || loading} onClick={handleUnlock}>
            {loading ? 'Unlocking…' : 'Unlock'}
          </Button>
          <button type="button" onClick={onForgot} className="link-btn">
            Forgot password? Recover with recovery phrase
          </button>
        </div>
      </div>
    </div>
  );
}

function TxRow({ tx, address }: { tx: AppState['recentTxs'][number]; address: string }) {
  const isOut = !!tx.from && tx.from === address;
  return (
    <div className="tx-row">
      <div className={cls('tx-icon', isOut ? 'tx-out' : 'tx-in')}>
        {isOut ? <Icons.Send /> : <Icons.Receive />}
      </div>
      <div className="flex-1 min-h-0" style={{ minWidth: 0 }}>
        <p className="text-sm font-semibold">{isOut ? 'Sent' : 'Received'}</p>
        <p className="text-xs text-gray-500 font-mono truncate">
          {isOut
            ? (tx.to ? `To ${shortAddress(tx.to)}` : tx.hash?.slice(0, 18) + '…')
            : (tx.from ? `From ${shortAddress(tx.from)}` : tx.hash?.slice(0, 18) + '…')}
        </p>
      </div>
      <div className="text-right">
        {tx.amount_egoc != null && (
          <p className="text-sm font-bold" style={{ color: isOut ? 'var(--red)' : 'var(--green)' }}>
            {isOut ? '−' : '+'}{tx.amount_egoc.toLocaleString(undefined, { maximumFractionDigits: 6 })}
          </p>
        )}
        <p className="text-xs text-gray-600">{tx.timestamp ? timeAgo(tx.timestamp) : 'EGOC'}</p>
      </div>
    </div>
  );
}

function fmtUsd(v: number): string {
  if (v >= 1000) return '$' + v.toLocaleString(undefined, { maximumFractionDigits: 2 });
  if (v >= 1) return '$' + v.toFixed(2);
  if (v > 0) return '$' + v.toFixed(4);
  return '$0.00';
}

function AssetRow({
  asset,
  bal,
  sendable,
  onSend,
  onRemove,
}: {
  asset: TrackedAsset;
  bal?: AssetBalance;
  sendable: boolean;
  onSend: (a: TrackedAsset) => void;
  onRemove: (id: string) => void;
}) {
  const chain = CHAINS[asset.chain];
  return (
    <div className="tx-row">
      <div
        className="tx-icon font-bold"
        style={{ background: chain.color + '22', color: chain.color, fontSize: 15 }}
      >
        {chain.icon}
      </div>
      <div className="flex-1" style={{ minWidth: 0 }}>
        <p className="text-sm font-semibold">
          {asset.symbol}
          {sendable && (
            <span className="text-xs" style={{ color: 'var(--green)', marginLeft: 6, fontWeight: 600 }}>● my wallet</span>
          )}
        </p>
        <p className="text-xs text-gray-500 truncate">
          {bal?.error
            ? <span className="text-red-400">balance unavailable</span>
            : bal
              ? `${bal.balance.toLocaleString(undefined, { maximumFractionDigits: 8 })} ${asset.symbol}`
              : <span className="skeleton" style={{ display: 'inline-block', width: 70, height: 10 }} />}
        </p>
      </div>
      <div className="text-right">
        <p className="text-sm font-bold">{bal ? fmtUsd(bal.value_usd) : '—'}</p>
        <p className="text-xs text-gray-600">{bal && bal.price_usd > 0 ? fmtUsd(bal.price_usd) : asset.name}</p>
      </div>
      {sendable && (
        <button
          className="icon-btn"
          onClick={() => onSend(asset)}
          title={`Send ${asset.symbol}`}
          style={{ width: 26, height: 26, color: '#818cf8' }}
        >
          <span style={{ display: 'flex', width: 15, height: 15 }}><Icons.Send /></span>
        </button>
      )}
      <button
        className="icon-btn"
        onClick={() => onRemove(asset.id)}
        title={`Remove ${asset.symbol}`}
        style={{ width: 24, height: 24, fontSize: 14, color: 'var(--txt-3)' }}
      >
        ×
      </button>
    </div>
  );
}

function isMyAsset(asset: TrackedAsset, chainAddrs: Record<string, string>): boolean {
  const mine = chainAddrs[asset.chain];
  return !!mine && mine.toLowerCase() === asset.address.toLowerCase();
}

function HomeScreen({
  state,
  onRefresh,
  onNavigate,
  onSendAsset,
}: {
  state: AppState;
  onRefresh: () => void;
  onNavigate: (s: Screen) => void;
  onSendAsset: (a: TrackedAsset) => void;
}) {
  const [toast, setToast] = useState('');
  const [faucetLoading, setFaucetLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [assets, setAssets] = useState<TrackedAsset[]>([]);
  const [assetBals, setAssetBals] = useState<Record<string, AssetBalance>>({});
  const [chainAddrs, setChainAddrs] = useState<Record<string, string>>({});

  useEffect(() => {
    sendMsg<{ addresses: Record<string, string> }>('EGO_GET_CHAIN_ADDRESSES')
      .then(resp => { if (resp.success && resp.data) setChainAddrs(resp.data.addresses); });
  }, []);

  const loadAssets = useCallback(async () => {
    const resp = await sendMsg<{ assets: TrackedAsset[] }>('EGO_GET_ASSETS');
    if (resp.success && resp.data) {
      setAssets(resp.data.assets);
      if (resp.data.assets.length > 0) {
        const balResp = await sendMsg<{ balances: AssetBalance[] }>('EGO_REFRESH_ASSETS');
        if (balResp.success && balResp.data) {
          const map: Record<string, AssetBalance> = {};
          for (const b of balResp.data.balances) map[b.id] = b;
          setAssetBals(map);
        }
      }
    }
  }, []);

  useEffect(() => { loadAssets(); }, [loadAssets]);

  async function handleRemoveAsset(id: string) {
    await sendMsg('EGO_REMOVE_ASSET', { id });
    setAssets(prev => prev.filter(a => a.id !== id));
    flash('Asset removed');
  }

  function flash(msg: string) {
    setToast(msg);
    setTimeout(() => setToast(''), 2200);
  }

  function copyAddress() {
    navigator.clipboard.writeText(state.address);
    flash('Address copied');
  }

  async function handleFaucet() {
    setFaucetLoading(true);
    const resp = await sendMsg('EGO_FAUCET', {});
    setFaucetLoading(false);
    if (resp.success) {
      flash('100 EGOC requested from faucet');
      onRefresh();
    } else {
      flash(resp.error ?? 'Faucet unavailable');
    }
  }

  function handleRefresh() {
    setRefreshing(true);
    onRefresh();
    loadAssets();
    setTimeout(() => setRefreshing(false), 700);
  }

  return (
    <div className="flex flex-col h-full min-h-0 screen-enter">
      <div className="flex-1 overflow-y-auto" style={{ paddingBottom: 8 }}>
        {/* Balance hero */}
        <div className="mx-4 mt-4 hero-card">
          <div className="flex items-center justify-center gap-2 mb-1">
            <p className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--txt-3)' }}>Total Balance</p>
            {state.blockHeight > 0 && (
              <span className="text-xs" style={{ color: 'var(--txt-3)' }}>· #{state.blockHeight.toLocaleString()}</span>
            )}
          </div>
          <p className="text-3xl font-extrabold" style={{ letterSpacing: '-0.02em', position: 'relative' }}>
            {state.balance.toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 6 })}
            <span className="text-base font-semibold grad-text" style={{ marginLeft: 7 }}>EGOC</span>
          </p>
          <p className="text-xs mt-1" style={{ color: 'var(--txt-3)', position: 'relative' }}>
            {state.balanceUegoc.toLocaleString()} uEGOC
          </p>

          {/* Quick actions */}
          <div className="flex mt-4" style={{ position: 'relative', gap: 4 }}>
            <button className="qa-btn" onClick={() => onNavigate('send')}>
              <span className="qa-circle"><Icons.Send /></span>
              Send
            </button>
            <button className="qa-btn" onClick={() => onNavigate('receive')}>
              <span className="qa-circle"><Icons.Receive /></span>
              Receive
            </button>
            {state.network === 'testnet' && (
              <button className="qa-btn" onClick={handleFaucet} disabled={faucetLoading}>
                <span className="qa-circle" style={faucetLoading ? { opacity: 0.6 } : undefined}>
                  {faucetLoading
                    ? <span className="animate-spin" style={{ display: 'flex' }}><Icons.Refresh /></span>
                    : <span style={{ display: 'flex', width: 19, height: 19 }}><Icons.Faucet /></span>}
                </span>
                Faucet
              </button>
            )}
            <button className="qa-btn" onClick={() => onNavigate('activity')}>
              <span className="qa-circle"><Icons.Activity /></span>
              Activity
            </button>
          </div>
        </div>

        {/* Address chip */}
        <button
          onClick={copyAddress}
          className="card card-hover mx-4 mt-3 w-full flex items-center justify-between cursor-pointer"
          style={{ width: 'calc(100% - 2rem)', fontFamily: 'inherit', textAlign: 'left' }}
        >
          <div style={{ minWidth: 0 }}>
            <p className="ego-label" style={{ marginBottom: 2 }}>Address</p>
            <p className="font-mono text-sm text-gray-300">{shortAddress(state.address)}</p>
          </div>
          <span className="icon-btn" style={{ pointerEvents: 'none' }}><Icons.Copy /></span>
        </button>

        {/* Tracked assets */}
        <div className="mx-4 mt-4">
          <div className="flex items-center justify-between mb-2">
            <p className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--txt-3)' }}>Assets</p>
            <button
              className="btn btn-ghost"
              onClick={() => onNavigate('addAsset')}
              style={{ padding: '3px 9px', fontSize: '0.72rem', color: '#818cf8' }}
            >
              + Add coin / token
            </button>
          </div>
          {assets.length === 0 ? (
            <button
              className="card card-hover w-full text-center cursor-pointer"
              onClick={() => onNavigate('addAsset')}
              style={{ fontFamily: 'inherit', padding: '14px' }}
            >
              <p className="text-sm text-gray-400">Track other coins &amp; tokens</p>
              <p className="text-xs text-gray-600 mt-1">BTC · ETH · BNB · SOL · DOGE · LTC · ERC-20 · BEP-20</p>
            </button>
          ) : (
            <div className="flex flex-col gap-2">
              {assets.map(a => (
                <AssetRow
                  key={a.id}
                  asset={a}
                  bal={assetBals[a.id]}
                  sendable={isMyAsset(a, chainAddrs)}
                  onSend={onSendAsset}
                  onRemove={handleRemoveAsset}
                />
              ))}
            </div>
          )}
        </div>

        {/* Recent transactions */}
        <div className="mx-4 mt-4 mb-3">
          <div className="flex items-center justify-between mb-2">
            <p className="text-xs font-semibold uppercase tracking-wide" style={{ color: 'var(--txt-3)' }}>Recent Activity</p>
            <button className="icon-btn" onClick={handleRefresh} title="Refresh" style={{ width: 28, height: 28 }}>
              <span className={refreshing ? 'animate-spin' : ''} style={{ display: 'flex' }}><Icons.Refresh /></span>
            </button>
          </div>
          {state.recentTxs.length === 0 ? (
            <div className="card text-center py-6">
              <p className="text-sm text-gray-500">No transactions yet</p>
              <p className="text-xs text-gray-600 mt-1">Your activity will appear here</p>
            </div>
          ) : (
            <div className="flex flex-col gap-2">
              {state.recentTxs.slice(0, 5).map((tx, i) => (
                <TxRow key={i} tx={tx} address={state.address} />
              ))}
            </div>
          )}
        </div>
      </div>
      <Toast message={toast} />
    </div>
  );
}

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
    if (!to.startsWith('egot1')) { setError('Invalid address (must start with egot1)'); return; }

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
      <div className="flex flex-col h-full screen-enter">
        <Header title="Send EGOC" onBack={onBack} />
        <div className="flex-1 flex flex-col items-center justify-center p-6 gap-4">
          <div
            className="flex items-center justify-center fade-in"
            style={{
              width: 72, height: 72, borderRadius: '50%',
              background: 'rgba(52,211,153,0.12)',
              border: '1px solid rgba(52,211,153,0.4)',
              color: 'var(--green)',
              boxShadow: '0 0 40px -8px rgba(52,211,153,0.5)',
            }}
          >
            <Icons.Check />
          </div>
          <p className="text-xl font-bold text-green-400">Transaction Sent</p>
          <div className="card w-full">
            <p className="ego-label">Transaction Hash</p>
            <p className="font-mono text-xs text-gray-300 break-all">{txHash}</p>
          </div>
          <Button onClick={onBack}>Back to Home</Button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full screen-enter">
      <Header title="Send EGOC" onBack={onBack} />
      <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-4">
        <div className="card flex items-center gap-3">
          <img src={LOGO_URL} alt="" style={{ width: 30, height: 30, borderRadius: '50%' }} />
          <div style={{ minWidth: 0 }}>
            <p className="ego-label" style={{ marginBottom: 2 }}>From</p>
            <p className="font-mono text-sm text-gray-300">{shortAddress(address)}</p>
          </div>
        </div>
        <Input label="Recipient Address" value={to} onChange={setTo} placeholder="egot1…" autoFocus />
        <Input label="Amount (EGOC)" type="number" value={amount} onChange={setAmount} placeholder="0.00" />
        <Input label="Memo (optional)" value={memo} onChange={setMemo} placeholder="Optional note" />
        <ErrorBox message={error} />
        <Button disabled={!to || !amount || loading} onClick={handleSend}>
          {loading ? 'Sending…' : `Send${network === 'testnet' ? ' on Testnet' : ''}`}
        </Button>
      </div>
    </div>
  );
}

function ReceiveScreen({ address, onBack }: { address: string; onBack: () => void }) {
  const [copied, setCopied] = useState(false);

  function copyAddress() {
    navigator.clipboard.writeText(address);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  return (
    <div className="flex flex-col h-full screen-enter">
      <Header title="Receive EGOC" onBack={onBack} />
      <div className="flex-1 overflow-y-auto flex flex-col items-center p-6 gap-5">
        <p className="text-sm text-gray-400 text-center">
          Share your address or QR code to receive EGOC.
        </p>
        <div style={{ display: 'flex', justifyContent: 'center' }}>
          <QRCode data={address} size={172} />
        </div>
        <div className="card w-full">
          <p className="ego-label">Your Address</p>
          <p className="font-mono text-sm text-gray-300 break-all" style={{ userSelect: 'all' }}>{address}</p>
        </div>
        <Button onClick={copyAddress} variant={copied ? 'secondary' : 'primary'}>
          {copied ? '✓ Copied' : 'Copy Address'}
        </Button>
      </div>
    </div>
  );
}

function ActivityScreen({
  txs,
  address,
  onRefresh,
}: {
  txs: AppState['recentTxs'];
  address: string;
  onRefresh: () => void;
}) {
  const [refreshing, setRefreshing] = useState(false);

  function handleRefresh() {
    setRefreshing(true);
    onRefresh();
    setTimeout(() => setRefreshing(false), 700);
  }

  return (
    <div className="flex flex-col h-full screen-enter">
      <div className="topbar">
        <span className="text-base font-bold grad-text flex-1">Activity</span>
        <button className="icon-btn" onClick={handleRefresh} title="Refresh">
          <span className={refreshing ? 'animate-spin' : ''} style={{ display: 'flex' }}><Icons.Refresh /></span>
        </button>
      </div>
      <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-2">
        {txs.length === 0 ? (
          <div className="flex-1 flex flex-col items-center justify-center gap-2">
            <div
              className="flex items-center justify-center"
              style={{ width: 56, height: 56, borderRadius: '50%', background: 'var(--bg-2)', border: '1px solid var(--line)', color: 'var(--txt-3)' }}
            >
              <span style={{ width: 24, height: 24, display: 'flex' }}><Icons.Activity /></span>
            </div>
            <p className="text-sm text-gray-500">No transactions found</p>
            <p className="text-xs text-gray-600">Send or receive EGOC to see activity here</p>
          </div>
        ) : (
          txs.map((tx, i) => <TxRow key={i} tx={tx} address={address} />)
        )}
      </div>
    </div>
  );
}

function AddAssetScreen({ onBack }: { onBack: () => void }) {
  const [mode, setMode] = useState<'coin' | 'token'>('coin');
  const [chain, setChain] = useState<ChainId>('BTC');
  const [address, setAddress] = useState('');
  const [contract, setContract] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [chainAddrs, setChainAddrs] = useState<Record<string, string>>({});

  useEffect(() => {
    sendMsg<{ addresses: Record<string, string> }>('EGO_GET_CHAIN_ADDRESSES')
      .then(resp => { if (resp.success && resp.data) setChainAddrs(resp.data.addresses); });
  }, []);

  const chainIds = Object.keys(CHAINS) as ChainId[];
  const tokenChains = chainIds.filter(c => CHAINS[c].tokens);
  const visibleChains = mode === 'token' ? tokenChains : chainIds;
  const activeChain = mode === 'token' && !CHAINS[chain].tokens ? 'ETH' : chain;

  async function handleAdd() {
    setError('');
    setLoading(true);
    const resp = await sendMsg<{ asset: TrackedAsset }>('EGO_ADD_ASSET', {
      chain: activeChain,
      address: address.trim(),
      contract: mode === 'token' ? contract.trim() : undefined,
    });
    setLoading(false);
    if (resp.success) {
      onBack();
    } else {
      setError(resp.error ?? 'Failed to add asset');
    }
  }

  const canSubmit = address.trim().length > 10 && (mode === 'coin' || contract.trim().length === 42);

  return (
    <div className="flex flex-col h-full screen-enter">
      <Header title="Add Asset" onBack={onBack} />
      <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-4">
        {/* Mode toggle */}
        <div className="flex gap-2">
          {(['coin', 'token'] as const).map(m => {
            const active = mode === m;
            return (
              <button
                key={m}
                className="btn"
                onClick={() => { setMode(m); setError(''); if (m === 'token' && !CHAINS[chain].tokens) setChain('ETH'); }}
                style={{
                  flex: 1,
                  padding: '9px 0',
                  fontSize: '0.8rem',
                  background: active ? 'rgba(99,102,241,0.16)' : 'var(--bg-3)',
                  border: `1px solid ${active ? 'rgba(129,140,248,0.55)' : 'var(--line-2)'}`,
                  color: active ? '#c7d2fe' : 'var(--txt-2)',
                }}
              >
                {m === 'coin' ? 'Coin' : 'Token (ERC-20 / BEP-20)'}
              </button>
            );
          })}
        </div>

        {/* Chain picker */}
        <div>
          <label className="ego-label">{mode === 'token' ? 'Token network' : 'Blockchain'}</label>
          <div className="grid grid-cols-3 gap-2">
            {visibleChains.map(c => {
              const info = CHAINS[c];
              const active = activeChain === c;
              return (
                <button
                  key={c}
                  onClick={() => setChain(c)}
                  className="card card-hover cursor-pointer"
                  style={{
                    fontFamily: 'inherit',
                    padding: '10px 6px',
                    textAlign: 'center',
                    borderColor: active ? info.color + '99' : undefined,
                    background: active ? info.color + '14' : undefined,
                  }}
                >
                  <div className="font-bold" style={{ color: info.color, fontSize: 17 }}>{info.icon}</div>
                  <div className="text-xs font-semibold mt-1" style={{ color: active ? 'var(--txt)' : 'var(--txt-2)' }}>{c}</div>
                </button>
              );
            })}
          </div>
        </div>

        {mode === 'token' && (
          <Input
            label="Token Contract Address"
            value={contract}
            onChange={setContract}
            placeholder="0x…"
          />
        )}

        <div>
          <div className="flex items-center justify-between">
            <label className="ego-label">{`Your ${CHAINS[activeChain].name} Address`}</label>
            {chainAddrs[activeChain] && (
              <button
                className="btn btn-ghost"
                onClick={() => setAddress(chainAddrs[activeChain])}
                style={{ padding: '2px 8px', fontSize: '0.7rem', color: '#818cf8', marginBottom: 6 }}
              >
                Use my wallet address
              </button>
            )}
          </div>
          <Input
            value={address}
            onChange={setAddress}
            placeholder={activeChain === 'ETH' || activeChain === 'BNB' || activeChain === 'POL' ? '0x…' : `${CHAINS[activeChain].name} address`}
            onEnter={handleAdd}
          />
        </div>

        <div className="alert alert-info">
          {chainAddrs[activeChain]
            ? 'Use your wallet address (derived from your seed) to send and receive, or paste any address to watch it read-only.'
            : `${CHAINS[activeChain].name} assets are watch-only — balances and prices are tracked, but sending requires that chain's native wallet.`}
        </div>

        <ErrorBox message={error} />
        <Button disabled={!canSubmit || loading} onClick={handleAdd}>
          {loading ? 'Verifying…' : 'Add Asset'}
        </Button>
      </div>
    </div>
  );
}

function SendAssetScreen({ asset, onBack }: { asset: TrackedAsset; onBack: () => void }) {
  const chain = CHAINS[asset.chain];
  const [to, setTo] = useState('');
  const [amount, setAmount] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [result, setResult] = useState<{ txid: string; explorer_url: string } | null>(null);

  async function handleSend() {
    setError('');
    setLoading(true);
    const resp = await sendMsg<{ txid: string; explorer_url: string }>('EGO_SEND_EXTERNAL', {
      chain: asset.chain,
      to: to.trim(),
      amount: amount.trim(),
      contract: asset.contract,
      decimals: asset.decimals,
    });
    setLoading(false);
    if (resp.success && resp.data) {
      setResult(resp.data);
    } else {
      setError(resp.error ?? 'Transaction failed');
    }
  }

  if (result) {
    return (
      <div className="flex flex-col h-full screen-enter">
        <Header title={`Send ${asset.symbol}`} onBack={onBack} />
        <div className="flex-1 flex flex-col items-center justify-center p-6 gap-4">
          <div
            className="flex items-center justify-center fade-in"
            style={{
              width: 72, height: 72, borderRadius: '50%',
              background: 'rgba(52,211,153,0.12)',
              border: '1px solid rgba(52,211,153,0.4)',
              color: 'var(--green)',
              boxShadow: '0 0 40px -8px rgba(52,211,153,0.5)',
            }}
          >
            <Icons.Check />
          </div>
          <p className="text-xl font-bold text-green-400">Broadcast Successful</p>
          <div className="card w-full">
            <p className="ego-label">Transaction ID</p>
            <p className="font-mono text-xs text-gray-300 break-all">{result.txid}</p>
          </div>
          <Button variant="secondary" onClick={() => window.open(result.explorer_url, '_blank')}>
            View on Explorer ↗
          </Button>
          <Button onClick={onBack}>Done</Button>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full screen-enter">
      <Header title={`Send ${asset.symbol}`} onBack={onBack} />
      <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-4">
        <div className="card flex items-center gap-3">
          <div
            className="tx-icon font-bold"
            style={{ background: chain.color + '22', color: chain.color, fontSize: 16 }}
          >
            {chain.icon}
          </div>
          <div style={{ minWidth: 0 }}>
            <p className="text-sm font-semibold">{asset.symbol} · {asset.name}</p>
            <p className="font-mono text-xs text-gray-500 truncate">{asset.address}</p>
          </div>
        </div>

        <Input
          label="Recipient Address"
          value={to}
          onChange={setTo}
          placeholder={asset.chain === 'BTC' ? 'bc1…, 1…, or 3…' : '0x…'}
          autoFocus
        />
        <Input
          label={`Amount (${asset.symbol})`}
          type="number"
          value={amount}
          onChange={setAmount}
          placeholder="0.00"
          onEnter={handleSend}
        />

        <div className="alert alert-warn">
          {asset.chain === 'BTC'
            ? 'The network fee is added on top of the amount and deducted from your BTC balance.'
            : asset.contract
              ? `Gas is paid in ${asset.chain === 'ETH' ? 'ETH' : 'BNB'} from this same address.`
              : 'The network fee (gas) is deducted from your balance in addition to the amount.'}
          {' '}Mainnet transactions are irreversible — double-check the recipient.
        </div>

        <ErrorBox message={error} />
        <Button disabled={!to || !amount || loading} onClick={handleSend}>
          {loading ? 'Signing & broadcasting…' : `Send ${asset.symbol}`}
        </Button>
      </div>
    </div>
  );
}

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
    <div className="flex flex-col h-full screen-enter">
      <div className="topbar">
        <span className="text-base font-bold grad-text flex-1">Settings</span>
      </div>
      <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-3">
        {/* Network */}
        <div className="card">
          <p className="ego-label">Network</p>
          <div className="flex gap-2 mt-1">
            {(['testnet', 'mainnet'] as const).map(n => {
              const active = state.network === n;
              return (
                <button
                  key={n}
                  onClick={() => onNetworkChange(n)}
                  className="btn"
                  style={{
                    flex: 1,
                    padding: '9px 0',
                    fontSize: '0.8rem',
                    background: active ? 'rgba(99,102,241,0.16)' : 'var(--bg-3)',
                    border: `1px solid ${active ? 'rgba(129,140,248,0.55)' : 'var(--line-2)'}`,
                    color: active ? '#c7d2fe' : 'var(--txt-2)',
                  }}
                >
                  {active && <span className="net-dot" style={{ background: 'var(--green)' }} />}
                  {n === 'testnet' ? 'Testnet' : 'Mainnet'}
                </button>
              );
            })}
          </div>
        </div>

        {/* Address */}
        <div className="card">
          <div className="flex items-center justify-between mb-1">
            <p className="ego-label" style={{ marginBottom: 0 }}>Your Address</p>
            <button
              className="btn btn-ghost"
              onClick={() => copyItem(state.address, 'address')}
              style={{ padding: '3px 8px', fontSize: '0.72rem', color: copied === 'address' ? 'var(--green)' : '#818cf8' }}
            >
              {copied === 'address' ? '✓ Copied' : 'Copy'}
            </button>
          </div>
          <p className="font-mono text-xs text-gray-400 break-all">{state.address}</p>
        </div>

        {/* Recovery phrase */}
        <div className="card">
          <p className="ego-label">Recovery Phrase</p>
          {!showPhrase ? (
            <div className="flex flex-col gap-2 mt-1">
              <p className="text-xs text-gray-500">Enter your password to reveal the 24-word recovery phrase.</p>
              <Input type="password" value={password} onChange={setPassword} placeholder="Your password" onEnter={revealPhrase} />
              <ErrorBox message={phraseError} />
              <Button variant="secondary" disabled={!password || phraseLoading} onClick={revealPhrase}>
                {phraseLoading ? 'Verifying…' : 'Reveal Phrase'}
              </Button>
            </div>
          ) : (
            <div className="flex flex-col gap-2 mt-1">
              <div className="alert alert-warn" style={{ padding: '8px 11px' }}>
                Never share these words. Anyone with them controls your funds.
              </div>
              <div className="grid grid-cols-3 gap-1">
                {mnemonic.map((word, i) => (
                  <div key={i} className="word-badge">
                    <span className="num">{i + 1}</span>
                    {word}
                  </div>
                ))}
              </div>
              <div className="flex gap-2 mt-1">
                <Button
                  variant="secondary"
                  small
                  onClick={() => copyItem(mnemonic.join(' '), 'mnemonic')}
                >
                  {copied === 'mnemonic' ? '✓ Copied' : 'Copy all'}
                </Button>
                <Button
                  variant="ghost"
                  small
                  onClick={() => { setShowPhrase(false); setMnemonic([]); setPassword(''); }}
                >
                  Hide
                </Button>
              </div>
            </div>
          )}
        </div>

        <Button variant="danger" onClick={onLock}>
          <Icons.Lock /> Lock Wallet
        </Button>

        <p className="text-xs text-gray-600 text-center mt-1">Ego Wallet v1.0.0 · Manifest V3</p>
      </div>
    </div>
  );
}

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
    <div className="flex flex-col h-full screen-enter">
      <Header title="Connection Request" />
      <div className="flex-1 flex flex-col items-center justify-center p-6 gap-5">
        <div
          className="flex items-center justify-center float"
          style={{
            width: 64, height: 64, borderRadius: '50%',
            background: 'rgba(99,102,241,0.12)',
            border: '1px solid rgba(129,140,248,0.4)',
            color: '#a5b4fc',
            boxShadow: '0 0 40px -8px rgba(99,102,241,0.6)',
          }}
        >
          <Icons.Link />
        </div>
        <div className="text-center">
          <h2 className="text-lg font-bold text-white mb-1">Connect to dApp</h2>
          <p className="text-sm text-gray-400">This site wants to connect to your wallet</p>
        </div>
        <div className="card w-full">
          <p className="ego-label">Origin</p>
          <p className="font-semibold text-blue-400 break-all">{conn.origin}</p>
          {conn.title && (
            <>
              <p className="ego-label mt-3">Site</p>
              <p className="text-sm text-gray-300">{conn.title}</p>
            </>
          )}
        </div>
        <div className="alert alert-info w-full" style={{ textAlign: 'center' }}>
          Connecting shares your wallet address with this site.
        </div>
        <div className="flex gap-3 w-full">
          <Button variant="secondary" onClick={onReject} fullWidth>Reject</Button>
          <Button variant="primary" onClick={onApprove} fullWidth>Connect</Button>
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [state, dispatch] = useReducer(reducer, INIT);

  const [wizardMnemonic, setWizardMnemonic] = useState<string[]>([]);
  const [importInput, setImportInput] = useState('');
  const [wizardMode, setWizardMode] = useState<'create' | 'import'>('create');
  const [sendAssetTarget, setSendAssetTarget] = useState<TrackedAsset | null>(null);

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

  function navigate(screen: Screen) {
    dispatch({ type: 'SET_SCREEN', screen });
    if (screen === 'home') refreshAll();
  }

  async function handleLock() {
    await sendMsg('EGO_LOCK');
    dispatch({ type: 'SET_SCREEN', screen: 'unlock' });
  }

  async function handleUnlocked() {
    await loadState();
  }

  async function handleNetworkChange(network: 'testnet' | 'mainnet') {
    await sendMsg('EGO_SET_NETWORK', { network });
    dispatch({ type: 'SET_WALLET', address: state.address, network });
  }

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

  function handleWizardDone() {
    loadState();
  }

  if (state.loading) {
    return (
      <>
        <StyleTag />
        <div className="flex flex-col h-full items-center justify-center gap-4" style={{ background: 'var(--bg)' }}>
          <img src={LOGO_URL} alt="Ego" className="logo-glow float" style={{ width: 52, height: 52, borderRadius: '50%' }} />
          <span className="text-blue-400"><Icons.Spinner /></span>
        </div>
      </>
    );
  }

  const nodeOnline = state.nodeStatus === 'healthy' || state.nodeStatus === 'ok';

  return (
    <>
      <StyleTag />
      <div className="flex flex-col h-full overflow-hidden" style={{ background: 'var(--bg)' }}>
        {state.screen === 'home' && (
          <Header title="Ego Wallet" onLock={handleLock} network={state.network} nodeOnline={nodeOnline} />
        )}

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
            <UnlockScreen
              onUnlocked={handleUnlocked}
              onForgot={() => {
                setWizardMode('import');
                dispatch({ type: 'SET_SCREEN', screen: 'import' });
              }}
            />
          )}

          {state.screen === 'home' && (
            <HomeScreen
              state={state}
              onRefresh={refreshAll}
              onNavigate={navigate}
              onSendAsset={(a) => { setSendAssetTarget(a); navigate('sendAsset'); }}
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
            <ActivityScreen txs={state.recentTxs} address={state.address} onRefresh={refreshAll} />
          )}

          {state.screen === 'addAsset' && (
            <AddAssetScreen onBack={() => navigate('home')} />
          )}

          {state.screen === 'sendAsset' && sendAssetTarget && (
            <SendAssetScreen asset={sendAssetTarget} onBack={() => navigate('home')} />
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

        {['home', 'send', 'receive', 'activity', 'settings'].includes(state.screen) && (
          <Navbar screen={state.screen} onNavigate={navigate} />
        )}
      </div>
    </>
  );
}
