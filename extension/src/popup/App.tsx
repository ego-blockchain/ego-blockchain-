import React, { useCallback, useEffect, useReducer, useRef, useState } from 'react';
import qrcode from 'qrcode-generator';
import { generateSeed, seedToMnemonic } from '../shared/crypto';
import { CHAINS, type ChainId } from '../shared/assets';
import type { DappRequestKind, ExtMessage, ExtResponse, PendingRequest, TrackedAsset, AssetBalance } from '../shared/types';
import {
  DENOMINATIONS_UEGOC,
  MAX_SPENDS,
  denominate,
  pickNotesFor,
  type NoteStatus,
  type NoteView,
} from '../shared/shielded';

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

const IS_APPROVAL_WINDOW = new URLSearchParams(window.location.search).get('approval') === '1';

const STYLES = `
  @import url('https://fonts.googleapis.com/css2?family=Montserrat:wght@600;700;800&family=Lato:wght@400;700&family=JetBrains+Mono:wght@500&display=swap');

  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }

  :root {
    --font-display: 'Montserrat', 'Segoe UI', system-ui, sans-serif;
    --font-body:    'Lato', 'Segoe UI', system-ui, sans-serif;
    --font-mono:    'JetBrains Mono', 'SF Mono', ui-monospace, monospace;

    --bg:     #05070c;
    --bg-1:   #0a0e16;
    --bg-2:   #10161f;
    --bg-3:   #182130;
    --line:   rgba(201,212,227,0.12);
    --line-2: rgba(201,212,227,0.22);
    --txt:    #f5f8fc;
    --txt-1:  #e3e9f2;
    --txt-2:  #c9d4e3;
    --txt-3:  #9aa6ba;
    --txt-4:  #7f8ca3;

    --lime:   #d2eb2b;
    --mint:   #00e5b0;
    --amber:  #ffb547;
    --sky:    #8fd3ff;
    --green:  #2ef2c2;
    --red:    #ff7a93;
    --blue:   #8fd3ff;

    --accent:      #d2eb2b;
    --accent-2:    #00e5b0;
    --accent-fill: #d2eb2b;
    --accent-hover:#e0f74a;
    --accent-ink:  #0b0f02;
    --accent-text: #d8f03c;
    --brand-text:  #2ef2c2;
    --accent-tint: rgba(210,235,43,0.13);
    --accent-line: rgba(210,235,43,0.45);
    --accent-glow: rgba(210,235,43,0.55);
    --mint-tint:   rgba(0,229,176,0.13);
    --mint-line:   rgba(0,229,176,0.42);
    --pos-tint:    rgba(46,242,194,0.13);
    --neg-tint:    rgba(255,122,147,0.13);
    --grad:        linear-gradient(120deg, #d2eb2b 0%, #00e5b0 100%);

    --qa-send:     #d2eb2b;
    --qa-receive:  #2ef2c2;
    --qa-shield:   #ffb547;
    --qa-activity: #ff9ec4;

    --alert-error-txt:   #ffc2cd;
    --alert-success-txt: #a8f7e1;
    --alert-info-txt:    #cdeeff;
    --alert-warn-txt:    #ffe0a8;

    --hero-bg:   linear-gradient(160deg, #111a17 0%, #0e141d 52%, #09121a 100%);
    --hero-line: rgba(210,235,43,0.24);
    --glow-a:    rgba(196,240,58,0.20);
    --glow-b:    rgba(0,229,176,0.30);
    --cube:      url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='28' height='48' viewBox='0 0 28 48'%3E%3Cpath d='M14 0 L28 8 L28 24 L14 32 L0 24 L0 8 Z M14 16 L0 8 M14 16 L28 8 M14 16 L14 32 M0 24 L14 32 L14 48 L0 56 L-14 48 L-14 32 Z M0 40 L-14 32 M0 40 L14 32 M0 40 L0 56 M28 24 L42 32 L42 48 L28 56 L14 48 L14 32 Z M28 40 L14 32 M28 40 L42 32 M28 40 L28 56 M0 -24 L14 -16 L14 0 L0 8 L-14 0 L-14 -16 Z M0 -8 L-14 -16 M0 -8 L14 -16 M0 -8 L0 8 M28 -24 L42 -16 L42 0 L28 8 L14 0 L14 -16 Z M28 -8 L14 -16 M28 -8 L42 -16 M28 -8 L28 8' fill='none' stroke='%23ffffff' stroke-width='0.8'/%3E%3C/svg%3E");
    --cube-opacity: 0.10;
    --topbar-bg: rgba(5,7,12,0.84);
    --scroll:    #2a3446;
    --qr-ring:   rgba(210,235,43,0.35);
    color-scheme: dark;
  }

  :root[data-theme="light"] {
    --bg:     #f2f4ee;
    --bg-1:   #ffffff;
    --bg-2:   #ffffff;
    --bg-3:   #eaeee7;
    --line:   rgba(16,24,20,0.11);
    --line-2: rgba(16,24,20,0.19);
    --txt:    #0d1310;
    --txt-1:  #1c2621;
    --txt-2:  #39443e;
    --txt-3:  #55615b;
    --txt-4:  #69756f;

    --green:  #007a5c;
    --red:    #c42d4c;
    --amber:  #9a5600;
    --sky:    #0a6aa6;
    --blue:   #0a6aa6;

    --accent-text: #536500;
    --brand-text:  #00775f;
    --accent-tint: rgba(150,175,0,0.14);
    --accent-line: rgba(115,140,0,0.45);
    --accent-glow: rgba(150,175,0,0.45);
    --mint-tint:   rgba(0,140,110,0.10);
    --mint-line:   rgba(0,140,110,0.38);
    --pos-tint:    rgba(0,122,92,0.10);
    --neg-tint:    rgba(196,45,76,0.10);
    --grad:        linear-gradient(120deg, #5a6d00 0%, #007a62 100%);

    --qa-send:     #5a6d00;
    --qa-receive:  #00775f;
    --qa-shield:   #9a5600;
    --qa-activity: #b02f68;

    --alert-error-txt:   #8f1730;
    --alert-success-txt: #005c45;
    --alert-info-txt:    #0b4d78;
    --alert-warn-txt:    #6e3c00;

    --hero-bg:   linear-gradient(160deg, #fbfdf0 0%, #f2f9f4 58%, #edf6f6 100%);
    --hero-line: rgba(95,115,0,0.24);
    --glow-a:    rgba(210,235,43,0.55);
    --glow-b:    rgba(0,229,176,0.30);
    --cube:      url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='28' height='48' viewBox='0 0 28 48'%3E%3Cpath d='M14 0 L28 8 L28 24 L14 32 L0 24 L0 8 Z M14 16 L0 8 M14 16 L28 8 M14 16 L14 32 M0 24 L14 32 L14 48 L0 56 L-14 48 L-14 32 Z M0 40 L-14 32 M0 40 L14 32 M0 40 L0 56 M28 24 L42 32 L42 48 L28 56 L14 48 L14 32 Z M28 40 L14 32 M28 40 L42 32 M28 40 L28 56 M0 -24 L14 -16 L14 0 L0 8 L-14 0 L-14 -16 Z M0 -8 L-14 -16 M0 -8 L14 -16 M0 -8 L0 8 M28 -24 L42 -16 L42 0 L28 8 L14 0 L14 -16 Z M28 -8 L14 -16 M28 -8 L42 -16 M28 -8 L28 8' fill='none' stroke='%23203020' stroke-width='0.8'/%3E%3C/svg%3E");
    --cube-opacity: 0.08;
    --topbar-bg: rgba(255,255,255,0.88);
    --scroll:    #c3c9cf;
    --qr-ring:   rgba(95,115,0,0.30);
    color-scheme: light;
  }

  html, body { background: var(--bg); }
  body {
    font-family: var(--font-body);
    color: var(--txt);
    -webkit-font-smoothing: antialiased;
  }
  h1, h2, h3, .font-display, .text-2xl, .text-3xl, .font-extrabold { font-family: var(--font-display); letter-spacing: -0.01em; }

  .link-btn {
    background: none; border: none; cursor: pointer;
    color: var(--txt-3); font-family: inherit; font-size: 0.76rem; font-weight: 700;
    margin: 6px auto 0; display: block; padding: 4px;
    text-decoration: underline; text-underline-offset: 3px;
    transition: color 0.15s ease;
  }
  .link-btn:hover:not(:disabled) { color: var(--accent-text); }
  .link-btn:disabled { opacity: 0.45; cursor: not-allowed; }

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
  .relative { position: relative; }
  .absolute { position: absolute; }
  .inline-block { display: inline-block; }
  .overflow-hidden { overflow: hidden; }
  .overflow-y-auto { overflow-y: auto; }
  .rounded-lg { border-radius: 0.5rem; }
  .rounded-xl { border-radius: 0.75rem; }
  .rounded-2xl { border-radius: 1rem; }
  .rounded-full { border-radius: 9999px; }
  .text-white { color: var(--txt); }
  .text-gray-300 { color: var(--txt-1); }
  .text-gray-400 { color: var(--txt-2); }
  .text-gray-500 { color: var(--txt-3); }
  .text-gray-600 { color: var(--txt-4); }
  .text-blue-400 { color: var(--brand-text); }
  .text-blue-300 { color: var(--brand-text); }
  .text-green-400 { color: var(--green); }
  .text-red-400 { color: var(--red); }
  .text-xs { font-size: 0.74rem; line-height: 1.05rem; }
  .text-sm { font-size: 0.86rem; line-height: 1.3rem; }
  .text-base { font-size: 1rem; line-height: 1.5rem; }
  .text-lg { font-size: 1.125rem; line-height: 1.75rem; }
  .text-xl { font-size: 1.25rem; line-height: 1.75rem; }
  .text-2xl { font-size: 1.5rem; line-height: 2rem; }
  .text-3xl { font-size: 2rem; line-height: 2.4rem; }
  .font-medium { font-weight: 500; }
  .font-semibold { font-weight: 700; }
  .font-bold { font-weight: 700; }
  .font-extrabold { font-weight: 800; }
  .font-mono { font-family: var(--font-mono); letter-spacing: -0.01em; }
  .tracking-wide { letter-spacing: 0.06em; }
  .uppercase { text-transform: uppercase; font-family: var(--font-display); letter-spacing: 0.1em; }
  .break-all { word-break: break-all; }
  .truncate { overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .text-center { text-align: center; }
  .text-right { text-align: right; }
  .leading-relaxed { line-height: 1.6; }
  .cursor-pointer { cursor: pointer; }
  .p-3 { padding: 0.75rem; }
  .p-4 { padding: 1rem; }
  .p-6 { padding: 1.5rem; }
  .px-3 { padding-left: 0.75rem; padding-right: 0.75rem; }
  .px-4 { padding-left: 1rem; padding-right: 1rem; }
  .py-2 { padding-top: 0.5rem; padding-bottom: 0.5rem; }
  .py-3 { padding-top: 0.75rem; padding-bottom: 0.75rem; }
  .py-6 { padding-top: 1.5rem; padding-bottom: 1.5rem; }
  .pt-3 { padding-top: 0.75rem; }
  .mt-1 { margin-top: 0.25rem; }
  .mt-2 { margin-top: 0.5rem; }
  .mt-3 { margin-top: 0.75rem; }
  .mt-4 { margin-top: 1rem; }
  .mb-1 { margin-bottom: 0.25rem; }
  .mb-2 { margin-bottom: 0.5rem; }
  .mb-3 { margin-bottom: 0.75rem; }
  .mx-4 { margin-left: 1rem; margin-right: 1rem; }
  .mr-2 { margin-right: 0.5rem; }

  @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
  @keyframes fadeUp {
    from { opacity: 0.4; transform: translateY(6px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  @keyframes fadeIn { from { opacity: 0.4; } to { opacity: 1; } }
  @keyframes shimmer {
    0%   { background-position: -200% 0; }
    100% { background-position: 200% 0; }
  }
  @keyframes pulseDot {
    0%   { box-shadow: 0 0 0 0 rgba(46,242,194,0.55); }
    70%  { box-shadow: 0 0 0 7px rgba(46,242,194,0); }
    100% { box-shadow: 0 0 0 0 rgba(46,242,194,0); }
  }
  @keyframes floaty {
    0%, 100% { transform: translateY(0); }
    50%      { transform: translateY(-6px); }
  }
  @keyframes orbit { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
  @keyframes drift {
    from { transform: translate3d(-7%, -5%, 0) rotate(0deg) scale(1); }
    to   { transform: translate3d(7%, 5%, 0) rotate(10deg) scale(1.08); }
  }

  .animate-spin { animation: spin 1s linear infinite; }
  .screen-enter { animation: fadeUp 0.22s ease both; }
  .fade-in { animation: fadeIn 0.3s ease both; }

  .skeleton {
    background: linear-gradient(90deg, var(--bg-2) 25%, var(--bg-3) 50%, var(--bg-2) 75%);
    background-size: 200% 100%;
    animation: shimmer 1.4s infinite;
    border-radius: 8px;
  }

  .card {
    background: var(--bg-2);
    border: 1px solid var(--line);
    border-radius: 16px;
    padding: 14px;
  }
  .card-hover { transition: border-color 0.15s, transform 0.15s, background 0.15s; }
  .card-hover:hover { border-color: var(--accent-line); background: var(--bg-3); }

  .hero-card {
    position: relative;
    isolation: isolate;
    overflow: hidden;
    border-radius: 22px;
    padding: 18px 16px 16px;
    text-align: center;
    background: var(--hero-bg);
    border: 1px solid var(--hero-line);
    box-shadow: 0 22px 44px -28px var(--accent-glow);
  }
  .hero-card::before {
    content: '';
    position: absolute;
    inset: -45%;
    z-index: -2;
    background:
      radial-gradient(32% 28% at 28% 30%, var(--glow-a), transparent 72%),
      radial-gradient(36% 32% at 76% 72%, var(--glow-b), transparent 72%);
    animation: drift 16s ease-in-out infinite alternate;
  }
  .hero-card::after {
    content: '';
    position: absolute;
    inset: 0;
    z-index: -1;
    background-image: var(--cube);
    background-size: 28px 48px;
    opacity: var(--cube-opacity);
    -webkit-mask-image: radial-gradient(120% 90% at 50% 0%, #000 30%, transparent 85%);
    mask-image: radial-gradient(120% 90% at 50% 0%, #000 30%, transparent 85%);
  }
  .hero-head { display: flex; align-items: center; justify-content: center; gap: 8px; margin-bottom: 6px; }
  .hero-label {
    font-family: var(--font-display); font-weight: 700; font-size: 0.68rem;
    letter-spacing: 0.14em; text-transform: uppercase; color: var(--txt-2);
  }
  .block-pill {
    display: inline-flex; align-items: center; gap: 6px;
    font-family: var(--font-display); font-weight: 700; font-size: 0.64rem; letter-spacing: 0.04em;
    padding: 3px 8px; border-radius: 999px;
    color: var(--brand-text); background: var(--mint-tint); border: 1px solid var(--mint-line);
    font-variant-numeric: tabular-nums;
  }
  .live-dot { width: 6px; height: 6px; border-radius: 50%; background: var(--green); animation: pulseDot 2s ease-out infinite; }
  .hero-amount {
    font-family: var(--font-display); font-weight: 800; font-size: 1.9rem; line-height: 2.3rem;
    letter-spacing: -0.03em; color: var(--txt); font-variant-numeric: tabular-nums;
  }
  .hero-amount-md { font-size: 1.6rem; line-height: 2rem; }
  .hero-amount-sm { font-size: 1.3rem; line-height: 1.7rem; }
  .hero-number { white-space: nowrap; }
  .hero-unit {
    white-space: nowrap;
    font-size: 0.9rem; font-weight: 800; letter-spacing: 0.04em; margin-left: 7px;
    background: var(--grad); -webkit-background-clip: text; background-clip: text; -webkit-text-fill-color: transparent;
  }
  .hero-sub { font-size: 0.74rem; color: var(--txt-3); margin-top: 2px; font-variant-numeric: tabular-nums; }
  .qa-row { display: flex; gap: 4px; margin-top: 16px; }

  .btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 6px;
    font-family: var(--font-display);
    font-weight: 700;
    font-size: 0.86rem;
    letter-spacing: 0.01em;
    border-radius: 14px;
    border: none;
    cursor: pointer;
    padding: 12px 16px;
    transition: transform 0.12s, box-shadow 0.15s, background 0.15s, opacity 0.15s, border-color 0.15s, color 0.15s;
    user-select: none;
  }
  .btn:active:not(:disabled) { transform: scale(0.97); }
  .btn:disabled { opacity: 0.45; cursor: not-allowed; }
  .btn-primary:disabled {
    opacity: 1; background: var(--bg-3); color: var(--txt-4);
    box-shadow: none; border: 1px solid var(--line);
  }
  .btn:focus-visible, .icon-btn:focus-visible, .qa-btn:focus-visible, .nav-btn:focus-visible, .link-btn:focus-visible {
    outline: 2px solid var(--accent-text); outline-offset: 2px;
  }

  .btn-primary {
    background: var(--accent-fill);
    color: var(--accent-ink);
    box-shadow: 0 12px 26px -16px var(--accent-glow), inset 0 -2px 0 rgba(0,0,0,0.12);
  }
  .btn-primary:hover:not(:disabled) { background: var(--accent-hover); box-shadow: 0 14px 30px -14px var(--accent-glow), inset 0 -2px 0 rgba(0,0,0,0.12); }

  .btn-secondary {
    background: var(--bg-3);
    color: var(--txt);
    border: 1px solid var(--line-2);
  }
  .btn-secondary:hover:not(:disabled) { border-color: var(--mint-line); color: var(--txt); }

  .btn-danger {
    background: var(--neg-tint);
    color: var(--red);
    border: 1px solid color-mix(in srgb, var(--red) 45%, transparent);
  }
  .btn-danger:hover:not(:disabled) { background: color-mix(in srgb, var(--red) 20%, transparent); }

  .btn-ghost { background: transparent; color: var(--txt-2); padding: 8px 12px; }
  .btn-ghost:hover:not(:disabled) { color: var(--txt); background: var(--bg-3); }

  .icon-btn {
    display: flex; align-items: center; justify-content: center;
    width: 34px; height: 34px;
    border-radius: 11px;
    background: transparent;
    border: none;
    color: var(--txt-2);
    cursor: pointer;
    transition: background 0.15s, color 0.15s;
  }
  .icon-btn:hover { background: var(--bg-3); color: var(--txt); }

  .qa-btn {
    --qa: var(--qa-send);
    display: flex; flex-direction: column; align-items: center; gap: 7px;
    background: transparent; border: none; cursor: pointer;
    color: var(--txt-1); font-family: var(--font-display); font-size: 0.7rem; font-weight: 700;
    letter-spacing: 0.02em;
    flex: 1;
  }
  .qa-send     { --qa: var(--qa-send); }
  .qa-receive  { --qa: var(--qa-receive); }
  .qa-shield   { --qa: var(--qa-shield); }
  .qa-activity { --qa: var(--qa-activity); }
  .qa-circle {
    width: 48px; height: 48px;
    border-radius: 16px;
    display: flex; align-items: center; justify-content: center;
    color: var(--qa);
    background: color-mix(in srgb, var(--qa) 15%, transparent);
    border: 1px solid color-mix(in srgb, var(--qa) 40%, transparent);
    transition: transform 0.15s, box-shadow 0.2s, background 0.15s;
  }
  .qa-btn:hover .qa-circle {
    transform: translateY(-2px);
    background: color-mix(in srgb, var(--qa) 26%, transparent);
    box-shadow: 0 10px 22px -12px var(--qa);
  }
  .qa-btn:disabled { opacity: 0.6; cursor: wait; }
  .qa-circle svg { width: 20px; height: 20px; }

  .ego-label {
    display: block;
    font-family: var(--font-display);
    font-size: 0.68rem;
    font-weight: 700;
    letter-spacing: 0.1em;
    text-transform: uppercase;
    color: var(--txt-3);
    margin-bottom: 6px;
  }
  .ego-input {
    width: 100%;
    border-radius: 13px;
    background: var(--bg-2);
    border: 1px solid var(--line-2);
    color: var(--txt);
    padding: 12px 13px;
    font-size: 0.9rem;
    font-family: var(--font-body);
    outline: none;
    transition: border-color 0.15s, box-shadow 0.15s;
  }
  .ego-input::placeholder { color: var(--txt-4); }
  .ego-input:focus {
    border-color: var(--accent-line);
    box-shadow: 0 0 0 3px var(--accent-tint);
  }

  .topbar {
    display: flex; align-items: center; gap: 10px;
    padding: 12px 14px 12px 16px;
    background: var(--topbar-bg);
    backdrop-filter: blur(12px);
    border-bottom: 1px solid var(--line);
    min-height: 56px;
  }
  .topbar-title {
    font-family: var(--font-display); font-weight: 800; font-size: 1.02rem;
    letter-spacing: -0.01em; color: var(--txt);
  }
  .grad-text {
    background: var(--grad);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
  }
  .net-pill {
    display: inline-flex; align-items: center; gap: 6px;
    font-family: var(--font-display);
    font-size: 0.66rem; font-weight: 700; letter-spacing: 0.04em;
    padding: 5px 10px;
    border-radius: 999px;
    border: 1px solid var(--line-2);
    background: var(--bg-2);
    color: var(--txt-1);
    white-space: nowrap;
  }
  .net-dot { width: 7px; height: 7px; border-radius: 50%; }

  .tx-row {
    display: flex; align-items: center; gap: 11px;
    padding: 11px 12px;
    border-radius: 14px;
    background: var(--bg-2);
    border: 1px solid var(--line);
    transition: border-color 0.15s, background 0.15s;
  }
  .tx-row:hover { border-color: var(--line-2); background: var(--bg-3); }
  .tx-icon {
    width: 36px; height: 36px; border-radius: 12px;
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0;
  }
  .tx-in  { background: var(--pos-tint); color: var(--green); }
  .tx-out { background: var(--neg-tint); color: var(--red); }
  .tx-shield { background: color-mix(in srgb, var(--amber) 14%, transparent); color: var(--amber); }
  .tx-pending {
    font-family: var(--font-display); font-size: 0.6rem; font-weight: 800; letter-spacing: 0.06em; text-transform: uppercase;
    padding: 2px 6px; border-radius: 999px; color: var(--amber);
    background: color-mix(in srgb, var(--amber) 14%, transparent);
  }
  .tx-icon svg { width: 16px; height: 16px; }

  .word-badge {
    display: inline-flex;
    align-items: center;
    background: var(--accent-tint);
    border: 1px solid var(--accent-line);
    border-radius: 9px;
    padding: 6px 8px;
    font-size: 0.78rem;
    font-family: var(--font-mono);
    color: var(--txt);
  }
  .word-badge span.num { color: var(--txt-3); margin-right: 6px; font-size: 0.66rem; }

  .logo-glow { filter: drop-shadow(0 0 14px var(--accent-glow)); }
  .logo-orbit {
    position: absolute; inset: -10px;
    border-radius: 50%;
    background: conic-gradient(from 0deg, transparent 10%, #d2eb2b 32%, #00e5b0 58%, transparent 88%);
    animation: orbit 4s linear infinite;
    opacity: 0.85;
    -webkit-mask: radial-gradient(farthest-side, transparent calc(100% - 3px), #000 calc(100% - 2px));
    mask: radial-gradient(farthest-side, transparent calc(100% - 3px), #000 calc(100% - 2px));
  }
  .float { animation: floaty 4.5s ease-in-out infinite; }
  .splash-glow {
    background:
      radial-gradient(70% 45% at 30% 0%, var(--glow-a) 0%, transparent 70%),
      radial-gradient(60% 40% at 85% 15%, var(--glow-b) 0%, transparent 70%);
  }

  .navbar {
    display: flex;
    background: var(--bg-1);
    border-top: 1px solid var(--line);
    padding: 5px 6px 7px;
  }
  .nav-btn {
    flex: 1;
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    gap: 3px;
    padding: 8px 2px 6px;
    cursor: pointer;
    border: none;
    background: transparent;
    color: var(--txt-3);
    font-family: var(--font-display);
    font-size: 0.64rem;
    font-weight: 700;
    letter-spacing: 0.02em;
    border-radius: 12px;
    transition: color 0.15s, background 0.15s;
    position: relative;
  }
  .nav-btn:hover { color: var(--txt-1); }
  .nav-btn.active { color: var(--accent-text); background: var(--accent-tint); }
  .nav-btn.active::after {
    content: '';
    position: absolute; top: -5px; left: 50%; transform: translateX(-50%);
    width: 22px; height: 3px; border-radius: 0 0 3px 3px;
    background: var(--grad);
  }
  .nav-btn svg { width: 20px; height: 20px; }

  .toast {
    position: fixed;
    bottom: 76px; left: 50%; transform: translateX(-50%);
    background: var(--bg-3);
    border: 1px solid var(--accent-line);
    color: var(--txt);
    font-size: 0.8rem;
    font-weight: 700;
    border-radius: 999px;
    padding: 9px 16px;
    box-shadow: 0 12px 30px -12px rgba(0,0,0,0.7);
    animation: fadeUp 0.2s ease both;
    z-index: 9999;
    white-space: nowrap;
  }

  ::-webkit-scrollbar { width: 5px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--scroll); border-radius: 3px; }

  .divider { height: 1px; background: var(--line); border: none; }

  .alert {
    border-radius: 13px;
    padding: 11px 13px;
    font-size: 0.82rem;
    line-height: 1.5;
    animation: fadeUp 0.18s ease both;
  }
  .alert-error   { background: var(--neg-tint);  border: 1px solid color-mix(in srgb, var(--red) 45%, transparent);   color: var(--alert-error-txt); }
  .alert-success { background: var(--pos-tint);  border: 1px solid color-mix(in srgb, var(--green) 45%, transparent); color: var(--alert-success-txt); }
  .alert-info    { background: color-mix(in srgb, var(--sky) 12%, transparent); border: 1px solid color-mix(in srgb, var(--sky) 40%, transparent); color: var(--alert-info-txt); }
  .alert-warn    { background: color-mix(in srgb, var(--amber) 12%, transparent); border: 1px solid color-mix(in srgb, var(--amber) 42%, transparent); color: var(--alert-warn-txt); }

  .checkbox-row {
    display: flex; align-items: flex-start; gap: 10px;
    cursor: pointer;
    padding: 12px 13px;
    border-radius: 13px;
    background: var(--bg-2);
    border: 1px solid var(--line);
    transition: border-color 0.15s;
  }
  .checkbox-row:hover { border-color: var(--accent-line); }
  .checkbox-row input { accent-color: var(--accent-fill); }

  .section-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
  .section-label {
    font-family: var(--font-display); font-weight: 700; font-size: 0.7rem;
    letter-spacing: 0.12em; text-transform: uppercase; color: var(--txt-2);
  }
  .text-link { color: var(--brand-text); font-weight: 700; }

  .stat-grid { display: grid; grid-template-columns: repeat(3, 1fr); gap: 8px; }
  .stat-tile { background: var(--bg-2); border: 1px solid var(--line); border-radius: 13px; padding: 9px 10px; min-width: 0; }
  .stat-tile .k { font-family: var(--font-display); font-size: 0.6rem; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; color: var(--txt-3); }
  .stat-tile .v { font-family: var(--font-display); font-size: 0.98rem; font-weight: 800; margin-top: 2px; font-variant-numeric: tabular-nums; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; color: var(--txt); }
  .stat-tile .u { font-size: 0.6rem; font-weight: 700; color: var(--txt-3); margin-left: 3px; }
  .segmented { display: flex; gap: 4px; padding: 3px; background: var(--bg-2); border: 1px solid var(--line); border-radius: 13px; }
  .segmented button {
    flex: 1; border: none; background: transparent; color: var(--txt-2);
    font-family: var(--font-display); font-size: 0.78rem; font-weight: 700;
    padding: 8px; border-radius: 10px; cursor: pointer;
    transition: background 0.15s, color 0.15s;
  }
  .segmented button.on { background: var(--accent-fill); color: var(--accent-ink); }
  .segmented button:focus-visible, .chip-btn:focus-visible, .shielded-line:focus-visible { outline: 2px solid var(--accent-text); outline-offset: 1px; }
  .preview-pill {
    font-family: var(--font-display);
    font-size: 0.58rem; font-weight: 800; letter-spacing: 0.08em; text-transform: uppercase;
    padding: 3px 8px; border-radius: 999px; white-space: nowrap;
    background: color-mix(in srgb, var(--amber) 16%, transparent); color: var(--amber);
    border: 1px solid color-mix(in srgb, var(--amber) 40%, transparent);
  }
  .note-list { border: 1px solid var(--line); border-radius: 13px; overflow: hidden; }
  .note-row { display: flex; align-items: center; gap: 8px; padding: 10px 11px; font-size: 0.76rem; background: var(--bg-2); }
  .note-row + .note-row { border-top: 1px solid var(--line); }
  .note-amt { font-family: var(--font-display); font-weight: 800; font-variant-numeric: tabular-nums; white-space: nowrap; color: var(--txt); }
  .note-state { flex: 1; min-width: 0; color: var(--txt-2); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .note-date { color: var(--txt-3); font-size: 0.68rem; white-space: nowrap; }
  .dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
  .chip-btn {
    font-family: var(--font-display); font-size: 0.66rem; font-weight: 700;
    padding: 4px 9px; border-radius: 8px; cursor: pointer;
    border: 1px solid var(--line-2); background: transparent; color: var(--txt-1);
  }
  .chip-btn:hover:not(:disabled) { color: var(--txt); border-color: var(--accent-line); background: var(--accent-tint); }
  .chip-btn:disabled { opacity: 0.45; cursor: not-allowed; }
  .hint { font-size: 0.76rem; line-height: 1.5; color: var(--txt-2); }
  .hint-warn { color: var(--amber); }
  .shielded-line {
    position: relative; display: inline-flex; align-items: center; gap: 6px;
    margin-top: 10px; padding: 4px 10px; border-radius: 999px; cursor: pointer;
    font-family: var(--font-display); font-size: 0.7rem; font-weight: 700;
    background: color-mix(in srgb, var(--amber) 14%, transparent);
    border: 1px solid color-mix(in srgb, var(--amber) 40%, transparent);
    color: var(--amber);
  }

  @media (prefers-reduced-motion: reduce) {
    .hero-card::before, .live-dot, .net-dot, .logo-orbit, .float, .skeleton, .screen-enter, .fade-in, .toast, .alert { animation: none; }
  }
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
  | 'dappRequest'
  | 'activity'
  | 'addAsset'
  | 'sendAsset'
  | 'shield';

interface AppState {
  screen: Screen;
  address: string;
  balance: number;
  balanceUegoc: number;
  network: 'testnet' | 'mainnet';
  loading: boolean;
  error: string;
  pendingRequest: PendingRequest | null;
  nodeStatus: string;
  blockHeight: number;
  recentTxs: Array<{ hash: string; from?: string; to?: string; amount_egoc?: number; timestamp?: number; type?: string; pending?: boolean }>;
}

type Action =
  | { type: 'SET_SCREEN'; screen: Screen }
  | { type: 'SET_WALLET'; address: string; network: 'testnet' | 'mainnet' }
  | { type: 'SET_BALANCE'; balance: number; balanceUegoc: number }
  | { type: 'SET_LOADING'; loading: boolean }
  | { type: 'SET_ERROR'; error: string }
  | { type: 'SET_NODE'; status: string; blockHeight: number }
  | { type: 'SET_TXS'; txs: AppState['recentTxs'] }
  | { type: 'SET_PENDING_REQ'; request: PendingRequest | null };

function reducer(state: AppState, action: Action): AppState {
  switch (action.type) {
    case 'SET_SCREEN': return { ...state, screen: action.screen, error: '' };
    case 'SET_WALLET': return { ...state, address: action.address, network: action.network };
    case 'SET_BALANCE': return { ...state, balance: action.balance, balanceUegoc: action.balanceUegoc };
    case 'SET_LOADING': return { ...state, loading: action.loading };
    case 'SET_ERROR': return { ...state, error: action.error };
    case 'SET_NODE': return { ...state, nodeStatus: action.status, blockHeight: action.blockHeight };
    case 'SET_TXS': return { ...state, recentTxs: action.txs };
    case 'SET_PENDING_REQ': return { ...state, pendingRequest: action.request };
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
  pendingRequest: null,
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
  Shield: () => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2} style={{ width: 14, height: 14 }}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
    </svg>
  ),
  ShieldLg: () => (
    <svg fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
      <path strokeLinecap="round" strokeLinejoin="round" d="M12 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016A11.955 11.955 0 0112 2.944z" />
      <path strokeLinecap="round" strokeLinejoin="round" d="M9.5 11.5V10a2.5 2.5 0 015 0v1.5m-6 0h7v4h-7z" />
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
        boxShadow: '0 0 0 1px var(--qr-ring), 0 14px 40px -16px var(--accent-glow)',
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
      <span className="topbar-title flex-1">{title}</span>
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
        className="flex-1 flex flex-col items-center justify-center p-6 gap-5 splash-glow"
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
          <span>Non-custodial · Ed25519 · AES-256-GCM</span>
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
            style={{ marginTop: 2, accentColor: 'var(--accent-fill)' }}
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
  const strengthColor = ['var(--red)', 'var(--amber)', 'var(--accent-text)', 'var(--green)'][strength];

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
        className="flex-1 flex flex-col items-center justify-center p-6 gap-5 splash-glow"
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

function txLabel(type: string | undefined, isOut: boolean): string {
  switch (type) {
    case 'faucet': return 'Testnet faucet';
    case 'shield': return 'Shielded';
    case 'unshield': return isOut ? 'Private send' : 'Private payout';
    case 'stake': return 'Staked';
    case 'unstake': return 'Unstaked';
    case 'call': return 'Contract call';
    case 'deploy': return 'Contract deployed';
    default: return isOut ? 'Sent' : 'Received';
  }
}

function TxRow({ tx, address }: { tx: AppState['recentTxs'][number]; address: string }) {
  const isOut = !!tx.from && tx.from === address;
  const isShield = tx.type === 'shield';
  return (
    <div className="tx-row">
      <div className={cls('tx-icon', isShield ? 'tx-shield' : isOut ? 'tx-out' : 'tx-in')}>
        {isShield ? <Icons.ShieldLg /> : isOut ? <Icons.Send /> : <Icons.Receive />}
      </div>
      <div className="flex-1 min-h-0" style={{ minWidth: 0 }}>
        <p className="text-sm font-semibold">{txLabel(tx.type, isOut)}</p>
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
        {tx.pending
          ? <span className="tx-pending">Pending</span>
          : <p className="text-xs text-gray-600">{tx.timestamp ? timeAgo(tx.timestamp) : 'EGOC'}</p>}
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
          style={{ width: 26, height: 26, color: 'var(--brand-text)' }}
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

interface ShieldedStatusView {
  enabled: boolean;
  active: boolean;
  pool_address: string;
  pool_balance_uegoc: number;
  leaf_count: number;
  denominations_uegoc: number[];
  min_fee_uegoc: number;
  current_fee_uegoc: number;
  deposit_fee_uegoc: number;
  spendable_uegoc: number;
  max_spends: number;
  proof_system: string;
  behind: boolean;
  notes: NoteView[];
  ready_balance_uegoc: number;
  pending_balance_uegoc: number;
}

function egoc(uegoc: number): string {
  return (uegoc / 1_000_000).toLocaleString(undefined, { maximumFractionDigits: 6 });
}

function parseEgoc(input: string): number | null {
  const t = input.trim();
  if (!/^\d+(\.\d{0,6})?$/.test(t)) return null;
  const [whole, frac = ''] = t.split('.');
  const v = Number(whole) * 1_000_000 + Number((frac + '000000').slice(0, 6));
  return Number.isSafeInteger(v) && v > 0 ? v : null;
}

const NOTE_STATE: Record<NoteStatus, { label: string; color: string }> = {
  pending:   { label: 'Confirming · waiting for a block', color: 'var(--amber)' },
  ready:     { label: 'In the pool', color: 'var(--green)' },
  spending:  { label: 'Sending…', color: 'var(--amber)' },
  settling:  { label: 'Sent · waiting for the network to agree', color: 'var(--amber)' },
  spent:     { label: 'Sent from the pool', color: 'var(--txt-3)' },
  cancelled: { label: 'Cancelled · stayed in your balance', color: 'var(--txt-3)' },
  returned:  { label: 'Never reached a block · returned', color: 'var(--txt-3)' },
};

function ShieldScreen({ onBack }: { onBack: () => void }) {
  const [st, setSt] = useState<ShieldedStatusView | null>(null);
  const [loadError, setLoadError] = useState('');
  const [tab, setTab] = useState<'shield' | 'send'>('shield');
  const [amount, setAmount] = useState('');
  const [sendAmount, setSendAmount] = useState('');
  const [recipient, setRecipient] = useState('');
  const [busy, setBusy] = useState('');
  const [msg, setMsg] = useState<{ kind: 'success' | 'error' | 'info'; text: string } | null>(null);
  const inFlight = useRef(false);

  const refresh = useCallback(async () => {
    if (inFlight.current) return;
    inFlight.current = true;
    const r = await sendMsg<ShieldedStatusView>('EGO_SHIELDED_STATUS');
    inFlight.current = false;
    if (r.success && r.data) {
      setSt(r.data);
      setLoadError('');
    } else {
      setLoadError(r.error ?? 'Could not reach your Ego node.');
    }
  }, []);

  useEffect(() => {
    refresh();
    const id = setInterval(refresh, 4_000);
    return () => clearInterval(id);
  }, [refresh]);

  async function run<T>(
    key: string,
    type: ExtMessage['type'],
    payload: Record<string, unknown>,
    done: (d: T) => string,
  ): Promise<boolean> {
    setBusy(key);
    setMsg(null);
    const r = await sendMsg<T>(type, payload);
    setBusy('');
    if (r.success) setMsg({ kind: 'success', text: done(r.data as T) });
    else setMsg({ kind: 'error', text: r.error ?? 'Something went wrong.' });
    refresh();
    return r.success;
  }

  const notes = st?.notes ?? [];
  const ready = notes.filter(n => n.status === 'ready');
  const open = !!st && st.enabled && st.active;
  const depositFee = st?.deposit_fee_uegoc ?? 0;
  const withdrawFee = st?.current_fee_uegoc ?? 0;

  const shieldUegoc = parseEgoc(amount);
  const split = shieldUegoc ? denominate(shieldUegoc) : { notes: [] as number[], remainder: 0 };
  const shieldCost = split.notes.reduce((a, v) => a + v, 0) + depositFee * split.notes.length;

  const sendUegoc = parseEgoc(sendAmount);
  const picked = sendUegoc ? pickNotesFor(sendUegoc, ready) : null;
  const reachable = sendUegoc ? pickNotesFor(sendUegoc, ready, Number.POSITIVE_INFINITY) : null;
  const readySizes = [...new Set(ready.map(n => n.value_uegoc))].sort((a, b) => a - b).map(egoc).join(', ');
  const recipientOk = /^egot1[02-9ac-hj-np-z]{20,}$/.test(recipient.trim());

  const live = notes.filter(n => n.status !== 'spent');
  const spent = notes.filter(n => n.status === 'spent');

  function shieldHint(): React.ReactNode {
    if (!amount.trim()) {
      return `Notes come in fixed sizes of ${DENOMINATIONS_UEGOC.map(egoc).join(', ')} EGOC so amounts cannot identify them. Each note costs a ${egoc(depositFee)} EGOC fee.`;
    }
    if (!shieldUegoc) return <span className="hint-warn">Enter an amount in EGOC, up to 6 decimals.</span>;
    if (split.notes.length === 0) return <span className="hint-warn">Below the smallest note (1 EGOC).</span>;
    return (
      <>
        {split.notes.length} note{split.notes.length === 1 ? '' : 's'}: {split.notes.map(egoc).join(' + ')} EGOC.
        {split.remainder > 0 && <> {egoc(split.remainder)} EGOC stays in your balance.</>}
        {' '}Fees {split.notes.length} × {egoc(depositFee)} EGOC.
        {st && shieldCost > st.spendable_uegoc && (
          <span className="hint-warn"> You have {egoc(st.spendable_uegoc)} EGOC free.</span>
        )}
      </>
    );
  }

  function sendHint(): React.ReactNode {
    if (!sendAmount.trim()) {
      return `The ${egoc(withdrawFee)} EGOC fee comes out of the amount, so the recipient gets that much less.`;
    }
    if (!sendUegoc) return <span className="hint-warn">Enter an amount in EGOC, up to 6 decimals.</span>;
    if (!reachable) {
      return (
        <span className="hint-warn">
          That amount cannot be made from your notes. Shielded coins move in fixed sizes
          {readySizes ? ` of ${readySizes} EGOC` : ''}, so pick a total you can build from them.
        </span>
      );
    }
    if (!picked) return <span className="hint-warn">That needs more than {MAX_SPENDS} notes. Send it in two parts.</span>;
    if (sendUegoc <= withdrawFee) return <span className="hint-warn">The amount must be larger than the fee.</span>;
    return `The recipient gets ${egoc(sendUegoc - withdrawFee)} EGOC after the ${egoc(withdrawFee)} EGOC fee. Proving takes a few seconds per note.`;
  }

  function rowAction(n: NoteView): React.ReactNode {
    if (n.status === 'pending' && n.deposit_tx) {
      return (
        <button
          className="chip-btn"
          disabled={!!busy}
          title="Take this deposit back before it reaches the pool"
          onClick={() => run<number>('row:' + n.commitment, 'EGO_SHIELD_CANCEL_DEPOSIT', { commitment: n.commitment },
            v => `Deposit cancelled. ${egoc(v)} EGOC stays in your balance.`)}
        >
          Cancel
        </button>
      );
    }
    if (n.status === 'spending' && n.spent_tx) {
      return (
        <button
          className="chip-btn"
          disabled={!!busy}
          title="Stop waiting on this send and make the note spendable again"
          onClick={() => run<number>('row:' + n.commitment, 'EGO_SHIELD_CANCEL_WITHDRAWAL', { spent_tx: n.spent_tx },
            k => `Send cancelled. ${k} note${k === 1 ? ' is' : 's are'} spendable again.`)}
        >
          Cancel
        </button>
      );
    }
    if (n.status === 'spent') {
      return (
        <button
          className="chip-btn"
          disabled={!!busy}
          title="Remove from this wallet's history"
          aria-label="Remove from history"
          onClick={() => run<void>('row:' + n.commitment, 'EGO_SHIELD_FORGET', { commitment: n.commitment }, () => 'Removed from this wallet.')}
        >
          ×
        </button>
      );
    }
    return null;
  }

  return (
    <div className="flex flex-col h-full screen-enter">
      <Header title="Shielded Pool" onBack={onBack} />
      <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-3">
        {!st && !loadError && (
          <div className="flex items-center justify-center py-6 text-blue-400"><Icons.Spinner /></div>
        )}
        {loadError && (
          <div className="alert alert-error">
            {loadError}
            <button className="link-btn" style={{ margin: '6px 0 0', color: 'inherit' }} onClick={refresh}>Try again</button>
          </div>
        )}
        {st && (
          <>
            <div className="flex items-center gap-2">
              <span className="preview-pill">Testnet preview</span>
              <span className="text-xs text-gray-500">{st.leaf_count.toLocaleString()} notes deposited so far</span>
            </div>

            <div className="stat-grid">
              <div className="stat-tile">
                <div className="k">Ready</div>
                <div className="v">{egoc(st.ready_balance_uegoc)}<span className="u">EGOC</span></div>
              </div>
              <div className="stat-tile">
                <div className="k">Confirming</div>
                <div className="v">{egoc(st.pending_balance_uegoc)}<span className="u">EGOC</span></div>
              </div>
              <div className="stat-tile">
                <div className="k">Whole pool</div>
                <div className="v">{egoc(st.pool_balance_uegoc)}<span className="u">EGOC</span></div>
              </div>
            </div>

            {!open && (
              <div className="alert alert-warn">
                {!st.enabled
                  ? 'Your node has shielded transactions switched off.'
                  : 'This chain has not activated the shielded pool yet.'}
              </div>
            )}
            {st.behind && (
              <div className="alert alert-info">Your node is still catching up with the network. Statuses settle once it has.</div>
            )}
            {msg && <div className={`alert alert-${msg.kind}`}>{msg.text}</div>}

            <div className="segmented" role="tablist" aria-label="Shielded actions">
              <button id="shield-tab-in" role="tab" aria-selected={tab === 'shield'} className={tab === 'shield' ? 'on' : ''} onClick={() => setTab('shield')}>
                Shield
              </button>
              <button id="shield-tab-out" role="tab" aria-selected={tab === 'send'} className={tab === 'send' ? 'on' : ''} onClick={() => setTab('send')}>
                Send privately
              </button>
            </div>

            {tab === 'shield' ? (
              <div className="card flex flex-col gap-3">
                <Input label="Amount to shield (EGOC)" value={amount} onChange={setAmount} placeholder="e.g. 25" />
                <p className="hint">{shieldHint()}</p>
                <Button
                  disabled={!open || !!busy || split.notes.length === 0}
                  onClick={async () => {
                    const ok = await run<{ notes: number[]; shielded_uegoc: number }>(
                      'shield', 'EGO_SHIELD_DEPOSIT', { amount_uegoc: shieldUegoc },
                      d => `Shielded ${egoc(d.shielded_uegoc)} EGOC as ${d.notes.length} note${d.notes.length === 1 ? '' : 's'}. They become spendable once their deposits are in a block.`,
                    );
                    if (ok) setAmount('');
                  }}
                >
                  {busy === 'shield' ? 'Shielding…' : 'Shield'}
                </Button>
              </div>
            ) : (
              <div className="card flex flex-col gap-3">
                <div className="flex items-center justify-between">
                  <span className="ego-label" style={{ marginBottom: 0 }}>Available to send</span>
                  <span className="text-sm font-bold">{egoc(st.ready_balance_uegoc)} EGOC</span>
                </div>
                <Input label="Amount (EGOC)" value={sendAmount} onChange={setSendAmount} placeholder="e.g. 10" />
                <Input label="Recipient" value={recipient} onChange={setRecipient} placeholder="egot1…" />
                <p className="hint">{sendHint()}</p>
                <Button
                  disabled={!open || !!busy || !picked || !recipientOk || !sendUegoc || sendUegoc <= withdrawFee}
                  onClick={async () => {
                    if (!picked) return;
                    const ok = await run<{ payout_uegoc: number; recipient: string }>(
                      'send', 'EGO_SHIELD_WITHDRAW', { commitments: picked, recipient: recipient.trim() },
                      d => `Sending ${egoc(d.payout_uegoc)} EGOC to ${shortAddress(d.recipient)}. It lands with the next block.`,
                    );
                    if (ok) setSendAmount('');
                  }}
                >
                  {busy === 'send' ? 'Proving…' : 'Prove & send'}
                </Button>
              </div>
            )}

            {notes.length > 0 && (
              <div className="flex flex-col gap-2">
                <div className="flex items-center justify-between">
                  <p className="section-label">Shielded history</p>
                  {spent.length > 1 && (
                    <button
                      className="chip-btn"
                      disabled={!!busy}
                      onClick={() => run<number>('forget', 'EGO_SHIELD_FORGET_SPENT', {},
                        k => `Removed ${k} finished entr${k === 1 ? 'y' : 'ies'} from this wallet.`)}
                    >
                      Clear finished
                    </button>
                  )}
                </div>
                <div className="note-list">
                  {[...live, ...spent].map(n => (
                    <div key={n.commitment} className="note-row">
                      <span className="dot" style={{ background: NOTE_STATE[n.status].color }} />
                      <span className="note-amt" style={n.status === 'spent' ? { color: 'var(--txt-3)' } : undefined}>
                        {egoc(n.value_uegoc)}
                      </span>
                      <span className="note-state" title={NOTE_STATE[n.status].label}>
                        {NOTE_STATE[n.status].label}{n.source === 'desktop' ? ' · from Ego Desktop' : ''}
                      </span>
                      <span className="note-date">
                        {new Date(n.created_at * 1000).toLocaleDateString(undefined, { month: 'short', day: 'numeric' })}
                      </span>
                      {busy === 'row:' + n.commitment ? <span className="text-xs text-gray-500">…</span> : rowAction(n)}
                    </div>
                  ))}
                </div>
              </div>
            )}

            <p className="text-xs text-gray-500 leading-relaxed">
              Shielding records your coins in the pool only as a commitment. Sending from the pool pays any
              address with a zero-knowledge proof, and nothing on the chain links the two. Notes this wallet
              holds in Ego Desktop on this computer appear here too, and notes made here or in an updated Ego
              Desktop come back when you import your recovery phrase. The circuit is unaudited, so use it on
              the testnet only.
            </p>
            <button
              className="link-btn"
              disabled={!open || !!busy}
              onClick={() => run<number>('scan', 'EGO_SHIELD_SCAN', {},
                k => (k > 0 ? `Found ${k} note${k === 1 ? '' : 's'} from your recovery phrase.` : 'No other notes from your recovery phrase are in the pool.'))}
            >
              {busy === 'scan' ? 'Scanning…' : 'Scan the pool for notes from your recovery phrase'}
            </button>
          </>
        )}
      </div>
    </div>
  );
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
  const [refreshing, setRefreshing] = useState(false);
  const [assets, setAssets] = useState<TrackedAsset[]>([]);
  const [assetBals, setAssetBals] = useState<Record<string, AssetBalance>>({});
  const [chainAddrs, setChainAddrs] = useState<Record<string, string>>({});
  const [shieldedTotal, setShieldedTotal] = useState(0);
  const balanceText = (Math.floor(state.balanceUegoc / 10_000) / 100)
    .toLocaleString(undefined, { minimumFractionDigits: 2, maximumFractionDigits: 2 });

  useEffect(() => {
    sendMsg<ShieldedStatusView>('EGO_SHIELDED_STATUS').then(r => {
      if (r.success && r.data) setShieldedTotal(r.data.ready_balance_uegoc + r.data.pending_balance_uegoc);
    });
  }, []);

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

  function handleRefresh() {
    setRefreshing(true);
    onRefresh();
    loadAssets();
    setTimeout(() => setRefreshing(false), 700);
  }

  return (
    <div className="flex flex-col h-full min-h-0 screen-enter">
      <div className="flex-1 overflow-y-auto" style={{ paddingBottom: 8 }}>
        <div className="mx-4 mt-4 hero-card">
          <div className="hero-head">
            <p className="hero-label">Total balance</p>
            {state.blockHeight > 0 && (
              <span className="block-pill" title="Latest block on your Ego node">
                <span className="live-dot" />
                Block {state.blockHeight.toLocaleString()}
              </span>
            )}
          </div>
          <p className={cls('hero-amount', balanceText.length > 12 ? 'hero-amount-sm' : balanceText.length > 9 && 'hero-amount-md')}>
            <span className="hero-number">{balanceText}</span>
            <span className="hero-unit">EGOC</span>
          </p>
          <p className="hero-sub">{state.balanceUegoc.toLocaleString()} uEGOC</p>
          {shieldedTotal > 0 && (
            <button className="shielded-line" onClick={() => onNavigate('shield')}>
              <Icons.Shield />
              {egoc(shieldedTotal)} EGOC shielded
            </button>
          )}

          <div className="qa-row">
            <button className="qa-btn qa-send" onClick={() => onNavigate('send')}>
              <span className="qa-circle"><Icons.Send /></span>
              Send
            </button>
            <button className="qa-btn qa-receive" onClick={() => onNavigate('receive')}>
              <span className="qa-circle"><Icons.Receive /></span>
              Receive
            </button>
            <button className="qa-btn qa-shield" onClick={() => onNavigate('shield')}>
              <span className="qa-circle"><Icons.ShieldLg /></span>
              Shield
            </button>
            <button className="qa-btn qa-activity" onClick={() => onNavigate('activity')}>
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
            <p className="section-label">Assets</p>
            <button
              className="btn btn-ghost"
              onClick={() => onNavigate('addAsset')}
              style={{ padding: '3px 9px', fontSize: '0.72rem', color: 'var(--brand-text)' }}
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
              <p className="text-xs text-gray-600 mt-1">Watch balances you hold on other networks</p>
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
            <p className="section-label">Recent Activity</p>
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
              background: 'var(--pos-tint)',
              border: '1px solid color-mix(in srgb, var(--green) 45%, transparent)',
              color: 'var(--green)',
              boxShadow: '0 0 40px -10px var(--green)',
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
        <span className="topbar-title flex-1">Activity</span>
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
                  background: active ? 'var(--accent-tint)' : 'var(--bg-3)',
                  border: `1px solid ${active ? 'var(--accent-line)' : 'var(--line-2)'}`,
                  color: active ? 'var(--accent-text)' : 'var(--txt-2)',
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
                style={{ padding: '2px 8px', fontSize: '0.7rem', color: 'var(--brand-text)', marginBottom: 6 }}
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
              background: 'var(--pos-tint)',
              border: '1px solid color-mix(in srgb, var(--green) 45%, transparent)',
              color: 'var(--green)',
              boxShadow: '0 0 40px -10px var(--green)',
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
        <span className="topbar-title flex-1">Settings</span>
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
                    background: active ? 'var(--accent-tint)' : 'var(--bg-3)',
                    border: `1px solid ${active ? 'var(--accent-line)' : 'var(--line-2)'}`,
                    color: active ? 'var(--accent-text)' : 'var(--txt-2)',
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
              style={{ padding: '3px 8px', fontSize: '0.72rem', color: copied === 'address' ? 'var(--green)' : 'var(--brand-text)' }}
            >
              {copied === 'address' ? '✓ Copied' : 'Copy'}
            </button>
          </div>
          <p className="font-mono text-xs text-gray-400 break-all">{state.address}</p>
        </div>

        <ConnectedSites />

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

        <p className="text-xs text-gray-600 text-center mt-1">Ego Wallet v{chrome.runtime.getManifest().version}</p>
      </div>
    </div>
  );
}

const REQUEST_TEXT: Record<DappRequestKind, { title: string; ask: string; approve: string }> = {
  connect: { title: 'Connection Request', ask: 'wants to connect to your wallet', approve: 'Connect' },
  send:    { title: 'Payment Request',    ask: 'asks you to send a payment',      approve: 'Approve & Send' },
  call:    { title: 'Contract Call',      ask: 'asks you to call a contract',     approve: 'Approve Call' },
  sign:    { title: 'Signature Request',  ask: 'asks you to sign a message',      approve: 'Sign' },
};

function clip(text: string, max: number): string {
  return text.length > max ? `${text.slice(0, max)}… (${text.length.toLocaleString()} characters)` : text;
}

function DAppRequestScreen({
  request,
  address,
  network,
  onApprove,
  onReject,
  onDone,
}: {
  request: PendingRequest;
  address: string;
  network: 'testnet' | 'mainnet';
  onApprove: () => Promise<string | null>;
  onReject: () => void;
  onDone: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState('');
  const text = REQUEST_TEXT[request.kind];
  const insecure = request.origin.startsWith('http://');

  async function approve() {
    setBusy(true);
    const error = await onApprove();
    if (error) setFailed(error);
    setBusy(false);
  }

  return (
    <div className="flex flex-col h-full screen-enter">
      <Header title={text.title} />
      <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-3">
        <div className="card">
          <p className="ego-label">Site</p>
          <p className="font-semibold text-blue-400 break-all">{request.origin}</p>
          <p className="text-xs text-gray-400 mt-1">{text.ask}</p>
          {insecure && (
            <p className="text-xs mt-1" style={{ color: 'var(--amber)' }}>
              This site does not use https, so anyone on your network could change what it asks for.
            </p>
          )}
        </div>

        {request.kind === 'connect' && (
          <div className="alert alert-info">
            The site will see your address {shortAddress(address)} and can ask you to approve payments.
            It cannot move anything without your approval here.
          </div>
        )}

        {request.kind === 'send' && (
          <>
            <div className="card">
              <p className="ego-label">Amount</p>
              <p className="text-xl font-bold text-white">{(request.amount_egoc ?? 0).toLocaleString(undefined, { maximumFractionDigits: 6 })} EGOC</p>
              <p className="ego-label mt-3">To</p>
              <p className="font-mono text-xs text-gray-300 break-all">{request.to}</p>
              {request.memo && (
                <>
                  <p className="ego-label mt-3">Memo</p>
                  <p className="font-mono text-xs text-gray-300 break-all">{clip(request.memo, 256)}</p>
                </>
              )}
              <p className="ego-label mt-3">From</p>
              <p className="font-mono text-xs text-gray-400">{shortAddress(address)} · {network === 'testnet' ? 'Testnet' : 'Mainnet'}</p>
            </div>
            <div className="alert alert-warn">Check the address and the amount. A sent payment cannot be reversed.</div>
          </>
        )}

        {request.kind === 'call' && (
          <>
            <div className="card">
              <p className="ego-label">Contract</p>
              <p className="font-mono text-xs text-gray-300 break-all">{request.contractAddr}</p>
              <p className="ego-label mt-3">Function</p>
              <p className="font-mono text-sm text-white">{request.entrypoint}</p>
              <p className="ego-label mt-3">Arguments</p>
              <p className="font-mono text-xs text-gray-400 break-all">{request.callArgs ? clip(request.callArgs, 400) : 'none'}</p>
            </div>
            <div className="alert alert-warn">A contract call can move your coins. Approve only calls you expected from this site.</div>
          </>
        )}

        {request.kind === 'sign' && (
          <>
            <div className="card">
              <p className="ego-label">Message</p>
              {request.messageText !== undefined ? (
                <p className="text-sm text-gray-200" style={{ whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>{clip(request.messageText, 2000)}</p>
              ) : (
                <p className="font-mono text-xs text-gray-400 break-all">0x{clip(request.message ?? '', 600)}</p>
              )}
            </div>
            <div className="alert alert-info">
              Signing proves you own this address. Ego Wallet marks the message as a signed message, so the signature
              cannot be reused as a payment.
            </div>
          </>
        )}

        {failed ? (
          <>
            <div className="alert alert-error">{failed}</div>
            <Button onClick={onDone}>Continue</Button>
          </>
        ) : (
          <div className="flex gap-3 w-full mt-auto">
            <Button variant="secondary" onClick={onReject} disabled={busy}>Reject</Button>
            <Button variant="primary" onClick={approve} disabled={busy}>{busy ? 'Working…' : text.approve}</Button>
          </div>
        )}
      </div>
    </div>
  );
}

function ConnectedSites() {
  const [sites, setSites] = useState<string[] | null>(null);

  const load = useCallback(async () => {
    const resp = await sendMsg<{ sites: string[] }>('EGO_LIST_SITES');
    setSites(resp.success && resp.data ? resp.data.sites : []);
  }, []);

  useEffect(() => { load(); }, [load]);

  async function disconnect(origin: string) {
    await sendMsg('EGO_DISCONNECT_SITE', { origin });
    load();
  }

  return (
    <div className="card">
      <p className="ego-label">Connected Sites</p>
      {sites !== null && sites.length === 0 && (
        <p className="text-xs text-gray-500">No site is connected. A site has to ask, and you approve each payment it requests.</p>
      )}
      {sites !== null && sites.length > 0 && (
        <div className="flex flex-col gap-2 mt-1">
          {sites.map(site => (
            <div key={site} className="flex items-center gap-2">
              <span className="text-xs text-gray-300 break-all flex-1">{site}</span>
              <Button variant="ghost" small fullWidth={false} onClick={() => disconnect(site)}>Disconnect</Button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [state, dispatch] = useReducer(reducer, INIT);

  const [wizardMnemonic, setWizardMnemonic] = useState<string[]>([]);
  const [importInput, setImportInput] = useState('');
  const [wizardMode, setWizardMode] = useState<'create' | 'import'>('create');
  const [sendAssetTarget, setSendAssetTarget] = useState<TrackedAsset | null>(null);

  const screenRef = useRef(state.screen);
  useEffect(() => { screenRef.current = state.screen; }, [state.screen]);

  const loadState = useCallback(async () => {
    const resp = await sendMsg<{
      hasWallet: boolean;
      locked: boolean;
      address?: string;
      publicKeyHex?: string;
      network?: string;
      pendingRequest?: PendingRequest;
    }>('EGO_GET_STATE');

    dispatch({ type: 'SET_LOADING', loading: false });

    if (!resp.success || !resp.data) return;
    const { hasWallet, locked, address, network, pendingRequest } = resp.data;

    dispatch({ type: 'SET_PENDING_REQ', request: pendingRequest ?? null });

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
      if (pendingRequest) {
        dispatch({ type: 'SET_SCREEN', screen: 'dappRequest' });
        return;
      }
      if (IS_APPROVAL_WINDOW) {
        window.close();
        return;
      }
      dispatch({ type: 'SET_SCREEN', screen: 'home' });
      loadBalance(address, (network ?? 'testnet') as 'testnet' | 'mainnet');
      loadTxs();
      loadNodeHealth();
    }
  }, []);

  useEffect(() => { loadState(); }, [loadState]);

  useEffect(() => {
    const timer = setInterval(async () => {
      const screen = screenRef.current;
      if (screen !== 'home' && !(IS_APPROVAL_WINDOW && screen !== 'dappRequest' && screen !== 'unlock')) return;
      const resp = await sendMsg<{ locked: boolean; pendingRequest?: PendingRequest }>('EGO_GET_STATE');
      if (!resp.success || !resp.data || resp.data.locked || !resp.data.pendingRequest) return;
      dispatch({ type: 'SET_PENDING_REQ', request: resp.data.pendingRequest });
      dispatch({ type: 'SET_SCREEN', screen: 'dappRequest' });
    }, 1500);
    return () => clearInterval(timer);
  }, []);

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

  async function nextRequest() {
    dispatch({ type: 'SET_PENDING_REQ', request: null });
    await loadState();
  }

  async function handleApproveRequest(): Promise<string | null> {
    if (!state.pendingRequest) return null;
    const resp = await sendMsg('EGO_APPROVE_REQUEST', { requestId: state.pendingRequest.requestId });
    if (!resp.success) return resp.error ?? 'The request failed.';
    await nextRequest();
    return null;
  }

  async function handleRejectRequest() {
    if (state.pendingRequest) {
      await sendMsg('EGO_REJECT_REQUEST', { requestId: state.pendingRequest.requestId });
    }
    await nextRequest();
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

          {state.screen === 'shield' && (
            <ShieldScreen onBack={() => navigate('home')} />
          )}

          {state.screen === 'settings' && (
            <SettingsScreen
              state={state}
              onLock={handleLock}
              onNetworkChange={handleNetworkChange}
            />
          )}

          {state.screen === 'dappRequest' && state.pendingRequest && (
            <DAppRequestScreen
              key={state.pendingRequest.requestId}
              request={state.pendingRequest}
              address={state.address}
              network={state.network}
              onApprove={handleApproveRequest}
              onReject={handleRejectRequest}
              onDone={nextRequest}
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
