import React, { useState, useEffect, useMemo, useRef } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';
import { fetch as tauriFetch, Body } from '@tauri-apps/api/http';
import { useWallet } from '../App';
import qrcode from 'qrcode-generator';

import { RELAY_HTTP as RELAY, RPC_URL } from '../config';

function makeQR(text: string): string {
  if (!text) return '';
  try {
    const qr = qrcode(0, 'M');
    qr.addData(text);
    qr.make();
    return qr.createDataURL(4, 0);
  } catch {
    return '';
  }
}

// Matches src/commands/wallet.rs Balance struct
interface Balance {
  egoc: number;
  uegoc: number;
  formatted: string;
}

interface RemoteNodeInfo {
  address: string;
  public_key_hex: string;
  peer_id: string;
  payout_address: string | null;
  balance_uegoc: number;
  balance_egoc: number;
  formatted: string;
  block_height: number;
  rpc_url: string;
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
}

interface SendForm {
  to: string;
  amount: string;
  memo: string;
}

interface TxResult {
  hash: string;
  success: boolean;
  message: string;
  block_height?: number;
}

// ── Multi-Chain Types ─────────────────────────────────────────────────────────
interface ExternalAddress {
  chain: string;
  symbol: string;
  address: string;
  network: string;
  address_type: string;
  explorer_prefix: string;
  color: string;
  icon: string;
  contract?: string | null;
}

interface CustomToken {
  id: string;
  symbol: string;
  name: string;
  chain: string;
  chain_symbol: string;
  contract: string | null;
  decimals: number;
  color: string;
  icon: string;
}

interface TokenInfo {
  symbol: string;
  name: string;
  decimals: number;
}

interface BalanceResult {
  raw: string;
  formatted: string;
  usd: number;
}

interface ExternalTx {
  hash: string;
  from: string;
  to: string;
  value: string;
  symbol: string;
  timestamp: number;
  block: number;
  status: string;
  explorer_url: string;
}

// ── Swap Types ────────────────────────────────────────────────────────────────
interface SwapAsset {
  id: string;
  symbol: string;
  name: string;
  icon: string;
  img?: string;
  coingecko_id: string | null;
  is_ego: boolean;
}

const CG = 'https://assets.coingecko.com/coins/images';
const SWAP_ASSETS: SwapAsset[] = [
  { id: 'egoc',  symbol: 'EGOC',  name: 'Ego Coin',       icon: 'E', img: '/egoc.png',                                      coingecko_id: null,          is_ego: true  },
  { id: 'egusd', symbol: 'EGUSD', name: 'Ego Stablecoin', icon: 'E', img: '/egusd.png',                                     coingecko_id: null,          is_ego: true  },
  { id: 'btc',   symbol: 'BTC',   name: 'Bitcoin',        icon: '₿', img: `${CG}/1/small/bitcoin.png`,                      coingecko_id: 'bitcoin',     is_ego: false },
  { id: 'eth',   symbol: 'ETH',   name: 'Ethereum',       icon: 'Ξ', img: `${CG}/279/small/ethereum.png`,                   coingecko_id: 'ethereum',    is_ego: false },
  { id: 'bnb',   symbol: 'BNB',   name: 'BNB',            icon: '◆', img: `${CG}/825/small/bnb-icon2_2x.png`,               coingecko_id: 'binancecoin', is_ego: false },
  { id: 'sol',   symbol: 'SOL',   name: 'Solana',         icon: '◎', img: `${CG}/4128/small/solana.png`,                    coingecko_id: 'solana',      is_ego: false },
  { id: 'xrp',   symbol: 'XRP',   name: 'XRP',            icon: 'X', img: `${CG}/44/small/xrp-symbol-white-128.png`,        coingecko_id: 'ripple',      is_ego: false },
  { id: 'ada',   symbol: 'ADA',   name: 'Cardano',        icon: '₳', img: `${CG}/975/small/cardano.png`,                    coingecko_id: 'cardano',     is_ego: false },
  { id: 'trx',   symbol: 'TRX',   name: 'Tron',           icon: 'T', img: `${CG}/1094/small/tron-logo.png`,                 coingecko_id: 'tron',        is_ego: false },
  { id: 'dot',   symbol: 'DOT',   name: 'Polkadot',       icon: '●', img: `${CG}/12171/small/polkadot.png`,                 coingecko_id: 'polkadot',    is_ego: false },
  { id: 'link',  symbol: 'LINK',  name: 'Chainlink',      icon: '⬡', img: `${CG}/877/small/chainlink-new-logo.png`,         coingecko_id: 'chainlink',   is_ego: false },
  { id: 'shib',  symbol: 'SHIB',  name: 'Shiba Inu',      icon: '🐕',img: `${CG}/11939/small/shiba.png`,                    coingecko_id: 'shiba-inu',   is_ego: false },
  { id: 'usdt',  symbol: 'USDT',  name: 'Tether',         icon: '$', img: `${CG}/325/small/Tether.png`,                     coingecko_id: 'tether',      is_ego: false },
  { id: 'usdc',  symbol: 'USDC',  name: 'USD Coin',       icon: '$', img: `${CG}/6319/small/usd-coin.png`,                  coingecko_id: 'usd-coin',    is_ego: false },
];

const CHAIN_ICONS: Record<string, string> = {
  'Bitcoin':   `${CG}/1/small/bitcoin.png`,
  'Ethereum':  `${CG}/279/small/ethereum.png`,
  'BNB Chain': `${CG}/825/small/bnb-icon2_2x.png`,
  'Solana':    `${CG}/4128/small/solana.png`,
  'XRP':       `${CG}/44/small/xrp-symbol-white-128.png`,
  'Cardano':   `${CG}/975/small/cardano.png`,
  'Tron':      `${CG}/1094/small/tron-logo.png`,
  'Polkadot':  `${CG}/12171/small/polkadot.png`,
  'Litecoin':  `${CG}/2/small/litecoin.png`,
  'Dogecoin':  `${CG}/5/small/dogecoin.png`,
  'USDT':      `${CG}/325/small/Tether.png`,
  'USDC':      `${CG}/6319/small/usd-coin.png`,
};

const EGOC_USD   = 2.45;
const EGUSD_USD  = 1.00;
const BRIDGE_FEE = 0.005; // 0.5%

const BRIDGE_DEPOSIT_ADDRS: Record<string, string> = {
  BTC:  'bc1qego10bridgexxxxxxxxxxxxxxxxxxxxxxxx',
  ETH:  '0xEgo10BridgeXXXXXXXXXXXXXXXXXXXXXXXX',
  BNB:  '0xEgo10BridgeBNBXXXXXXXXXXXXXXXXXXXXX',
  ADA:  'addr1ego10bridgexxxxxxxxxxxxxxxxxxxxxxxx',
  USDT: '0xEgo10BridgeUSDTXXXXXXXXXXXXXXXXXXXX',
  USDC: '0xEgo10BridgeUSDCXXXXXXXXXXXXXXXXXXXX',
};

const EVM_CHAINS = ['Ethereum', 'BNB Chain', 'Polygon', 'Avalanche', 'Arbitrum', 'Optimism'];

function assetUsdPrice(asset: SwapAsset, rates: Record<string, number>): number {
  if (asset.id === 'egoc')  return EGOC_USD;
  if (asset.id === 'egusd') return EGUSD_USD;
  if (asset.coingecko_id && rates[asset.coingecko_id]) return rates[asset.coingecko_id];
  return 0;
}

function calcSwapOutput(
  fromAsset: SwapAsset,
  toAsset: SwapAsset,
  fromAmount: number,
  rates: Record<string, number>,
): number {
  const fromUsd = assetUsdPrice(fromAsset, rates);
  const toUsd   = assetUsdPrice(toAsset, rates);
  if (!fromUsd || !toUsd) return 0;
  const gross = (fromAmount * fromUsd) / toUsd;
  return gross * (1 - BRIDGE_FEE);
}

function AssetIcon({ asset, size = 24 }: { asset: SwapAsset; size?: number }) {
  if (asset.img) {
    return (
      <img
        src={asset.img}
        alt={asset.symbol}
        style={{ width: size, height: size, borderRadius: '50%', objectFit: 'cover', flexShrink: 0 }}
      />
    );
  }
  return <span style={{ fontSize: size * 0.7, lineHeight: 1 }}>{asset.icon}</span>;
}

function timeAgo(ts: number) {
  const diff = Math.floor(Date.now() / 1000 - ts);
  if (diff < 60)    return `${diff}s ago`;
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

const FIAT_RATE = EGOC_USD;

function shortHash(h: string) {
  return h.length > 16 ? h.slice(0, 10) + '...' + h.slice(-6) : h;
}
function shortAddr(a: string) {
  return a.length > 16 ? a.slice(0, 10) + '...' + a.slice(-4) : a;
}
function statusBadge(s: string) {
  if (s === 'Confirmed') return 'bg-green-500/20 text-green-400';
  if (s === 'Pending')   return 'bg-yellow-500/20 text-yellow-400';
  return 'bg-red-500/20 text-red-400';
}
function statusIcon(s: string) {
  if (s === 'Confirmed') return '✅';
  if (s === 'Pending')   return '⏳';
  return '❌';
}
function formatAgo(ts: number) {
  const diff = Math.floor(Date.now() / 1000 - ts);
  if (diff < 60)    return `${diff}s ago`;
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

const WalletPage: React.FC = () => {
  const { wallet, reload: reloadWallet } = useWallet();
  const myAddress = wallet?.address ?? '';
  const addressQR = useMemo(() => makeQR(myAddress), [myAddress]);

  const [balance, setBalance]       = useState<Balance | null>(null);
  const [txs, setTxs]               = useState<LedgerTx[]>([]);
  const [tab, setTab]               = useState<'all' | 'sent' | 'received'>('all');
  const [selectedTx, setSelectedTx] = useState<LedgerTx | null>(null);
  const [showSend, setShowSend]     = useState(false);
  const [showReceive, setShowReceive] = useState(false);
  const [sendForm, setSendForm]     = useState<SendForm>({ to: '', amount: '', memo: '' });
  const [sending, setSending]       = useState(false);
  const [txResult, setTxResult]     = useState<TxResult | null>(null);
  const [copied, setCopied]         = useState(false);

  // Remote node viewer
  const [showRemoteNode, setShowRemoteNode] = useState(false);
  const [remoteRpcUrl, setRemoteRpcUrl]     = useState(RPC_URL);
  const [remoteNode, setRemoteNode]         = useState<RemoteNodeInfo | null>(null);
  const [remoteLoading, setRemoteLoading]   = useState(false);
  const [remoteError, setRemoteError]       = useState('');

  // Email 2FA confirmation
  type EmailStep = 'idle' | 'code_entry' | 'confirmed' | 'expired';
  const [emailStep, setEmailStep]     = useState<EmailStep>('idle');
  const [txId, setTxId]               = useState('');
  const [maskedEmail, setMaskedEmail] = useState('');
  const [codeInput, setCodeInput]     = useState('');
  const [codeError, setCodeError]     = useState('');
  const [codeLoading, setCodeLoading] = useState(false);

  // ── Swap state ────────────────────────────────────────────────────────────
  const [showSwap, setShowSwap]       = useState(false);
  const [swapStep, setSwapStep]       = useState<'quote' | 'deposit' | 'done'>('quote');
  const [swapFrom, setSwapFrom]       = useState<SwapAsset>(SWAP_ASSETS[2]); // BTC
  const [swapTo, setSwapTo]           = useState<SwapAsset>(SWAP_ASSETS[0]); // EGOC
  const [swapAmount, setSwapAmount]   = useState('');
  const [swapRates, setSwapRates]     = useState<Record<string, number>>({});
  const [swapRateLoading, setSwapRateLoading] = useState(false);

  // ── Multi-chain state ─────────────────────────────────────────────────────
  const [showAddresses, setShowAddresses]   = useState(false);
  const [extAddresses, setExtAddresses]     = useState<ExternalAddress[]>([]);
  const [loadingAddr, setLoadingAddr]       = useState(false);
  const [customTokens, setCustomTokens]     = useState<CustomToken[]>([]);
  const [balances, setBalances]             = useState<Record<string, BalanceResult>>({});
  const [loadingBal, setLoadingBal]         = useState<Record<string, boolean>>({});
  const [txHistory, setTxHistory]           = useState<Record<string, ExternalTx[]>>({});
  const [loadingTx, setLoadingTx]           = useState<Record<string, boolean>>({});
  const [expandedTx, setExpandedTx]         = useState<string | null>(null);
  const [copiedChain, setCopiedChain]       = useState<string | null>(null);
  const [hiddenChains, setHiddenChains]     = useState<Set<string>>(
    () => new Set(JSON.parse(localStorage.getItem('ego_hidden_chains') ?? '[]'))
  );
  const [showManageCoins, setShowManageCoins] = useState(false);
  const [showAddToken, setShowAddToken]     = useState(false);
  const [addTokenChain, setAddTokenChain]   = useState('Ethereum');
  const [addTokenContract, setAddTokenContract] = useState('');
  const [addTokenInfo, setAddTokenInfo]     = useState<TokenInfo | null>(null);
  const [addTokenLoading, setAddTokenLoading] = useState(false);
  const [addTokenError, setAddTokenError]   = useState('');

  useEffect(() => {
    load();
    const unsub = listen('ego://chain-updated', () => {
      load();
      reloadWallet();
    });
    return () => { unsub.then(fn => fn()); };
  }, [myAddress]);

  async function load() {
    try {
      const bal = await invoke<Balance>('get_balance');
      const history = await invoke<LedgerTx[]>('get_transaction_history');
      setBalance(bal);
      setTxs(history);
    } catch (e) {
      console.error(e);
    }
  }

  // ── Remote node ───────────────────────────────────────────────────────────
  async function queryRemoteNode() {
    if (!remoteRpcUrl.trim()) return;
    setRemoteLoading(true);
    setRemoteError('');
    setRemoteNode(null);
    try {
      const info = await invoke<RemoteNodeInfo>('query_remote_node', { rpcUrl: remoteRpcUrl.trim() });
      setRemoteNode(info);
    } catch (e: any) {
      setRemoteError(String(e));
    } finally {
      setRemoteLoading(false);
    }
  }

  // ── Send ──────────────────────────────────────────────────────────────────
  async function handleSend() {
    if (!sendForm.to || !sendForm.amount) return;
    setSending(true);
    try {
      const amount  = Math.floor(parseFloat(sendForm.amount) * 1_000_000);
      const request = { to_address: sendForm.to, amount, memo: sendForm.memo || null };

      try {
        // Try email 2FA first — request_tx_code fails if no email is on file
        const res = await invoke<{ tx_id: string; masked_email: string }>(
          'request_tx_code', { request }
        );
        setTxId(res.tx_id);
        setMaskedEmail(res.masked_email);
        setCodeInput('');
        setCodeError('');
        setEmailStep('code_entry');
        setSending(false);
      } catch (e: any) {
        const msg = String(e);
        if (msg.includes('No email on file')) {
          // No email configured — send directly without 2FA
          const res = await invoke<TxResult>('send_transaction', { request });
          setTxResult(res);
          await load(); reloadWallet();
        } else {
          throw e;
        }
      }
    } catch (e: any) {
      setTxResult({ hash: '', success: false, message: String(e) });
    } finally {
      setSending(false);
    }
  }

  // ── Confirm code ───────────────────────────────────────────────────────────
  async function handleConfirmCode() {
    if (!codeInput.trim()) return;
    setCodeLoading(true);
    setCodeError('');
    try {
      const res = await invoke<TxResult>('confirm_tx_code', {
        txId: txId, code: codeInput.trim(),
      });
      setEmailStep('confirmed');
      setTxResult(res);
      await load(); reloadWallet();
    } catch (e: any) {
      setCodeError(String(e).replace(/^.*Error:/, '').trim());
    } finally {
      setCodeLoading(false);
    }
  }

  function resetSend() {
    setShowSend(false);
    setSendForm({ to: '', amount: '', memo: '' });
    setTxResult(null);
    setEmailStep('idle');
    setTxId('');
    setMaskedEmail('');
    setCodeInput('');
    setCodeError('');
  }

  async function copyAddr() {
    if (!myAddress) return;
    await navigator.clipboard.writeText(myAddress);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  // ── Swap helpers ──────────────────────────────────────────────────────────
  async function openSwap() {
    setSwapStep('quote');
    setSwapAmount('');
    setShowSwap(true);
    setSwapRateLoading(true);
    try {
      const rates = await invoke<Record<string, number>>('fetch_swap_rates');
      setSwapRates(rates);
    } catch {
      setSwapRates({});
    } finally {
      setSwapRateLoading(false);
    }
  }

  function flipSwapAssets() {
    setSwapFrom(swapTo);
    setSwapTo(swapFrom);
    setSwapAmount('');
  }

  const swapOutput = swapAmount
    ? calcSwapOutput(swapFrom, swapTo, parseFloat(swapAmount) || 0, swapRates)
    : 0;

  const fromUsdPrice = assetUsdPrice(swapFrom, swapRates);
  const toUsdPrice   = assetUsdPrice(swapTo,   swapRates);
  const swapUsdVal   = (parseFloat(swapAmount) || 0) * fromUsdPrice;

  // ── Multi-chain helpers ───────────────────────────────────────────────────
  async function loadExternalAddresses() {
    setLoadingAddr(true);
    try {
      const addrs = await invoke<ExternalAddress[]>('get_external_addresses');
      setExtAddresses(addrs);
      const tokens = await invoke<CustomToken[]>('get_custom_tokens');
      setCustomTokens(tokens);
    } catch (e) {
      console.error(e);
    } finally {
      setLoadingAddr(false);
    }
  }

  async function fetchBalance(chain: string, address: string, symbol: string, contract?: string) {
    const key = contract ? `${chain}:${contract}` : chain;
    setLoadingBal(p => ({ ...p, [key]: true }));
    try {
      const result = await invoke<BalanceResult>('fetch_chain_balance', {
        chainSymbol: symbol, address, contract: contract ?? null,
      });
      setBalances(p => ({ ...p, [key]: result }));
    } catch {
      setBalances(p => ({ ...p, [key]: { raw: '0', formatted: '—', usd: 0 } }));
    } finally {
      setLoadingBal(p => ({ ...p, [key]: false }));
    }
  }

  async function fetchTxHistory(chain: string, address: string, symbol: string) {
    setLoadingTx(p => ({ ...p, [chain]: true }));
    try {
      const txs = await invoke<ExternalTx[]>('fetch_chain_transactions', {
        chainSymbol: symbol, address, contract: null,
      });
      setTxHistory(p => ({ ...p, [chain]: txs }));
    } catch {
      setTxHistory(p => ({ ...p, [chain]: [] }));
    } finally {
      setLoadingTx(p => ({ ...p, [chain]: false }));
    }
  }

  function toggleTxHistory(chain: string, address: string, symbol: string) {
    if (expandedTx === chain) { setExpandedTx(null); return; }
    setExpandedTx(chain);
    if (!txHistory[chain]) fetchTxHistory(chain, address, symbol);
  }

  async function detectToken() {
    if (!addTokenContract.trim()) return;
    setAddTokenLoading(true);
    setAddTokenError('');
    setAddTokenInfo(null);
    try {
      const info = await invoke<TokenInfo>('lookup_token_info', {
        chainSymbol: chainSymbolFor(addTokenChain),
        contractAddress: addTokenContract.trim(),
      });
      setAddTokenInfo(info);
    } catch (e: any) {
      setAddTokenError(String(e));
    } finally {
      setAddTokenLoading(false);
    }
  }

  async function saveCustomToken() {
    if (!addTokenInfo) return;
    try {
      await invoke('add_custom_token', {
        symbol:      addTokenInfo.symbol,
        name:        addTokenInfo.name,
        chain:       addTokenChain,
        chainSymbol: chainSymbolFor(addTokenChain),
        contract:    addTokenContract.trim() || null,
        decimals:    addTokenInfo.decimals,
        color:       null,
        icon:        null,
      });
      const tokens = await invoke<CustomToken[]>('get_custom_tokens');
      setCustomTokens(tokens);
      setShowAddToken(false);
      setAddTokenContract('');
      setAddTokenInfo(null);
    } catch (e: any) {
      setAddTokenError(String(e));
    }
  }

  async function removeToken(id: string) {
    try {
      await invoke('remove_custom_token', { id });
      setCustomTokens(p => p.filter(t => t.id !== id));
    } catch {}
  }

  function hideChain(chain: string) {
    const next = new Set(hiddenChains).add(chain);
    setHiddenChains(next);
    localStorage.setItem('ego_hidden_chains', JSON.stringify([...next]));
  }

  function showChain(chain: string) {
    const next = new Set(hiddenChains);
    next.delete(chain);
    setHiddenChains(next);
    localStorage.setItem('ego_hidden_chains', JSON.stringify([...next]));
  }

  async function copyChainAddress(chain: string, address: string) {
    await navigator.clipboard.writeText(address);
    setCopiedChain(chain);
    setTimeout(() => setCopiedChain(c => c === chain ? null : c), 2000);
  }

  function chainSymbolFor(chain: string) {
    const map: Record<string, string> = {
      'Ethereum': 'ETH', 'BNB Chain': 'BNB', 'Polygon': 'MATIC',
      'Avalanche': 'AVAX', 'Arbitrum': 'ETH', 'Optimism': 'ETH',
      'Bitcoin': 'BTC', 'Solana': 'SOL', 'Cardano': 'ADA',
      'XRP': 'XRP', 'Tron': 'TRX', 'Litecoin': 'LTC', 'Dogecoin': 'DOGE',
    };
    return map[chain] ?? chain;
  }

  useEffect(() => {
    if (showAddresses && extAddresses.length === 0) loadExternalAddresses();
  }, [showAddresses]);

  const filteredTxs = txs.filter(tx => {
    if (tab === 'sent')     return tx.from === myAddress;
    if (tab === 'received') return tx.to === myAddress;
    return true;
  });

  const egocBal  = balance ? balance.egoc : (wallet ? wallet.balance_uegoc / 1_000_000 : 0);
  const formatted = balance?.formatted ?? wallet?.balance_formatted ?? '—';
  const fiatBal   = (egocBal * FIAT_RATE).toLocaleString('en-US', { style: 'currency', currency: 'USD' });

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-5">
      {/* Balance card */}
      <div className="bg-gradient-to-br from-blue-600 via-blue-700 to-purple-700 rounded-2xl p-6 shadow-xl">
        <div className="flex justify-between items-start mb-4">
          <div>
            <div className="text-blue-200 text-xs mb-1">Total Balance</div>
            <div className="flex items-baseline gap-2">
              <div className="text-4xl font-black tracking-tight">{formatted}</div>
              <span className="text-yellow-300 text-sm font-bold bg-yellow-400/20 px-2 py-0.5 rounded-full">TEST</span>
            </div>
            <div className="text-blue-300 text-sm mt-1">≈ {fiatBal} USD</div>
          </div>
          <div className="text-right">
            <div className="text-blue-200 text-xs mb-1">Network</div>
            <div className="text-yellow-300 font-bold text-sm">Ego Testnet</div>
            <div className="text-blue-300 text-xs">1 EGOC = 1,000,000 uEGOC</div>
          </div>
        </div>

        <div className="bg-white/10 rounded-lg px-3 py-2 mb-5 font-mono text-xs text-blue-100 truncate">
          {myAddress || 'Loading address…'}
        </div>

        <div className="grid grid-cols-3 gap-3">
          {[
            { label: '↑ Send',    action: () => { setShowSend(true); setTxResult(null); } },
            { label: '↓ Receive', action: () => setShowReceive(true) },
            { label: '⇄ Swap',   action: openSwap },
          ].map(btn => (
            <button
              key={btn.label}
              onClick={btn.action}
              className="bg-white/20 hover:bg-white/30 transition rounded-xl py-2.5 text-sm font-semibold"
            >
              {btn.label}
            </button>
          ))}
        </div>
      </div>

      {/* ── MULTI-CHAIN WALLET ── */}
      <div className="bg-gray-800/60 rounded-2xl border border-gray-700/50 overflow-hidden">
        <button
          onClick={() => setShowAddresses(v => !v)}
          className="w-full flex items-center justify-between px-5 py-4 hover:bg-gray-700/30 transition"
        >
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-indigo-500/15 flex items-center justify-center text-lg">🌐</div>
            <div className="text-left">
              <div className="font-semibold text-sm">Multi-Chain Wallet</div>
              <div className="text-xs text-gray-400">BTC · ETH · BNB · SOL · ADA · LTC · DOGE + custom tokens</div>
            </div>
          </div>
          <span className="text-gray-500 text-sm">{showAddresses ? '▲' : '▼'}</span>
        </button>

        {showAddresses && (
          <div className="border-t border-gray-700/50 px-5 pb-5 pt-4 space-y-3">
            {loadingAddr ? (
              <div className="text-center py-6 text-gray-400 text-sm">Loading addresses…</div>
            ) : (
              <>
                {/* ── EGOC row ── */}
                {!hiddenChains.has('EGOC') && (
                  <div className="bg-gray-900/60 rounded-xl overflow-hidden border border-gray-700/40">
                    <div className="flex items-center justify-between px-4 py-3 gap-3">
                      <div className="flex items-center gap-3 min-w-0">
                        <div className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0 overflow-hidden" style={{ background: '#1a56ff22' }}>
                          <img src="/egoc.png" alt="EGOC" className="w-6 h-6 rounded-full object-cover" />
                        </div>
                        <div className="min-w-0">
                          <div className="flex items-center gap-1.5">
                            <span className="text-sm font-semibold">EGOC</span>
                            <span className="text-yellow-400 text-[9px] font-bold bg-yellow-400/15 px-1 py-px rounded">TEST</span>
                          </div>
                          <div className="text-xs font-mono text-gray-400 truncate">{myAddress}</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className="text-xs px-2 py-1 rounded-lg bg-gray-700/60">{formatted} <span className="text-yellow-400/70">Test</span></span>
                        <button
                          onClick={() => copyChainAddress('EGOC', myAddress)}
                          className={`text-xs px-2 py-1 rounded-lg transition ${copiedChain === 'EGOC' ? 'bg-green-500/20 text-green-400' : 'bg-gray-700/60 hover:bg-gray-700'}`}
                          title="Copy address"
                        >
                          {copiedChain === 'EGOC' ? '✓' : '📋'}
                        </button>
                        <button onClick={() => hideChain('EGOC')} className="text-xs px-2 py-1 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 transition" title="Hide">✕</button>
                      </div>
                    </div>
                  </div>
                )}

                {/* ── EGUSD row ── */}
                {!hiddenChains.has('EGUSD') && (
                  <div className="bg-gray-900/60 rounded-xl overflow-hidden border border-gray-700/40">
                    <div className="flex items-center justify-between px-4 py-3 gap-3">
                      <div className="flex items-center gap-3 min-w-0">
                        <div className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0 overflow-hidden" style={{ background: '#10b98122' }}>
                          <img src="/egusd.png" alt="EGUSD" className="w-6 h-6 rounded-full object-cover" />
                        </div>
                        <div className="min-w-0">
                          <div className="text-sm font-semibold">EGUSD</div>
                          <div className="text-xs font-mono text-gray-400 truncate">{myAddress}</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className="text-xs px-2 py-1 rounded-lg bg-gray-700/60">0.00 EGUSD</span>
                        <button
                          onClick={() => copyChainAddress('EGUSD', myAddress)}
                          className={`text-xs px-2 py-1 rounded-lg transition ${copiedChain === 'EGUSD' ? 'bg-green-500/20 text-green-400' : 'bg-gray-700/60 hover:bg-gray-700'}`}
                          title="Copy address"
                        >
                          {copiedChain === 'EGUSD' ? '✓' : '📋'}
                        </button>
                        <button onClick={() => hideChain('EGUSD')} className="text-xs px-2 py-1 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 transition" title="Hide">✕</button>
                      </div>
                    </div>
                  </div>
                )}

                {/* ── External chain rows ── */}
                {extAddresses.length === 0 ? (
                  <div className="text-center py-4 text-gray-400 text-sm">No addresses generated yet.</div>
                ) : (
                  extAddresses.filter(a => !hiddenChains.has(a.chain)).map(addr => {
                    const balKey = addr.contract ? `${addr.chain}:${addr.contract}` : addr.chain;
                    const bal = balances[balKey];
                    const chainTokens = customTokens.filter(t => t.chain_symbol === addr.symbol);
                    const isCopied = copiedChain === addr.chain;
                    return (
                      <div key={addr.chain} className="bg-gray-900/60 rounded-xl overflow-hidden border border-gray-700/40">
                        {/* Chain row */}
                        <div className="flex items-center justify-between px-4 py-3 gap-3">
                          <div className="flex items-center gap-3 min-w-0">
                            <div
                              className="w-9 h-9 rounded-lg flex items-center justify-center text-lg shrink-0 font-bold overflow-hidden"
                              style={{ background: addr.color + '22', color: addr.color }}
                            >
                              {CHAIN_ICONS[addr.chain] ? (
                                <img src={CHAIN_ICONS[addr.chain]} alt={addr.chain} className="w-6 h-6 rounded-full object-cover" />
                              ) : (
                                addr.icon
                              )}
                            </div>
                            <div className="min-w-0">
                              <div className="text-sm font-semibold">{addr.chain}</div>
                              <div className="text-xs font-mono text-gray-400 truncate">{addr.address}</div>
                            </div>
                          </div>
                          <div className="flex items-center gap-2 shrink-0">
                            <button
                              onClick={() => fetchBalance(addr.chain, addr.address, addr.symbol, addr.contract ?? undefined)}
                              className="text-xs px-2 py-1 rounded-lg bg-gray-700/60 hover:bg-gray-700 transition"
                              title="Fetch balance"
                            >
                              {loadingBal[balKey] ? '…' : bal ? bal.formatted : '💰'}
                            </button>
                            <button
                              onClick={() => toggleTxHistory(addr.chain, addr.address, addr.symbol)}
                              className="text-xs px-2 py-1 rounded-lg bg-gray-700/60 hover:bg-gray-700 transition"
                              title="Transaction history"
                            >
                              {expandedTx === addr.chain ? '▲' : '📋'}
                            </button>
                            <button
                              onClick={() => copyChainAddress(addr.chain, addr.address)}
                              className={`text-xs px-2 py-1 rounded-lg transition ${isCopied ? 'bg-green-500/20 text-green-400' : 'bg-gray-700/60 hover:bg-gray-700'}`}
                              title="Copy address"
                            >
                              {isCopied ? '✓' : '📋'}
                            </button>
                            <button
                              onClick={() => hideChain(addr.chain)}
                              className="text-xs px-2 py-1 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 transition"
                              title="Hide this coin"
                            >
                              ✕
                            </button>
                          </div>
                        </div>

                        {/* TX history */}
                        {expandedTx === addr.chain && (
                          <div className="border-t border-gray-700/40 px-4 py-3 space-y-2">
                            {loadingTx[addr.chain] ? (
                              <div className="text-xs text-gray-400">Loading history…</div>
                            ) : (txHistory[addr.chain] ?? []).length === 0 ? (
                              <div className="text-xs text-gray-500">No recent transactions found.</div>
                            ) : (
                              (txHistory[addr.chain] ?? []).slice(0, 10).map(tx => (
                                <a
                                  key={tx.hash}
                                  href={tx.explorer_url}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="flex items-center justify-between text-xs py-1.5 border-b border-gray-700/30 last:border-0 hover:text-blue-400 transition"
                                >
                                  <div className="flex items-center gap-2 min-w-0">
                                    <span>{tx.from.toLowerCase() === addr.address.toLowerCase() ? '↑' : '↓'}</span>
                                    <span className="font-mono text-gray-400 truncate">{tx.hash.slice(0, 12)}…</span>
                                  </div>
                                  <div className="text-right shrink-0 ml-2">
                                    <span className="font-semibold">{tx.value}</span>
                                    <span className="text-gray-500 ml-1">{timeAgo(tx.timestamp)}</span>
                                  </div>
                                </a>
                              ))
                            )}
                          </div>
                        )}

                        {/* Custom tokens for this chain */}
                        {chainTokens.map(tok => {
                          const tokKey = `${tok.chain}:${tok.contract ?? tok.symbol}`;
                          const tokBal = balances[tokKey];
                          const tokAddr = extAddresses.find(a => a.symbol === tok.chain_symbol)?.address ?? '';
                          return (
                            <div key={tok.id} className="flex items-center justify-between px-4 py-2 bg-gray-800/40 border-t border-gray-700/30">
                              <div className="flex items-center gap-2 min-w-0">
                                <div className="w-6 h-6 rounded text-xs flex items-center justify-center" style={{ background: tok.color + '22', color: tok.color }}>
                                  {tok.icon}
                                </div>
                                <div className="min-w-0">
                                  <div className="text-xs font-semibold">{tok.symbol}</div>
                                  <div className="text-xs text-gray-500 truncate">{tok.name}</div>
                                  {tokAddr && <div className="text-xs font-mono text-gray-600 truncate">{tokAddr}</div>}
                                </div>
                              </div>
                              <div className="flex items-center gap-2 shrink-0">
                                <button
                                  onClick={() => {
                                    if (tokAddr) fetchBalance(tok.chain, tokAddr, tok.symbol, tok.contract ?? undefined);
                                  }}
                                  className="text-xs px-2 py-1 rounded-lg bg-gray-700/60 hover:bg-gray-700 transition"
                                >
                                  {loadingBal[tokKey] ? '…' : tokBal ? tokBal.formatted : '💰'}
                                </button>
                                <button
                                  onClick={() => removeToken(tok.id)}
                                  className="text-xs px-2 py-1 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 transition"
                                >
                                  ✕
                                </button>
                              </div>
                            </div>
                          );
                        })}
                      </div>
                    );
                  })
                )}
              </>
            )}

            {/* Bottom action buttons */}
            <div className="grid grid-cols-2 gap-2">
              <button
                onClick={() => setShowAddToken(true)}
                className="py-2 rounded-xl border border-dashed border-gray-600 hover:border-indigo-500 hover:bg-indigo-500/5 text-gray-400 hover:text-indigo-400 text-sm transition"
              >
                + Add Token
              </button>
              <button
                onClick={() => setShowManageCoins(true)}
                className="py-2 rounded-xl border border-dashed border-gray-600 hover:border-blue-500 hover:bg-blue-500/5 text-gray-400 hover:text-blue-400 text-sm transition"
              >
                ⚙ Manage Coins
              </button>
            </div>
          </div>
        )}
      </div>

      {/* Transaction history */}
      <div className="bg-gray-800 rounded-2xl overflow-hidden border border-gray-700">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-700">
          <h3 className="font-semibold">Transactions</h3>
          <div className="flex gap-1">
            {(['all', 'sent', 'received'] as const).map(t => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={`px-3 py-1 rounded-lg text-xs capitalize transition ${
                  tab === t ? 'bg-blue-600 text-white' : 'text-gray-400 hover:bg-gray-700'
                }`}
              >
                {t}
              </button>
            ))}
          </div>
        </div>

        {filteredTxs.length === 0 ? (
          <div className="py-12 text-center text-gray-500">
            <div className="text-4xl mb-3">📋</div>
            <div className="text-sm">No transactions yet</div>
            <div className="text-xs mt-1 text-gray-600">Send your first transaction to get started</div>
          </div>
        ) : (
          <div className="divide-y divide-gray-700/50">
            {filteredTxs.map(tx => {
              const isSent = tx.from === myAddress;
              return (
                <button
                  key={tx.hash}
                  onClick={() => setSelectedTx(tx)}
                  className="w-full flex items-center justify-between px-5 py-4 hover:bg-gray-700/40 transition text-left"
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div className={`w-10 h-10 rounded-xl flex items-center justify-center text-lg shrink-0 ${
                      isSent ? 'bg-red-500/15' : 'bg-green-500/15'
                    }`}>
                      {isSent ? '↑' : '↓'}
                    </div>
                    <div className="min-w-0">
                      <div className="text-sm font-mono text-gray-300 truncate">{shortHash(tx.hash)}</div>
                      <div className="text-xs text-gray-500">
                        {isSent ? `To: ${shortAddr(tx.to)}` : `From: ${shortAddr(tx.from)}`}
                        {tx.memo && <span className="ml-2 text-gray-600">• {tx.memo}</span>}
                      </div>
                    </div>
                  </div>
                  <div className="text-right shrink-0 ml-3">
                    <div className={`text-sm font-semibold ${isSent ? 'text-red-400' : 'text-green-400'}`}>
                      {isSent ? '-' : '+'}{(tx.amount / 1_000_000).toFixed(2)} EGOC
                    </div>
                    <div className="flex items-center justify-end gap-1.5 mt-0.5">
                      <span className={`inline-block w-1.5 h-1.5 rounded-full ${
                        tx.status === 'Confirmed' ? 'bg-green-400' :
                        tx.status === 'Pending'   ? 'bg-yellow-400' : 'bg-red-400'
                      }`}></span>
                      <span className="text-xs text-gray-500">{formatAgo(tx.timestamp)}</span>
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>


      {/* ── SWAP MODAL ── */}
      {showSwap && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-md border border-gray-700 shadow-2xl">
            <div className="flex justify-between items-center mb-5">
              <h3 className="text-lg font-bold">⇄ Swap</h3>
              <button onClick={() => setShowSwap(false)} className="text-gray-400 hover:text-white text-xl">✕</button>
            </div>

            {swapStep === 'quote' && (
              <div className="space-y-4">
                {/* From */}
                <div className="bg-gray-900 rounded-xl p-4 overflow-hidden">
                  <div className="text-xs text-gray-400 mb-2">You send</div>
                  <div className="flex gap-3 items-center">
                    <div className="relative shrink-0">
                      <select
                        value={swapFrom.id}
                        onChange={e => setSwapFrom(SWAP_ASSETS.find(a => a.id === e.target.value)!)}
                        className="bg-gray-700 rounded-xl pl-9 pr-3 py-2 text-sm font-semibold focus:outline-none focus:ring-1 focus:ring-blue-500 appearance-none max-w-[140px]"
                      >
                        {SWAP_ASSETS.map(a => (
                          <option key={a.id} value={a.id}>{a.symbol} — {a.name}</option>
                        ))}
                      </select>
                      <div className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2">
                        <AssetIcon asset={swapFrom} size={20} />
                      </div>
                    </div>
                    <input
                      type="number"
                      min="0"
                      value={swapAmount}
                      onChange={e => setSwapAmount(e.target.value)}
                      placeholder="0.00"
                      className="flex-1 min-w-0 bg-transparent text-2xl font-bold outline-none text-right w-0"
                    />
                  </div>
                  {swapAmount && fromUsdPrice > 0 && (
                    <div className="text-right text-xs text-gray-500 mt-1">
                      ≈ ${swapUsdVal.toFixed(2)} USD
                    </div>
                  )}
                </div>

                {/* Flip */}
                <div className="flex justify-center">
                  <button
                    onClick={flipSwapAssets}
                    className="w-10 h-10 rounded-full bg-gray-700 hover:bg-gray-600 flex items-center justify-center text-xl transition"
                  >
                    ↕
                  </button>
                </div>

                {/* To */}
                <div className="bg-gray-900 rounded-xl p-4">
                  <div className="text-xs text-gray-400 mb-2">You receive</div>
                  <div className="flex gap-3 items-center">
                    <div className="relative">
                      <select
                        value={swapTo.id}
                        onChange={e => setSwapTo(SWAP_ASSETS.find(a => a.id === e.target.value)!)}
                        className="bg-gray-700 rounded-xl pl-9 pr-3 py-2 text-sm font-semibold focus:outline-none focus:ring-1 focus:ring-blue-500 appearance-none"
                      >
                        {SWAP_ASSETS.filter(a => a.id !== swapFrom.id).map(a => (
                          <option key={a.id} value={a.id}>{a.symbol} — {a.name}</option>
                        ))}
                      </select>
                      <div className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2">
                        <AssetIcon asset={swapTo} size={20} />
                      </div>
                    </div>
                    <div className="flex-1 text-right">
                      {swapRateLoading ? (
                        <span className="text-gray-500 text-sm">Loading rates…</span>
                      ) : swapOutput > 0 ? (
                        <span className="text-2xl font-bold text-green-400">{swapOutput.toFixed(6)}</span>
                      ) : (
                        <span className="text-2xl font-bold text-gray-600">0.00</span>
                      )}
                    </div>
                  </div>
                  {swapOutput > 0 && toUsdPrice > 0 && (
                    <div className="text-right text-xs text-gray-500 mt-1">
                      ≈ ${(swapOutput * toUsdPrice).toFixed(2)} USD
                    </div>
                  )}
                </div>

                {/* Rate info */}
                {!swapRateLoading && fromUsdPrice > 0 && toUsdPrice > 0 && (
                  <div className="bg-gray-700/40 rounded-xl px-4 py-3 text-xs space-y-1">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Rate</span>
                      <span>1 {swapFrom.symbol} = {(fromUsdPrice / toUsdPrice).toFixed(6)} {swapTo.symbol}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Bridge fee</span>
                      <span>0.5%</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Protocol</span>
                      <span className="text-yellow-400">EGO-10 Bridge</span>
                    </div>
                  </div>
                )}

                <button
                  onClick={() => swapOutput > 0 && setSwapStep('deposit')}
                  disabled={!swapAmount || swapOutput <= 0 || swapRateLoading}
                  className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-40 disabled:cursor-not-allowed py-3 rounded-xl font-semibold transition"
                >
                  Continue
                </button>
              </div>
            )}

            {swapStep === 'deposit' && (
              <div className="space-y-4">
                <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-xl p-4 text-sm text-yellow-300">
                  Send exactly <strong>{swapAmount} {swapFrom.symbol}</strong> to the bridge address below.
                  You will receive <strong>{swapOutput.toFixed(6)} {swapTo.symbol}</strong> to your Ego wallet.
                </div>

                <div className="bg-gray-900 rounded-xl p-4 space-y-2">
                  <div className="text-xs text-gray-400">Bridge Deposit Address ({swapFrom.symbol})</div>
                  <div className="font-mono text-xs text-green-400 break-all">
                    {BRIDGE_DEPOSIT_ADDRS[swapFrom.symbol] ?? '— coming soon —'}
                  </div>
                  <button
                    onClick={async () => {
                      const addr = BRIDGE_DEPOSIT_ADDRS[swapFrom.symbol];
                      if (addr) await navigator.clipboard.writeText(addr);
                    }}
                    className="mt-2 text-xs bg-gray-700 hover:bg-gray-600 px-3 py-1 rounded-lg transition"
                  >
                    Copy Address
                  </button>
                </div>

                <div className="text-xs text-gray-500 text-center">
                  After your deposit is detected on-chain, EGOC will be credited to your wallet automatically.
                </div>

                <div className="grid grid-cols-2 gap-3">
                  <button
                    onClick={() => setSwapStep('quote')}
                    className="py-3 rounded-xl bg-gray-700 hover:bg-gray-600 font-semibold text-sm transition"
                  >
                    ← Back
                  </button>
                  <button
                    onClick={() => setSwapStep('done')}
                    className="py-3 rounded-xl bg-green-600 hover:bg-green-500 font-semibold text-sm transition"
                  >
                    Done ✓
                  </button>
                </div>
              </div>
            )}

            {swapStep === 'done' && (
              <div className="text-center space-y-4">
                <div className="text-5xl">✅</div>
                <div className="text-xl font-bold">Swap Initiated</div>
                <p className="text-sm text-gray-400">
                  Once your {swapFrom.symbol} deposit is confirmed, {swapOutput.toFixed(6)} {swapTo.symbol} will be credited to your wallet.
                </p>
                <button
                  onClick={() => setShowSwap(false)}
                  className="w-full bg-blue-600 hover:bg-blue-500 py-3 rounded-xl font-semibold transition"
                >
                  Close
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── MANAGE COINS MODAL ── */}
      {showManageCoins && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-md border border-gray-700 shadow-2xl">
            <div className="flex justify-between items-center mb-5">
              <h3 className="text-lg font-bold">Manage Coins</h3>
              <button onClick={() => setShowManageCoins(false)} className="text-gray-400 hover:text-white text-xl">✕</button>
            </div>
            <div className="space-y-2">
              {extAddresses.map(addr => {
                const hidden = hiddenChains.has(addr.chain);
                return (
                  <div key={addr.chain} className="flex items-center justify-between px-4 py-3 rounded-xl bg-gray-900/60 border border-gray-700/40">
                    <div className="flex items-center gap-3">
                      <div
                        className="w-8 h-8 rounded-lg flex items-center justify-center text-base font-bold shrink-0"
                        style={{ background: addr.color + '22', color: addr.color }}
                      >
                        {addr.icon}
                      </div>
                      <div>
                        <div className="text-sm font-semibold">{addr.chain}</div>
                        <div className="text-xs text-gray-500">{addr.symbol} · {addr.address_type}</div>
                      </div>
                    </div>
                    <button
                      onClick={() => hidden ? showChain(addr.chain) : hideChain(addr.chain)}
                      className={`text-xs px-3 py-1.5 rounded-lg font-semibold transition ${
                        hidden
                          ? 'bg-blue-600 hover:bg-blue-500 text-white'
                          : 'bg-gray-700 hover:bg-red-500/20 text-gray-300 hover:text-red-400'
                      }`}
                    >
                      {hidden ? '+ Add' : '✕ Hide'}
                    </button>
                  </div>
                );
              })}
            </div>
            <button
              onClick={() => setShowManageCoins(false)}
              className="w-full mt-4 bg-gray-700 hover:bg-gray-600 py-3 rounded-xl font-semibold text-sm transition"
            >
              Done
            </button>
          </div>
        </div>
      )}

      {/* ── ADD CUSTOM TOKEN MODAL ── */}
      {showAddToken && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-md border border-gray-700 shadow-2xl">
            <div className="flex justify-between items-center mb-5">
              <h3 className="text-lg font-bold">Add Custom Token</h3>
              <button onClick={() => { setShowAddToken(false); setAddTokenInfo(null); setAddTokenError(''); setAddTokenContract(''); }} className="text-gray-400 hover:text-white text-xl">✕</button>
            </div>

            <div className="space-y-4">
              {/* Chain picker */}
              <div>
                <div className="text-xs text-gray-400 mb-2">Network</div>
                <div className="grid grid-cols-3 gap-2">
                  {EVM_CHAINS.map(c => (
                    <button
                      key={c}
                      onClick={() => setAddTokenChain(c)}
                      className={`py-2 rounded-xl text-xs font-semibold transition ${
                        addTokenChain === c ? 'bg-indigo-600 text-white' : 'bg-gray-700 hover:bg-gray-600 text-gray-300'
                      }`}
                    >
                      {c}
                    </button>
                  ))}
                </div>
              </div>

              {/* Contract address */}
              <div>
                <label className="text-xs text-gray-400 block mb-1.5">Contract Address</label>
                <div className="flex gap-2">
                  <input
                    value={addTokenContract}
                    onChange={e => { setAddTokenContract(e.target.value); setAddTokenInfo(null); setAddTokenError(''); }}
                    placeholder="0x..."
                    className="flex-1 bg-gray-900 border border-gray-700 focus:border-indigo-500 rounded-xl px-3 py-2.5 text-sm font-mono outline-none transition"
                  />
                  <button
                    onClick={detectToken}
                    disabled={!addTokenContract.trim() || addTokenLoading}
                    className="bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 px-4 rounded-xl text-sm font-semibold transition"
                  >
                    {addTokenLoading ? '…' : 'Detect'}
                  </button>
                </div>
              </div>

              {addTokenError && (
                <div className="bg-red-500/10 border border-red-500/30 rounded-xl px-4 py-3 text-sm text-red-400">
                  {addTokenError}
                </div>
              )}

              {addTokenInfo && (
                <div className="bg-indigo-500/10 border border-indigo-500/20 rounded-xl px-4 py-3 space-y-1">
                  <div className="text-xs text-gray-400">Detected Token</div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-400">Symbol</span>
                    <span className="font-bold">{addTokenInfo.symbol}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-400">Name</span>
                    <span>{addTokenInfo.name}</span>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-400">Decimals</span>
                    <span>{addTokenInfo.decimals}</span>
                  </div>
                </div>
              )}

              <button
                onClick={saveCustomToken}
                disabled={!addTokenInfo}
                className="w-full bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 disabled:cursor-not-allowed py-3 rounded-xl font-semibold transition"
              >
                Add Token
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── SEND MODAL ── */}
      {showSend && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-md border border-gray-700 shadow-2xl">
            {emailStep === 'code_entry' ? (
              <div className="space-y-5">
                <div className="flex justify-between items-center">
                  <h3 className="text-lg font-bold">Confirm Transaction</h3>
                  <button onClick={resetSend} className="text-gray-400 hover:text-white text-xl">✕</button>
                </div>
                <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl p-4 text-sm text-center space-y-1">
                  <div className="text-blue-300 font-semibold">Verification code sent</div>
                  <div className="text-gray-400">
                    Check <span className="text-white font-mono">{maskedEmail}</span> for a 6-digit code.
                  </div>
                </div>
                <div>
                  <label className="text-xs text-gray-400 block mb-1.5">Enter 6-digit code</label>
                  <input
                    autoFocus
                    value={codeInput}
                    onChange={e => { setCodeInput(e.target.value.replace(/\D/g, '').slice(0, 6)); setCodeError(''); }}
                    onKeyDown={e => e.key === 'Enter' && codeInput.length === 6 && handleConfirmCode()}
                    className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-xl font-mono text-center tracking-widest outline-none transition"
                    placeholder="000000"
                    maxLength={6}
                  />
                  {codeError && <p className="text-red-400 text-xs mt-1.5">{codeError}</p>}
                </div>
                <div className="flex gap-3">
                  <button
                    onClick={resetSend}
                    className="flex-1 bg-gray-700 hover:bg-gray-600 py-3 rounded-xl font-semibold text-sm transition"
                  >
                    Cancel
                  </button>
                  <button
                    onClick={handleConfirmCode}
                    disabled={codeInput.length !== 6 || codeLoading}
                    className="flex-1 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 py-3 rounded-xl font-semibold text-sm transition flex items-center justify-center gap-2"
                  >
                    {codeLoading
                      ? <><div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />Verifying…</>
                      : 'Confirm Send'}
                  </button>
                </div>
              </div>
            ) : emailStep === 'expired' ? (
              <div className="text-center space-y-4">
                <div className="text-5xl">⏰</div>
                <div className="text-xl font-bold">Confirmation Expired</div>
                <p className="text-sm text-gray-400">The confirmation link expired. Please try sending again.</p>
                <button onClick={resetSend} className="w-full bg-blue-600 hover:bg-blue-500 py-3 rounded-xl font-semibold transition">Close</button>
              </div>
            ) : txResult ? (
              <div className="text-center space-y-4">
                <div className="text-5xl">{txResult.success ? '✅' : '❌'}</div>
                <div className="text-xl font-bold">
                  {txResult.success ? 'Transaction Sent!' : 'Transaction Failed'}
                </div>
                <p className="text-sm text-gray-400">{txResult.message}</p>
                {txResult.hash && (
                  <div className="bg-gray-900 rounded-xl p-4 text-left">
                    <div className="text-xs text-gray-400 mb-1">Transaction Hash</div>
                    <div className="text-xs font-mono text-green-400 break-all">{txResult.hash}</div>
                    <div className="mt-3 grid grid-cols-2 gap-2 text-xs text-gray-400">
                      <div><span className="text-gray-500">Status</span><br /><span className="text-yellow-400">Pending</span></div>
                      <div><span className="text-gray-500">Block</span><br /><span>#{txResult.block_height ?? 'pending'}</span></div>
                      <div><span className="text-gray-500">Fee</span><br /><span className="text-green-400">Free ✓</span></div>
                      <div><span className="text-gray-500">Network</span><br />Testnet</div>
                    </div>
                  </div>
                )}
                <button onClick={resetSend} className="w-full bg-blue-600 hover:bg-blue-500 py-3 rounded-xl font-semibold transition">
                  Done
                </button>
              </div>
            ) : (
              <>
                <div className="flex justify-between items-center mb-5">
                  <h3 className="text-lg font-bold">Send EGOC</h3>
                  <button onClick={resetSend} className="text-gray-400 hover:text-white text-xl">✕</button>
                </div>
                <div className="space-y-4">
                  <div>
                    <label className="text-xs text-gray-400 block mb-1.5">Recipient Address</label>
                    <input
                      value={sendForm.to}
                      onChange={e => setSendForm(f => ({ ...f, to: e.target.value }))}
                      className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm font-mono outline-none transition"
                      placeholder="egot1..."
                    />
                  </div>
                  <div>
                    <label className="text-xs text-gray-400 block mb-1.5">Amount (EGOC)</label>
                    <div className="relative">
                      <input
                        type="number"
                        min="0"
                        value={sendForm.amount}
                        onChange={e => setSendForm(f => ({ ...f, amount: e.target.value }))}
                        className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none transition pr-16"
                        placeholder="0.00"
                      />
                      <button
                        onClick={() => setSendForm(f => ({ ...f, amount: String(egocBal) }))}
                        className="absolute right-3 top-1/2 -translate-y-1/2 text-xs text-blue-400 hover:text-blue-300 font-semibold"
                      >
                        MAX
                      </button>
                    </div>
                    <div className="flex justify-between text-xs text-gray-500 mt-1">
                      <span>Available: {formatted}</span>
                      {sendForm.amount && (
                        <span>≈ ${(parseFloat(sendForm.amount || '0') * FIAT_RATE).toFixed(2)}</span>
                      )}
                    </div>
                  </div>
                  <div>
                    <label className="text-xs text-gray-400 block mb-1.5">Memo <span className="text-gray-600">(optional)</span></label>
                    <input
                      value={sendForm.memo}
                      onChange={e => setSendForm(f => ({ ...f, memo: e.target.value }))}
                      className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none transition"
                      placeholder="Payment for..."
                    />
                  </div>
                  <div className="bg-gray-900 rounded-xl p-3 space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Transfer fee</span>
                      <span className="text-green-400 font-medium">Free ✓</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Signature</span>
                      <span className="text-gray-300">Ed25519 + Dilithium-3</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-gray-400">Network</span>
                      <span className="text-gray-300">Ego Testnet</span>
                    </div>
                  </div>
                  <button
                    onClick={handleSend}
                    disabled={!sendForm.to || !sendForm.amount || sending}
                    className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-40 disabled:cursor-not-allowed py-3 rounded-xl font-semibold transition"
                  >
                    {sending ? '⏳ Signing & Broadcasting…' : 'Send EGOC'}
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* ── RECEIVE MODAL ── */}
      {showReceive && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-md border border-gray-700 shadow-2xl text-center">
            <div className="flex justify-between items-center mb-5">
              <h3 className="text-lg font-bold">Receive EGOC</h3>
              <button onClick={() => setShowReceive(false)} className="text-gray-400 hover:text-white text-xl">✕</button>
            </div>
            <div className="bg-white rounded-2xl p-4 inline-block mb-5">
              {addressQR ? (
                <img src={addressQR} alt="Wallet QR Code" className="w-40 h-40" style={{ imageRendering: 'pixelated' }} />
              ) : (
                <div className="w-40 h-40 bg-gray-100 rounded-xl flex items-center justify-center text-4xl">📷</div>
              )}
              <div className="text-gray-500 text-xs mt-2 text-center">Scan to send EGOC</div>
            </div>
            <div className="bg-gray-900 rounded-xl p-4 mb-5 text-left">
              <div className="text-xs text-gray-400 mb-1.5">Your Testnet Address</div>
              <div className="text-xs font-mono text-green-400 break-all leading-relaxed">{myAddress}</div>
            </div>
            <div className="grid grid-cols-2 gap-3">
              <button
                onClick={copyAddr}
                className={`py-3 rounded-xl font-semibold text-sm transition ${
                  copied ? 'bg-green-600' : 'bg-blue-600 hover:bg-blue-500'
                }`}
              >
                {copied ? '✓ Copied!' : '📋 Copy Address'}
              </button>
              <button onClick={() => setShowReceive(false)} className="bg-gray-700 hover:bg-gray-600 py-3 rounded-xl font-semibold text-sm transition">
                Close
              </button>
            </div>
          </div>
        </div>
      )}

      {/* ── TX DETAIL MODAL ── */}
      {selectedTx && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-md border border-gray-700 shadow-2xl">
            <div className="flex justify-between items-center mb-5">
              <h3 className="text-lg font-bold">Transaction Details</h3>
              <button onClick={() => setSelectedTx(null)} className="text-gray-400 hover:text-white text-xl">✕</button>
            </div>
            <div className={`rounded-xl p-4 text-center mb-5 ${
              selectedTx.status === 'Confirmed' ? 'bg-green-500/10 border border-green-500/20' :
              selectedTx.status === 'Pending'   ? 'bg-yellow-500/10 border border-yellow-500/20' :
              'bg-red-500/10 border border-red-500/20'
            }`}>
              <div className="text-3xl mb-1">{statusIcon(selectedTx.status)}</div>
              <div className={`text-2xl font-black ${
                selectedTx.from === myAddress ? 'text-red-400' : 'text-green-400'
              }`}>
                {selectedTx.from === myAddress ? '-' : '+'}
                {(selectedTx.amount / 1_000_000).toFixed(6)} EGOC
              </div>
              <div className={`text-sm mt-0.5 ${statusBadge(selectedTx.status).split(' ')[1]}`}>
                {selectedTx.status}
              </div>
            </div>
            <div className="space-y-3">
              {[
                { label: 'Hash',      val: selectedTx.hash,       mono: true },
                { label: 'From',      val: selectedTx.from,       mono: true },
                { label: 'To',        val: selectedTx.to,         mono: true },
                { label: 'Amount',    val: `${(selectedTx.amount / 1_000_000).toFixed(6)} EGOC` },
                { label: 'Fee',       val: 'Free (wallet-to-wallet)' },
                { label: 'Block',     val: selectedTx.block_height != null ? `#${selectedTx.block_height.toLocaleString()}` : 'Unconfirmed' },
                { label: 'Nonce',     val: String(selectedTx.nonce) },
                { label: 'Timestamp', val: new Date(selectedTx.timestamp * 1000).toLocaleString() },
                { label: 'Signature', val: selectedTx.signature.slice(0, 32) + '…', mono: true },
                ...(selectedTx.memo ? [{ label: 'Memo', val: selectedTx.memo }] : []),
              ].map(({ label, val, mono }) => (
                <div key={label} className="flex justify-between items-start gap-4 py-1 border-b border-gray-700/50 last:border-0">
                  <span className="text-gray-400 text-sm shrink-0">{label}</span>
                  <span className={`text-right text-sm break-all ${mono ? 'font-mono text-xs text-gray-300' : 'text-white'}`}>
                    {val}
                  </span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default WalletPage;
