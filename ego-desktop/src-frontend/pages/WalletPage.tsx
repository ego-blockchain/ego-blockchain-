import React, { useState, useEffect, useMemo, useRef } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';
import { fetch as tauriFetch, Body } from '@tauri-apps/api/http';
import { useWallet } from '../App';
import qrcode from 'qrcode-generator';
import Pagination from '../components/Pagination';

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

interface Balance {
  egoc: number;
  uegoc: number;
  formatted: string;
  egusd: number;
  uegusd: number;
  pending_out_uegoc: number;
  pending_in_uegoc: number;
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
  fee_uegoc: number;
  memo?: string;
  timestamp: number;
  signature: string;
  status: string;
  block_height?: number;
  nonce: number;
  tx_type?: string;
  is_private?: boolean;
}

interface SendForm {
  to: string;
  amount: string;
  memo: string;
  isPrivate: boolean;
}

interface TxResult {
  hash: string;
  success: boolean;
  message: string;
  block_height?: number;
}

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

interface SwapAsset {
  id: string;
  symbol: string;
  name: string;
  icon: string;
  img?: string;
  coingecko_id: string | null;
  is_ego: boolean;
  presale?: boolean;
}

const CG = 'https://assets.coingecko.com/coins/images';
const SWAP_ASSETS: SwapAsset[] = [
  { id: 'egoc',  symbol: 'EGOC',  name: 'Ego Coin',       icon: 'E', img: '/egoc.png',                                      coingecko_id: null,          is_ego: true,  presale: false },
  { id: 'btc',   symbol: 'BTC',   name: 'Bitcoin',        icon: '₿', img: `${CG}/1/small/bitcoin.png`,                      coingecko_id: 'bitcoin',     is_ego: false, presale: true  },
  { id: 'eth',   symbol: 'ETH',   name: 'Ethereum',       icon: 'Ξ', img: `${CG}/279/small/ethereum.png`,                   coingecko_id: 'ethereum',    is_ego: false, presale: true  },
  { id: 'bnb',   symbol: 'BNB',   name: 'BNB',            icon: '◆', img: `${CG}/825/small/bnb-icon2_2x.png`,               coingecko_id: 'binancecoin', is_ego: false, presale: true  },
  { id: 'sol',   symbol: 'SOL',   name: 'Solana',         icon: '◎', img: `${CG}/4128/small/solana.png`,                    coingecko_id: 'solana',      is_ego: false, presale: true  },
  { id: 'xrp',   symbol: 'XRP',   name: 'XRP',            icon: 'X', img: `${CG}/44/small/xrp-symbol-white-128.png`,        coingecko_id: 'ripple',      is_ego: false, presale: false },
  { id: 'ada',   symbol: 'ADA',   name: 'Cardano',        icon: '₳', img: `${CG}/975/small/cardano.png`,                    coingecko_id: 'cardano',     is_ego: false, presale: true  },
  { id: 'trx',   symbol: 'TRX',   name: 'Tron',           icon: 'T', img: `${CG}/1094/small/tron-logo.png`,                 coingecko_id: 'tron',        is_ego: false, presale: true  },
  { id: 'dot',   symbol: 'DOT',   name: 'Polkadot',       icon: '●', img: `${CG}/12171/small/polkadot.png`,                 coingecko_id: 'polkadot',    is_ego: false, presale: false },
  { id: 'link',  symbol: 'LINK',  name: 'Chainlink',      icon: '⬡', img: `${CG}/877/small/chainlink-new-logo.png`,         coingecko_id: 'chainlink',   is_ego: false, presale: false },
  { id: 'shib',  symbol: 'SHIB',  name: 'Shiba Inu',      icon: '🐕',img: `${CG}/11939/small/shiba.png`,                    coingecko_id: 'shiba-inu',   is_ego: false, presale: false },
  { id: 'usdt',  symbol: 'USDT',  name: 'Tether',         icon: '$', img: `${CG}/325/small/Tether.png`,                     coingecko_id: 'tether',      is_ego: false, presale: true  },
  { id: 'usdc',  symbol: 'USDC',  name: 'USD Coin',       icon: '$', img: `${CG}/6319/small/usdc.png`,                      coingecko_id: 'usd-coin',    is_ego: false, presale: false },
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
  'USDC':      `${CG}/6319/small/usdc.png`,
};

const EGOC_USD   = 2.45;
const EGUSD_USD  = 1.00;
const BRIDGE_FEE = 0.005;

// Presale tiers — price rises as each tier sells out.
// Tier 0 (Early Bird) is live; tiers 1-2 unlock when the prior tier is exhausted.
const PRESALE_LAUNCH_PRICE = 2.00; // USD at Genesis Block
const PRESALE_TIERS = [
  { label: 'Early Bird',     price: 0.50,  cap: 20_000_000,  sold: 0,          discount: 75 },
  { label: 'Pre-Sale A',     price: 1.00,  cap: 50_000_000,  sold: 0,          discount: 50 },
  { label: 'Pre-Sale B',     price: 1.50,  cap: 100_000_000, sold: 0,          discount: 25 },
] as const;
// Active tier index — 0 = Early Bird currently live
const ACTIVE_TIER_IDX = 0;
const ACTIVE_TIER = PRESALE_TIERS[ACTIVE_TIER_IDX];

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
    // Ego-native assets have their own circular frame with dark bg — use contain, no extra rounding
    const isNative = asset.is_ego;
    return (
      <img
        src={asset.img}
        alt={asset.symbol}
        style={{
          width: size, height: size, flexShrink: 0,
          borderRadius: isNative ? '8px' : '50%',
          objectFit: isNative ? 'contain' : 'cover',
          background: isNative ? '#0a0f1e' : 'transparent',
        }}
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

// Transaction times are shown in San Francisco time (US Pacific) — one canonical
// chain clock for everyone. timeZoneName:'short' appends PST/PDT.
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

const FIAT_RATE = EGOC_USD;

function shortHash(h: string) {
  return h.length > 16 ? h.slice(0, 10) + '...' + h.slice(-6) : h;
}
function shortAddr(a: string) {
  return a.length > 16 ? a.slice(0, 10) + '...' + a.slice(-4) : a;
}
function statusBadge(s: string) {
  if (s === 'Confirmed') return 'bg-green-500/20 text-green-400';
  if (s === 'Pending' || s.startsWith('Confirming')) return 'bg-yellow-500/20 text-yellow-400';
  return 'bg-red-500/20 text-red-400';
}
function statusIcon(s: string) {
  if (s === 'Confirmed') return '✅';
  if (s === 'Pending' || s.startsWith('Confirming')) return '⏳';
  return '❌';
}
function formatAgo(ts: number) {
  const diff = Math.floor(Date.now() / 1000 - ts);
  if (diff < 60)    return `${diff}s ago`;
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function isRewardTx(tx: LedgerTx): boolean {
  const systemPrefixes = [
    'egot1faucet', 'egot1genesis', 'egot1staking', 'egot1system',
    'egot1coverage', 'egot1nodereward', 'egot1collateral', 'egot1slashpool',
    'egot1storagefees', 'egot1burn', 'egot1nodepool', 'egot1rewards'
  ];
  return (
    ['reward', 'coinbase', 'fee_distribution', 'post_reward', 'faucet'].includes(tx.tx_type || '') ||
    systemPrefixes.some(p => tx.from.startsWith(p))
  );
}

const WalletPage: React.FC = () => {
  const { wallet, reload: reloadWallet } = useWallet();
  const myAddress = wallet?.address ?? '';
  const addressQR = useMemo(() => makeQR(myAddress), [myAddress]);

  const [balance, setBalance]       = useState<Balance | null>(null);
  const [creditsBal, setCreditsBal] = useState<{ credits: number; usd_value: number; egoc_price_usd: number } | null>(null);
  const [showCredits, setShowCredits] = useState(false);
  const [creditsAmt, setCreditsAmt]   = useState('');
  const [creditsBusy, setCreditsBusy] = useState(false);
  const [creditsMsg, setCreditsMsg]   = useState<string | null>(null);
  const [egusdSendTo, setEgusdSendTo]   = useState('');
  const [egusdSendAmt, setEgusdSendAmt] = useState('');
  const [txs, setTxs]               = useState<LedgerTx[]>([]);
  const [tab, setTab]               = useState<'all' | 'sent' | 'received' | 'rewards'>('all');
  const [txPage, setTxPage]         = useState(1);
  const [txPageSize, setTxPageSize] = useState(25);
  const [clearingPending, setClearingPending] = useState(false);
  const [selectedTx, setSelectedTx] = useState<LedgerTx | null>(null);
  const [showSend, setShowSend]     = useState(false);
  const [showReceive, setShowReceive] = useState(false);
  const [sendForm, setSendForm]     = useState<SendForm>({ to: '', amount: '', memo: '', isPrivate: false });
  const [sending, setSending]       = useState(false);
  const [txResult, setTxResult]         = useState<TxResult | null>(null);
  const [txConfirmedHeight, setTxConfirmedHeight] = useState<number | null>(null);
  const [txFee, setTxFee]           = useState<{ fee_uegoc: number; fee_usd: number } | null>(null);
  const [copied, setCopied]         = useState(false);

  const [showRemoteNode, setShowRemoteNode] = useState(false);
  const [remoteRpcUrl, setRemoteRpcUrl]     = useState(RPC_URL);
  const [remoteNode, setRemoteNode]         = useState<RemoteNodeInfo | null>(null);
  const [remoteLoading, setRemoteLoading]   = useState(false);
  const [remoteError, setRemoteError]       = useState('');

  type EmailStep = 'idle' | 'review' | 'no_password_prompt' | 'set_password_inline' | 'pin_entry' | 'code_entry' | 'confirmed' | 'expired';
  const [emailStep, setEmailStep]     = useState<EmailStep>('idle');
  const [pinInput, setPinInput]       = useState('');
  const [pinError, setPinError]       = useState('');

  const [isLiveMode, setIsLiveMode]         = useState(false);
  const [mainnetAddress, setMainnetAddress] = useState('');
  const [showPresale, setShowPresale]           = useState(false);
  const [presaleRecords, setPresaleRecords]     = useState<any[]>([]);
  const [showPresaleRecords, setShowPresaleRecords] = useState(false);
  const [presalePayAsset, setPresalePayAsset]   = useState(SWAP_ASSETS[2]); // BTC default
  const [presalePayAmount, setPresalePayAmount] = useState('');
  const [presaleOutput, setPresaleOutput]       = useState(0);
  const [presaleDepositAddr, setPresaleDepositAddr] = useState('');
  const [presaleStep, setPresaleStep]           = useState<'buy' | 'deposit' | 'done'>('buy');
  const [presaleLoading, setPresaleLoading]     = useState(false);
  const [presaleError, setPresaleError]         = useState('');
  const [presaleRates, setPresaleRates]         = useState<Record<string, number>>({});
  const [presaleRatesLoading, setPresaleRatesLoading] = useState(false);
  const [presalePassword, setPresalePassword]   = useState('');
  const [presalePassword2, setPresalePassword2] = useState('');
  const [presaleIouJson, setPresaleIouJson]     = useState('');
  const [presaleAddrBal, setPresaleAddrBal]     = useState<string | null>(null);
  const [presaleAddrBalLoading, setPresaleAddrBalLoading] = useState(false);
  const [presalePayBal, setPresalePayBal]       = useState<number | null>(null);
  const [presalePayBalLoading, setPresalePayBalLoading] = useState(false);
  const [presalePayMethod, setPresalePayMethod] = useState<'crypto' | 'card'>('crypto');
  const [presaleCardUsd, setPresaleCardUsd]     = useState('');
  const [stripeSessionId, setStripeSessionId]   = useState('');
  const [stripeVerifying, setStripeVerifying]   = useState(false);
  const [stripeVerified, setStripeVerified]     = useState(false);
  const [stripeError, setStripeError]           = useState('');
  const [showSwap, setShowSwap]       = useState(false);
  const [swapStep, setSwapStep]       = useState<'quote' | 'deposit' | 'done'>('quote');
  const [swapFrom, setSwapFrom]       = useState<SwapAsset>(SWAP_ASSETS[2]); // BTC
  const [swapTo, setSwapTo]           = useState<SwapAsset>(SWAP_ASSETS[3]); // ETH
  const [swapAmount, setSwapAmount]   = useState('');
  const [swapRates, setSwapRates]     = useState<Record<string, number>>({});
  const [swapRateLoading, setSwapRateLoading] = useState(false);
  // symbol → numeric balance for external assets in the swap modal
  const [swapExtBalances, setSwapExtBalances] = useState<Record<string, number | null>>({});
  const [swapBalFetching, setSwapBalFetching] = useState(false);
  // ChangeNow real swap state
  const [cnMinAmount, setCnMinAmount]         = useState<number>(0);
  const [cnNetworkFee, setCnNetworkFee]       = useState<number>(0);
  const [cnNetworkFeeUsd, setCnNetworkFeeUsd] = useState<number>(0);
  const [cnEstLoading, setCnEstLoading]       = useState(false);
  const [cnEstError, setCnEstError]           = useState('');
  const [cnExchangeId, setCnExchangeId]       = useState('');
  const [cnDepositAddr, setCnDepositAddr]     = useState('');
  const [cnDepositExtra, setCnDepositExtra]   = useState<string | null>(null);
  const [cnCreating, setCnCreating]           = useState(false);
  const [cnCreateError, setCnCreateError]     = useState('');
  const [cnStatus, setCnStatus]               = useState('');
  const [cnStatusHash, setCnStatusHash]       = useState('');
  const cnPollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const [showAddresses, setShowAddresses]   = useState(false);
  const [extAddresses, setExtAddresses]     = useState<ExternalAddress[]>([]);
  const [loadingAddr, setLoadingAddr]       = useState(false);
  const [customTokens, setCustomTokens]     = useState<CustomToken[]>([]);
  const [balances, setBalances]             = useState<Record<string, BalanceResult>>({});
  const [loadingBal, setLoadingBal]         = useState<Record<string, boolean>>({});
  const [txHistory, setTxHistory]           = useState<Record<string, ExternalTx[]>>({});
  const [loadingTx, setLoadingTx]           = useState<Record<string, boolean>>({});
  const [txHistoryError, setTxHistoryError] = useState<Record<string, string>>({});
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

  // External (multichain) send modal
  const [extSend, setExtSend] = useState<{
    chain: string; symbol: string; address: string;
    contract?: string | null; decimals?: number; color: string; icon: string;
    balanceKey: string; explorerPrefix: string;
  } | null>(null);
  const [extSendTo, setExtSendTo]           = useState('');
  const [extSendAmount, setExtSendAmount]   = useState('');
  const [extSendFee, setExtSendFee]         = useState('');
  const [extSendFeeLoading, setExtSendFeeLoading] = useState(false);
  const [extSending, setExtSending]         = useState(false);
  const [extSendTxid, setExtSendTxid]   = useState('');
  const [extSendError, setExtSendError] = useState('');
  // Email 2FA for external sends
  const [extEmailStep, setExtEmailStep]     = useState<'form' | 'code_entry'>('form');
  const [extTxId, setExtTxId]               = useState('');
  const [extMaskedEmail, setExtMaskedEmail] = useState('');
  const [extOtp, setExtOtp]                 = useState(['', '', '', '', '', '']);
  const extOtpRefs                          = useRef<(HTMLInputElement | null)[]>([]);
  const [extCodeInput, setExtCodeInput]     = useState('');
  const [extCodeError, setExtCodeError]     = useState('');
  const [extCodeLoading, setExtCodeLoading] = useState(false);

  useEffect(() => {
    invoke<Record<string, number>>('fetch_swap_rates').then(setSwapRates).catch(() => {});
    invoke<any[]>('presale_list_iou').then(setPresaleRecords).catch(() => {});
  }, []);

  useEffect(() => {
    load();
    if (myAddress && !mainnetAddress) {
      invoke<string>('get_mainnet_address').then(setMainnetAddress).catch(() => {});
    }
    const unsub = listen('ego://chain-updated', () => {
      load();
      reloadWallet();
    });
    return () => { unsub.then(fn => fn()); };
  }, [myAddress]);

  useEffect(() => {
    const unsub = listen('wallet-balance-updated', () => { load(); reloadWallet(); });
    return () => { unsub.then(fn => fn()); };
  }, []);

  useEffect(() => {
    const loadCredits = () =>
      invoke<{ credits: number; usd_value: number; egoc_price_usd: number }>('get_credits_balance')
        .then(setCreditsBal).catch(() => {});
    loadCredits();
    const unsub = listen('wallet-balance-updated', loadCredits);
    const id = setInterval(loadCredits, 30000);
    return () => { unsub.then(fn => fn()); clearInterval(id); };
  }, []);

  useEffect(() => {
    const id = setInterval(load, 30000);
    return () => clearInterval(id);
  }, []);

  const loadingRef = useRef(false);
  const lastTxSigRef = useRef<string>('');
  async function load() {
    if (loadingRef.current) return;
    loadingRef.current = true;
    try {
      const bal = await invoke<Balance>('get_balance');
      const history = await invoke<LedgerTx[]>('get_transaction_history');
      setBalance(prev =>
        prev && prev.uegoc === bal.uegoc && prev.uegusd === bal.uegusd ? prev : bal
      );
      const sig = `${history.length}|${history[0]?.hash ?? ''}|${history[0]?.status ?? ''}`;
      if (sig !== lastTxSigRef.current) {
        lastTxSigRef.current = sig;
        setTxs(history);
      }
    } catch (e) {
      console.error(e);
    } finally {
      loadingRef.current = false;
    }
  }

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

  async function submitTx() {
    if (!sendForm.to || !sendForm.amount) return;
    const amount  = Math.floor(parseFloat(sendForm.amount) * 1_000_000);
    const request = { to_address: sendForm.to, amount, memo: sendForm.memo || null, is_private: sendForm.isPrivate };
    try {
      const res = await invoke<TxResult>('send_transaction', { request });
      setEmailStep('idle');
      setTxResult(res);
      load().catch(() => {});
      reloadWallet();
    } catch (e: any) {
      const msg = String(e).replace(/^.*Error:/, '').trim();
      setEmailStep('idle');
      setTxResult({ hash: '', success: false, message: msg });
    }
  }

  async function handleSend() {
    if (!sendForm.to || !sendForm.amount) return;
    if (sendForm.to.trim() === myAddress.trim()) {
      setTxResult({ hash: '', success: false, message: 'Cannot send to your own address' });
      return;
    }
    setSending(true);
    try {
      await submitTx();
    } catch (e: any) {
      setEmailStep('idle');
      setTxResult({ hash: '', success: false, message: String(e) });
    } finally {
      setSending(false);
    }
  }


  function resetSend() {
    setShowSend(false);
    setSending(false);
    setSendForm({ to: '', amount: '', memo: '', isPrivate: false });
    setTxResult(null);
    setTxConfirmedHeight(null);
    setEmailStep('idle');
    setPinInput('');
    setPinError('');
  }

  async function handleClearPending() {
    setClearingPending(true);
    try {
      await invoke('clear_pending_transactions');
      await load().catch(() => {});
    } finally {
      setClearingPending(false);
    }
  }

  async function copyAddr() {
    if (!myAddress) return;
    await navigator.clipboard.writeText(myAddress);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  async function openPresale() {
    setPresaleStep('buy');
    setPresalePayAmount('');
    setPresaleOutput(0);
    setPresaleError('');
    setPresaleDepositAddr('');
    setPresalePassword('');
    setPresalePassword2('');
    setPresaleIouJson('');
    setPresaleAddrBal(null);
    setPresalePayBal(null);
    setPresalePayMethod('crypto');
    setPresaleCardUsd('');
    setStripeSessionId('');
    setStripeVerifying(false);
    setStripeVerified(false);
    setStripeError('');
    setShowPresale(true);
    setPresaleRatesLoading(true);
    try {
      const rates = await invoke<Record<string, number>>('fetch_swap_rates');
      setPresaleRates(rates);
    } catch { setPresaleRates({}); }
    finally { setPresaleRatesLoading(false); }
    fetchPresalePayBal(presalePayAsset);
  }

  async function fetchPresalePayBal(asset: SwapAsset) {
    setPresalePayBal(null);
    setPresalePayBalLoading(true);
    try {
      const addrs = extAddresses.length > 0
        ? extAddresses
        : await invoke<ExternalAddress[]>('get_external_addresses');
      const ext = addrs.find(a => a.symbol === asset.symbol && !a.contract);
      if (!ext) { setPresalePayBal(0); return; }
      const res = await invoke<BalanceResult>('fetch_chain_balance', {
        chainSymbol: asset.symbol, address: ext.address, contract: null,
      });
      const num = parseFloat(res.raw) || 0;
      setPresalePayBal(num);
    } catch { setPresalePayBal(0); }
    finally { setPresalePayBalLoading(false); }
  }

  function calcPresaleOutput(paySymbol: string, payAmount: number, rates: Record<string, number>): number {
    const asset = SWAP_ASSETS.find(a => a.symbol === paySymbol);
    if (!asset) return 0;
    const usdPrice = assetUsdPrice(asset, rates);
    if (!usdPrice) return 0;
    return (payAmount * usdPrice) / ACTIVE_TIER.price;
  }

  async function openSwap() {
    setSwapStep('quote');
    setSwapAmount('');
    setCnToAmount(0);
    setCnEstError('');
    setCnCreateError('');
    setCnExchangeId('');
    setCnDepositAddr('');
    setCnDepositExtra(null);
    setCnStatus('');
    setCnStatusHash('');
    setCnMinAmount(0);
    setCnNetworkFee(0);
    setCnNetworkFeeUsd(0);
    if (cnPollRef.current) clearInterval(cnPollRef.current);
    setShowSwap(true);
    setSwapRateLoading(true);
    setSwapBalFetching(true);

    // Fetch rates and external balances in parallel
    const [ratesResult, addrsResult] = await Promise.allSettled([
      invoke<Record<string, number>>('fetch_swap_rates'),
      extAddresses.length > 0
        ? Promise.resolve(extAddresses)
        : invoke<ExternalAddress[]>('get_external_addresses'),
    ]);

    if (ratesResult.status === 'fulfilled') setSwapRates(ratesResult.value);
    else setSwapRates({});
    setSwapRateLoading(false);

    const addrs: ExternalAddress[] = addrsResult.status === 'fulfilled' ? addrsResult.value : [];
    if (addrsResult.status === 'fulfilled' && extAddresses.length === 0) setExtAddresses(addrs);

    // Fetch balance for every non-ego swap asset that has a known address
    const externalAssets = SWAP_ASSETS.filter(a => !a.is_ego);
    const results = await Promise.allSettled(
      externalAssets.map(async asset => {
        const ext = addrs.find(a => a.symbol === asset.symbol);
        if (!ext) return { symbol: asset.symbol, balance: null };
        try {
          const res = await invoke<BalanceResult>('fetch_chain_balance', {
            chainSymbol: asset.symbol,
            address: ext.address,
            contract: ext.contract ?? null,
          });
          return { symbol: asset.symbol, balance: parseFloat(res.formatted) || 0 };
        } catch {
          return { symbol: asset.symbol, balance: null };
        }
      })
    );

    const balMap: Record<string, number | null> = {};
    for (const r of results) {
      if (r.status === 'fulfilled') balMap[r.value.symbol] = r.value.balance;
    }
    setSwapExtBalances(balMap);
    setSwapBalFetching(false);
  }

  function flipSwapAssets() {
    setSwapFrom(swapTo);
    setSwapTo(swapFrom);
    setSwapAmount('');
    setCnEstError('');
    setCnMinAmount(0);
  }

  // True when both assets are external (non-ego) → use ChangeNow real API
  const useChangenow = !swapFrom.is_ego && !swapTo.is_ego;

  // ChangeNow live estimate — fires whenever amount / pair changes (debounced 600ms)
  const [cnToAmount, setCnToAmount] = useState(0);
  useEffect(() => {
    if (!useChangenow || !showSwap) return;
    const amt = parseFloat(swapAmount);
    if (!amt || amt <= 0) { setCnToAmount(0); setCnEstError(''); return; }
    setCnEstLoading(true);
    setCnEstError('');
    const t = setTimeout(async () => {
      try {
        const res = await invoke<{ to_amount: number; min_amount: number; network_fee: number; network_fee_usd: number }>('changenow_estimate', {
          fromSymbol: swapFrom.symbol,
          toSymbol:   swapTo.symbol,
          fromAmount: amt,
        });
        setCnToAmount(res.to_amount);
        setCnMinAmount(res.min_amount);
        setCnNetworkFee(res.network_fee);
        setCnNetworkFeeUsd(res.network_fee_usd);
        setCnEstError('');
      } catch (e: any) {
        setCnToAmount(0);
        setCnEstError(String(e).replace(/^Error: /, ''));
      } finally {
        setCnEstLoading(false);
      }
    }, 600);
    return () => clearTimeout(t);
  }, [swapAmount, swapFrom.symbol, swapTo.symbol, useChangenow, showSwap]);

  // For non-CN pairs keep the local math output
  const swapOutput = useChangenow
    ? cnToAmount
    : (swapAmount ? calcSwapOutput(swapFrom, swapTo, parseFloat(swapAmount) || 0, swapRates) : 0);

  const fromUsdPrice = assetUsdPrice(swapFrom, swapRates);
  const toUsdPrice   = assetUsdPrice(swapTo,   swapRates);
  const swapUsdVal   = (parseFloat(swapAmount) || 0) * fromUsdPrice;

  // Balance for the "from" asset — EGOC from ledger, externals from live on-chain fetch
  const swapFromBalance: number | null = swapFrom.is_ego
    ? (swapFrom.id === 'egusd' ? (balance?.egusd ?? null) : (balance?.egoc ?? null))
    : (swapExtBalances[swapFrom.symbol] ?? null);
  const swapInsufficientBalance =
    swapFromBalance !== null &&
    parseFloat(swapAmount) > 0 &&
    parseFloat(swapAmount) > swapFromBalance;

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
    setTxHistoryError(p => ({ ...p, [chain]: '' }));
    try {
      const txs = await invoke<ExternalTx[]>('fetch_chain_transactions', {
        chainSymbol: symbol, address, contract: null,
      });
      setTxHistory(p => ({ ...p, [chain]: txs }));
    } catch (e: any) {
      setTxHistory(p => ({ ...p, [chain]: [] }));
      setTxHistoryError(p => ({ ...p, [chain]: String(e) }));
    } finally {
      setLoadingTx(p => ({ ...p, [chain]: false }));
    }
  }

  function toggleTxHistory(chain: string, address: string, symbol: string) {
    if (expandedTx === chain) { setExpandedTx(null); return; }
    setExpandedTx(chain);
    // Always re-fetch when opening (don't cache stale empty results)
    fetchTxHistory(chain, address, symbol);
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

  async function openExtSend(info: NonNullable<typeof extSend>) {
    setExtSend(info);
    setExtSendTo(''); setExtSendAmount(''); setExtSendTxid('');
    setExtSendError(''); setExtSendFee('');
    setExtEmailStep('form'); setExtTxId(''); setExtMaskedEmail('');
    setExtOtp(['', '', '', '', '', '']); setExtCodeInput(''); setExtCodeError('');
    if (!info) return;
    fetchBalance(info.chain, info.address, info.symbol, info.contract ?? undefined);
    invoke<Record<string, number>>('fetch_swap_rates').then(setSwapRates).catch(() => {});
    setExtSendFeeLoading(true);
    try {
      const fee = await invoke<string>('estimate_external_fee', {
        chainSymbol: info.symbol, contract: info.contract ?? null,
      });
      setExtSendFee(fee);
    } catch { setExtSendFee(''); }
    setExtSendFeeLoading(false);
  }

  async function doExtSend() {
    if (!extSend || !extSendTo.trim() || !extSendAmount.trim()) return;
    setExtSending(true); setExtSendError(''); setExtSendTxid('');
    try {
      const txid = await invoke<string>('send_external_tx', {
        chainSymbol: extSend.symbol,
        toAddress:   extSendTo.trim(),
        amountStr:   extSendAmount.trim(),
        contract:    extSend.contract ?? null,
        decimals:    extSend.decimals ?? null,
      });
      setExtSendTxid(txid);
    } catch (e: any) {
      setExtSendError(String(e).replace(/^.*Error:/, '').trim());
    } finally {
      setExtSending(false);
    }
  }

  function handleExtOtpInput(i: number, val: string) {
    const v = val.replace(/[^0-9a-zA-Z]/g, '').slice(-1).toUpperCase();
    const next = [...extOtp]; next[i] = v; setExtOtp(next);
    setExtCodeInput(next.join('')); setExtCodeError('');
    if (v && i < 5) extOtpRefs.current[i + 1]?.focus();
  }

  function handleExtOtpKeyDown(i: number, e: React.KeyboardEvent) {
    if (e.key === 'Backspace' && !extOtp[i] && i > 0) extOtpRefs.current[i - 1]?.focus();
    if (e.key === 'Enter' && extOtp.join('').length === 6) handleExtConfirmCode();
  }

  async function handleExtConfirmCode() {
    if (extCodeInput.length !== 6) return;
    setExtCodeLoading(true); setExtCodeError('');
    try {
      const timeout = new Promise<never>((_, reject) =>
        setTimeout(() => reject('Verification timed out. Please check your transaction history.'), 30_000)
      );
      const txid = await Promise.race([
        invoke<string>('confirm_ext_tx', { txId: extTxId, code: extCodeInput }),
        timeout,
      ]);
      setExtSendTxid(txid);
      setExtEmailStep('form');
    } catch (e: any) {
      const msg = String(e).replace(/^.*Error:/, '').trim();
      setExtCodeError(msg);
      if (msg.includes('cancelled') || msg.includes('expired')) {
        setExtEmailStep('form');
      }
    } finally {
      setExtCodeLoading(false);
    }
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
    // Hide internal protocol txs (e.g. validator BLS-key registration) — they're
    // not user transfers and only confuse the wallet history.
    if (tx.tx_type === 'validator_register') return false;
    if (tab === 'sent')     return tx.from === myAddress;
    if (tab === 'received') return tx.to === myAddress;
    return true;
  });
  const pagedTxs = filteredTxs.slice((txPage - 1) * txPageSize, txPage * txPageSize);

  const egocBal  = balance ? balance.egoc : (wallet ? wallet.balance_uegoc / 1_000_000 : 0);
  const formatted = balance?.formatted ?? wallet?.balance_formatted ?? '—';
  const fiatBal   = (egocBal * FIAT_RATE).toLocaleString('en-US', { style: 'currency', currency: 'USD' });

  return (
    <div className="p-6 max-w-3xl mx-auto space-y-5">
      {}
      <div className={`rounded-2xl p-6 shadow-xl transition-all duration-500 ${isLiveMode ? 'bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 border border-gray-700' : 'bg-gradient-to-br from-blue-600 via-blue-700 to-purple-700'}`}>
        <div className="flex justify-between items-start mb-4">
          <div>
            <div className={`text-xs mb-1 ${isLiveMode ? 'text-gray-400' : 'text-blue-200'}`}>Total Balance</div>
            <div className="flex items-baseline gap-2">
              <div className="text-4xl font-black tracking-tight">
                {isLiveMode ? '0.00 EGOC' : formatted}
              </div>
            </div>
            <div className={`text-sm mt-1 ${isLiveMode ? 'text-gray-500' : 'text-blue-300'}`}>
              {isLiveMode ? '≈ $0.00 USD' : `≈ ${fiatBal} USD`}
            </div>
            {!isLiveMode && balance && balance.pending_out_uegoc > 0 && (
              <div className="text-xs mt-1 text-yellow-300 font-medium">
                {(balance.pending_out_uegoc / 1_000_000).toFixed(2)} EGOC pending · available {((balance.uegoc - balance.pending_out_uegoc) / 1_000_000).toFixed(2)} EGOC
              </div>
            )}
            {!isLiveMode && creditsBal && (
              <div className="text-xs mt-1 text-emerald-300 font-medium">
                {creditsBal.usd_value.toFixed(2)} EGUSD · stable ≡ ${creditsBal.usd_value.toFixed(2)}
              </div>
            )}
          </div>

          {/* Network + flip button */}
          <div className="flex flex-col items-end gap-1.5">
            <button
              onClick={async () => {
                const next = !isLiveMode;
                setIsLiveMode(next);
                if (next && !mainnetAddress) {
                  try {
                    const addr = await invoke<string>('get_mainnet_address');
                    setMainnetAddress(addr);
                  } catch {}
                }
              }}
              title="Switch network view"
              className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-xl border text-xs font-bold transition-all ${
                isLiveMode
                  ? 'bg-green-500/10 border-green-500/40 text-green-400 hover:bg-green-500/20'
                  : 'bg-yellow-400/10 border-yellow-400/30 text-yellow-300 hover:bg-yellow-400/20'
              }`}
            >
              <svg width="12" height="12" viewBox="0 0 12 12" fill="none" className="shrink-0">
                <path d="M2 4h8M2 4l2-2M2 4l2 2M10 8H2M10 8l-2-2M10 8l-2 2" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round"/>
              </svg>
              {isLiveMode ? '🟢 Mainnet' : '🟡 Testnet'}
            </button>
            <div className={`text-xs text-right ${isLiveMode ? 'text-gray-500' : 'text-blue-300'}`}>
              {isLiveMode ? 'Coming soon' : 'Ego Chain · v0.1.0'}
            </div>
          </div>
        </div>

        {!isLiveMode && (
          <div className="rounded-lg px-3 py-2 mb-5 font-mono text-xs truncate bg-white/10 text-blue-100">
            {myAddress || 'Loading address…'}
          </div>
        )}
        {isLiveMode && <div className="mb-5" />}

        <div className="grid grid-cols-4 gap-2">
          {[
            {
              label: '↑ Send',
              live: false,
              action: () => { setShowSend(true); setTxResult(null); invoke<{ fee_uegoc: number; fee_usd: number }>('get_tx_fee', { txType: 'transfer' }).then(setTxFee).catch(() => {}); }
            },
            { label: '↓ Receive', live: false, action: () => setShowReceive(true) },
            { label: '⇄ Swap',   live: true,  action: openSwap },
            {
              label: '$ EGUSD',
              live: false,
              action: () => {
                setCreditsMsg(null);
                setCreditsAmt('');
                setShowCredits(true);
                invoke<{ credits: number; usd_value: number; egoc_price_usd: number }>('get_credits_balance')
                  .then(setCreditsBal).catch(() => {});
              },
            },
          ].map(btn => {
            const disabled = isLiveMode && !btn.live;
            return (
              <button
                key={btn.label}
                onClick={disabled ? undefined : btn.action}
                title={disabled ? 'Not available on testnet' : undefined}
                className={`transition rounded-xl py-2.5 text-sm font-semibold ${
                  disabled
                    ? 'bg-white/5 text-white/30 cursor-not-allowed'
                    : 'bg-white/20 hover:bg-white/30'
                }`}
              >
                {disabled ? btn.label.split(' ')[1] + ' —' : btn.label}
              </button>
            );
          })}
          {/* Pre-Sale — animated gradient button */}
          <button
            onClick={openPresale}
            className="relative rounded-xl py-2.5 text-sm font-bold overflow-hidden"
            style={{ color: '#fff' }}
          >
            <span
              className="absolute inset-0 rounded-xl"
              style={{
                background: 'linear-gradient(270deg, #6366f1, #a855f7, #ec4899, #f59e0b, #a855f7, #6366f1)',
                backgroundSize: '300% 300%',
                animation: 'presaleBtnShift 3s ease infinite',
              }}
            />
            <span className="relative z-10 drop-shadow-sm">Pre-Sale</span>
          </button>
        </div>
        <style>{`
          @keyframes presaleBtnShift {
            0%   { background-position: 0% 50%; }
            50%  { background-position: 100% 50%; }
            100% { background-position: 0% 50%; }
          }
        `}</style>
      </div>

      {}
      <div className="bg-gray-800/60 rounded-2xl border border-gray-700/50 overflow-hidden">
        <button
          onClick={() => setShowAddresses(v => !v)}
          className="w-full flex items-center justify-between px-5 py-4 hover:bg-gray-700/30 transition"
        >
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-xl bg-indigo-500/15 flex items-center justify-center text-lg">🌐</div>
            <div className="text-left">
              <div className="flex items-center gap-2">
                <span className="font-semibold text-sm">Multi-Chain Wallet</span>
              </div>
              <div className="text-xs text-gray-400">
                BTC · ETH · BNB · SOL · ADA · TRX · USDT
              </div>
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
                {}
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
                            <span className="text-yellow-400 text-[9px] font-bold bg-yellow-400/15 px-1 py-px rounded">TESTNET</span>
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

                {!hiddenChains.has('EGOC_MAIN') && (
                  <div className="bg-gray-900/60 rounded-xl overflow-hidden border border-gray-700/40">
                    <div className="flex items-center justify-between px-4 py-3 gap-3">
                      <div className="flex items-center gap-3 min-w-0">
                        <div className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0 overflow-hidden" style={{ background: '#1a56ff22' }}>
                          <img src="/egoc.png" alt="EGOC" className="w-6 h-6 rounded-full object-cover" />
                        </div>
                        <div className="min-w-0">
                          <div className="flex items-center gap-1.5">
                            <span className="text-sm font-semibold">EGOC</span>
                            <span className="text-green-400 text-[9px] font-bold bg-green-400/15 px-1 py-px rounded">MAINNET</span>
                          </div>
                          <div className="text-xs text-gray-500 truncate">Address available at launch</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2 shrink-0">
                        <span className="text-xs px-2 py-1 rounded-lg bg-gray-700/60 text-gray-500">Coming soon</span>
                        <button onClick={() => hideChain('EGOC_MAIN')} className="text-xs px-2 py-1 rounded-lg bg-red-500/10 hover:bg-red-500/20 text-red-400 transition" title="Hide">✕</button>
                      </div>
                    </div>
                  </div>
                )}

                {}

                {}
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
                        {}
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
                              onClick={() => openExtSend({ chain: addr.chain, symbol: addr.symbol, address: addr.address, contract: addr.contract, color: addr.color, icon: addr.icon, balanceKey: balKey, explorerPrefix: addr.explorer_prefix })}
                              className="text-xs px-2 py-1 rounded-lg bg-blue-600/20 hover:bg-blue-600/40 text-blue-400 hover:text-blue-300 transition"
                              title="Send"
                            >
                              ↑ Send
                            </button>
                            <button
                              onClick={() => toggleTxHistory(addr.chain, addr.address, addr.symbol)}
                              className="text-xs px-2 py-1 rounded-lg bg-gray-700/60 hover:bg-gray-700 transition"
                              title="Transaction history"
                            >
                              {expandedTx === addr.chain ? '▲' : '🕐'}
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

                        {}
                        {expandedTx === addr.chain && (
                          <div className="border-t border-gray-700/40 px-4 py-3 space-y-2">
                            {loadingTx[addr.chain] ? (
                              <div className="text-xs text-gray-400">Loading history…</div>
                            ) : (
                              <>
                                {txHistoryError[addr.chain] && (
                                  <div className="text-xs text-red-400 mb-2">{txHistoryError[addr.chain]}</div>
                                )}
                                {(txHistory[addr.chain] ?? []).length === 0 ? (
                                  <div className="text-xs text-gray-500 mb-2">No cached transactions.</div>
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
                                <a
                                  href={`${addr.explorer_prefix}${addr.address}`}
                                  target="_blank"
                                  rel="noreferrer"
                                  className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 transition pt-1"
                                >
                                  View full history on {addr.chain === 'BNB Chain' ? 'BscScan' : addr.chain === 'Ethereum' ? 'Etherscan' : addr.chain === 'Solana' ? 'Solscan' : addr.chain === 'XRP' ? 'XRPScan' : addr.chain === 'Tron' ? 'Tronscan' : addr.chain === 'Litecoin' ? 'Litecoin Explorer' : addr.chain === 'Dogecoin' ? 'Dogechain' : addr.chain === 'Cardano' ? 'Cardanoscan' : 'Explorer'} ↗
                                </a>
                              </>
                            )}
                          </div>
                        )}

                        {}
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
                                {tokAddr && (
                                  <button
                                    onClick={() => openExtSend({ chain: tok.chain, symbol: tok.symbol, address: tokAddr, contract: tok.contract, decimals: tok.decimals, color: tok.color, icon: tok.icon, balanceKey: tokKey, explorerPrefix: extAddresses.find(a => a.symbol === tok.chain_symbol)?.explorer_prefix ?? '' })}
                                    className="text-xs px-2 py-1 rounded-lg bg-blue-600/20 hover:bg-blue-600/40 text-blue-400 hover:text-blue-300 transition"
                                    title="Send"
                                  >
                                    ↑
                                  </button>
                                )}
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

            {}
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

      {}
      <div className="bg-gray-800 rounded-2xl overflow-hidden border border-gray-700">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-700">
          <h3 className="font-semibold">Transactions</h3>
          <div className="flex items-center gap-2">
            {txs.some(tx => tx.status === 'Pending' || tx.status === 'Confirming (0/3)') && (
              <button
                onClick={handleClearPending}
                disabled={clearingPending}
                className="px-3 py-1 rounded-lg text-xs text-yellow-400 border border-yellow-500/30 hover:bg-yellow-500/10 disabled:opacity-40 transition"
              >
                {clearingPending ? 'Clearing…' : 'Clear Pending'}
              </button>
            )}
            <div className="flex gap-1">
              {(['all', 'sent', 'received'] as const).map(t => (
                <button
                  key={t}
                  onClick={() => { setTab(t); setTxPage(1); }}
                  className={`px-3 py-1 rounded-lg text-xs capitalize transition ${
                    tab === t
                      ? 'bg-blue-600 text-white'
                      : 'text-gray-400 hover:bg-gray-700'
                  }`}
                >
                  {t}
                </button>
              ))}
            </div>
          </div>
        </div>

        {filteredTxs.length === 0 ? (
          <div className="py-12 text-center text-gray-500">
            <div className="text-4xl mb-3">📋</div>
            <div className="text-sm">No transactions yet</div>
            <div className="text-xs mt-1 text-gray-600">
              Send your first transaction to get started
            </div>
          </div>
        ) : (
          <>
          <div className="divide-y divide-gray-700/50">
            {pagedTxs.map(tx => {
              const isReward = isRewardTx(tx);
              const isSent = !isReward && tx.from === myAddress;
              const rewardLabel = tx.tx_type === 'coinbase' ? 'Block Reward'
                : tx.from.startsWith('egot1staking') ? 'Staking Reward'
                : (tx.from.startsWith('egot1faucet') || tx.tx_type === 'faucet') ? 'Test Coins'
                : 'Mining Reward';
              return (
                <button
                  key={tx.hash}
                  onClick={() => setSelectedTx(tx)}
                  className={`w-full flex items-center justify-between px-5 py-4 hover:bg-gray-700/40 transition text-left ${tx.is_private ? 'bg-yellow-500/5' : ''}`}
                >
                  <div className="flex items-center gap-3 min-w-0">
                    <div className={`w-10 h-10 rounded-xl flex items-center justify-center text-lg shrink-0 ${
                      tx.is_private ? 'bg-yellow-500/20 text-yellow-500' : isReward ? 'bg-yellow-500/15' : isSent ? 'bg-red-500/15' : 'bg-green-500/15'
                    }`}>
                      {tx.is_private ? '🛡' : isReward ? '⚡' : isSent ? '↑' : '↓'}
                    </div>
                    <div className="min-w-0">
                      <div className="text-sm font-mono text-gray-300 truncate">
                        {tx.is_private ? <span className="text-yellow-400 font-bold">Shielded · {isSent ? 'Sent' : 'Received'}</span> : (isReward ? rewardLabel : shortHash(tx.hash))}
                      </div>
                      <div className="text-xs text-gray-500">
                        {isReward
                          ? `Block #${tx.block_height ?? '—'}` : tx.is_private ? 'On-chain identities hidden'
                          : isSent ? `To: ${shortAddr(tx.to)}` : `From: ${shortAddr(tx.from)}`}
                        {tx.memo && <span className="ml-2 text-gray-600">• {tx.memo}</span>}
                      </div>
                    </div>
                  </div>
                  <div className="text-right shrink-0 ml-3">
                    <div className={`text-sm font-semibold ${isReward ? 'text-yellow-400' : isSent ? 'text-red-400' : 'text-green-400'}`}>
                      {isSent ? '-' : '+'}{(tx.amount / 1_000_000).toFixed(2)} EGOC
                    </div>
                    <div className="flex items-center justify-end gap-1.5 mt-0.5">
                      <span className={`inline-block w-1.5 h-1.5 rounded-full ${
                        tx.status === 'Confirmed' ? 'bg-green-400' :
                        (tx.status === 'Pending' || tx.status.startsWith('Confirming')) ? 'bg-yellow-400' : 'bg-red-400'
                      }`}></span>
                      <span className="text-xs text-gray-500">{formatAgo(tx.timestamp)}</span>
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
          <Pagination
            total={filteredTxs.length}
            page={txPage}
            pageSize={txPageSize}
            onPage={setTxPage}
            onPageSize={ps => { setTxPageSize(ps); setTxPage(1); }}
          />
          </>
        )}
      </div>

      {presaleRecords.length > 0 && (
        <div className="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
          <button
            onClick={() => setShowPresaleRecords(o => !o)}
            className="w-full flex items-center justify-between px-5 py-4 hover:bg-gray-700/40 transition"
          >
            <div className="flex items-center gap-3">
              <div className="w-9 h-9 rounded-xl bg-purple-500/15 flex items-center justify-center text-lg">🪙</div>
              <div className="text-left">
                <div className="text-sm font-semibold">Pre-Sale Records</div>
                <div className="text-xs text-gray-400">{presaleRecords.length} purchase{presaleRecords.length !== 1 ? 's' : ''}</div>
              </div>
            </div>
            <span className="text-gray-500 text-xs">{showPresaleRecords ? '▲' : '▼'}</span>
          </button>
          {showPresaleRecords && (
            <div className="divide-y divide-gray-700/50 border-t border-gray-700/50">
              {presaleRecords.map((r: any) => (
                <div key={r.id} className="px-5 py-4 flex items-center justify-between gap-3">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="w-9 h-9 rounded-xl bg-blue-500/10 flex items-center justify-center text-sm font-bold text-blue-300 shrink-0">
                      {r.pay_symbol}
                    </div>
                    <div className="min-w-0">
                      <div className="text-sm font-semibold text-white">
                        {r.egoc_amount.toLocaleString(undefined, { maximumFractionDigits: 2 })} EGOC
                      </div>
                      <div className="text-xs text-gray-400">
                        Paid {r.pay_amount} {r.pay_symbol} · ${r.usd_value.toFixed(2)} USD
                      </div>
                      <div className="text-xs text-gray-500 font-mono truncate mt-0.5">{r.deposit_address}</div>
                    </div>
                  </div>
                  <div className="shrink-0 text-right">
                    <span className={`inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-xs font-semibold ${
                      r.status === 'confirmed'
                        ? 'bg-green-500/15 text-green-400'
                        : 'bg-yellow-500/15 text-yellow-400'
                    }`}>
                      <span className={`w-1.5 h-1.5 rounded-full ${r.status === 'confirmed' ? 'bg-green-400' : 'bg-yellow-400'}`}></span>
                      {r.status === 'confirmed' ? 'Confirmed' : 'Pending'}
                    </span>
                    <div className="text-xs text-gray-600 mt-1">
                      {new Date(r.timestamp * 1000).toLocaleDateString()}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {showPresale && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm" onClick={e => { if (e.target === e.currentTarget) setShowPresale(false); }}>
          <div className="bg-gray-800 rounded-2xl w-full max-w-4xl border border-gray-700 shadow-2xl overflow-hidden">

            {/* Header */}
            <div className="bg-gradient-to-r from-blue-900/60 to-purple-900/60 px-6 py-4 border-b border-gray-700/50 flex items-center justify-between gap-6">
              <div className="flex items-center gap-3 min-w-0">
                <img src="/egoc.png" className="w-8 h-8 rounded-full shrink-0" onError={e => { (e.target as HTMLImageElement).style.display = 'none'; }} />
                <div className="min-w-0">
                  <div className="flex items-center gap-2">
                    <h3 className="text-base font-bold">EGOC Pre-Sale</h3>
                    <span className="text-[9px] font-bold bg-yellow-400/20 text-yellow-300 px-1.5 py-px rounded border border-yellow-400/30 shrink-0">TIER {ACTIVE_TIER_IDX + 1} / {PRESALE_TIERS.length}</span>
                    <span className="text-[9px] font-bold bg-red-500/20 text-red-400 px-1.5 py-px rounded border border-red-500/30 shrink-0 animate-pulse">⏳ {ACTIVE_TIER.label.toUpperCase()}</span>
                  </div>
                  <p className="text-xs text-gray-400">Before Genesis Block · Encrypted IOU · <span className="text-green-400 font-semibold">{ACTIVE_TIER.discount}% off launch — price rises each round</span></p>
                </div>
              </div>
              {/* Price + tier ladder */}
              <div className="flex items-center gap-4 shrink-0">
                <div className="text-right">
                  <div className="text-xs text-gray-400">Your price</div>
                  <div className="text-xl font-black text-green-400">${ACTIVE_TIER.price.toFixed(2)}<span className="text-xs font-normal text-gray-400 ml-1">/ EGOC</span></div>
                  <div className="text-[10px] text-green-400 font-bold">↓{ACTIVE_TIER.discount}% off launch (${PRESALE_LAUNCH_PRICE.toFixed(2)})</div>
                </div>
                <div className="hidden sm:flex flex-col gap-0.5">
                  {PRESALE_TIERS.map((t, i) => (
                    <div key={t.label} className={`flex items-center gap-1.5 text-[10px] rounded px-1.5 py-0.5 ${i === ACTIVE_TIER_IDX ? 'bg-green-500/20 text-green-300 font-bold' : i < ACTIVE_TIER_IDX ? 'text-gray-600 line-through' : 'text-gray-500'}`}>
                      <span>{i === ACTIVE_TIER_IDX ? '▶' : i < ACTIVE_TIER_IDX ? '✓' : '○'}</span>
                      <span>{t.label}</span>
                      <span className="font-semibold">${t.price.toFixed(2)}</span>
                      <span className="text-[9px] opacity-70">({(t.cap / 1_000_000).toFixed(0)}M)</span>
                    </div>
                  ))}
                </div>
                <button onClick={() => setShowPresale(false)} className="text-gray-400 hover:text-white text-lg leading-none ml-2">✕</button>
              </div>
            </div>

            {/* Step indicator */}
            <div className="flex items-center gap-1 px-6 pt-3 pb-0">
              {(['buy', 'deposit', 'done'] as const).map((s, i) => (
                <div key={s} className="flex items-center gap-1">
                  <div className={`w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold transition-colors ${presaleStep === s ? 'bg-blue-600 text-white' : i < ['buy','deposit','done'].indexOf(presaleStep) ? 'bg-green-600 text-white' : 'bg-gray-700 text-gray-500'}`}>{i+1}</div>
                  <span className={`text-[10px] ${presaleStep === s ? 'text-white' : 'text-gray-500'}`}>{['Amount & Password', presalePayMethod === 'card' ? 'Download IOU' : 'Send Payment', 'Done'][i]}</span>
                  {i < 2 && <div className="w-6 h-px bg-gray-600 mx-1" />}
                </div>
              ))}
            </div>

            <div className="p-6 pt-4">
              {/* ── Step 1: Amount + password ── */}
              {presaleStep === 'buy' && (
                <>
                  {/* Payment method tabs */}
                  <div className="flex gap-1 mb-4 bg-gray-900 rounded-xl p-1">
                    {(['crypto', 'card'] as const).map(m => (
                      <button
                        key={m}
                        onClick={() => { setPresalePayMethod(m); setStripeError(''); setStripeSessionId(''); setStripeVerified(false); }}
                        className={`flex-1 py-1.5 rounded-lg text-xs font-semibold transition ${presalePayMethod === m ? 'bg-gray-700 text-white' : 'text-gray-500 hover:text-gray-300'}`}
                      >
                        {m === 'crypto' ? '🪙 Crypto' : '💳 Card / Apple Pay'}
                      </button>
                    ))}
                  </div>

                  <div className="grid grid-cols-2 gap-4">
                    {/* Left col — crypto or card */}
                    {presalePayMethod === 'crypto' ? (
                      <div className="space-y-3">
                        <div className="bg-blue-900/20 border border-blue-500/20 rounded-xl p-3 text-xs text-blue-300">
                          <div className="font-semibold text-blue-200 mb-1">How it works</div>
                          No EGOC exist yet. You get an <strong>encrypted IOU file</strong>. When Ego Chain launches, every IOU is written into the Genesis Block and EGOC minted to your mainnet address.
                        </div>

                        {/* Pay with */}
                        <div className="bg-gray-900 rounded-xl p-3">
                          <div className="flex items-center justify-between mb-2">
                            <div className="text-xs text-gray-400">Pay with</div>
                            <div className="text-xs text-gray-500">
                              Balance:{' '}
                              {presalePayBalLoading
                                ? <span className="text-gray-600">checking…</span>
                                : presalePayBal !== null
                                  ? <span className={presalePayBal === 0 ? 'text-red-400' : 'text-gray-300'}>{presalePayBal} {presalePayAsset.symbol}</span>
                                  : <span className="text-gray-600">—</span>}
                            </div>
                          </div>
                          <div className="flex gap-2 items-center">
                            <div className="relative shrink-0">
                              <select
                                value={presalePayAsset.id}
                                onChange={e => {
                                  const a = SWAP_ASSETS.find(x => x.id === e.target.value)!;
                                  setPresalePayAsset(a);
                                  setPresalePayAmount('');
                                  setPresaleOutput(0);
                                  fetchPresalePayBal(a);
                                }}
                                className="bg-gray-700 rounded-lg pl-8 pr-2 py-1.5 text-sm font-semibold focus:outline-none appearance-none max-w-[130px]"
                              >
                                {SWAP_ASSETS.filter(a => a.presale).map(a => (
                                  <option key={a.id} value={a.id}>{a.symbol} — {a.name}</option>
                                ))}
                              </select>
                              <div className="pointer-events-none absolute left-1.5 top-1/2 -translate-y-1/2">
                                <AssetIcon asset={presalePayAsset} size={18} />
                              </div>
                            </div>
                            <input
                              type="number" min="0"
                              value={presalePayAmount}
                              onChange={e => {
                                setPresalePayAmount(e.target.value);
                                setPresaleOutput(calcPresaleOutput(presalePayAsset.symbol, parseFloat(e.target.value) || 0, presaleRates));
                              }}
                              placeholder="0.00"
                              className="flex-1 min-w-0 w-0 bg-transparent text-xl font-bold outline-none text-right [appearance:textfield] [&::-webkit-outer-spin-button]:appearance-none [&::-webkit-inner-spin-button]:appearance-none"
                            />
                          </div>
                          {(() => {
                            const amt = parseFloat(presalePayAmount) || 0;
                            const asset = SWAP_ASSETS.find(a => a.symbol === presalePayAsset.symbol);
                            const usd = amt * (asset ? assetUsdPrice(asset, presaleRates) : 0);
                            const insufficient = presalePayBal !== null && amt > 0 && amt > presalePayBal;
                            return (
                              <div className="mt-1 flex justify-between text-xs">
                                {insufficient
                                  ? <span className="text-red-400">Insufficient balance</span>
                                  : <span />}
                                {usd > 0 && <span className="text-gray-500">≈ ${usd.toFixed(2)} USD</span>}
                              </div>
                            );
                          })()}
                        </div>

                        {/* You receive */}
                        <div className="bg-gray-900 rounded-xl p-3">
                          <div className="text-xs text-gray-400 mb-0.5">You receive (IOU)</div>
                          <div className="text-xl font-bold text-green-400">{presaleOutput > 0 ? presaleOutput.toLocaleString('en-US', { maximumFractionDigits: 4 }) : '—'} EGOC</div>
                          {presaleOutput > 0 && <div className="text-xs text-gray-500 mt-0.5">Credited at Genesis Block</div>}
                        </div>
                      </div>
                    ) : (
                      /* Card / Apple Pay left col */
                      <div className="space-y-3">
                        <div className="bg-blue-900/20 border border-blue-500/20 rounded-xl p-3 text-xs text-blue-300">
                          <div className="font-semibold text-blue-200 mb-1">Pay with card or Apple Pay</div>
                          Checkout via Stripe. You get the same encrypted IOU file. EGOC minted at Genesis Block launch.
                        </div>

                        <div className="bg-gray-900 rounded-xl p-3 space-y-2">
                          <div className="text-xs text-gray-400">Amount (USD)</div>
                          <div className="flex items-center gap-2">
                            <span className="text-gray-400 text-lg font-bold">$</span>
                            <input
                              type="number" min="10"
                              value={presaleCardUsd}
                              onChange={e => {
                                setPresaleCardUsd(e.target.value);
                                const usd = parseFloat(e.target.value) || 0;
                                setPresaleOutput(usd > 0 ? Math.floor((usd / ACTIVE_TIER.price) * 100) / 100 : 0);
                              }}
                              placeholder="100"
                              className="flex-1 bg-transparent text-xl font-bold outline-none [appearance:textfield] [&::-webkit-outer-spin-button]:appearance-none [&::-webkit-inner-spin-button]:appearance-none"
                            />
                            <span className="text-xs text-gray-500">USD</span>
                          </div>
                          <div className="text-xs text-gray-500">Minimum $10 · ${ACTIVE_TIER.price.toFixed(2)} / EGOC · {ACTIVE_TIER.discount}% off launch</div>
                        </div>

                        <div className="bg-gray-900 rounded-xl p-3">
                          <div className="text-xs text-gray-400 mb-0.5">You receive (IOU)</div>
                          <div className="text-xl font-bold text-green-400">{presaleOutput > 0 ? presaleOutput.toLocaleString('en-US', { maximumFractionDigits: 4 }) : '—'} EGOC</div>
                          {presaleOutput > 0 && <div className="text-xs text-gray-500 mt-0.5">Credited at Genesis Block</div>}
                        </div>

                        {stripeError && <div className="text-xs text-red-400">{stripeError}</div>}

                        {!stripeSessionId ? (
                          <button
                            onClick={async () => {
                              const usd = parseFloat(presaleCardUsd) || 0;
                              if (usd < 10) { setStripeError('Minimum $10'); return; }
                              setPresaleLoading(true); setStripeError('');
                              try {
                                const sess = await invoke<{ session_id: string; checkout_url: string; egoc_amount: number }>('presale_stripe_checkout', {
                                  egocAmount: presaleOutput,
                                  usdAmount: usd,
                                });
                                setStripeSessionId(sess.session_id);
                                const { open } = await import('@tauri-apps/api/shell');
                                await open(sess.checkout_url);
                              } catch (e: any) { setStripeError(String(e).replace(/^Error: /, '')); }
                              finally { setPresaleLoading(false); }
                            }}
                            disabled={!presaleCardUsd || (parseFloat(presaleCardUsd) || 0) < 10 || presaleLoading}
                            className="w-full py-2.5 rounded-xl font-semibold text-sm bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 disabled:cursor-not-allowed transition"
                          >
                            {presaleLoading ? 'Opening Stripe…' : 'Checkout with Stripe →'}
                          </button>
                        ) : (
                          <div className="space-y-2">
                            <div className="text-xs text-yellow-300 bg-yellow-500/10 border border-yellow-500/20 rounded-xl p-2">
                              Browser checkout opened. Complete payment then click Verify below.
                            </div>
                            <button
                              onClick={async () => {
                                setStripeVerifying(true); setStripeError('');
                                try {
                                  const result = await invoke<{ paid: boolean; status: string; egoc_amount: number }>('presale_stripe_verify', { sessionId: stripeSessionId });
                                  if (!result.paid) { setStripeError(`Payment not confirmed yet (status: ${result.status}). Try again in a moment.`); return; }
                                  setStripeVerified(true);
                                } catch (e: any) { setStripeError(String(e).replace(/^Error: /, '')); }
                                finally { setStripeVerifying(false); }
                              }}
                              disabled={stripeVerifying}
                              className="w-full py-2 rounded-xl font-semibold text-sm bg-green-700 hover:bg-green-600 disabled:opacity-40 transition"
                            >
                              {stripeVerifying ? 'Verifying…' : '✓ Verify Payment'}
                            </button>
                            {stripeVerified && (
                              <div className="text-xs text-green-400 font-semibold text-center">Payment confirmed! Set your password →</div>
                            )}
                          </div>
                        )}
                      </div>
                    )}

                    {/* Right col — password (same for both methods) */}
                    <div className="space-y-3">
                      <div className="bg-gray-900 rounded-xl p-3 space-y-2 h-full flex flex-col justify-between">
                        <div>
                          <div className="text-xs font-semibold text-gray-300 mb-1">IOU Encryption Password</div>
                          <div className="text-xs text-gray-500 mb-3">Encrypts your IOU file. <strong className="text-yellow-300">Keep it — losing it means losing your claim.</strong></div>
                          <input
                            type="password"
                            value={presalePassword}
                            onChange={e => setPresalePassword(e.target.value)}
                            placeholder="Strong password…"
                            className="w-full bg-gray-700 rounded-lg px-3 py-2 text-sm outline-none focus:ring-1 focus:ring-blue-500 mb-2"
                          />
                          <input
                            type="password"
                            value={presalePassword2}
                            onChange={e => setPresalePassword2(e.target.value)}
                            placeholder="Confirm password…"
                            className="w-full bg-gray-700 rounded-lg px-3 py-2 text-sm outline-none focus:ring-1 focus:ring-blue-500"
                          />
                          {presalePassword && presalePassword2 && presalePassword !== presalePassword2 && (
                            <div className="text-xs text-red-400 mt-1">Passwords do not match</div>
                          )}
                        </div>
                        {presaleError && <div className="text-xs text-red-400 mt-2">{presaleError}</div>}
                        {presalePayMethod === 'crypto' ? (
                          <button
                            onClick={async () => {
                              if (!presalePayAmount || presaleOutput <= 0) return;
                              if (!presalePassword || presalePassword !== presalePassword2) return;
                              setPresaleLoading(true);
                              setPresaleError('');
                              try {
                                const asset = SWAP_ASSETS.find(a => a.symbol === presalePayAsset.symbol)!;
                                const usdPrice = assetUsdPrice(asset, presaleRates);
                                const iouJson = await invoke<string>('presale_create_iou', {
                                  paySymbol:   presalePayAsset.symbol,
                                  payAmount:   parseFloat(presalePayAmount),
                                  payUsdPrice: usdPrice,
                                  password:    presalePassword,
                                });
                                setPresaleIouJson(iouJson);
                                const iou = JSON.parse(iouJson);
                                const depAddr = iou.payment?.deposit_address ?? '';
                                setPresaleDepositAddr(depAddr);
                                setPresaleAddrBal(null);
                                setPresaleStep('deposit');
                                if (depAddr && !depAddr.startsWith('—')) {
                                  setPresaleAddrBalLoading(true);
                                  invoke<{ formatted: string }>('fetch_chain_balance', {
                                    chainSymbol: presalePayAsset.symbol,
                                    address: depAddr,
                                    contract: null,
                                  }).then(r => setPresaleAddrBal(r.formatted)).catch(() => setPresaleAddrBal('0')).finally(() => setPresaleAddrBalLoading(false));
                                }
                              } catch (e: any) { setPresaleError(String(e).replace(/^Error: /, '')); }
                              finally { setPresaleLoading(false); }
                            }}
                            disabled={!presalePayAmount || presaleOutput <= 0 || !presalePassword || presalePassword !== presalePassword2 || presaleRatesLoading || presaleLoading || (presalePayBal !== null && (parseFloat(presalePayAmount) || 0) > presalePayBal)}
                            className="w-full mt-3 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 disabled:cursor-not-allowed py-2.5 rounded-xl font-semibold text-sm transition"
                          >
                            {presaleLoading ? 'Generating IOU…' : 'Generate IOU →'}
                          </button>
                        ) : (
                          <button
                            onClick={async () => {
                              if (!stripeVerified || !stripeSessionId) return;
                              if (!presalePassword || presalePassword !== presalePassword2) return;
                              setPresaleLoading(true); setPresaleError('');
                              try {
                                const iouJson = await invoke<string>('presale_stripe_create_iou', {
                                  sessionId: stripeSessionId,
                                  egocAmount: presaleOutput,
                                  usdAmount: parseFloat(presaleCardUsd) || 0,
                                  password: presalePassword,
                                });
                                setPresaleIouJson(iouJson);
                                setPresaleDepositAddr('');
                                setPresaleStep('deposit');
                              } catch (e: any) { setPresaleError(String(e).replace(/^Error: /, '')); }
                              finally { setPresaleLoading(false); }
                            }}
                            disabled={!stripeVerified || !stripeSessionId || !presalePassword || presalePassword !== presalePassword2 || presaleLoading}
                            className="w-full mt-3 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 disabled:cursor-not-allowed py-2.5 rounded-xl font-semibold text-sm transition"
                          >
                            {presaleLoading ? 'Generating IOU…' : 'Generate IOU →'}
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                </>
              )}

              {/* ── Step 2: Send + download IOU ── */}
              {presaleStep === 'deposit' && (
                <div className="grid grid-cols-2 gap-4">
                  {/* Left — download */}
                  <div className="space-y-3">
                    <div className="bg-green-900/20 border border-green-500/30 rounded-xl p-3 space-y-2">
                      <div className="text-sm font-semibold text-green-300">{presalePayMethod === 'card' ? '1 — Download IOU file' : '1 — Download IOU file'}</div>
                      <div className="text-xs text-gray-400">Your proof of purchase. Store it safely — it is the only way to claim your EGOC at launch.</div>
                      <button
                        onClick={() => {
                          const blob = new Blob([presaleIouJson], { type: 'application/json' });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url;
                          a.download = `ego-presale-iou--${Date.now()}.json`;
                          a.click();
                          URL.revokeObjectURL(url);
                        }}
                        className="w-full py-2 rounded-xl bg-green-600 hover:bg-green-500 font-semibold text-sm transition"
                      >
                        ⬇ Download IOU File
                      </button>
                    </div>
                    <div className="bg-gray-900/60 rounded-xl p-3 text-xs space-y-1">
                      <div className="font-semibold text-gray-300">Your allocation</div>
                      <div className="text-gray-400">{presaleOutput.toLocaleString('en-US', { maximumFractionDigits: 4 })} EGOC — credited at Genesis Block</div>
                      <div className="text-gray-500">Address assigned at mainnet launch</div>
                    </div>
                  </div>
                  {/* Right — send (crypto) or done (card) */}
                  <div className="space-y-3">
                    {presalePayMethod === 'card' ? (
                      <>
                        <div className="bg-green-900/20 border border-green-500/30 rounded-xl p-3 text-xs text-green-300 space-y-1">
                          <div className="font-semibold text-green-200 text-sm">Payment confirmed</div>
                          <div>Your card payment was processed by Stripe. Download your IOU file and keep it safe.</div>
                        </div>
                        <div className="bg-gray-900/60 rounded-xl p-3 text-xs space-y-1">
                          <div className="flex justify-between"><span className="text-gray-400">Paid</span><span>${presaleCardUsd} USD</span></div>
                          <div className="flex justify-between"><span className="text-gray-400">Stripe session</span><span className="font-mono text-gray-500 truncate max-w-[120px]">{stripeSessionId}</span></div>
                        </div>
                        <button onClick={() => setPresaleStep('done')} className="w-full py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 font-semibold text-sm transition">Continue →</button>
                      </>
                    ) : (
                      <>
                        <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-xl p-3 text-xs text-yellow-200">
                          <div className="font-semibold mb-1">2 — Send payment</div>
                          Send <strong>{presalePayAmount} {presalePayAsset.symbol}</strong> to reserve <strong>{presaleOutput.toLocaleString('en-US', { maximumFractionDigits: 4 })} EGOC</strong>.
                        </div>
                        <div className="bg-gray-900 rounded-xl p-3 space-y-2">
                          <div className="flex items-center justify-between">
                            <div className="text-xs text-gray-400">Deposit address — {presalePayAsset.symbol}</div>
                            <div className="text-xs font-mono">
                              {presaleAddrBalLoading
                                ? <span className="text-gray-500">checking…</span>
                                : presaleAddrBal !== null
                                  ? <span className={presaleAddrBal === '0' || presaleAddrBal.startsWith('0.') ? 'text-gray-500' : 'text-yellow-400'}>{presaleAddrBal} {presalePayAsset.symbol}</span>
                                  : null}
                            </div>
                          </div>
                          <div className="font-mono text-xs text-green-400 break-all leading-relaxed">{presaleDepositAddr}</div>
                          <button onClick={() => navigator.clipboard.writeText(presaleDepositAddr)} className="text-xs bg-gray-700 hover:bg-gray-600 px-3 py-1.5 rounded-lg transition">Copy</button>
                        </div>
                        {presaleError && <div className="text-xs text-red-400">{presaleError}</div>}
                        <div className="grid grid-cols-2 gap-2">
                          <button onClick={() => setPresaleStep('buy')} className="py-2.5 rounded-xl bg-gray-700 hover:bg-gray-600 font-semibold text-sm transition">← Back</button>
                          <button onClick={() => setPresaleStep('done')} className="py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 font-semibold text-sm transition">Sent →</button>
                        </div>
                      </>
                    )}
                  </div>
                </div>
              )}

              {/* ── Step 3: Done ── */}
              {presaleStep === 'done' && (
                <div className="grid grid-cols-2 gap-4 items-start">
                  <div className="space-y-3">
                    <div className="text-4xl">📄</div>
                    <div className="text-xl font-bold">IOU Reserved</div>
                    <div className="text-xs text-gray-400 bg-blue-900/20 border border-blue-500/20 rounded-xl p-3">
                      When Ego Chain launches, all pre-sale IOUs are included in the Genesis Block. Your IOU file + password are the only proof needed to claim your EGOC.
                    </div>
                  </div>
                  <div className="space-y-3">
                    <div className="bg-gray-900/60 rounded-xl p-3 text-sm space-y-2">
                      <div className="flex justify-between"><span className="text-gray-400">Allocation</span><span className="font-bold text-green-400">{presaleOutput.toLocaleString('en-US', { maximumFractionDigits: 4 })} EGOC</span></div>
                      {presalePayMethod === 'card'
                        ? <div className="flex justify-between"><span className="text-gray-400">Paid with</span><span>Card / Apple Pay (${presaleCardUsd} USD)</span></div>
                        : <div className="flex justify-between"><span className="text-gray-400">Paid with</span><span>{presalePayAmount} {presalePayAsset.symbol}</span></div>}
                      <div className="flex justify-between"><span className="text-gray-400">Price</span><span>${ACTIVE_TIER.price.toFixed(2)} / EGOC <span className="text-green-400 text-xs">({ACTIVE_TIER.label} — {ACTIVE_TIER.discount}% off)</span></span></div>
                      <div className="flex justify-between"><span className="text-gray-400">Status</span><span className={presalePayMethod === 'card' ? 'text-green-400 font-semibold' : 'text-yellow-400 font-semibold'}>{presalePayMethod === 'card' ? 'Paid' : 'Pending'}</span></div>
                    </div>
                    <div className="grid grid-cols-2 gap-2">
                      <button
                        onClick={() => {
                          const blob = new Blob([presaleIouJson], { type: 'application/json' });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement('a');
                          a.href = url;
                          a.download = `ego-presale-iou--${Date.now()}.json`;
                          a.click();
                          URL.revokeObjectURL(url);
                        }}
                        className="py-2.5 rounded-xl bg-gray-700 hover:bg-gray-600 font-semibold text-sm transition"
                      >⬇ IOU</button>
                      <button onClick={() => setShowPresale(false)} className="py-2.5 rounded-xl bg-blue-600 hover:bg-blue-500 font-semibold text-sm transition">Done</button>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {}
      {showSwap && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm" onClick={e => { if (e.target === e.currentTarget) { setShowSwap(false); if (cnPollRef.current) clearInterval(cnPollRef.current); } }}>
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-md border border-gray-700 shadow-2xl">
            <div className="flex justify-between items-center mb-5">
              <h3 className="text-lg font-bold">⇄ Swap</h3>
              <button onClick={() => setShowSwap(false)} className="text-gray-400 hover:text-white text-xl">✕</button>
            </div>

            {swapStep === 'quote' && (
              <div className="space-y-4">
                {}
                <div className="bg-gray-900 rounded-xl p-4 overflow-hidden">
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs text-gray-400">You send</span>
                    {swapBalFetching && !swapFrom.is_ego ? (
                      <span className="text-xs text-gray-500 animate-pulse">Fetching balance…</span>
                    ) : swapFromBalance !== null ? (
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-gray-500">
                          Balance: <span className={swapInsufficientBalance ? 'text-red-400' : 'text-gray-300'}>{swapFromBalance.toFixed(swapFrom.is_ego ? 4 : 8)} {swapFrom.symbol}</span>
                        </span>
                        {swapFromBalance > 0 && (
                          <button
                            onClick={() => setSwapAmount(String(swapFromBalance))}
                            className="text-[10px] font-bold text-blue-400 hover:text-blue-300 bg-blue-500/10 hover:bg-blue-500/20 px-1.5 py-0.5 rounded transition"
                          >
                            MAX
                          </button>
                        )}
                      </div>
                    ) : !swapFrom.is_ego ? (
                      <span className="text-xs text-gray-600">No address on file</span>
                    ) : null}
                  </div>
                  <div className="flex gap-3 items-center">
                    <div className="relative shrink-0">
                      <select
                        value={swapFrom.id}
                        onChange={e => setSwapFrom(SWAP_ASSETS.find(a => a.id === e.target.value)!)}
                        className="bg-gray-700 rounded-xl pl-9 pr-3 py-2 text-sm font-semibold focus:outline-none focus:ring-1 focus:ring-blue-500 appearance-none max-w-[140px]"
                      >
                        {SWAP_ASSETS.filter(a => !a.is_ego).map(a => (
                          <option key={a.id} value={a.id}>{a.symbol} — {a.name}</option>
                        ))}
                      </select>
                      <div className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2">
                        <AssetIcon asset={swapFrom} size={20} />
                      </div>
                    </div>
                    <div className="flex-1 min-w-0 flex items-center gap-1 justify-end">
                      <input
                        type="number"
                        min="0"
                        value={swapAmount}
                        onChange={e => setSwapAmount(e.target.value)}
                        placeholder="0.00"
                        className="min-w-0 w-0 flex-1 bg-transparent text-2xl font-bold outline-none text-right [appearance:textfield] [&::-webkit-outer-spin-button]:appearance-none [&::-webkit-inner-spin-button]:appearance-none"
                      />
                      <div className="flex flex-col gap-px shrink-0">
                        <button
                          type="button"
                          onClick={() => setSwapAmount(v => String(Math.max(0, (parseFloat(v) || 0) + 1)))}
                          className="w-3.5 h-3.5 rounded-sm bg-gray-600 hover:bg-blue-600 flex items-center justify-center text-gray-400 hover:text-white transition-colors leading-none"
                          style={{ fontSize: '7px' }}
                        >▲</button>
                        <button
                          type="button"
                          onClick={() => setSwapAmount(v => String(Math.max(0, (parseFloat(v) || 0) - 1)))}
                          className="w-3.5 h-3.5 rounded-sm bg-gray-600 hover:bg-blue-600 flex items-center justify-center text-gray-400 hover:text-white transition-colors leading-none"
                          style={{ fontSize: '7px' }}
                        >▼</button>
                      </div>
                    </div>
                  </div>
                  {swapAmount && fromUsdPrice > 0 && (
                    <div className="text-right text-xs text-gray-500 mt-1">
                      ≈ ${swapUsdVal.toFixed(2)} USD
                    </div>
                  )}
                  {swapInsufficientBalance && (
                    <div className="text-right text-xs text-red-400 mt-1 font-medium">
                      Insufficient balance — you only have {swapFromBalance!.toFixed(4)} {swapFrom.symbol}
                    </div>
                  )}
                </div>

                {}
                <div className="flex justify-center -my-1 relative z-10">
                  <button
                    onClick={flipSwapAssets}
                    className="w-9 h-9 rounded-xl bg-gray-600 hover:bg-blue-600 border-2 border-gray-800 flex flex-col items-center justify-center gap-px transition-colors group shadow-lg"
                    title="Flip assets"
                  >
                    <svg width="10" height="7" viewBox="0 0 10 7" fill="none" className="group-hover:text-white text-gray-300 transition-colors">
                      <path d="M5 0L9.33 6H0.67L5 0Z" fill="currentColor"/>
                    </svg>
                    <svg width="10" height="7" viewBox="0 0 10 7" fill="none" className="group-hover:text-white text-gray-300 transition-colors">
                      <path d="M5 7L0.67 1H9.33L5 7Z" fill="currentColor"/>
                    </svg>
                  </button>
                </div>

                {}
                <div className="bg-gray-900 rounded-xl p-4">
                  <div className="text-xs text-gray-400 mb-2">You receive</div>
                  <div className="flex gap-3 items-center min-w-0">
                    <div className="relative shrink-0">
                      <select
                        value={swapTo.id}
                        onChange={e => setSwapTo(SWAP_ASSETS.find(a => a.id === e.target.value)!)}
                        className="bg-gray-700 rounded-xl pl-9 pr-3 py-2 text-sm font-semibold focus:outline-none focus:ring-1 focus:ring-blue-500 appearance-none max-w-[140px]"
                      >
                        {SWAP_ASSETS.filter(a => !a.is_ego && a.id !== swapFrom.id).map(a => (
                          <option key={a.id} value={a.id}>{a.symbol} — {a.name}</option>
                        ))}
                      </select>
                      <div className="pointer-events-none absolute left-2 top-1/2 -translate-y-1/2">
                        <AssetIcon asset={swapTo} size={20} />
                      </div>
                    </div>
                    <div className="flex-1 min-w-0 text-right overflow-hidden">
                      {swapRateLoading ? (
                        <span className="text-gray-500 text-sm">Loading rates…</span>
                      ) : swapOutput > 0 ? (
                        <span className="block truncate text-xl font-bold text-green-400" title={swapOutput.toFixed(8)}>
                          {swapOutput >= 1e9
                            ? swapOutput.toExponential(4)
                            : swapOutput.toFixed(swapOutput < 0.001 ? 8 : 6)}
                        </span>
                      ) : (
                        <span className="text-xl font-bold text-gray-600">0.00</span>
                      )}
                    </div>
                  </div>
                  {swapOutput > 0 && toUsdPrice > 0 && (
                    <div className="text-right text-xs text-gray-500 mt-1 truncate">
                      ≈ ${(swapOutput * toUsdPrice) >= 1e9
                        ? (swapOutput * toUsdPrice).toExponential(2)
                        : (swapOutput * toUsdPrice).toLocaleString('en-US', { maximumFractionDigits: 2 })} USD
                    </div>
                  )}
                </div>

                {}
                {cnEstError && (
                  <div className="text-xs text-red-400 text-center bg-red-500/10 rounded-xl px-3 py-2">{cnEstError}</div>
                )}
                {cnMinAmount > 0 && parseFloat(swapAmount) > 0 && parseFloat(swapAmount) < cnMinAmount && (
                  <div className="text-xs text-yellow-400 text-center bg-yellow-500/10 rounded-xl px-3 py-2">
                    Minimum swap: {cnMinAmount} {swapFrom.symbol}
                  </div>
                )}

                {!useChangenow && !swapRateLoading && fromUsdPrice > 0 && toUsdPrice > 0 && (
                  <div className="bg-gray-700/40 rounded-xl px-4 py-3 text-xs space-y-1">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Rate</span>
                      <span>1 {swapFrom.symbol} = {(fromUsdPrice / toUsdPrice).toFixed(6)} {swapTo.symbol}</span>
                    </div>
                    {parseFloat(swapAmount) > 0 && (
                      <div className="flex justify-between">
                        <span className="text-gray-400">Fee</span>
                        <span>
                          {(parseFloat(swapAmount) * BRIDGE_FEE).toFixed(6)} {swapFrom.symbol}
                          {fromUsdPrice > 0 ? ` (≈$${(parseFloat(swapAmount) * BRIDGE_FEE * fromUsdPrice).toFixed(2)})` : ''}
                        </span>
                      </div>
                    )}
                  </div>
                )}
                {useChangenow && swapOutput > 0 && fromUsdPrice > 0 && toUsdPrice > 0 && (() => {
                  const theoretical = (parseFloat(swapAmount) || 0) * fromUsdPrice / toUsdPrice;
                  const feeAmt = theoretical - swapOutput;
                  const feePct = theoretical > 0 ? (feeAmt / theoretical * 100) : 0;
                  const feeUsd = feeAmt * toUsdPrice;
                  return (
                    <div className="bg-gray-700/40 rounded-xl px-4 py-3 text-xs space-y-1">
                      <div className="flex justify-between">
                        <span className="text-gray-400">Fee</span>
                        <span>{feeAmt.toFixed(6)} {swapTo.symbol} ({feePct.toFixed(2)}%{feeUsd > 0 ? ` ≈$${feeUsd.toFixed(2)}` : ''})</span>
                      </div>
                    </div>
                  );
                })()}

                <button
                  onClick={async () => {
                    if (swapOutput <= 0 || swapInsufficientBalance) return;
                    if (useChangenow) {
                      // Find the to-address for the destination asset
                      const toExt = extAddresses.find(a => a.symbol === swapTo.symbol);
                      if (!toExt) {
                        setCnCreateError(`No ${swapTo.symbol} address found. Visit the multichain section first.`);
                        return;
                      }
                      setCnCreating(true);
                      setCnCreateError('');
                      try {
                        const ex = await invoke<{ id: string; deposit_address: string; deposit_extra_id: string | null; to_amount: number }>('changenow_create_exchange', {
                          fromSymbol: swapFrom.symbol,
                          toSymbol:   swapTo.symbol,
                          fromAmount: parseFloat(swapAmount),
                          toAddress:  toExt.address,
                        });
                        setCnExchangeId(ex.id);
                        setCnDepositAddr(ex.deposit_address);
                        setCnDepositExtra(ex.deposit_extra_id);
                        setSwapStep('deposit');
                        // Start polling status
                        if (cnPollRef.current) clearInterval(cnPollRef.current);
                        cnPollRef.current = setInterval(async () => {
                          try {
                            const st = await invoke<{ status: string; to_amount: number | null; hash_out: string | null }>('changenow_get_status', { exchangeId: ex.id });
                            setCnStatus(st.status);
                            if (st.hash_out) setCnStatusHash(st.hash_out);
                            if (st.status === 'finished' || st.status === 'failed' || st.status === 'refunded') {
                              clearInterval(cnPollRef.current!);
                            }
                          } catch {}
                        }, 10_000);
                      } catch (e: any) {
                        setCnCreateError(String(e).replace(/^Error: /, ''));
                      } finally {
                        setCnCreating(false);
                      }
                    } else {
                      setSwapStep('deposit');
                    }
                  }}
                  disabled={!swapAmount || swapOutput <= 0 || swapRateLoading || cnEstLoading || swapInsufficientBalance || cnCreating || (cnMinAmount > 0 && parseFloat(swapAmount) < cnMinAmount)}
                  className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-40 disabled:cursor-not-allowed py-3 rounded-xl font-semibold transition"
                >
                  {cnCreating ? 'Creating swap…' : swapInsufficientBalance ? 'Insufficient Balance' : 'Continue'}
                </button>
                {cnCreateError && (
                  <div className="text-xs text-red-400 text-center">{cnCreateError}</div>
                )}
              </div>
            )}

            {swapStep === 'deposit' && (
              <div className="space-y-4">
                <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-xl p-4 text-sm text-yellow-300">
                  Send exactly <strong>{swapAmount} {swapFrom.symbol}</strong> to the address below.
                  You will receive <strong>{swapOutput.toFixed(useChangenow ? 8 : 6)} {swapTo.symbol}</strong>.
                </div>

                {!useChangenow && (
                  <div className="bg-red-500/10 border border-red-500/40 rounded-xl px-4 py-3 text-xs text-red-300">
                    ⚠️ <span className="font-semibold">Bridge not live yet.</span> Do NOT send real crypto to the address below — it is a placeholder. The Ego bridge launches at mainnet. Testnet only.
                  </div>
                )}
                <div className="bg-gray-900 rounded-xl p-4 space-y-2">
                  <div className="text-xs text-gray-400">
                    {useChangenow ? 'ChangeNow Deposit Address' : 'Bridge Deposit Address'} ({swapFrom.symbol})
                  </div>
                  <div className="font-mono text-xs text-green-400 break-all">
                    {useChangenow ? cnDepositAddr : (BRIDGE_DEPOSIT_ADDRS[swapFrom.symbol] ?? '— coming soon —')}
                  </div>
                  {cnDepositExtra && (
                    <div className="text-xs text-gray-400 mt-1">
                      Memo / Destination Tag: <span className="text-yellow-300 font-mono">{cnDepositExtra}</span>
                    </div>
                  )}
                  <button
                    onClick={async () => {
                      const addr = useChangenow ? cnDepositAddr : BRIDGE_DEPOSIT_ADDRS[swapFrom.symbol];
                      if (addr) await navigator.clipboard.writeText(addr);
                    }}
                    className="mt-2 text-xs bg-gray-700 hover:bg-gray-600 px-3 py-1 rounded-lg transition"
                  >
                    Copy Address
                  </button>
                </div>

                {useChangenow && cnStatus && (
                  <div className={`text-xs text-center px-3 py-2 rounded-xl font-medium ${
                    cnStatus === 'finished' ? 'bg-green-500/15 text-green-400' :
                    cnStatus === 'failed' || cnStatus === 'refunded' ? 'bg-red-500/15 text-red-400' :
                    'bg-blue-500/10 text-blue-300 animate-pulse'
                  }`}>
                    Status: {cnStatus}
                    {cnStatusHash && <span className="ml-2 font-mono opacity-70">{cnStatusHash.slice(0, 16)}…</span>}
                  </div>
                )}

                {!useChangenow && (
                  <div className="text-xs text-gray-500 text-center">
                    After your deposit is detected, EGOC will be credited to your wallet automatically.
                  </div>
                )}

                <div className="grid grid-cols-2 gap-3">
                  <button
                    onClick={() => { setSwapStep('quote'); if (cnPollRef.current) clearInterval(cnPollRef.current); }}
                    className="py-3 rounded-xl bg-gray-700 hover:bg-gray-600 font-semibold text-sm transition"
                  >
                    ← Back
                  </button>
                  <button
                    onClick={() => setSwapStep('done')}
                    className="py-3 rounded-xl bg-green-600 hover:bg-green-500 font-semibold text-sm transition"
                  >
                    {cnStatus === 'finished' ? 'Complete ✓' : 'Done ✓'}
                  </button>
                </div>
              </div>
            )}

            {swapStep === 'done' && (
              <div className="text-center space-y-4">
                <div className="text-5xl">{cnStatus === 'finished' ? '✅' : useChangenow ? '⏳' : '✅'}</div>
                <div className="text-xl font-bold">
                  {cnStatus === 'finished' ? 'Swap Complete!' : useChangenow ? 'Swap In Progress' : 'Swap Initiated'}
                </div>
                {useChangenow && cnExchangeId && (
                  <div className="text-xs text-gray-500 font-mono break-all">ID: {cnExchangeId}</div>
                )}
                {useChangenow && cnStatus && (
                  <div className={`text-sm font-medium ${cnStatus === 'finished' ? 'text-green-400' : cnStatus === 'failed' ? 'text-red-400' : 'text-blue-300 animate-pulse'}`}>
                    {cnStatus}
                  </div>
                )}
                <p className="text-sm text-gray-400">
                  {cnStatus === 'finished'
                    ? `${swapOutput.toFixed(8)} ${swapTo.symbol} has been sent to your wallet.`
                    : `Once your ${swapFrom.symbol} deposit is confirmed, ${swapOutput.toFixed(useChangenow ? 8 : 6)} ${swapTo.symbol} will be sent to your address.`}
                </p>
                <button
                  onClick={() => { setShowSwap(false); if (cnPollRef.current) clearInterval(cnPollRef.current); }}
                  className="w-full bg-blue-600 hover:bg-blue-500 py-3 rounded-xl font-semibold transition"
                >
                  Close
                </button>
              </div>
            )}
          </div>
        </div>
      )}

      {}
      {showManageCoins && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm" onClick={e => { if (e.target === e.currentTarget) setShowManageCoins(false); }}>
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

      {}
      {showAddToken && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm" onClick={e => { if (e.target === e.currentTarget) { setShowAddToken(false); setAddTokenInfo(null); setAddTokenError(''); setAddTokenContract(''); } }}>
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-md border border-gray-700 shadow-2xl">
            <div className="flex justify-between items-center mb-5">
              <h3 className="text-lg font-bold">Add Custom Token</h3>
              <button onClick={() => { setShowAddToken(false); setAddTokenInfo(null); setAddTokenError(''); setAddTokenContract(''); }} className="text-gray-400 hover:text-white text-xl">✕</button>
            </div>

            <div className="space-y-4">
              {}
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

              {}
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

      {}
      {showCredits && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm" onClick={e => { if (e.target === e.currentTarget) setShowCredits(false); }}>
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-md border border-gray-700 shadow-2xl">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-bold">$ EGUSD — Stable Dollar</h3>
              <button onClick={() => setShowCredits(false)} className="text-gray-400 hover:text-white text-xl">✕</button>
            </div>
            <div className="rounded-xl bg-gray-900 border border-gray-700 p-4 mb-4">
              <div className="text-xs text-gray-400 mb-1">Your EGUSD</div>
              <div className="text-2xl font-black">{(creditsBal?.usd_value ?? 0).toFixed(2)} EGUSD <span className="text-sm font-semibold text-emerald-400">= ${(creditsBal?.usd_value ?? 0).toFixed(2)}</span></div>
              <div className="text-xs text-gray-500 mt-1">1 EGUSD = 1 US dollar, always. EGUSD never changes value — use it for payments, fees and bills.</div>
            </div>
            <div className="space-y-3">
              <div>
                <label className="text-xs text-gray-400 block mb-1.5">Convert EGOC → EGUSD (burns EGOC at the live price)</label>
                <input
                  type="number"
                  min="0"
                  value={creditsAmt}
                  onChange={e => setCreditsAmt(e.target.value)}
                  placeholder="EGOC amount"
                  className="w-full bg-gray-900 border border-gray-700 focus:border-emerald-500 rounded-xl px-4 py-3 text-sm outline-none transition"
                />
              </div>
              {creditsBal && parseFloat(creditsAmt) > 0 && (
                <div className="text-xs text-gray-400">
                  ≈ {(Math.floor(parseFloat(creditsAmt) * creditsBal.egoc_price_usd * 100) / 100).toFixed(2)} EGUSD
                  at ${creditsBal.egoc_price_usd.toFixed(2)}/EGOC
                </div>
              )}
              {creditsMsg && (
                <div className="text-xs px-3 py-2 rounded-lg bg-emerald-500/15 text-emerald-300">{creditsMsg}</div>
              )}
              <button
                disabled={creditsBusy || !(parseFloat(creditsAmt) > 0)}
                onClick={async () => {
                  setCreditsBusy(true);
                  setCreditsMsg(null);
                  try {
                    const res = await invoke<{ hash: string; credits: number; message: string }>('mint_credits', {
                      amountUegoc: Math.round(parseFloat(creditsAmt) * 1_000_000),
                    });
                    setCreditsMsg(res.message);
                    setCreditsAmt('');
                  } catch (err) {
                    setCreditsMsg(String(err));
                  } finally {
                    setCreditsBusy(false);
                  }
                }}
                className="w-full py-3 bg-emerald-600 hover:bg-emerald-500 disabled:opacity-40 rounded-xl font-semibold text-sm transition"
              >
                {creditsBusy ? 'Converting…' : 'Convert to EGUSD'}
              </button>
              <div className="text-[11px] text-gray-500 leading-relaxed">
                Conversion is one-way: EGOC is burned (reducing supply) and EGUSD is minted at the network
                oracle price. EGUSD is Ego's native stable dollar for real-world payments.
              </div>

              <div className="border-t border-gray-700 pt-3">
                <label className="text-xs text-gray-400 block mb-1.5">Send EGUSD</label>
                <input
                  type="text"
                  value={egusdSendTo}
                  onChange={e => setEgusdSendTo(e.target.value)}
                  placeholder="Recipient address (egot1…)"
                  className="w-full bg-gray-900 border border-gray-700 focus:border-emerald-500 rounded-xl px-4 py-3 text-sm outline-none transition mb-2 font-mono"
                />
                <input
                  type="number"
                  min="0"
                  step="0.01"
                  value={egusdSendAmt}
                  onChange={e => setEgusdSendAmt(e.target.value)}
                  placeholder="Amount in EGUSD (e.g. 25.00)"
                  className="w-full bg-gray-900 border border-gray-700 focus:border-emerald-500 rounded-xl px-4 py-3 text-sm outline-none transition mb-2"
                />
                <button
                  disabled={creditsBusy || !(parseFloat(egusdSendAmt) > 0) || !egusdSendTo.trim().startsWith('egot1')}
                  onClick={async () => {
                    setCreditsBusy(true);
                    setCreditsMsg(null);
                    try {
                      const res = await invoke<{ hash: string; credits: number; message: string }>('pay_credits', {
                        toAddress: egusdSendTo.trim(),
                        credits: Math.round(parseFloat(egusdSendAmt) * 100),
                      });
                      setCreditsMsg(res.message);
                      setEgusdSendAmt('');
                      setEgusdSendTo('');
                    } catch (err) {
                      setCreditsMsg(String(err));
                    } finally {
                      setCreditsBusy(false);
                    }
                  }}
                  className="w-full py-3 bg-gray-700 hover:bg-gray-600 disabled:opacity-40 rounded-xl font-semibold text-sm transition"
                >
                  {creditsBusy ? 'Sending…' : 'Send EGUSD'}
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {}
      {showSend && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-md border border-gray-700 shadow-2xl">
            {emailStep === 'review' ? (
              <div className="space-y-4">
                <div className="flex justify-between items-center">
                  <h3 className="text-lg font-bold">Review Transaction</h3>
                  <button onClick={() => setEmailStep('idle')} className="text-gray-400 hover:text-white text-xl">✕</button>
                </div>
                {/* Security notice */}
                <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-3 text-xs text-yellow-200/80">
                  Verify every field below. This is exactly what will be signed — your wallet commits to these values cryptographically. Once signed, the transaction cannot be altered.
                </div>
                {/* Structured breakdown — same fields that go into signing bytes */}
                <div className="bg-gray-900 rounded-xl p-4 space-y-3 text-sm font-mono">
                  <div>
                    <div className="text-gray-500 text-xs mb-0.5">From</div>
                    <div className="text-green-400 break-all">{myAddress}</div>
                  </div>
                  <div className="border-t border-gray-700/50" />
                  <div>
                    <div className="text-gray-500 text-xs mb-0.5">To</div>
                    <div className="text-white break-all">{sendForm.to}</div>
                  </div>
                  <div className="border-t border-gray-700/50" />
                  <div className="flex justify-between items-center">
                    <div>
                      <div className="text-gray-500 text-xs mb-0.5">Amount</div>
                      <div className="text-white text-base font-bold">{parseFloat(sendForm.amount || '0').toFixed(6)} EGOC</div>
                    </div>
                    <div className="text-right">
                      <div className="text-gray-500 text-xs mb-0.5">Fee</div>
                      <div className="text-yellow-400">{txFee ? (txFee.fee_uegoc / 1_000_000).toFixed(4) : '…'} EGOC</div>
                    </div>
                  </div>
                  <div className="border-t border-gray-700/50" />
                  <div>
                    <div className="text-gray-500 text-xs mb-0.5">Memo</div>
                    <div className="text-gray-300 italic">{sendForm.memo || '(none)'}</div>
                  </div>
                  <div className="border-t border-gray-700/50" />
                  <div className="flex justify-between text-xs">
                    <div><span className="text-gray-500">Signature</span> <span className="text-gray-300">Ed25519 + Dilithium-3</span></div>
                    <div><span className="text-gray-500">Network</span> <span className="text-blue-300">Testnet (chain_id=1)</span></div>
                  </div>
                </div>
                <div className="flex gap-3">
                  <button
                    onClick={() => setEmailStep('idle')}
                    className="flex-1 bg-gray-700 hover:bg-gray-600 py-3 rounded-xl font-semibold text-sm transition"
                  >
                    Back
                  </button>
                  <button
                onClick={() => handleSend()}
                    disabled={sending}
                    className="flex-1 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 py-3 rounded-xl font-semibold text-sm transition flex items-center justify-center gap-2"
                  >
                    {sending
                      ? <><div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" />Signing…</>
                      : 'Confirm & Sign'}
                  </button>
                </div>
              </div>
            ) : txResult ? (
              <div className="text-center space-y-4">
                <div className="text-5xl">{txResult.success ? (txConfirmedHeight != null ? '✅' : '⏳') : '❌'}</div>
                <div className="text-xl font-bold">
                  {txResult.success ? (txConfirmedHeight != null ? 'Transaction Confirmed!' : 'Transaction Submitted') : 'Transaction Failed'}
                </div>
                <p className="text-sm text-gray-400">{txResult.message}</p>
                {txResult.hash && (
                  <div className="bg-gray-900 rounded-xl p-4 text-left">
                    <div className="text-xs text-gray-400 mb-1">Transaction Hash</div>
                    <div className="text-xs font-mono text-green-400 break-all">{txResult.hash}</div>
                    <div className="mt-3 grid grid-cols-2 gap-2 text-xs text-gray-400">
                      <div><span className="text-gray-500">Status</span><br />{txConfirmedHeight != null ? <span className="text-green-400">Confirmed</span> : <span className="text-yellow-400">Awaiting Block...</span>}</div>
                      <div><span className="text-gray-500">Block</span><br /><span>#{txConfirmedHeight ?? txResult.block_height ?? '—'}</span></div>
                      <div><span className="text-gray-500">Fee</span><br /><span className="text-yellow-400">{txFee ? `${(txFee.fee_uegoc / 1_000_000).toFixed(4)} EGOC (~$${txFee.fee_usd.toFixed(2)})` : '—'}</span></div>
                      <div><span className="text-gray-500">Network</span><br />Ego Network</div>
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
                  <div className="flex items-center justify-between bg-gray-900/50 p-3 rounded-xl border border-gray-700/50">
                    <div className="flex items-center gap-3">
                      <div className="w-8 h-8 rounded-lg bg-yellow-500/10 flex items-center justify-center text-yellow-500">🛡</div>
                      <div>
                        <div className="text-sm font-semibold">Private Transaction</div>
                        <div className="text-[10px] text-gray-500 uppercase font-bold tracking-wider">Shielded with ZK-Proofs</div>
                      </div>
                    </div>
                    <button
                      onClick={() => setSendForm(f => ({ ...f, isPrivate: !f.isPrivate }))}
                      className={`w-10 h-5 rounded-full transition-colors relative ${sendForm.isPrivate ? 'bg-yellow-500' : 'bg-gray-700'}`}
                    >
                      <div className={`absolute top-1 w-3 h-3 rounded-full bg-white transition-all ${sendForm.isPrivate ? 'left-6' : 'left-1'}`} />
                    </button>
                  </div>
                  {(sendForm.isPrivate || (parseFloat(sendForm.amount) >= 50000)) && (
                    <div className="bg-yellow-500/5 border border-yellow-500/20 rounded-xl p-3 text-[11px] text-yellow-200/70 leading-relaxed">
                      {parseFloat(sendForm.amount) >= 50000 
                        ? "High-value transaction detected. Automatic shielding enabled for Whale Protection (≥ 50,000 EGOC)."
                        : "Shielded transactions hide your address and the recipient's address from the public ledger."}
                    </div>
                  )}
                  <div className="bg-gray-900 rounded-xl p-3 space-y-2 text-sm">
                    <div className="flex justify-between">
                      <span className="text-gray-400">Transfer fee</span>
                      <span className="text-yellow-400 font-medium">
                        {txFee
                          ? `${(txFee.fee_uegoc / 1_000_000).toFixed(4)} EGOC (~$${txFee.fee_usd.toFixed(2)})`
                          : '…'}
                      </span>
                    </div>
                    <div className="flex justify-between text-xs">
                      <span className="text-gray-500">Total deducted</span>
                      <span className="text-gray-300">
                        {sendForm.amount && txFee
                          ? `${((parseFloat(sendForm.amount) || 0) + txFee.fee_uegoc / 1_000_000).toFixed(4)} EGOC`
                          : '—'}
                      </span>
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
                    onClick={() => { if (sendForm.to && sendForm.amount) setEmailStep('review'); }}
                    disabled={!sendForm.to || !sendForm.amount || sending}
                    className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-40 disabled:cursor-not-allowed py-3 rounded-xl font-semibold transition"
                  >
                    Review & Sign
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {}
      {showReceive && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm" onClick={e => { if (e.target === e.currentTarget) setShowReceive(false); }}>
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

      {}
      {selectedTx && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm" onClick={e => { if (e.target === e.currentTarget) setSelectedTx(null); }}>
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-md border border-gray-700 shadow-2xl">
            <div className="flex justify-between items-center mb-5">
              <h3 className="text-lg font-bold">Transaction Details</h3>
              <button onClick={() => setSelectedTx(null)} className="text-gray-400 hover:text-white text-xl">✕</button>
            </div>
            <div className={`rounded-xl p-4 text-center mb-5 ${
              selectedTx.status === 'Confirmed' ? 'bg-green-500/10 border border-green-500/20' :
              (selectedTx.status === 'Pending' || selectedTx.status.startsWith('Confirming')) ? 'bg-yellow-500/10 border border-yellow-500/20' :
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
                {
                  label: 'Fee',
                  val: (() => {
                    const isReward = selectedTx.from.startsWith('egot1rewards') || selectedTx.from.startsWith('egot1faucet') || selectedTx.from.startsWith('egot1staking');
                    if (isReward) return 'No fee (system tx)';
                    if (selectedTx.fee_uegoc > 0) return `${(selectedTx.fee_uegoc / 1_000_000).toFixed(4)} EGOC`;
                    return 'Fee not recorded';
                  })(),
                },
                { label: 'Block',     val: selectedTx.block_height != null ? `#${selectedTx.block_height.toLocaleString()}` : 'Unconfirmed' },
                { label: 'Nonce',     val: String(selectedTx.nonce) },
                { label: 'Timestamp', val: sfTime(selectedTx.timestamp) },
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

      {/* External (multichain) send modal */}
      {extSend && (
        <div
          className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-[9999] p-4"
          onClick={e => { if (e.target === e.currentTarget) setExtSend(null); }}
        >
          <div className="bg-gray-800 border border-gray-700 rounded-2xl w-full max-w-sm shadow-2xl overflow-hidden">
            {/* Header */}
            <div className="flex items-center justify-between px-5 py-4 border-b border-gray-700"
              style={{ background: extSend.color + '18' }}>
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-lg flex items-center justify-center text-lg font-bold"
                  style={{ background: extSend.color + '33', color: extSend.color }}>
                  {extSend.icon}
                </div>
                <div>
                  <div className="font-semibold">Send {extSend.symbol}</div>
                  <div className="text-xs text-gray-400">{extSend.chain}</div>
                </div>
              </div>
              <button onClick={() => setExtSend(null)} className="text-gray-400 hover:text-white text-xl">✕</button>
            </div>

            <div className="p-5 space-y-4">
              {extSendTxid ? (
                <div className="text-center space-y-3">
                  <div className="text-4xl">✅</div>
                  <div className="font-bold text-green-400">Sent!</div>
                  <div className="bg-gray-900 rounded-xl p-3">
                    <div className="text-xs text-gray-400 mb-1">Transaction ID</div>
                    <div className="text-xs font-mono text-green-400 break-all">{extSendTxid}</div>
                  </div>
                  <button onClick={() => setExtSend(null)}
                    className="w-full bg-blue-600 hover:bg-blue-500 py-3 rounded-xl font-semibold transition">
                    Done
                  </button>
                </div>
              ) : (
                <>
                  {/* Balance row */}
                  {(() => {
                    const bal = balances[extSend.balanceKey];
                    const cgId = SWAP_ASSETS.find(a => a.symbol === extSend.symbol)?.coingecko_id;
                    const price = cgId ? (swapRates[cgId] ?? 0) : 0;
                    const amt = parseFloat(bal?.formatted ?? '0');
                    const usd = price > 0 && amt > 0 ? amt * price : 0;
                    return (
                      <div className="flex items-center justify-between bg-gray-900/60 rounded-xl px-4 py-2.5">
                        <span className="text-xs text-gray-400">Available</span>
                        <div className="text-right">
                          <div className="text-sm font-semibold">{bal?.formatted ?? '—'}</div>
                          <div className="text-xs text-gray-400">
                            {usd > 0 ? `≈ $${usd.toFixed(2)} USD` : price > 0 ? 'Loading…' : ''}
                          </div>
                        </div>
                      </div>
                    );
                  })()}
                  <div>
                    <label className="block text-xs text-gray-400 mb-1">Recipient Address</label>
                    <input
                      value={extSendTo}
                      onChange={e => setExtSendTo(e.target.value)}
                      placeholder={extSend.symbol === 'BTC' ? 'bc1q…' : extSend.symbol === 'ETH' ? '0x…' : 'Address'}
                      className="w-full bg-gray-900 border border-gray-600 focus:border-blue-500 rounded-xl px-4 py-2.5 text-sm font-mono placeholder-gray-600 outline-none"
                    />
                  </div>
                  <div>
                    <label className="block text-xs text-gray-400 mb-1">Amount ({extSend.symbol})</label>
                    <input
                      value={extSendAmount}
                      onChange={e => setExtSendAmount(e.target.value)}
                      placeholder="0.00"
                      type="text"
                      inputMode="decimal"
                      className="w-full bg-gray-900 border border-gray-600 focus:border-blue-500 rounded-xl px-4 py-2.5 text-sm outline-none"
                    />
                  </div>
                  {(extSendFee || extSendFeeLoading) && (
                    <div className="text-xs text-gray-400 flex items-center gap-1">
                      <span>Est. fee:</span>
                      <span className="text-yellow-400">{extSendFeeLoading ? '…' : extSendFee}</span>
                    </div>
                  )}
                  {extSendError && (
                    <div className="text-xs text-red-400 bg-red-400/10 rounded-lg px-3 py-2 break-all">
                      {extSendError}
                    </div>
                  )}
                  <div className="grid grid-cols-2 gap-3 pt-1">
                    <button onClick={() => setExtSend(null)}
                      className="py-3 rounded-xl border border-gray-600 text-gray-400 hover:text-white hover:border-gray-500 transition text-sm">
                      Cancel
                    </button>
                    <button
                      onClick={doExtSend}
                      disabled={extSending || !extSendTo.trim() || !extSendAmount.trim()}
                      className="py-3 rounded-xl bg-blue-600 hover:bg-blue-500 disabled:opacity-50 disabled:cursor-not-allowed font-semibold text-sm transition"
                    >
                      {extSending ? 'Sending…' : `Send ${extSend.symbol}`}
                    </button>
                  </div>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default WalletPage;
