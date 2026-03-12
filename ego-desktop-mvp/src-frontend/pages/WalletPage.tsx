import React, { useState, useEffect, useMemo, useRef } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';
import { fetch as tauriFetch, Body } from '@tauri-apps/api/http';
import { useWallet } from '../App';
import qrcode from 'qrcode-generator';

const RELAY = 'http://40.233.82.42:8080';

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

// Matches src/ledger.rs LedgerTx struct
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

const FIAT_RATE = 2.45; // 1 EGOC = $2.45

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

  const [balance, setBalance] = useState<Balance | null>(null);
  const [txs, setTxs] = useState<LedgerTx[]>([]);
  const [tab, setTab] = useState<'all' | 'sent' | 'received'>('all');
  const [selectedTx, setSelectedTx] = useState<LedgerTx | null>(null);
  const [showSend, setShowSend] = useState(false);
  const [showReceive, setShowReceive] = useState(false);
  const [sendForm, setSendForm] = useState<SendForm>({ to: '', amount: '', memo: '' });
  const [sending, setSending] = useState(false);
  const [txResult, setTxResult] = useState<TxResult | null>(null);
  const [copied, setCopied] = useState(false);

  // Email confirmation flow
  type EmailStep = 'idle' | 'waiting' | 'confirmed' | 'cancelled' | 'expired';
  const [emailStep, setEmailStep]     = useState<EmailStep>('idle');
  const [emailToken, setEmailToken]   = useState('');
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    load();
    // Refresh balance + history whenever a peer pushes a new transaction to us.
    const unsub = listen('ego://chain-updated', () => {
      load();
      reloadWallet();
    });
    return () => { unsub.then(fn => fn()); };
  }, [myAddress]);

  async function load() {
    try {
      // get_balance runs first — it lazily credits any incoming txs from other
      // wallets and saves them, so get_transaction_history sees the full list.
      const bal = await invoke<Balance>('get_balance');
      const history = await invoke<LedgerTx[]>('get_transaction_history');
      setBalance(bal);
      setTxs(history);
    } catch (e) {
      console.error(e);
    }
  }

  async function handleSend() {
    if (!sendForm.to || !sendForm.amount) return;
    setSending(true);
    try {
      const amount = Math.floor(parseFloat(sendForm.amount) * 1_000_000);
      const request = { to_address: sendForm.to, amount, memo: sendForm.memo || null };

      // Check if user has a verified email on the relay
      let hasEmail = false;
      try {
        const r = await tauriFetch<{ registered: boolean; email_verified: boolean }>(
          `${RELAY}/users/${myAddress}`
        );
        hasEmail = r.data.registered && r.data.email_verified;
      } catch {}

      if (hasEmail) {
        // Email confirmation flow
        const prepared = await invoke<{
          tx_json: string; block_json: string; tx_hash: string; amount: number; from: string; to: string;
        }>('prepare_transaction', { request });

        const res = await tauriFetch<{ success: boolean; message: string }>(
          `${RELAY}/tx/pending`,
          { method: 'POST', body: Body.json({
            address:    prepared.from,
            tx_json:    prepared.tx_json,
            block_json: prepared.block_json,
            tx_type:    'send',
            amount:     prepared.amount,
            to:         prepared.to,
          })}
        );
        if (!res.data.success) throw new Error(res.data.message);
        const token = res.data.message; // relay returns token as message
        setEmailToken(token);
        setEmailStep('waiting');
        setSending(false);

        // Poll /tx/status/:token every 3s
        pollRef.current = setInterval(async () => {
          try {
            const s = await tauriFetch<{ status: string }>(`${RELAY}/tx/status/${token}`);
            if (s.data.status === 'confirmed') {
              clearInterval(pollRef.current!);
              setEmailStep('confirmed');
              // Commit locally
              const result = await invoke<TxResult>('commit_transaction', {
                txJson: prepared.tx_json, blockJson: prepared.block_json,
              });
              setTxResult(result);
              await load(); reloadWallet();
            } else if (s.data.status === 'cancelled') {
              clearInterval(pollRef.current!);
              setEmailStep('cancelled');
            } else if (s.data.status === 'expired') {
              clearInterval(pollRef.current!);
              setEmailStep('expired');
            }
          } catch {}
        }, 3000);

        // Auto-expire after 31 min
        setTimeout(() => {
          if (pollRef.current) { clearInterval(pollRef.current); setEmailStep('expired'); }
        }, 31 * 60 * 1000);
      } else {
        // No email registered — send directly
        const res = await invoke<TxResult>('send_transaction', { request });
        setTxResult(res);
        await load(); reloadWallet();
      }
    } catch (e: any) {
      setTxResult({ hash: '', success: false, message: String(e) });
    } finally {
      setSending(false);
    }
  }

  function resetSend() {
    if (pollRef.current) { clearInterval(pollRef.current); pollRef.current = null; }
    setShowSend(false);
    setSendForm({ to: '', amount: '', memo: '' });
    setTxResult(null);
    setEmailStep('idle');
    setEmailToken('');
  }

  async function copyAddr() {
    if (!myAddress) return;
    await navigator.clipboard.writeText(myAddress);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  const filteredTxs = txs.filter(tx => {
    if (tab === 'sent')     return tx.from === myAddress;
    if (tab === 'received') return tx.to === myAddress;
    return true;
  });

  // Use live balance from get_balance invoke; fall back to wallet context
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
            <div className="text-4xl font-black tracking-tight">{formatted}</div>
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
            { label: '↑ Send',     action: () => { setShowSend(true); setTxResult(null); } },
            { label: '↓ Receive',  action: () => setShowReceive(true) },
            { label: '⇄ Swap',    action: () => {} },
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

      {/* ── SEND MODAL ── */}
      {showSend && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
          <div className="bg-gray-800 rounded-2xl p-6 w-full max-w-md border border-gray-700 shadow-2xl">
            {emailStep === 'waiting' ? (
              <div className="text-center space-y-4">
                <div className="text-5xl">📧</div>
                <div className="text-xl font-bold">Check Your Email</div>
                <p className="text-sm text-gray-400">
                  A confirmation email was sent to your registered address.<br />
                  Click <strong className="text-white">Confirm</strong> in the email to complete the transaction.
                </p>
                <div className="flex items-center justify-center gap-2 text-sm text-gray-400">
                  <div className="w-4 h-4 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
                  Waiting for confirmation…
                </div>
                <button onClick={resetSend} className="w-full bg-gray-700 hover:bg-gray-600 py-3 rounded-xl font-semibold text-sm transition">
                  Cancel
                </button>
              </div>
            ) : emailStep === 'cancelled' ? (
              <div className="text-center space-y-4">
                <div className="text-5xl">❌</div>
                <div className="text-xl font-bold">Transaction Cancelled</div>
                <p className="text-sm text-gray-400">You cancelled this transaction via email. No funds were moved.</p>
                <button onClick={resetSend} className="w-full bg-blue-600 hover:bg-blue-500 py-3 rounded-xl font-semibold transition">Close</button>
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

            {/* Real QR code */}
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

            {/* Status banner */}
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

            {/* Fields */}
            <div className="space-y-3">
              {[
                { label: 'Hash',       val: selectedTx.hash,              mono: true },
                { label: 'From',       val: selectedTx.from,              mono: true },
                { label: 'To',         val: selectedTx.to,                mono: true },
                { label: 'Amount',     val: `${(selectedTx.amount / 1_000_000).toFixed(6)} EGOC` },
                { label: 'Fee',        val: 'Free (wallet-to-wallet)' },
                { label: 'Block',      val: selectedTx.block_height != null ? `#${selectedTx.block_height.toLocaleString()}` : 'Unconfirmed' },
                { label: 'Nonce',      val: String(selectedTx.nonce) },
                { label: 'Timestamp',  val: new Date(selectedTx.timestamp * 1000).toLocaleString() },
                { label: 'Signature',  val: selectedTx.signature.slice(0, 32) + '…', mono: true },
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
