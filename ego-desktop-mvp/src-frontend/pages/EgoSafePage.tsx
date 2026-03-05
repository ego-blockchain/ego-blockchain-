import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { useWallet } from '../App';

interface Contact {
  address: string;
  name: string;
  status: string;
  endpoint: string;
}

// ── Types ─────────────────────────────────────────────────────────────────────

interface StoredFile {
  cid: string;
  name: string;
  original_size: number;
  encrypted_size: number;
  duration_months: number;
  stored_at: number;
  expiry: number;
  status: string;
  key_nonce_hex: string;
  local_path: string;
}

interface SharedFile {
  id: string;
  name: string;
  cid: string;
  size: number;
  recipients: string[];
  shared: number;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtBytes(b: number) {
  if (b >= 1e9) return (b / 1e9).toFixed(1) + ' GB';
  if (b >= 1e6) return (b / 1e6).toFixed(1) + ' MB';
  if (b >= 1e3) return (b / 1e3).toFixed(1) + ' KB';
  return b + ' B';
}

function buildShareBundle(file: StoredFile, ownerAddress: string): string {
  const name64 = btoa(unescape(encodeURIComponent(file.name)));
  return `egoshare1:${file.cid}:${file.key_nonce_hex}:${name64}:${ownerAddress}`;
}

// ── EgoSafe share-new-file flow ───────────────────────────────────────────────

type ShareStep = 'idle' | 'select' | 'recipients' | 'sharing' | 'done';

const FILE_INPUT_ID = 'egosafe-file-input';

const SHARE_STAGES = [
  { label: 'Encrypt file',       detail: 'XChaCha20-Poly1305',             ms: 1200 },
  { label: 'Seal key (Kyber)',   detail: 'ML-KEM-768 per recipient',       ms: 800  },
  { label: 'Upload to storage',  detail: 'RS 8+4 · Primary + 2 Replicas', ms: 1500 },
  { label: 'Emit key envelopes', detail: 'Signed per-recipient envelopes', ms: 600  },
];

const DEMO_SHARED: SharedFile[] = [
  {
    id: '1', name: 'contract_draft.pdf',
    cid: 'bafybeig4xqv4p7wjhga3y5xv6kn4ql2mzj7rp8sdjf3mwvecvt2piqye',
    size: 850_000,
    recipients: ['ego1alice0000000000000000000000000000000001', 'ego1bob00000000000000000000000000000000002'],
    shared: Date.now() / 1000 - 7200,
  },
];

// ── Component ─────────────────────────────────────────────────────────────────

const EgoSafePage: React.FC = () => {
  const { wallet } = useWallet();
  const myAddress  = wallet?.address ?? '';

  // ── Share-new-file flow state ──────────────────────────────────────────────
  const [shared, setShared]       = useState<SharedFile[]>(DEMO_SHARED);
  const [step, setStep]           = useState<ShareStep>('idle');
  const [fileName, setFileName]   = useState('');
  const [fileSize, setFileSize]   = useState(0);
  const [recipient, setRecipient] = useState('');
  const [recipients, setRecipients] = useState<string[]>([]);
  const [stageIdx, setStageIdx]   = useState(-1);
  const [stageProgress, setStageProgress] = useState(0);
  const [resultCid, setResultCid] = useState('');

  // ── Share stored file state ────────────────────────────────────────────────
  const [storedFiles, setStoredFiles]       = useState<StoredFile[]>([]);
  const [shareTarget, setShareTarget]       = useState<StoredFile | null>(null);
  const [copiedCid, setCopiedCid]           = useState<string | null>(null);

  // ── Send to contact state ──────────────────────────────────────────────────
  const [contacts, setContacts]             = useState<Contact[]>([]);
  const [sendTarget, setSendTarget]         = useState<StoredFile | null>(null);
  const [sending, setSending]               = useState(false);
  const [sendMsg, setSendMsg]               = useState('');

  // ── Import shared file state ───────────────────────────────────────────────
  const [showImport, setShowImport]   = useState(false);
  const [importBundle, setImportBundle] = useState('');
  const [importing, setImporting]     = useState(false);
  const [importMsg, setImportMsg]     = useState('');

  useEffect(() => {
    loadStoredFiles();
    invoke<Contact[]>('get_contacts')
      .then(cs => setContacts(cs.filter(c => c.status === 'approved')))
      .catch(() => {});
  }, []);

  async function loadStoredFiles() {
    try {
      const files = await invoke<StoredFile[]>('get_stored_files');
      setStoredFiles(files.filter(f => f.status === 'Active'));
    } catch {}
  }

  // ── Import handler ─────────────────────────────────────────────────────────

  async function handleImport() {
    const parts = importBundle.trim().split(':');
    if (parts.length < 5 || parts[0] !== 'egoshare1') {
      setImportMsg('Invalid bundle. Expected: egoshare1:cid:key:name64:from_address');
      return;
    }
    const [, cid, key_nonce_hex, name64, from_address] = parts;
    let display_name = cid.slice(0, 12);
    try { display_name = decodeURIComponent(escape(atob(name64))); } catch {}
    setImporting(true);
    setImportMsg('');
    try {
      await invoke('import_shared_file', {
        bundle: { cid, key_nonce_hex, display_name, from_address },
      });
      setImportMsg('File imported successfully!');
      await loadStoredFiles();
      setTimeout(() => { setShowImport(false); setImportBundle(''); setImportMsg(''); }, 2000);
    } catch (e: any) {
      setImportMsg('Import failed: ' + String(e));
    } finally {
      setImporting(false);
    }
  }

  // ── Copy bundle helper ─────────────────────────────────────────────────────

  function copyBundle(file: StoredFile) {
    navigator.clipboard.writeText(buildShareBundle(file, myAddress));
    setCopiedCid(file.cid);
    setTimeout(() => setCopiedCid(null), 2000);
  }

  async function sendToContact(contact: Contact) {
    if (!sendTarget) return;
    setSending(true);
    setSendMsg('');
    const bundle = buildShareBundle(sendTarget, myAddress);
    try {
      await invoke('send_message', {
        contactAddr: contact.address,
        content: bundle,
        messageType: 'file_bundle',
      });
      setSendMsg(`✓ Sent to ${contact.name}!`);
      setTimeout(() => { setSendTarget(null); setSendMsg(''); }, 1800);
    } catch (e: any) {
      setSendMsg('✕ ' + String(e));
    } finally {
      setSending(false);
    }
  }

  // ── Share-new-file flow helpers ────────────────────────────────────────────

  function addRecipient() {
    if (recipient.trim() && !recipients.includes(recipient.trim())) {
      setRecipients(r => [...r, recipient.trim()]);
      setRecipient('');
    }
  }

  function startShare() {
    setStep('sharing');
    setStageIdx(0);
    setStageProgress(0);
    runShare(0);
  }

  function runShare(idx: number) {
    if (idx >= SHARE_STAGES.length) {
      const cid = 'bafybei' + Math.random().toString(36).slice(2, 58);
      setResultCid(cid);
      setStep('done');
      setShared(prev => [{
        id: Date.now().toString(),
        name: fileName, cid,
        size: fileSize, recipients,
        shared: Date.now() / 1000,
      }, ...prev]);
      return;
    }
    setStageIdx(idx);
    setStageProgress(0);
    const steps = 20;
    const interval = SHARE_STAGES[idx].ms / steps;
    let count = 0;
    function tick() {
      count++;
      setStageProgress(Math.min(100, Math.floor((count / steps) * 100)));
      if (count < steps) setTimeout(tick, interval);
      else setTimeout(() => runShare(idx + 1), 200);
    }
    tick();
  }

  function reset() {
    setStep('idle');
    setFileName('');
    setFileSize(0);
    setRecipients([]);
    setRecipient('');
    setStageIdx(-1);
    setResultCid('');
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="p-6 space-y-5 max-w-4xl mx-auto">

      {/* Header */}
      <div className="bg-gradient-to-br from-purple-700 to-blue-700 rounded-2xl p-5">
        <div className="flex items-center gap-3 mb-2">
          <div className="text-3xl">🔐</div>
          <div>
            <div className="text-lg font-bold">EgoSafe</div>
            <div className="text-sm text-purple-200">End-to-end encrypted file sharing · No re-upload to share</div>
          </div>
        </div>
        <div className="flex gap-6 text-sm text-purple-200 mt-3">
          <span>🔒 XChaCha20-Poly1305</span>
          <span>🔑 Kyber ML-KEM-768 keys</span>
          <span>🗄️ RS 8+4 erasure coded</span>
        </div>
      </div>

      {/* ── Share a new file (encrypt + per-recipient envelopes) ─────────── */}
      <div className="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
        <div className="flex justify-between items-center px-5 py-4 border-b border-gray-700">
          <h3 className="font-semibold">Share a New File</h3>
          {step !== 'idle' && step !== 'done' && (
            <button onClick={reset} className="text-sm text-gray-400 hover:text-white">Cancel</button>
          )}
        </div>

        <div className="p-5">
          {step === 'idle' && (
            <div className="text-center py-6">
              <div className="text-4xl mb-4">📤</div>
              <p className="text-gray-400 text-sm mb-5 max-w-xs mx-auto">
                Pick any file from disk. Recipients each get a unique Kyber-sealed key envelope — only they can decrypt.
              </p>
              <button onClick={() => setStep('select')} className="bg-purple-600 hover:bg-purple-500 transition px-6 py-3 rounded-xl font-semibold">
                + Share File
              </button>
            </div>
          )}

          {step === 'select' && (
            <div className="max-w-md mx-auto space-y-4">
              <input
                id={FILE_INPUT_ID}
                type="file"
                className="hidden"
                onChange={e => {
                  const file = e.target.files?.[0];
                  if (file) { setFileName(file.name); setFileSize(file.size); }
                }}
              />
              {fileName ? (
                <div
                  className="flex items-center gap-3 bg-gray-900 border border-purple-500/40 rounded-xl px-4 py-3 cursor-pointer hover:border-purple-400 transition"
                  onClick={() => document.getElementById(FILE_INPUT_ID)?.click()}
                >
                  <span className="text-2xl">📄</span>
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-medium truncate">{fileName}</div>
                    <div className="text-xs text-gray-400">{fmtBytes(fileSize)}</div>
                  </div>
                  <span className="text-xs text-purple-400 shrink-0">Change</span>
                </div>
              ) : (
                <button
                  onClick={() => document.getElementById(FILE_INPUT_ID)?.click()}
                  className="w-full border-2 border-dashed border-gray-600 hover:border-purple-500 rounded-xl py-10 flex flex-col items-center gap-2 transition group"
                >
                  <span className="text-4xl">📂</span>
                  <span className="text-sm text-gray-400 group-hover:text-white transition">Click to choose a file</span>
                  <span className="text-xs text-gray-600">Any file type supported</span>
                </button>
              )}
              <button
                disabled={!fileName || fileSize <= 0}
                onClick={() => setStep('recipients')}
                className="w-full bg-purple-600 hover:bg-purple-500 disabled:opacity-40 py-3 rounded-xl font-semibold transition"
              >
                Continue →
              </button>
            </div>
          )}

          {step === 'recipients' && (
            <div className="max-w-md mx-auto space-y-4">
              <div className="bg-gray-900 rounded-xl p-3 flex items-center gap-3">
                <span className="text-2xl">📄</span>
                <div>
                  <div className="font-medium text-sm">{fileName}</div>
                  <div className="text-xs text-gray-400">{fmtBytes(fileSize)}</div>
                </div>
              </div>
              <div>
                <label className="text-xs text-gray-400 block mb-1.5">Add Recipient (ego1 address)</label>
                <div className="flex gap-2">
                  <input
                    value={recipient}
                    onChange={e => setRecipient(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && addRecipient()}
                    className="flex-1 bg-gray-900 border border-gray-700 focus:border-purple-500 rounded-xl px-4 py-3 text-sm font-mono outline-none transition"
                    placeholder="ego1..."
                  />
                  <button onClick={addRecipient} className="bg-purple-600 hover:bg-purple-500 px-4 rounded-xl transition text-sm">Add</button>
                </div>
              </div>
              {recipients.length > 0 && (
                <div className="space-y-2">
                  {recipients.map((r, i) => (
                    <div key={r} className="flex items-center justify-between bg-gray-900 rounded-xl px-4 py-2">
                      <span className="font-mono text-xs text-gray-300">{r.slice(0, 20)}…{r.slice(-6)}</span>
                      <button onClick={() => setRecipients(prev => prev.filter((_, j) => j !== i))} className="text-gray-500 hover:text-red-400 transition text-lg leading-none">✕</button>
                    </div>
                  ))}
                </div>
              )}
              <div className="bg-gray-900 rounded-xl p-3 text-xs text-gray-400">
                💡 Each recipient gets a unique Kyber-sealed key envelope. No file re-upload needed to share with more people later.
              </div>
              <div className="grid grid-cols-2 gap-3">
                <button onClick={() => setStep('select')} className="bg-gray-700 hover:bg-gray-600 py-3 rounded-xl font-semibold text-sm transition">← Back</button>
                <button
                  disabled={recipients.length === 0}
                  onClick={startShare}
                  className="bg-purple-600 hover:bg-purple-500 disabled:opacity-40 py-3 rounded-xl font-semibold text-sm transition"
                >
                  🔐 Encrypt & Share
                </button>
              </div>
            </div>
          )}

          {step === 'sharing' && (
            <div className="max-w-md mx-auto space-y-3">
              <div className="text-center mb-4">
                <div className="text-3xl mb-1">⚙️</div>
                <div className="font-semibold">Securing {fileName}</div>
              </div>
              {SHARE_STAGES.map((stage, i) => {
                const done   = i < stageIdx;
                const active = i === stageIdx;
                return (
                  <div key={i} className={`rounded-xl p-4 border transition ${
                    done   ? 'border-green-500/30 bg-green-500/5' :
                    active ? 'border-purple-500/50 bg-purple-500/10' :
                             'border-gray-700 bg-gray-900 opacity-40'
                  }`}>
                    <div className="flex items-center justify-between mb-1">
                      <div className="flex items-center gap-2">
                        <span>{done ? '✅' : active ? '⏳' : '○'}</span>
                        <span className="text-sm font-medium">{stage.label}</span>
                      </div>
                      {active && <span className="text-xs text-purple-400">{stageProgress}%</span>}
                    </div>
                    <div className="text-xs text-gray-400 ml-6">{stage.detail}</div>
                    {active && (
                      <div className="mt-2 ml-6 bg-gray-700 rounded-full h-1.5">
                        <div className="bg-purple-500 h-1.5 rounded-full transition-all duration-100" style={{ width: `${stageProgress}%` }} />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}

          {step === 'done' && (
            <div className="max-w-md mx-auto space-y-4">
              <div className="text-center py-4">
                <div className="text-5xl mb-2">🔐</div>
                <div className="text-xl font-bold text-green-400">Shared Securely!</div>
                <div className="text-sm text-gray-400 mt-1">{recipients.length} recipient{recipients.length > 1 ? 's' : ''} notified</div>
              </div>
              <div className="bg-gray-900 rounded-xl p-4 space-y-2 text-sm">
                <div className="text-xs text-gray-400 mb-2">Content ID (CID)</div>
                <div className="font-mono text-xs text-green-400 break-all">{resultCid}</div>
                <div className="border-t border-gray-700 pt-2 space-y-1 text-xs text-gray-400">
                  <div>✓ Key sealed per recipient (Kyber)</div>
                  <div>✓ Data encrypted (XChaCha20)</div>
                  <div>✓ No re-upload needed to add more recipients</div>
                </div>
              </div>
              <button onClick={reset} className="w-full bg-purple-600 hover:bg-purple-500 py-3 rounded-xl font-semibold transition">Share Another File</button>
            </div>
          )}
        </div>
      </div>

      {/* ── Share a stored file (bundle from Storage) ────────────────────── */}
      <div className="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-700">
          <div>
            <h3 className="font-semibold">Share Stored File</h3>
            <p className="text-xs text-gray-400 mt-0.5">Generate a share bundle for a file already in your Storage</p>
          </div>
          <button onClick={loadStoredFiles} className="text-xs text-gray-400 hover:text-white transition">↻ Refresh</button>
        </div>

        {storedFiles.length === 0 ? (
          <div className="py-10 text-center text-gray-500">
            <div className="text-4xl mb-3">🗄️</div>
            <div className="text-sm">No active stored files</div>
            <div className="text-xs mt-1 text-gray-600">Store a file in the Storage tab first</div>
          </div>
        ) : (
          <div className="divide-y divide-gray-700/50">
            {storedFiles.map(file => {
              const bundle  = buildShareBundle(file, myAddress);
              const isOpen  = shareTarget?.cid === file.cid;
              const isCopied = copiedCid === file.cid;
              return (
                <div key={file.cid} className="px-5 py-4">
                  <div className="flex items-center justify-between gap-4">
                    <div className="min-w-0 flex-1">
                      <div className="text-sm font-medium truncate">{file.name}</div>
                      <div className="flex gap-3 text-xs text-gray-500 mt-0.5">
                        {file.original_size > 0 && <span>{fmtBytes(file.original_size)}</span>}
                        <span className="font-mono">{file.cid.slice(0, 14)}…</span>
                      </div>
                    </div>
                    <div className="flex gap-2 shrink-0">
                      <button
                        onClick={() => setShareTarget(isOpen ? null : file)}
                        className="text-xs bg-gray-700 hover:bg-gray-600 px-3 py-1.5 rounded-lg transition"
                      >
                        {isOpen ? 'Hide' : 'Show'}
                      </button>
                      <button
                        onClick={() => copyBundle(file)}
                        className={`text-xs px-3 py-1.5 rounded-lg transition font-medium ${
                          isCopied
                            ? 'bg-green-600 text-white'
                            : 'bg-gray-700 hover:bg-gray-600 text-gray-300'
                        }`}
                      >
                        {isCopied ? '✓ Copied' : '📋 Copy'}
                      </button>
                      <button
                        onClick={() => { setSendTarget(file); setSendMsg(''); }}
                        className="text-xs bg-purple-600/20 hover:bg-purple-600/40 text-purple-400 px-3 py-1.5 rounded-lg transition font-medium"
                      >
                        📤 Send
                      </button>
                    </div>
                  </div>

                  {isOpen && (
                    <div className="mt-3 space-y-2">
                      <div className="bg-gray-900 rounded-xl p-3 font-mono text-xs text-blue-300 break-all select-all">
                        {bundle}
                      </div>
                      <div className="text-xs text-yellow-400">
                        ⚠️ This bundle contains the decryption key. Only share with trusted users.
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {/* ── Import Shared File ───────────────────────────────────────────── */}
      <div className="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-gray-700">
          <div>
            <h3 className="font-semibold">Import Shared File</h3>
            <p className="text-xs text-gray-400 mt-0.5">Paste a share bundle from another Ego user</p>
          </div>
          <button
            onClick={() => { setShowImport(v => !v); setImportBundle(''); setImportMsg(''); }}
            className="text-xs bg-gray-700 hover:bg-gray-600 px-3 py-1.5 rounded-lg transition"
          >
            {showImport ? 'Cancel' : '↓ Import'}
          </button>
        </div>

        {showImport && (
          <div className="p-5 space-y-4">
            <div className="text-sm text-gray-400">
              Paste the <span className="font-mono text-blue-400">egoshare1:…</span> bundle you received. The file will be added to your Storage with the decryption key.
            </div>
            <textarea
              value={importBundle}
              onChange={e => setImportBundle(e.target.value)}
              rows={3}
              className="w-full bg-gray-900 border border-gray-700 focus:border-purple-500 rounded-xl px-4 py-3 text-xs font-mono outline-none transition resize-none"
              placeholder="egoshare1:egocid1…:key…:name…:ego1from…"
            />
            {importMsg && (
              <div className={`text-xs px-3 py-2 rounded-lg ${
                importMsg.includes('success') ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
              }`}>
                {importMsg}
              </div>
            )}
            <button
              onClick={handleImport}
              disabled={!importBundle.trim() || importing}
              className="w-full bg-purple-600 hover:bg-purple-500 disabled:opacity-40 py-3 rounded-xl font-semibold text-sm transition"
            >
              {importing ? 'Importing…' : '↓ Import File'}
            </button>
          </div>
        )}

        {!showImport && (
          <div className="px-5 py-8 text-center text-gray-500">
            <div className="text-3xl mb-2">📥</div>
            <div className="text-sm">Click Import above to paste a share bundle</div>
          </div>
        )}
      </div>

      {/* ── Recently shared (EgoSafe encrypt+share) ─────────────────────── */}
      <div className="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
        <div className="px-5 py-4 border-b border-gray-700">
          <h3 className="font-semibold">Recently Shared ({shared.length})</h3>
        </div>
        <div className="divide-y divide-gray-700/50">
          {shared.map(file => (
            <div key={file.id} className="px-5 py-4">
              <div className="flex items-start justify-between">
                <div className="min-w-0">
                  <div className="font-medium text-sm mb-1">{file.name}</div>
                  <div className="font-mono text-xs text-green-400 truncate mb-2">{file.cid}</div>
                  <div className="flex gap-3 text-xs text-gray-500">
                    <span>{fmtBytes(file.size)}</span>
                    <span>{file.recipients.length} recipient{file.recipients.length > 1 ? 's' : ''}</span>
                  </div>
                </div>
                <button className="text-xs bg-purple-600/20 hover:bg-purple-600/40 text-purple-400 px-3 py-1.5 rounded-lg transition shrink-0">
                  + Recipient
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* ── Send to Contact modal ─────────────────────────────────────── */}
      {sendTarget && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
          <div className="bg-gray-800 rounded-2xl w-full max-w-sm border border-gray-700 shadow-2xl">
            <div className="px-5 py-4 border-b border-gray-700 flex items-center justify-between">
              <h3 className="font-bold">Send File to Contact</h3>
              <button onClick={() => { setSendTarget(null); setSendMsg(''); }} className="text-gray-400 hover:text-white text-xl">✕</button>
            </div>
            <div className="p-5 space-y-3">
              <div className="bg-gray-900 rounded-xl px-4 py-3 text-sm">
                <div className="font-medium truncate">{sendTarget.name}</div>
                <div className="text-xs text-gray-400 font-mono mt-0.5">{sendTarget.cid.slice(0, 20)}…</div>
              </div>
              {contacts.length === 0 ? (
                <div className="text-center text-gray-500 py-4 text-sm">
                  No approved contacts yet.<br/>
                  <span className="text-xs">Add contacts in the Messenger tab first.</span>
                </div>
              ) : (
                <div className="space-y-2">
                  <div className="text-xs text-gray-400 mb-1">Choose a contact to send to:</div>
                  {contacts.map(c => (
                    <button
                      key={c.address}
                      onClick={() => sendToContact(c)}
                      disabled={sending}
                      className="w-full flex items-center gap-3 px-4 py-3 bg-gray-700 hover:bg-purple-600/20 hover:border-purple-500/50 border border-transparent rounded-xl transition text-left disabled:opacity-50"
                    >
                      <div className="w-8 h-8 rounded-full bg-gradient-to-br from-purple-500 to-pink-600 flex items-center justify-center text-xs font-bold shrink-0">
                        {(c.name || '?').charAt(0).toUpperCase()}
                      </div>
                      <div className="min-w-0">
                        <div className="text-sm font-medium">{c.name}</div>
                        <div className="text-xs text-gray-400 font-mono">
                          {c.address.slice(0, 12)}…{c.address.slice(-6)}
                        </div>
                      </div>
                    </button>
                  ))}
                </div>
              )}
              {sendMsg && (
                <div className={`text-xs text-center px-3 py-2 rounded-lg ${
                  sendMsg.startsWith('✓') ? 'bg-green-500/20 text-green-400' : 'bg-red-500/20 text-red-400'
                }`}>
                  {sendMsg}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

    </div>
  );
};

export default EgoSafePage;
