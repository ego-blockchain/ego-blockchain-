import React, { useState, useEffect } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { open as openDialog } from '@tauri-apps/api/dialog';
import { listen } from '@tauri-apps/api/event';
import { useWallet } from '../App';
import { useConfirm } from '../hooks/useConfirm';

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

interface StoreFileResult {
  cid: string;
  name: string;
  key_nonce_hex: string;
}

interface SelectedContact {
  address: string;
  name: string;
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

const VIDEO_EXTS = ['.mp4', '.mkv', '.avi', '.mov', '.webm', '.m4v', '.flv', '.wmv', '.ts', '.mpg', '.mpeg'];

function isVideoFile(name: string): boolean {
  const lower = name.toLowerCase();
  return VIDEO_EXTS.some(ext => lower.endsWith(ext));
}

// ── EgoSafe share-new-file flow ───────────────────────────────────────────────

type ShareStep = 'idle' | 'select' | 'recipients' | 'sharing' | 'done';


// ── Component ─────────────────────────────────────────────────────────────────

const EgoSafePage: React.FC = () => {
  const { wallet } = useWallet();
  const myAddress  = wallet?.address ?? '';
  const { confirm, ConfirmDialog } = useConfirm();

  // ── Share-new-file flow state ──────────────────────────────────────────────
  const [shared, setShared]           = useState<SharedFile[]>([]);
  const [step, setStep]               = useState<ShareStep>('idle');
  const [fileName, setFileName]       = useState('');
  const [filePath, setFilePath]       = useState('');
  const [fileSize, setFileSize]       = useState(0);
  const [selectedContacts, setSelectedContacts] = useState<SelectedContact[]>([]);
  const [resultCid, setResultCid]     = useState('');
  const [shareError, setShareError]   = useState('');

  // ── Share stored file state ────────────────────────────────────────────────
  const [storedFiles, setStoredFiles]       = useState<StoredFile[]>([]);
  const [receivedFiles, setReceivedFiles]   = useState<StoredFile[]>([]);
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

  // ── Preview modal state ────────────────────────────────────────────────────
  const [previewFile, setPreviewFile] = useState<StoredFile | null>(null);
  const [preview, setPreview]         = useState<{ name: string; mime_type: string; data_base64: string; size_bytes: number; previewable: boolean } | null>(null);
  const [previewLoading, setPreviewLoading] = useState(false);


  useEffect(() => {
    loadStoredFiles();
    invoke<Contact[]>('get_contacts')
      .then(cs => setContacts(cs.filter(c => c.status === 'approved')))
      .catch(() => {});
    // Refresh when a new message arrives (file bundles auto-import in backend)
    const unlistenMsg = listen('ego://message-received', () => { loadStoredFiles(); });
    // Refresh when a P2P file download completes
    const unlistenDl  = listen('ego://file-downloaded', () => { loadStoredFiles(); });
    return () => {
      unlistenMsg.then(fn => fn());
      unlistenDl.then(fn => fn());
    };
  }, []);

  async function loadStoredFiles() {
    try {
      const files = await invoke<StoredFile[]>('get_stored_files');
      setStoredFiles(files.filter(f => f.status === 'Active'));
      setReceivedFiles(files.filter(f => f.status === 'Received'));
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

  async function startShare() {
    if (!filePath || selectedContacts.length === 0) return;
    setStep('sharing');
    setShareError('');
    try {
      const result = await invoke<StoreFileResult>('store_file', {
        request: { file_path: filePath, duration_months: 1 },
      });
      const name64 = btoa(unescape(encodeURIComponent(result.name)));
      const bundle = `egoshare1:${result.cid}:${result.key_nonce_hex}:${name64}:${myAddress}`;
      for (const c of selectedContacts) {
        await invoke('send_message', {
          contactAddr: c.address,
          content:     bundle,
          messageType: 'file_bundle',
        });
      }
      setResultCid(result.cid);
      setShared(prev => [{
        id: Date.now().toString(),
        name: fileName, cid: result.cid,
        size: fileSize,
        recipients: selectedContacts.map(c => c.address),
        shared: Date.now() / 1000,
      }, ...prev]);
      setStep('done');
    } catch (e: any) {
      setShareError(String(e));
      setStep('recipients');
    }
  }

  function reset() {
    setStep('idle');
    setFileName('');
    setFilePath('');
    setFileSize(0);
    setSelectedContacts([]);
    setResultCid('');
    setShareError('');
  }

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div className="p-6 space-y-5 max-w-4xl mx-auto">
      {ConfirmDialog}

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
              {fileName ? (
                <div
                  className="flex items-center gap-3 bg-gray-900 border border-purple-500/40 rounded-xl px-4 py-3 cursor-pointer hover:border-purple-400 transition"
                  onClick={async () => {
                    const p = await openDialog({ multiple: false });
                    if (typeof p === 'string') {
                      try {
                        const { size } = await invoke<{ size: number }>('get_file_metadata', { path: p });
                        if (size > 50 * 1024 * 1024) {
                          alert(`This file is ${(size / 1024 / 1024).toFixed(1)}MB. Maximum file size is 50MB.`);
                          return;
                        }
                      } catch (_) {
                        // Can't check size — proceed and let backend enforce
                      }
                      setFilePath(p);
                      setFileName(p.split(/[/\\]/).pop() ?? p);
                      setFileSize(0);
                    }
                  }}
                >
                  <span className="text-2xl">📄</span>
                  <div className="min-w-0 flex-1">
                    <div className="text-sm font-medium truncate">{fileName}</div>
                    <div className="text-xs text-gray-400">Click to change</div>
                  </div>
                  <span className="text-xs text-purple-400 shrink-0">Change</span>
                </div>
              ) : (
                <button
                  onClick={async () => {
                    const p = await openDialog({ multiple: false });
                    if (typeof p === 'string') {
                      setFilePath(p);
                      setFileName(p.split(/[/\\]/).pop() ?? p);
                      setFileSize(0);
                    }
                  }}
                  className="w-full border-2 border-dashed border-gray-600 hover:border-purple-500 rounded-xl py-10 flex flex-col items-center gap-2 transition group"
                >
                  <span className="text-4xl">📂</span>
                  <span className="text-sm text-gray-400 group-hover:text-white transition">Click to choose a file</span>
                  <span className="text-xs text-gray-600">Any file type supported</span>
                </button>
              )}
              <div className="flex items-start gap-2 bg-gray-700/50 border border-gray-600 rounded-xl px-4 py-3">
                <span className="text-gray-400 shrink-0 mt-0.5">ℹ️</span>
                <div className="text-xs text-gray-300 leading-relaxed">
                  Maximum file size is <strong>50MB</strong>. Files larger than 50MB cannot be shared.
                </div>
              </div>
              <button
                disabled={!filePath}
                onClick={async () => {
                  try {
                    const stat = await invoke<{ size: number }>('get_file_metadata', { path: filePath });
                    if (stat.size > 50 * 1024 * 1024) {
                      alert(`This file is ${(stat.size / 1024 / 1024).toFixed(1)}MB. Maximum file size is 50MB.`);
                      return;
                    }
                  } catch (_) {
                    // Can't check size — proceed and let backend enforce
                  }
                  setStep('recipients');
}}
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
                <div className="min-w-0">
                  <div className="font-medium text-sm truncate">{fileName}</div>
                  <div className="text-xs text-gray-400">Select contacts to send to</div>
                </div>
              </div>
              {contacts.length === 0 ? (
                <div className="text-center text-gray-500 py-4 text-sm">
                  No approved contacts yet.<br/>
                  <span className="text-xs">Add contacts in the Messenger tab first.</span>
                </div>
              ) : (
                <div className="space-y-2">
                  <div className="text-xs text-gray-400 mb-1">Select recipients:</div>
                  {contacts.map(c => {
                    const sel = selectedContacts.some(s => s.address === c.address);
                    return (
                      <button
                        key={c.address}
                        onClick={() => setSelectedContacts(prev =>
                          sel ? prev.filter(s => s.address !== c.address)
                              : [...prev, { address: c.address, name: c.name }]
                        )}
                        className={`w-full flex items-center gap-3 px-4 py-3 border rounded-xl transition text-left ${
                          sel
                            ? 'bg-purple-600/20 border-purple-500/50'
                            : 'bg-gray-900 border-gray-700 hover:border-purple-500/40'
                        }`}
                      >
                        <div className={`w-5 h-5 rounded border flex items-center justify-center shrink-0 ${sel ? 'bg-purple-600 border-purple-600' : 'border-gray-600'}`}>
                          {sel && <span className="text-xs text-white">✓</span>}
                        </div>
                        <div className="w-8 h-8 rounded-full bg-gradient-to-br from-purple-500 to-pink-600 flex items-center justify-center text-xs font-bold shrink-0">
                          {(c.name || '?').charAt(0).toUpperCase()}
                        </div>
                        <div className="min-w-0">
                          <div className="text-sm font-medium">{c.name}</div>
                          <div className="text-xs text-gray-400 font-mono">{c.address.slice(0, 12)}…{c.address.slice(-6)}</div>
                        </div>
                      </button>
                    );
                  })}
                </div>
              )}
              {shareError && (
                <div className="text-xs text-red-400 bg-red-500/10 rounded-xl px-3 py-2">{shareError}</div>
              )}
              <div className="grid grid-cols-2 gap-3">
                <button onClick={() => setStep('select')} className="bg-gray-700 hover:bg-gray-600 py-3 rounded-xl font-semibold text-sm transition">← Back</button>
                <button
                  disabled={selectedContacts.length === 0}
                  onClick={startShare}
                  className="bg-purple-600 hover:bg-purple-500 disabled:opacity-40 py-3 rounded-xl font-semibold text-sm transition"
                >
                  🔐 Encrypt & Share
                </button>
              </div>
            </div>
          )}

          {step === 'sharing' && (
            <div className="max-w-md mx-auto text-center py-8 space-y-4">
              <div className="text-4xl animate-spin">⚙️</div>
              <div className="font-semibold">Encrypting & sending {fileName}…</div>
              <div className="text-sm text-gray-400">
                Storing encrypted file and delivering to {selectedContacts.length} contact{selectedContacts.length !== 1 ? 's' : ''}
              </div>
            </div>
          )}

          {step === 'done' && (
            <div className="max-w-md mx-auto space-y-4">
              <div className="text-center py-4">
                <div className="text-5xl mb-2">🔐</div>
                <div className="text-xl font-bold text-green-400">Shared Securely!</div>
                <div className="text-sm text-gray-400 mt-1">{selectedContacts.length} recipient{selectedContacts.length !== 1 ? 's' : ''} notified</div>
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
                        onClick={async () => {
                          setPreviewFile(file);
                          setPreview(null);
                          setPreviewLoading(true);
                          try {
                            const p = await invoke<{ name: string; mime_type: string; data_base64: string; size_bytes: number; previewable: boolean }>('retrieve_file_preview', { cid: file.cid });
                            setPreview(p);
                          } catch {}
                          setPreviewLoading(false);
                        }}
                        className="text-xs bg-gray-700 hover:bg-gray-600 px-3 py-1.5 rounded-lg transition"
                      >
                        👁 View
                      </button>
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
                      <button
                        onClick={async () => {
                          if (!await confirm(`Delete "${file.name}"?`, { detail: 'This removes the encrypted copy from your storage and cannot be undone.', confirmLabel: 'Delete' })) return;
                          try {
                            await invoke('delete_stored_file', { cid: file.cid });
                            await loadStoredFiles();
                          } catch (e: any) { alert('Delete failed: ' + String(e)); }
                        }}
                        className="text-xs bg-red-600/20 hover:bg-red-600/40 text-red-400 px-3 py-1.5 rounded-lg transition font-medium"
                      >
                        🗑
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


{/* ── Received Files ───────────────────────────────────────────────── */}
{receivedFiles.length > 0 && (
  <div className="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
    <div className="flex items-center justify-between px-5 py-4 border-b border-gray-700">
      <div>
        <h3 className="font-semibold">Received Files ({receivedFiles.length})</h3>
        <p className="text-xs text-gray-400 mt-0.5">Files shared with you</p>
      </div>
      <button onClick={loadStoredFiles} className="text-xs text-gray-400 hover:text-white transition">↻ Refresh</button>
    </div>
    <div className="divide-y divide-gray-700/50">
      {receivedFiles.map(file => {
        const isReady = !!file.local_path && !file.local_path.startsWith('sender:');
        return (
          <div key={file.cid} className="px-5 py-4">
            <div className="flex items-center gap-4">
              <div className="text-2xl">{isReady ? '📥' : '⏳'}</div>
              <div className="min-w-0 flex-1">
                <div className="text-sm font-medium truncate">{file.name}</div>
                <div className="font-mono text-xs text-green-400 truncate mt-0.5">{file.cid.slice(0, 20)}…</div>
                {isVideoFile(file.name) && (
                  <div className="text-xs text-blue-400 mt-0.5">🎬 Video — delivered in chunks</div>
                )}
              </div>
              <div className="shrink-0 flex items-center gap-1.5">
                {isReady ? (
                  <>
                    <button
                      onClick={async () => {
                        try {
                          const path = await invoke<string>('download_stored_file', { cid: file.cid });
                          alert(`✅ Saved to: ${path}`);
                        } catch (e: any) { alert('Download failed: ' + String(e)); }
                      }}
                      className="text-xs bg-blue-600/20 hover:bg-blue-600/40 text-blue-400 px-3 py-1.5 rounded-lg transition font-medium"
                    >
                      ⬇ Download
                    </button>
                    <button
                      // Replace the preview button onClick for received files:
                      onClick={async () => {
                        // For video/PDF, just download and open instead of in-app preview
                        const ext = file.name.split('.').pop()?.toLowerCase() ?? '';
                        const isLarge = file.encrypted_size > 50 * 1024 * 1024; // 50MB
                        if (isLarge || ['mp4','mkv','avi','mov','webm','pdf','wav','mp3'].includes(ext)) {
                          try {
                            const path = await invoke<string>('download_stored_file', { cid: file.cid });
                            await invoke('open_file', { path });
                          } catch (e: any) { alert('Open failed: ' + String(e)); }
                          return;
                        }
                        setPreviewFile(file);
                        setPreview(null);
                        setPreviewLoading(true);
                        try {
                          const p = await invoke<{ name: string; mime_type: string; data_base64: string; size_bytes: number; previewable: boolean }>('retrieve_file_preview', { cid: file.cid });
                          setPreview(p);
                        } catch {}
                        setPreviewLoading(false);
                      }}
                      className="text-xs bg-gray-700 hover:bg-gray-600 px-3 py-1.5 rounded-lg transition"
                    >
                      👁 View
                    </button>
                  </>
                ) : (
                  <span className="text-xs bg-yellow-500/20 text-yellow-400 px-2 py-1 rounded-lg">
                    ⏳ Incoming…
                  </span>
                )}
                <button
                  onClick={async () => {
                    if (!await confirm(`Delete "${file.name}"?`, { confirmLabel: 'Delete' })) return;
                    try {
                      await invoke('delete_stored_file', { cid: file.cid });
                      await loadStoredFiles();
                    } catch (e: any) { alert('Delete failed: ' + String(e)); }
                  }}
                  className="text-xs bg-red-600/20 hover:bg-red-600/40 text-red-400 px-2 py-1.5 rounded-lg transition"
                >
                  🗑
                </button>
              </div>
            </div>
          </div>
        );
      })}
    </div>
  </div>
)}

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

      {/* ── File Preview Modal ───────────────────────────────────────── */}
      {previewFile && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4 backdrop-blur-sm">
          <div className="bg-gray-800 rounded-2xl w-full max-w-2xl border border-gray-700 shadow-2xl max-h-[90vh] flex flex-col">
            <div className="px-5 py-4 border-b border-gray-700 flex items-center justify-between shrink-0">
              <h3 className="font-bold truncate">{previewFile.name}</h3>
              <button onClick={() => { setPreviewFile(null); setPreview(null); }} className="text-gray-400 hover:text-white text-xl shrink-0 ml-3">✕</button>
            </div>
            <div className="flex-1 overflow-auto p-4">
              {previewLoading && <div className="text-center py-8 text-gray-400">Loading preview…</div>}
              {preview && !previewLoading && (
                preview.previewable ? (
                  preview.mime_type.startsWith('image/') ? (
                    <img src={`data:${preview.mime_type};base64,${preview.data_base64}`} alt={preview.name} className="max-w-full mx-auto rounded-lg" />
                  ) : preview.mime_type === 'application/pdf' ? (
                    <embed src={`data:application/pdf;base64,${preview.data_base64}`} type="application/pdf" className="w-full h-96 rounded-lg" />
                  ) : preview.mime_type.startsWith('video/') ? (
                    <video controls className="w-full rounded-lg">
                      <source src={`data:${preview.mime_type};base64,${preview.data_base64}`} type={preview.mime_type} />
                    </video>
                  ) : (
                    <pre className="text-xs text-gray-300 whitespace-pre-wrap break-all font-mono bg-gray-900 rounded-xl p-4 overflow-auto max-h-80">
                      {atob(preview.data_base64)}
                    </pre>
                  )
                ) : (
                  <div className="text-center py-8 text-gray-400">
                    <div className="text-4xl mb-3">📄</div>
                    <div className="text-sm">Preview not available for this file type</div>
                    <div className="text-xs text-gray-500 mt-1">{preview.mime_type}</div>
                  </div>
                )
              )}
            </div>
          </div>
        </div>
      )}

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
