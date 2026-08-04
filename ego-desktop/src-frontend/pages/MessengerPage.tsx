import React, { useEffect, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { open as openDialog } from '@tauri-apps/api/dialog';
import { open as openUrl } from '@tauri-apps/api/shell';
import { emit, listen } from '@tauri-apps/api/event';
import { useLocation } from 'react-router-dom';
import { writeText } from '@tauri-apps/api/clipboard';
import { useConfirm } from '../hooks/useConfirm';
import { Prism as SyntaxHighlighter } from 'react-syntax-highlighter';

import { vscDarkPlus } from 'react-syntax-highlighter/dist/esm/styles/prism';

function EgoAiIcon({ size = 36, className = "" }: { size?: number | string, className?: string }) {
  return (
    <svg width={size} height={size} viewBox="0 0 120 120" role="img" xmlns="http://www.w3.org/2000/svg" className={className}>
      <title>AI chatbot icon</title>
      <desc>Futuristic AI icon with circuit-inspired face and scan line eyes</desc>
      <rect fill="#0f1729" width="120" height="120" rx="32"/>
      <circle fill="none" stroke="#378ADD" strokeWidth="2" cx="60" cy="58" r="36" opacity="0.4"/>
      <circle fill="none" stroke="#378ADD" strokeWidth="1" cx="60" cy="58" r="30" opacity="0.25"/>
      <circle fill="#0C447C" cx="60" cy="58" r="26"/>
      <rect fill="#378ADD" x="36" y="50" width="16" height="5" rx="2.5"/>
      <rect fill="#378ADD" x="68" y="50" width="16" height="5" rx="2.5"/>
      <circle fill="#85B7EB" cx="44" cy="52" r="2"/>
      <circle fill="#85B7EB" cx="76" cy="52" r="2"/>
      <rect fill="#378ADD" x="42" y="66" width="6"  height="3" rx="1.5" opacity="0.9"/>
      <rect fill="#378ADD" x="51" y="66" width="18" height="3" rx="1.5"/>
      <rect fill="#378ADD" x="72" y="66" width="6"  height="3" rx="1.5" opacity="0.9"/>
      <line x1="60" y1="22" x2="60" y2="10" stroke="#378ADD" strokeWidth="1.5" opacity="0.5"/>
      <circle fill="#f5c842" cx="60" cy="8" r="4"/>
      <circle fill="#378ADD" cx="24" cy="44" r="3" opacity="0.6"/>
      <line x1="24" y1="44" x2="34" y2="44" stroke="#378ADD" strokeWidth="1" opacity="0.4"/>
      <circle fill="#378ADD" cx="24" cy="68" r="3" opacity="0.6"/>
      <line x1="24" y1="68" x2="34" y2="68" stroke="#378ADD" strokeWidth="1" opacity="0.4"/>
      <circle fill="#378ADD" cx="96" cy="44" r="3" opacity="0.6"/>
      <line x1="86" y1="44" x2="96" y2="44" stroke="#378ADD" strokeWidth="1" opacity="0.4"/>
      <circle fill="#378ADD" cx="96" cy="68" r="3" opacity="0.6"/>
      <line x1="86" y1="68" x2="96" y2="68" stroke="#378ADD" strokeWidth="1" opacity="0.4"/>
    </svg>
  );
}

interface Contact {
  address: string;
  name: string;
  ed25519_pubkey: string;
  shared_key_hex: string;
  status: string;
  added_at: number;
  endpoint: string;
  machine_id?: string;
}

interface Message {
  id: string;
  from: string;
  to: string;
  content: string;
  message_type: string;
  timestamp: number;
  outgoing: boolean;
  read: boolean;
  read_by_recipient: boolean;
}

function fmtTime(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

function fmtDate(ts: number): string {
  const d = new Date(ts * 1000);
  const now = new Date();
  const today = new Date(now.getFullYear(), now.getMonth(), now.getDate());
  const yesterday = new Date(today.getTime() - 86400000);
  const msgDay = new Date(d.getFullYear(), d.getMonth(), d.getDate());
  if (msgDay.getTime() === today.getTime()) return 'Today';
  if (msgDay.getTime() === yesterday.getTime()) return 'Yesterday';
  return d.toLocaleDateString([], { month: 'short', day: 'numeric', year: msgDay.getFullYear() !== today.getFullYear() ? 'numeric' : undefined });
}

function isSameDay(ts1: number, ts2: number): boolean {
  const d1 = new Date(ts1 * 1000);
  const d2 = new Date(ts2 * 1000);
  return d1.getFullYear() === d2.getFullYear() && d1.getMonth() === d2.getMonth() && d1.getDate() === d2.getDate();
}

function truncAddr(addr: string): string {
  if (addr.length <= 16) return addr;
  return addr.slice(0, 10) + '…' + addr.slice(-4);
}

function msgTypeLabel(t: string): string {
  if (t === 'file_bundle') return '📎 File Bundle';
  if (t === 'decrypt_key') return '🔑 Decrypt Key';
  return '';
}

const URL_RE = /(https?:\/\/[^\s<]+[^\s<.,:;!?)'"\]])/g;

function linkifyContent(text: string): React.ReactNode {
  // URL_RE has a single capturing group, so String.split interleaves
  // [text, url, text, url, ...] — odd indices are always the matched URLs.
  // (Deliberately not using URL_RE.test() here: it's a global regex, and
  // .test() on a global regex is stateful across calls — reusing it in a
  // loop like this alternates true/false unpredictably.)
  const parts = text.split(URL_RE);
  if (parts.length === 1) return text;
  return parts.map((part, i) =>
    i % 2 === 1 ? (
      <span
        key={i}
        onClick={e => { e.stopPropagation(); openUrl(part).catch(() => {}); }}
        className="underline text-blue-300 hover:text-blue-200 cursor-pointer break-all"
        title={part}
      >
        {part}
      </span>
    ) : (
      <React.Fragment key={i}>{part}</React.Fragment>
    )
  );
}

function isImageName(name: string): boolean {
  const ext = name.split('.').pop()?.toLowerCase() ?? '';
  return ['jpg','jpeg','png','gif','webp','bmp','svg'].includes(ext);
}

function InlineFilePreview({ cid, name }: { cid: string; name: string }) {
  const [src, setSrc] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let cancelled = false;
    invoke<{ mime_type: string; data_base64: string; previewable: boolean }>(
      'retrieve_file_preview', { cid }
    ).then(p => {
      if (!cancelled && p.previewable) {
        setSrc(`data:${p.mime_type};base64,${p.data_base64}`);
      } else if (!cancelled) {
        setFailed(true);
      }
    }).catch(() => { if (!cancelled) setFailed(true); });
    return () => { cancelled = true; };
  }, [cid]);

  if (failed || (!src && !isImageName(name))) return null;
  if (!src) {
    return (
      <div className="w-full h-24 rounded-xl bg-black/30 animate-pulse flex items-center justify-center">
        <span className="text-gray-500 text-xs">Loading…</span>
      </div>
    );
  }
  return (
    <img
      src={src}
      alt={name}
      className="w-full max-h-64 rounded-xl object-contain bg-black/20 cursor-pointer"
      onClick={() => { const w = window.open(); w?.document.write(`<img src="${src}" style="max-width:100%;background:#000"/>`); }}
    />
  );
}

function normalizeLang(lang: string): string {
  const map: Record<string, string> = {
    urego: 'rust', ego: 'rust', solidity: 'javascript',
    ts: 'typescript', js: 'javascript', sh: 'bash', shell: 'bash',
    toml: 'toml', yml: 'yaml', '': 'text',
  };
  return map[lang.toLowerCase()] ?? lang;
}

function parseInline(text: string): React.ReactNode[] {
  const parts: React.ReactNode[] = [];
  const regex = /(\*\*[^*]+\*\*|`[^`]+`)/g;
  let last = 0; let key = 0; let match: RegExpExecArray | null;
  while ((match = regex.exec(text)) !== null) {
    if (match.index > last) parts.push(text.slice(last, match.index));
    const tok = match[0];
    if (tok.startsWith('**'))
      parts.push(<strong key={key++} className="font-semibold text-white">{tok.slice(2, -2)}</strong>);
    else
      parts.push(<code key={key++} className="bg-white/10 text-blue-200 rounded px-1 py-0.5 text-xs font-mono">{tok.slice(1, -1)}</code>);
    last = match.index + tok.length;
  }
  if (last < text.length) parts.push(text.slice(last));
  return parts;
}

function AiMessageContent({ content }: { content: string }) {
  const [copied, setCopied] = useState<number | null>(null);

  const segments = content.split('```');

  function renderText(text: string, segIdx: number): React.ReactNode {
    const lines = text.split('\n');
    const nodes: React.ReactNode[] = [];
    const listItems: React.ReactNode[] = [];
    let listType: 'ul' | 'ol' | null = null;
    let listKey = 0;

    function flushList() {
      if (!listItems.length) return;
      nodes.push(listType === 'ul'
        ? <ul key={`ul-${listKey++}`} className="space-y-0.5 pl-4 list-disc">{[...listItems]}</ul>
        : <ol key={`ol-${listKey++}`} className="space-y-0.5 pl-4 list-decimal">{[...listItems]}</ol>
      );
      listItems.length = 0; listType = null;
    }

    lines.forEach((line, li) => {
      const hMatch = line.match(/^(#{1,3})\s+(.+)/);
      if (hMatch) {
        flushList();
        nodes.push(
          <div key={`h-${li}`} className="bg-white/10 rounded-lg px-3 py-1.5 my-1">
            <span className="font-semibold text-white text-sm">{parseInline(hMatch[2])}</span>
          </div>
        );
        return;
      }
      const ulMatch = line.match(/^[-*]\s+(.+)/);
      if (ulMatch) {
        if (listType !== 'ul') { flushList(); listType = 'ul'; }
        listItems.push(<li key={li} className="text-sm text-gray-200">{parseInline(ulMatch[1])}</li>);
        return;
      }
      const olMatch = line.match(/^\d+\.\s+(.+)/);
      if (olMatch) {
        if (listType !== 'ol') { flushList(); listType = 'ol'; }
        listItems.push(<li key={li} className="text-sm text-gray-200">{parseInline(olMatch[1])}</li>);
        return;
      }
      if (line.trim() === '') { flushList(); return; }
      flushList();
      nodes.push(
        <p key={`p-${li}`} className="text-sm leading-relaxed text-gray-100 break-words">
          {parseInline(line)}
        </p>
      );
    });
    flushList();
    return <div key={`seg-${segIdx}`} className="space-y-1.5">{nodes}</div>;
  }

  return (
    <div className="text-sm space-y-2">
      {segments.map((seg, i) => {
        if (i % 2 === 0) return seg.trim() ? renderText(seg, i) : null;

        const newline = seg.indexOf('\n');
        const lang = newline > -1 ? seg.slice(0, newline).trim() : '';
        const code = newline > -1 ? seg.slice(newline + 1) : seg;
        const handleCopy = async () => {
          await writeText(code);
          setCopied(i);
          setTimeout(() => setCopied(null), 2000);
        };
        return (
          <div key={i} className="rounded-xl overflow-hidden border border-white/10 my-1">
            <div className="flex items-center justify-between bg-[#1e1e1e] px-3 py-1.5 border-b border-white/5">
              <span className="text-xs text-gray-400 font-mono">{lang || 'code'}</span>
              <button
                onClick={handleCopy}
                className="text-xs text-gray-400 hover:text-white flex items-center gap-1 transition-colors"
              >
                {copied === i ? '✓ Copied' : '⎘ Copy'}
              </button>
            </div>
            <SyntaxHighlighter
              language={normalizeLang(lang)}
              style={vscDarkPlus}
              customStyle={{ margin: 0, borderRadius: 0, fontSize: '0.78rem', maxHeight: '360px', overflowY: 'auto' }}
              wrapLongLines={false}
            >
              {code.trimEnd()}
            </SyntaxHighlighter>
          </div>
        );
      })}
    </div>
  );
}

const EGO_AI_ADDRESS = 'ego_ai_assistant';

const EGO_AI_CONTACT: Contact = {
  address:        EGO_AI_ADDRESS,
  name:           'Ego AI',
  ed25519_pubkey: '',

  shared_key_hex: '',
  status:         'approved',
  added_at:       0,
  endpoint:       '',
};

interface AiMsg { role: 'user' | 'assistant'; content: string; ts: number; }

const MessengerPage: React.FC = () => {
  const { confirm, ConfirmDialog } = useConfirm();
  const location = useLocation();

  const [contacts, setContacts]     = useState<Contact[]>([]);
  const [selected, setSelected]     = useState<Contact | null>(null);
  const [messages, setMessages]     = useState<Message[]>([]);
  const [msgInput, setMsgInput]     = useState('');
  const [sending, setSending]       = useState(false);
  const [sendError, setSendError]   = useState('');
  const [showAttachMenu, setShowAttachMenu] = useState(false);
  const [attaching, setAttaching]   = useState(false);
  const [attachError, setAttachError] = useState('');
  const msgInputRef = useRef<HTMLTextAreaElement>(null);

  const [aiMessages, setAiMessages]       = useState<AiMsg[]>(() => {
    try {
      const saved = localStorage.getItem('ego-ai-messages');
      if (saved) return JSON.parse(saved) as AiMsg[];
    } catch {}
    return [];
  });
  const [aiThinking, setAiThinking]       = useState(false);

  const [showMyCard, setShowMyCard]         = useState(false);
  const [myCardName, setMyCardName]         = useState('');
  const [myCard, setMyCard]                 = useState('');
  const [generatingCard, setGeneratingCard] = useState(false);
  const [copied, setCopied]                 = useState(false);
  const [revoking, setRevoking]             = useState(false);
  const [revokeConfirm, setRevokeConfirm]   = useState(false);

  const [knownCids, setKnownCids] = useState<Set<string>>(new Set());

  const [showAdd, setShowAdd]     = useState(false);
  const [addBundle, setAddBundle] = useState('');
  const [addMyName, setAddMyName] = useState('');
  const [addMsg, setAddMsg]       = useState('');
  const [adding, setAdding]       = useState(false);

  const [pendingAction, setPendingAction] = useState<{
    contact: Contact;
    action: 'approve' | 'decline';
  } | null>(null);
  const [actionName, setActionName] = useState('');
  const [actioning, setActioning]   = useState(false);
  const [actionDone, setActionDone] = useState(false);

  const msgEndRef = useRef<HTMLDivElement>(null);

  type FileImportStatus = 'idle' | 'importing' | 'done' | 'error';
  const [fileImportStates, setFileImportStates] = useState<Record<string, { status: FileImportStatus; error?: string }>>({});
  const importTimers = useRef<Record<string, ReturnType<typeof setTimeout>>>({});

  const cidToMsgId = useRef<Record<string, string>>({});

  const [editingName, setEditingName] = useState(false);
  const [nameInput, setNameInput]     = useState('');
  const nameInputRef = useRef<HTMLInputElement>(null);

  interface P2pStatus { upnp: string; upnp_error: string | null; public_endpoint: string; p2p_port: number; relay_circuit_ready: boolean; }
  const [p2pStatus, setP2pStatus] = useState<P2pStatus | null>(null);

  async function loadContacts() {
    try {
      const cs = await invoke<Contact[]>('get_contacts');
      setContacts(cs);
    } catch (e) {
      console.error('get_contacts', e);
    }
  }

  // Open the right chat when navigated here from a notification click
  useEffect(() => {
    const addr = (location.state as any)?.openChat as string | undefined;
    if (!addr) return;
    invoke<Contact[]>('get_contacts').then(cs => {
      setContacts(cs);
      const contact = cs.find(c => c.address === addr && c.status === 'approved');
      if (contact) setSelected(contact);
    }).catch(() => {});
  }, [location.state]);

  async function loadKnownCids() {
    try {
      const files = await invoke<{ cid: string; local_path: string }[]>('get_egosafe_files');
      setKnownCids(new Set(
        files
          .filter(f => f.local_path && !f.local_path.startsWith('sender:'))
          .map(f => f.cid)
      ));
    } catch {}
  }

  async function loadMessages(addr: string) {
    try {
      const ms = await invoke<Message[]>('get_messages', { contactAddr: addr });
      setMessages(ms);
      if (ms.some(m => !m.outgoing && !m.read)) {
        await invoke('mark_messages_read', { contactAddr: addr });
        emit('ego://message-received');
      }
    } catch (e) {
      console.error('get_messages', e);
    }
  }

  const selectedRef = useRef<Contact | null>(null);
  useEffect(() => { selectedRef.current = selected; }, [selected]);

  useEffect(() => {
    try { localStorage.setItem('ego-ai-messages', JSON.stringify(aiMessages)); } catch {}
  }, [aiMessages]);

  useEffect(() => {
    invoke<P2pStatus>('get_p2p_status').then(setP2pStatus).catch(() => {});
    const unlistenP2p = listen('ego://p2p-status-changed', () => {
      invoke<P2pStatus>('get_p2p_status').then(setP2pStatus).catch(() => {});
    });
    return () => { unlistenP2p.then(fn => fn()); };
  }, []);

  useEffect(() => {
    loadContacts();
     loadKnownCids();
    const unlisteners: Promise<() => void>[] = [

      listen<Contact>('ego://contact-request', () => { loadContacts(); }),

      listen<Contact>('ego://contact-approved', (event) => {
        loadContacts();
        if (event.payload.address === selectedRef.current?.address) {
          loadMessages(event.payload.address);
        }
      }),

      listen('ego://contact-declined', () => { loadContacts(); }),
      listen<{ cid?: string }>('ego://file-downloaded', (event) => {
        loadKnownCids();
        const cid = event.payload?.cid;
        if (cid) {
          const msgId = cidToMsgId.current[cid];
          if (msgId) {
            clearTimeout(importTimers.current[msgId]);
            setFileImportStates(s => ({ ...s, [msgId]: { status: 'done' } }));
            delete cidToMsgId.current[cid];
          }
        }
      }),

      listen<Message>('ego://message-received', (event) => {
        const msg = event.payload;

        const cur = selectedRef.current;
        if (cur && (msg.from === cur.address || msg.to === cur.address)) {
          loadMessages(cur.address);
        }
      }),

      listen<{ to: string }>('ego://message-sent', (event) => {
        const cur = selectedRef.current;
        if (cur && cur.address === event.payload.to) {
          loadMessages(cur.address);
        }
      }),

      listen<{ contact: string }>('ego://messages-read-receipt', (event) => {
        const cur = selectedRef.current;
        if (cur && cur.address === event.payload.contact) {
          loadMessages(cur.address);
        }
      }),

    ];

    return () => {
      unlisteners.forEach(p => p.then(fn => fn()));

      Object.values(importTimers.current).forEach(clearTimeout);
    };
  }, []);

useEffect(() => {
  if (selected) {
    loadMessages(selected.address);
    loadKnownCids();
  } else {
    setMessages([]);
  }
}, [selected]);

  useEffect(() => {
    const id = requestAnimationFrame(() => {
      msgEndRef.current?.scrollIntoView({ behavior: 'auto' });
    });
    return () => cancelAnimationFrame(id);
  }, [messages, aiMessages, aiThinking]);

  async function handleRevokeBundle() {
    setRevoking(true);
    try {
      await invoke('revoke_contact_bundle');
      setMyCard('');
      setCopied(false);
      setRevokeConfirm(false);
    } catch (e: any) {
      console.error(e);
    } finally {
      setRevoking(false);
    }
  }

  async function handleGenerateCard() {
    if (!myCardName.trim()) return;
    setGeneratingCard(true);
    setMyCard('');
    setCopied(false);
    try {
      const card = await invoke<string>('get_my_contact_bundle', {
        myName: myCardName.trim(),
      });
      setMyCard(card);
      localStorage.setItem('ego-my-display-name', myCardName.trim());
    } catch (e: any) {
      console.error(e);
    } finally {
      setGeneratingCard(false);
    }
  }

  async function handleAddContact() {
    if (!addBundle.trim() || !addMyName.trim()) return;
    setAdding(true);
    setAddMsg('');
    try {
      await invoke<Contact>('import_contact', {
        bundle: addBundle.trim(),
        myName: addMyName.trim(),
      });
      setAddMsg('✓ Request sent! Waiting for them to approve…');
      await loadContacts();
      setTimeout(() => {
        setShowAdd(false);
        setAddBundle('');
        setAddMsg('');
      }, 2000);
    } catch (e: any) {
      setAddMsg(`✕ ${String(e)}`);
    } finally {
      setAdding(false);
    }
  }

  async function handleApprove() {
    if (!pendingAction || pendingAction.action !== 'approve' || !actionName.trim()) return;
    setActioning(true);
    try {
      await invoke<Contact>('approve_contact_request', {
        contactAddr: pendingAction.contact.address,
        myName: actionName.trim(),
      });
      localStorage.setItem('ego-my-display-name', actionName.trim());
      setActionDone(true);
      await loadContacts();
      setTimeout(() => closePendingAction(), 1500);
    } catch (e: any) {
      console.error('approve_contact_request', e);
    } finally {
      setActioning(false);
    }
  }

  async function handleDecline() {
    if (!pendingAction || pendingAction.action !== 'decline') return;
    setActioning(true);
    try {
      await invoke('decline_contact_request', {
        contactAddr: pendingAction.contact.address,
        myName: 'Me',
      });
      setActionDone(true);
      await loadContacts();
      setTimeout(() => closePendingAction(), 1500);
    } catch (e: any) {
      console.error('decline_contact_request', e);
    } finally {
      setActioning(false);
    }
  }

  async function handleSend(msgType: string = 'text') {
    if (!selected) return;

    if (selected.address === EGO_AI_ADDRESS) { await handleAiSend(); return; }
    if (!msgInput.trim()) return;
    setSending(true);
    setSendError('');
    const text = msgInput.trim();
    setMsgInput('');
    try {
      await invoke('send_message', {
        contactAddr: selected.address,
        content:     text,
        messageType: msgType,
      });

      await loadMessages(selected.address);
    } catch (e: any) {
      setSendError(String(e));
      setMsgInput(text);
    } finally {
      setSending(false);
    }
  }

  async function handlePickAttachment(isImage: boolean) {
    if (!selected || selected.address === EGO_AI_ADDRESS) return;
    setAttachError('');
    try {
      const path = await openDialog({
        multiple: false,
        filters: isImage
          ? [{ name: 'Images', extensions: ['png', 'jpg', 'jpeg', 'gif', 'webp', 'bmp'] }]
          : undefined,
      });
      if (typeof path !== 'string') return;

      const { size } = await invoke<{ size: number }>('get_file_metadata', { path });
      if (size > 250 * 1024 * 1024) {
        setAttachError(`This file is ${(size / 1024 / 1024).toFixed(1)} MB. Maximum file size is 250 MB.`);
        return;
      }

      setAttaching(true);
      const result = await invoke<{ cid: string }>('store_file', {
        request: { file_path: path, duration_months: 1, free: true, from_egosafe: true },
      });
      const bundle = await invoke<string>('create_public_share', { cid: result.cid });
      await invoke('send_message', {
        contactAddr: selected.address,
        content:     bundle,
        messageType: 'file_bundle',
      });
      await loadMessages(selected.address);
    } catch (e: any) {
      setAttachError(String(e));
    } finally {
      setAttaching(false);
    }
  }

  async function handleAiSend() {
    const text = msgInput.trim();
    if (!text) return;
    setMsgInput('');
    const userMsg: AiMsg = { role: 'user', content: text, ts: Date.now() / 1000 };
    setAiMessages(prev => [...prev, userMsg]);
    setAiThinking(true);
    try {
      const history = aiMessages.map(m => ({ role: m.role, content: m.content }));
      const reply = await invoke<string>('ask_ego_ai', { question: text, history });
      setAiMessages(prev => [...prev, { role: 'assistant', content: reply, ts: Date.now() / 1000 }]);
    } catch (e: any) {
      {
        setAiMessages(prev => [...prev, { role: 'assistant', content: `⚠️ ${String(e)}`, ts: Date.now() / 1000 }]);
      }
    } finally {
      setAiThinking(false);
    }
  }

  async function handleDeleteContact(addr: string) {
    if (!await confirm('Remove this contact?', { detail: 'All messages with this contact will remain but you will no longer be able to send new ones.', confirmLabel: 'Remove' })) return;
    try {
      await invoke('delete_contact', { contactAddr: addr });
      if (selected?.address === addr) setSelected(null);
      await loadContacts();
    } catch (e) { console.error(e); }
  }

  async function handleClearChat(addr: string) {
    if (!await confirm('Clear all messages?', { detail: 'This removes all messages with this contact from your device.', confirmLabel: 'Clear' })) return;
    try {
      await invoke('clear_messages', { contactAddr: addr });
      if (selected?.address === addr) setMessages([]);
    } catch (e) { console.error(e); }
  }

  async function handleRenameContact(addr: string, newName: string) {
    const trimmed = newName.trim();
    if (!trimmed) { setEditingName(false); return; }
    try {
      await invoke('rename_contact', { contactAddr: addr, newName: trimmed });
      await loadContacts();
      setSelected(prev => prev && prev.address === addr ? { ...prev, name: trimmed } : prev);
    } catch (e) { console.error(e); }
    setEditingName(false);
  }

  async function handleDeleteMessage(msgId: string) {
    try {
      await invoke('delete_message', { messageId: msgId });
      if (selected) await loadMessages(selected.address);
    } catch (e) { console.error(e); }
  }

  async function handleImportFile(msgId: string, content: string) {
    setFileImportStates(s => ({ ...s, [msgId]: { status: 'importing' } }));

    if (importTimers.current[msgId]) clearTimeout(importTimers.current[msgId]);
    importTimers.current[msgId] = setTimeout(() => {
      setFileImportStates(s => {
        if (s[msgId]?.status === 'importing')
          return { ...s, [msgId]: { status: 'error', error: 'Download timed out. Tap Retry.' } };
        return s;
      });
    }, 60_000);

    const parts        = content.trim().split(':');
    const cid          = parts[1] ?? '';
    const key_nonce_hex = parts[2] ?? '';
    const name64       = parts[3] ?? '';
    const from_address = parts[4] ?? '';
    let display_name   = cid.slice(0, 12);
    try { display_name = decodeURIComponent(escape(atob(name64))); } catch {}

    try {
      await invoke('import_shared_file', { bundle: { cid, key_nonce_hex, display_name, from_address } });

      cidToMsgId.current[cid] = msgId;
      await invoke('request_file_from_contact', { cid, fromAddr: from_address, content: content.trim() });
      await loadKnownCids();
    } catch (e: any) {
      clearTimeout(importTimers.current[msgId]);
      setFileImportStates(s => ({ ...s, [msgId]: { status: 'error', error: 'Import failed. Tap Retry.' } }));
    }
  }

  function closePendingAction() {
    setPendingAction(null);
    setActionName('');
    setActioning(false);
    setActionDone(false);
  }

  const approvedContacts   = contacts.filter(c => c.status === 'approved');
  const pendingInContacts  = contacts.filter(c => c.status === 'pending_in');
  const pendingOutContacts = contacts.filter(c => c.status === 'pending_out');

  return (
    <div className="flex flex-col h-full bg-gray-900 text-white overflow-hidden">
      {ConfirmDialog}

      {}
      {p2pStatus?.upnp === 'failed' && !p2pStatus.relay_circuit_ready && (
        <div className="bg-yellow-900/80 border-b border-yellow-600/40 px-4 py-2 flex items-start gap-2 shrink-0">
          <span className="text-yellow-400 shrink-0 mt-0.5">⚠️</span>
          <div className="text-xs text-yellow-200 leading-relaxed">
            <strong>Cross-network messaging may not work.</strong> UPnP port mapping failed and relay is not connected — peers on other networks can't reach you.
            Fix: forward <strong>TCP port {p2pStatus.p2p_port}</strong> to your local machine in your router settings.
          </div>
        </div>
      )}

      <div className="flex flex-1 overflow-hidden">

      {/* ── Left sidebar: contacts ── */}
      <div className="w-64 bg-gray-800 border-r border-gray-700 flex flex-col shrink-0">
        {/* Header */}
        <div className="px-4 py-3 border-b border-gray-700 flex items-center justify-between">
          <div>
            <h2 className="font-bold text-sm">Messenger</h2>
            <p className="text-xs text-gray-400">
              {approvedContacts.length} contact{approvedContacts.length !== 1 ? 's' : ''}
              {pendingInContacts.length > 0 && (
                <span className="ml-1 text-yellow-400 animate-pulse">
                  · {pendingInContacts.length} request{pendingInContacts.length !== 1 ? 's' : ''}
                </span>
              )}
            </p>
          </div>
          <div className="flex gap-1.5">
            <button
              onClick={() => { setShowMyCard(true); setMyCard(''); setMyCardName(''); setRevokeConfirm(false); }}
              className="w-7 h-7 bg-gray-600 hover:bg-gray-500 rounded-lg flex items-center justify-center text-sm transition-colors"
              title="Share my contact card"
            >
              📤
            </button>
            <button
              onClick={() => { setShowAdd(true); setAddBundle(''); setAddMsg(''); }}
              className="w-7 h-7 bg-blue-600 hover:bg-blue-500 rounded-lg flex items-center justify-center font-bold text-sm transition-colors"
              title="Add contact"
            >
              +
            </button>
          </div>
        </div>

        {/* Contact list */}
        <div className="flex-1 overflow-y-auto">

          {/* Ego AI — pinned at top */}
          <button
            onClick={() => setSelected(EGO_AI_CONTACT)}
            className={`w-full flex items-center gap-3 px-4 py-3 hover:bg-gray-700/60 transition-colors text-left border-b border-gray-700/50 ${
              selected?.address === EGO_AI_ADDRESS
                ? 'bg-yellow-500/10 border-l-2 border-yellow-400'
                : ''
            }`}
          >
            <EgoAiIcon size={36} className="shrink-0" />
            <div className="min-w-0 flex-1">
              <div className="text-sm font-semibold text-yellow-300">Ego AI</div>
              <div className="text-xs text-gray-400">Blockchain assistant</div>
            </div>
            <div className="w-2 h-2 rounded-full bg-green-400 shrink-0" title="Always online" />
          </button>

          {/* Pending-in: incoming contact requests */}
          {pendingInContacts.length > 0 && (
            <div className="border-b border-yellow-500/20">
              <div className="px-4 pt-3 pb-1">
                <div className="text-xs text-yellow-400 font-semibold uppercase tracking-wide">
                  Requests ({pendingInContacts.length})
                </div>
              </div>
              {pendingInContacts.map(c => (
                <div
                  key={c.address}
                  className="px-4 py-3 bg-yellow-500/5 border-l-2 border-yellow-500/40"
                >
                  <div className="flex items-center gap-2 mb-2">
                    <div className="w-8 h-8 rounded-full bg-gradient-to-br from-yellow-500 to-orange-600 flex items-center justify-center text-xs font-bold shrink-0">
                      {(c.name || '?').charAt(0).toUpperCase()}
                    </div>
                    <div className="min-w-0 flex-1">
                      <div className="text-sm font-medium truncate">{c.name || 'Unknown'}</div>
                    <div className="flex flex-col gap-0.5">
                      <div className="text-xs text-gray-400 font-mono">{truncAddr(c.address)}</div>
                      {c.machine_id && <div className="text-[10px] text-gray-500 font-mono italic">ID: {c.machine_id.slice(0, 8)}…</div>}
                    </div>
                    </div>
                  </div>
                  <div className="flex gap-1.5">
                    <button
                      onClick={() => {
                        setPendingAction({ contact: c, action: 'approve' });
                        setActionName(localStorage.getItem('ego-my-display-name') ?? '');
                        setActionDone(false);
                      }}
                      className="flex-1 py-1 bg-green-600 hover:bg-green-500 rounded-lg text-xs font-medium transition-colors"
                    >
                      Approve
                    </button>
                    <button
                      onClick={() => {
                        setPendingAction({ contact: c, action: 'decline' });
                        setActionName('');
                        setActionDone(false);
                      }}
                      className="flex-1 py-1 bg-red-700/80 hover:bg-red-600 rounded-lg text-xs font-medium transition-colors"
                    >
                      Decline
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Approved contacts */}
          {approvedContacts.map(c => (
            <button
              key={c.address}
              onClick={() => setSelected(c)}
              className={`w-full flex items-center gap-3 px-4 py-3 hover:bg-gray-700/60 transition-colors text-left ${
                selected?.address === c.address
                  ? 'bg-blue-600/15 border-l-2 border-blue-500'
                  : ''
              }`}
            >
              <div className="w-9 h-9 rounded-full bg-gradient-to-br from-purple-500 to-pink-600 flex items-center justify-center text-sm font-bold shrink-0">
                {(c.name || '?').charAt(0).toUpperCase()}
              </div>
              <div className="min-w-0 flex-1">
                <div className="text-sm font-medium truncate">{c.name || 'Unknown'}</div>
                <div className="text-xs text-gray-400 font-mono">{truncAddr(c.address)}</div>
              </div>
            </button>
          ))}

          {/* Pending-out: waiting for remote approval */}
          {pendingOutContacts.length > 0 && (
            <div className="px-4 pt-3 pb-1">
              <div className="text-xs text-gray-500 font-semibold uppercase tracking-wide">
                Awaiting Approval
              </div>
            </div>
          )}
          {pendingOutContacts.map(c => (
            <div
              key={c.address}
              className="flex items-center gap-3 px-4 py-3 opacity-60"
            >
              <div className="w-9 h-9 rounded-full bg-gray-600 flex items-center justify-center text-base shrink-0">
                ⏳
              </div>
              <div className="min-w-0 flex-1">
                <div className="text-sm text-gray-300 truncate">{c.name}</div>
                <div className="text-xs text-gray-500 mt-0.5">Waiting for approval…</div>
              </div>
              <button
                onClick={async () => {
                  try {
                    await invoke('delete_contact', { contactAddr: c.address });
                    await loadContacts();
                  } catch (e) { console.error(e); }
                }}
                className="shrink-0 w-6 h-6 flex items-center justify-center text-gray-500 hover:text-red-400 hover:bg-red-500/10 rounded-full transition-colors text-sm"
                title="Cancel request"
              >
                ✕
              </button>
            </div>
          ))}

          {contacts.length === 0 && (
            <div className="px-4 py-10 text-center text-gray-500">
              <div className="text-4xl mb-2">💬</div>
              <div className="text-sm">No contacts yet.</div>
              <div className="text-xs mt-1">Click + to add someone.</div>
            </div>
          )}
        </div>
      </div>

      {/* ── Right: chat panel ── */}
      <div className="flex-1 flex flex-col min-w-0">
        {selected ? (
          <>
            {/* Chat header */}
            {selected.address === EGO_AI_ADDRESS ? (
              <div className="px-6 py-3 border-b border-gray-700 flex items-center shrink-0 gap-3">
                <EgoAiIcon size={36} className="shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="font-semibold text-sm text-yellow-300">Ego AI</div>
                  <div className="text-xs text-gray-400">Ask about Ego blockchain, smart contracts, EIPs…</div>
                </div>
                {aiMessages.length > 0 && (
                  <button
                    onClick={() => setAiMessages([])}
                    title="Clear conversation"
                    className="shrink-0 px-2.5 py-1.5 text-xs text-gray-400 hover:text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
                  >
                    🗑 Clear
                  </button>
                )}
              </div>
            ) : (
              <div className="px-6 py-3 border-b border-gray-700 flex items-center shrink-0 gap-3">
                <div className="w-9 h-9 rounded-full bg-gradient-to-br from-purple-500 to-pink-600 flex items-center justify-center text-sm font-bold shrink-0">
                  {(selected.name || '?').charAt(0).toUpperCase()}
                </div>
                <div className="flex-1 min-w-0">
                  {editingName ? (
                    <input
                      ref={nameInputRef}
                      value={nameInput}
                      onChange={e => setNameInput(e.target.value)}
                      onKeyDown={e => {
                        if (e.key === 'Enter') handleRenameContact(selected.address, nameInput);
                        if (e.key === 'Escape') setEditingName(false);
                      }}
                      onBlur={() => handleRenameContact(selected.address, nameInput)}
                      autoFocus
                      className="bg-gray-700 border border-blue-500 rounded-lg px-2 py-0.5 text-sm font-semibold w-full outline-none"
                    />
                  ) : (
                    <div className="flex items-center gap-1.5 group/name">
                      <span className="font-semibold text-sm truncate">{selected.name}</span>
                      <button
                        onClick={() => { setNameInput(selected.name); setEditingName(true); setTimeout(() => nameInputRef.current?.select(), 0); }}
                        className="text-gray-500 hover:text-gray-300 text-xs px-1"
                        title="Edit name"
                      >
                        ✏️
                      </button>
                    </div>
                  )}
                  <div className="text-xs text-gray-400 font-mono">{truncAddr(selected.address)}</div>
                </div>
                <button
                  onClick={() => handleClearChat(selected.address)}
                  className="shrink-0 px-3 py-1.5 text-xs text-gray-400 hover:text-gray-300 hover:bg-gray-500/10 rounded-lg transition-colors"
                  title="Clear chat"
                >
                  Clear
                </button>
                <button
                  onClick={() => handleDeleteContact(selected.address)}
                  className="shrink-0 px-3 py-1.5 text-xs text-red-400 hover:text-red-300 hover:bg-red-500/10 rounded-lg transition-colors"
                  title="Remove contact"
                >
                  Remove
                </button>
              </div>
            )}

            {/* Messages */}
            <div className="flex-1 overflow-y-auto px-6 py-4 space-y-2 [&::-webkit-scrollbar]:hidden [-ms-overflow-style:none] [scrollbar-width:none]">

              {/* AI chat view */}
              {selected.address === EGO_AI_ADDRESS ? (
                <>
                  {aiMessages.length === 0 && !aiThinking && (
                    <div className="text-center text-gray-500 text-sm py-10">
                      <div className="flex justify-center mb-3"><EgoAiIcon size={64} /></div>
                      <div className="text-gray-300 font-medium mb-1">Ego AI Assistant</div>
                      <div className="text-xs text-gray-500 max-w-xs mx-auto leading-relaxed">
                        Ask me anything about Ego blockchain — smart contracts, EIPs, tokenomics, how to use this app, or get help writing Urego code.
                      </div>
                      <div className="mt-4 space-y-2">
                        {['How do I write a Urego token contract?', 'What is EGOC and how do I earn it?', 'Explain the HotStuff BFT consensus'].map(suggestion => (
                          <button
                            key={suggestion}
                            onClick={() => { setMsgInput(suggestion); }}
                            className="block w-full max-w-xs mx-auto text-xs bg-gray-700/60 hover:bg-gray-700 text-gray-300 px-4 py-2 rounded-xl transition-colors text-left"
                          >
                            💬 {suggestion}
                          </button>
                        ))}
                      </div>
                    </div>
                  )}
                  {aiMessages.map((m, i) => {
                    const showDateSep = i === 0 || !isSameDay(m.ts, aiMessages[i - 1].ts);
                    return (
                      <React.Fragment key={i}>
                        {showDateSep && (
                          <div className="flex items-center gap-3 my-3">
                            <div className="flex-1 h-px bg-gray-700" />
                            <span className="text-xs text-gray-500 px-1">{fmtDate(m.ts)}</span>
                            <div className="flex-1 h-px bg-gray-700" />
                          </div>
                        )}
                        <div className={`flex flex-col ${m.role === 'user' ? 'items-end' : 'items-start'} mb-1`}>
                          <p className="text-xs text-gray-500 mb-0.5 px-1">{fmtTime(m.ts)}</p>
                          <div className={`flex items-end gap-2`}>
                            {m.role === 'assistant' && (
                              <EgoAiIcon size={28} className="shrink-0" />
                            )}
                            <div className={`max-w-xs lg:max-w-md xl:max-w-lg px-4 py-2.5 rounded-2xl ${
                              m.role === 'user'
                                ? 'bg-blue-600 rounded-br-sm'
                                : 'bg-gray-700 rounded-bl-sm'
                            }`}>
                              {m.role === 'assistant'
                                ? <AiMessageContent content={m.content} />
                                : <p className="text-sm whitespace-pre-wrap break-words">{m.content}</p>
                              }
                            </div>
                          </div>
                        </div>
                      </React.Fragment>
                    );
                  })}
                  {aiThinking && (
                    <div className="flex items-end gap-2 justify-start">
                      <EgoAiIcon size={28} className="shrink-0 mb-1" />
                      <div className="bg-gray-700 rounded-2xl rounded-bl-sm px-4 py-3">
                        <div className="flex gap-1 items-center">
                          <span className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
                          <span className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
                          <span className="w-2 h-2 bg-gray-400 rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
                        </div>
                      </div>
                    </div>
                  )}
                </>
              ) : (
                <>
              {messages.length === 0 && (
                <div className="text-center text-gray-500 text-sm py-12">
                  <div className="text-3xl mb-2">🔐</div>
                  No messages yet — send an encrypted message below.
                </div>
              )}
              {messages.map((m, idx) => {
                const isFileBundle = m.message_type === 'file_bundle';
                const showDateSep = idx === 0 || !isSameDay(m.timestamp, messages[idx - 1].timestamp);
                return (
                  <React.Fragment key={m.id}>
                    {showDateSep && (
                      <div className="flex items-center gap-3 my-3">
                        <div className="flex-1 h-px bg-gray-700" />
                        <span className="text-xs text-gray-500 px-1">{fmtDate(m.timestamp)}</span>
                        <div className="flex-1 h-px bg-gray-700" />
                      </div>
                    )}
                  <div className={`flex flex-col ${m.outgoing ? 'items-end' : 'items-start'} group`}>
                    <p className="text-xs text-gray-500 mb-0.5 px-2 flex items-center gap-1">
                      {fmtTime(m.timestamp)}
                      {m.outgoing && (
                        <span
                          className={m.read_by_recipient ? 'text-blue-400' : 'text-gray-500'}
                          title={m.read_by_recipient ? 'Read' : 'Delivered'}
                        >
                          {m.read_by_recipient ? '✓✓' : '✓'}
                        </span>
                      )}
                    </p>
                  <div className={`flex items-end gap-1 ${m.outgoing ? 'justify-end' : 'justify-start'}`}>
                    {m.outgoing && (
                      <button
                        onClick={() => handleDeleteMessage(m.id)}
                        className="opacity-0 group-hover:opacity-100 transition-opacity w-5 h-5 flex items-center justify-center text-gray-500 hover:text-red-400 shrink-0 text-xs"
                        title="Delete message"
                      >
                        🗑
                      </button>
                    )}

                    {/* Avatar for incoming messages */}
                    {!m.outgoing && (
                      <div className="w-7 h-7 rounded-full bg-gradient-to-br from-purple-500 to-pink-600 flex items-center justify-center text-xs font-bold shrink-0">
                        {(selected?.name || '?').charAt(0).toUpperCase()}
                      </div>
                    )}

                    <div
                      className={`max-w-xs lg:max-w-md xl:max-w-lg px-4 py-2.5 rounded-2xl ${
                        m.outgoing
                          ? 'bg-blue-600 rounded-br-sm'
                          : 'bg-gray-700 rounded-bl-sm'
                      }`}
                    >
                      {m.message_type !== 'text' && (
                        <div className="text-xs font-semibold mb-1 opacity-80">
                          {msgTypeLabel(m.message_type)}
                        </div>
                      )}
                      {isFileBundle ? (() => {
                        const parts  = m.content.trim().split(':');
                        const cid    = parts[1] ?? '';
                        const name64 = parts[3] ?? '';
                        let display_name = cid.slice(0, 12);
                        try { display_name = decodeURIComponent(escape(atob(name64))); } catch {}

                        const alreadyKnown = knownCids.has(cid);
                        const importState = fileImportStates[m.id];
                        const isDone = alreadyKnown || importState?.status === 'done';
                        const isImporting = !isDone && importState?.status === 'importing';
                        const isError = !isDone && importState?.status === 'error';
                        const fileAvailable = alreadyKnown || importState?.status === 'done';
                        const isImage = isImageName(display_name);
                        return (
                          <div className="space-y-2 min-w-[200px] max-w-xs">
                            {/* Inline image preview when file is available locally */}
                            {fileAvailable && isImage && (
                              <InlineFilePreview cid={cid} name={display_name} />
                            )}
                            {/* File info row */}
                            <div className="flex items-center gap-2 bg-black/20 rounded-xl px-3 py-2">
                              <span className="text-2xl shrink-0">{isImage ? '🖼️' : '📎'}</span>
                              <div className="min-w-0">
                                <div className="flex items-center gap-1">
                                  <span className="text-sm font-medium truncate">{display_name}</span>
                                </div>
                                <div className="text-xs text-gray-400 font-mono">{cid.slice(0, 14)}…</div>
                              </div>
                            </div>
                            {!m.outgoing && (
                              <>
                                {isDone ? (
                                  <div className="w-full text-xs py-1.5 rounded-lg font-medium text-center bg-green-700/50 text-green-300">
                                    ✓ Saved to EgoSafe
                                  </div>
                                ) : isImporting ? (
                                  <div className="w-full text-xs py-1.5 rounded-lg font-medium text-center bg-gray-600/60 text-gray-300 cursor-default">
                                    <span className="animate-pulse">Receiving…</span>
                                  </div>
                                ) : isError ? (
                                  <div className="space-y-1">
                                    <div className="text-xs text-red-400 text-center">
                                      ✕ {importState?.error}
                                    </div>
                                    <button
                                      onClick={() => handleImportFile(m.id, m.content)}
                                      className="w-full text-xs py-1.5 rounded-lg font-medium bg-yellow-600 hover:bg-yellow-500 text-white transition"
                                    >
                                      ↺ Retry
                                    </button>
                                  </div>
                                ) : (
                                  <button
                                    onClick={() => handleImportFile(m.id, m.content)}
                                    className="w-full text-xs py-1.5 rounded-lg font-medium bg-purple-600 hover:bg-purple-500 text-white transition"
                                  >
                                    {isImage ? '🖼️ View Image' : '📥 Save File'}
                                  </button>
                                )}
                              </>
                            )}
                            {m.outgoing && (
                              fileAvailable && isImage ? null : (
                                <div className="text-xs text-center text-gray-400 py-0.5">
                                  Sent · waiting for recipient
                                </div>
                              )
                            )}
                          </div>
                        );
                      })() : (
                        <p className="text-sm whitespace-pre-wrap break-words">{linkifyContent(m.content)}</p>
                      )}
                    </div>

                    {!m.outgoing && (
                      <button
                        onClick={() => handleDeleteMessage(m.id)}
                        className="opacity-0 group-hover:opacity-100 transition-opacity w-5 h-5 flex items-center justify-center text-gray-500 hover:text-red-400 shrink-0 text-xs"
                        title="Delete message"
                      >
                        🗑
                      </button>
                    )}
                  </div>
                  </div>
                  </React.Fragment>
                );
              })}
                </>
              )}
              <div ref={msgEndRef} />
            </div>

            {sendError && selected.address !== EGO_AI_ADDRESS && (
              <div className="px-5 py-2 bg-red-500/10 border-t border-red-500/20">
                <span className="text-xs text-red-400">✕ {sendError}</span>
                <button
                  onClick={() => setSendError('')}
                  className="ml-2 text-xs text-gray-400 hover:text-white"
                >
                  ✕
                </button>
              </div>
            )}

            {/* Input area */}
            <div className="px-5 py-4 border-t border-gray-700 shrink-0 space-y-2">
              <div className="flex gap-2 items-end">
                <button
                  onClick={() => setShowAttachMenu(v => !v)}
                  disabled={selected.address === EGO_AI_ADDRESS || attaching}
                  title="Attach file or image"
                  className="shrink-0 w-10 h-10 flex items-center justify-center rounded-xl bg-gray-700 hover:bg-gray-600 disabled:opacity-40 text-lg transition-colors"
                >
                  {attaching ? <span className="animate-spin text-sm">⏳</span> : '📎'}
                </button>
                <textarea
                  ref={msgInputRef}
                  value={msgInput}
                  onChange={e => {
                    setMsgInput(e.target.value);
                    const el = e.target;
                    el.style.height = 'auto';
                    el.style.height = Math.min(el.scrollHeight, 160) + 'px';
                  }}
                  onKeyDown={e => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault();
                      handleSend('text');
                    }
                  }}
                  rows={1}
                  placeholder={selected.address === EGO_AI_ADDRESS ? 'Ask Ego AI anything…' : 'Type a message… Enter to send, Shift+Enter for a new line'}
                  className={`flex-1 bg-gray-700 border rounded-xl px-4 py-2.5 text-sm focus:outline-none resize-none leading-relaxed max-h-40 overflow-y-auto ${
                    selected.address === EGO_AI_ADDRESS
                      ? 'border-yellow-600/40 focus:border-yellow-400'
                      : 'border-gray-600 focus:border-blue-500'
                  }`}
                />
                <button
                  onClick={() => handleSend('text')}
                  disabled={(selected.address === EGO_AI_ADDRESS ? aiThinking : sending) || !msgInput.trim()}
                  className={`shrink-0 px-5 py-2.5 disabled:opacity-50 rounded-xl text-sm font-medium transition-colors ${
                    selected.address === EGO_AI_ADDRESS
                      ? 'bg-yellow-500 hover:bg-yellow-400 text-black'
                      : 'bg-blue-600 hover:bg-blue-500 text-white'
                  }`}
                >
                  {selected.address === EGO_AI_ADDRESS
                    ? (aiThinking ? '…' : 'Ask')
                    : (sending ? '…' : 'Send')}
                </button>
              </div>
              {showAttachMenu && selected.address !== EGO_AI_ADDRESS && (
                <div className="flex gap-2">
                  <button
                    onClick={() => { setShowAttachMenu(false); handlePickAttachment(false); }}
                    className="flex items-center gap-1.5 text-xs bg-gray-700 hover:bg-gray-600 px-3 py-1.5 rounded-lg transition-colors"
                  >
                    📄 File
                  </button>
                  <button
                    onClick={() => { setShowAttachMenu(false); handlePickAttachment(true); }}
                    className="flex items-center gap-1.5 text-xs bg-gray-700 hover:bg-gray-600 px-3 py-1.5 rounded-lg transition-colors"
                  >
                    🖼️ Image
                  </button>
                </div>
              )}
              {attachError && (
                <div className="text-xs text-red-400 bg-red-500/10 rounded-lg px-3 py-2">{attachError}</div>
              )}
            </div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center">
            <div className="text-center text-gray-500 max-w-sm px-4">
              <div className="text-7xl mb-4">🔐</div>
              <div className="text-xl font-semibold text-gray-300">Ego Messenger</div>
              <div className="text-sm mt-2">End-to-end encrypted, peer-to-peer</div>
              <div className="text-xs mt-4 text-gray-600 leading-relaxed">
                Share your contact card with someone. When they click Add Contact and paste it,
                you'll get a live notification to approve or decline.
              </div>
              <div className="flex gap-2 mt-6 justify-center">
                <button
                  onClick={() => { setShowMyCard(true); setMyCard(''); setMyCardName(''); setRevokeConfirm(false); }}
                  className="px-4 py-2.5 bg-gray-700 hover:bg-gray-600 text-white rounded-xl text-sm font-medium transition-colors"
                >
                  📤 My Card
                </button>
                <button
                  onClick={() => setShowAdd(true)}
                  className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-sm font-medium transition-colors"
                >
                  + Add Contact
                </button>
              </div>
            </div>
          </div>
        )}
      </div>

      </div>{}

      {}
      {showMyCard && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4" onClick={e => { if (e.target === e.currentTarget) setShowMyCard(false); }}>
          <div className="bg-gray-800 rounded-2xl w-full max-w-md shadow-2xl">
            <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between">
              <h3 className="font-bold text-lg">My Contact Card</h3>
              <button onClick={() => setShowMyCard(false)} className="text-gray-400 hover:text-white text-xl leading-none">✕</button>
            </div>
            <div className="p-6 space-y-4">
              <p className="text-sm text-gray-400 leading-relaxed">
                Generate your contact card and share it with anyone who wants to connect with you.
                When they paste it in <strong className="text-white">Add Contact</strong>, you'll get
                a live notification on this device to approve or decline.
              </p>
              <div className="bg-yellow-900/20 border border-yellow-700/40 rounded-xl px-4 py-3">
                <div className="text-xs text-yellow-400 font-semibold mb-1">🔑 Bundle exposed?</div>
                <p className="text-xs text-gray-400 mb-2">Revoking invalidates your current card. Anyone with the old bundle can no longer send you pairing requests. All existing approved contacts keep their connection and can still message you normally.</p>
                {!revokeConfirm ? (
                  <button
                    onClick={() => setRevokeConfirm(true)}
                    className="text-xs text-yellow-400 hover:text-yellow-300 underline transition-colors"
                  >
                    Revoke &amp; Regenerate Bundle
                  </button>
                ) : (
                  <div className="flex items-center gap-2">
                    <span className="text-xs text-yellow-300">Are you sure?</span>
                    <button
                      onClick={handleRevokeBundle}
                      disabled={revoking}
                      className="text-xs bg-red-600 hover:bg-red-500 disabled:opacity-50 px-3 py-1 rounded-lg font-semibold transition-colors"
                    >
                      {revoking ? 'Revoking…' : 'Yes, Revoke'}
                    </button>
                    <button
                      onClick={() => setRevokeConfirm(false)}
                      className="text-xs text-gray-400 hover:text-white transition-colors"
                    >
                      Cancel
                    </button>
                  </div>
                )}
              </div>
              <div>
                <label className="text-xs text-gray-400 mb-1.5 block">Your display name</label>
                <input
                  value={myCardName}
                  onChange={e => setMyCardName(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter') handleGenerateCard(); }}
                  placeholder="e.g. Alice"
                  autoFocus
                  className="w-full bg-gray-700 border border-gray-600 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-blue-500"
                />
              </div>
              <button
                onClick={handleGenerateCard}
                disabled={!myCardName.trim() || generatingCard}
                className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-50 py-2.5 rounded-xl text-sm font-medium transition-colors"
              >
                {generatingCard ? 'Generating…' : 'Generate Card'}
              </button>
              {myCard && (() => {
                const shortBundle = myCard.length > 45 ? myCard.slice(0, 45) + '…' : myCard;
                return (
                  <div className="space-y-3">
                    <div className="text-xs text-green-400 font-medium">✓ Card ready — click Copy and share it:</div>
                    <div className="bg-gray-900 rounded-xl px-4 py-3 flex items-center gap-3">
                      <div className="w-10 h-10 rounded-full bg-gradient-to-br from-blue-500 to-purple-600 flex items-center justify-center text-lg font-black shrink-0">
                        {myCardName.charAt(0).toUpperCase()}
                      </div>
                      <div className="min-w-0">
                        <div className="text-sm font-semibold text-white">{myCardName}</div>
                        <div className="text-xs text-gray-400 font-mono mt-0.5" title={myCard}>{shortBundle}</div>
                      </div>
                    </div>
                    <button
                      onClick={async () => {
                        await writeText(myCard);
                        setCopied(true);
                        setTimeout(() => setCopied(false), 2000);
                      }}
                      className={`w-full py-2 rounded-xl text-sm font-medium transition-colors ${
                        copied
                          ? 'bg-green-800 text-green-300 cursor-default'
                          : 'bg-green-600 hover:bg-green-500'
                      }`}
                    >
                      {copied ? '✓ Copied!' : '📋 Copy Card'}
                    </button>
                  </div>
                );
              })()}
            </div>
          </div>
        </div>
      )}

      {/* ── Add Contact modal ── */}
      {showAdd && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4" onClick={e => { if (e.target === e.currentTarget) setShowAdd(false); }}>
          <div className="bg-gray-800 rounded-2xl w-full max-w-md shadow-2xl">
            <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between">
              <h3 className="font-bold text-lg">Add Contact</h3>
              <button onClick={() => setShowAdd(false)} className="text-gray-400 hover:text-white text-xl leading-none">✕</button>
            </div>
            <div className="p-6 space-y-4">
              <p className="text-sm text-gray-400 leading-relaxed">
                Paste the other person's contact card. A connection request will be sent
                directly to their device — they'll get a notification to approve or decline.
              </p>
              <div>
                <label className="text-xs text-gray-400 mb-1.5 block">Their contact card</label>
                <textarea
                  value={addBundle}
                  onChange={e => setAddBundle(e.target.value)}
                  placeholder="egocontact1:…"
                  rows={3}
                  autoFocus
                  className="w-full bg-gray-700 border border-gray-600 rounded-xl px-4 py-2.5 text-xs font-mono focus:outline-none focus:border-blue-500 resize-none"
                />
              </div>
              <div>
                <label className="text-xs text-gray-400 mb-1.5 block">Your display name (they'll see this)</label>
                <input
                  value={addMyName}
                  onChange={e => setAddMyName(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter') handleAddContact(); }}
                  placeholder="e.g. Bob"
                  className="w-full bg-gray-700 border border-gray-600 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-blue-500"
                />
              </div>
              <button
                onClick={handleAddContact}
                disabled={!addBundle.trim() || !addMyName.trim() || adding}
                className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-50 py-2.5 rounded-xl text-sm font-medium transition-colors"
              >
                {adding ? 'Sending request…' : 'Send Contact Request'}
              </button>
              {addMsg && (
                <div className={`text-sm text-center py-2 px-3 rounded-xl ${
                  addMsg.startsWith('✓')
                    ? 'text-green-400 bg-green-500/10'
                    : 'text-red-400 bg-red-500/10'
                }`}>
                  {addMsg}
                </div>
              )}
            </div>
          </div>
        </div>
      )}

      {}
      {pendingAction && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4" onClick={e => { if (e.target === e.currentTarget) { setPendingAction(null); setActionDone(false); } }}>
          <div className="bg-gray-800 rounded-2xl w-full max-w-md shadow-2xl">
            <div className="px-6 py-4 border-b border-gray-700 flex items-center justify-between">
              <h3 className="font-bold">
                {actionDone
                  ? pendingAction.action === 'approve' ? '✓ Approved' : '✓ Declined'
                  : pendingAction.action === 'approve' ? 'Approve Contact' : 'Decline Contact'}
              </h3>
              <button onClick={closePendingAction} className="text-gray-400 hover:text-white text-xl leading-none">✕</button>
            </div>
            <div className="p-6 space-y-4">
              <div className="flex items-center gap-3 bg-gray-700/50 rounded-xl p-3">
                <div className="w-10 h-10 rounded-full bg-gradient-to-br from-yellow-500 to-orange-600 flex items-center justify-center text-sm font-bold shrink-0">
                  {(pendingAction.contact.name || '?').charAt(0).toUpperCase()}
                </div>
                <div>
                  <div className="font-medium text-sm">{pendingAction.contact.name}</div>
                  <div className="text-xs text-gray-400 font-mono">{truncAddr(pendingAction.contact.address)}</div>
                </div>
              </div>

              {actionDone ? (
                <p className="text-sm text-center text-green-400">
                  {pendingAction.action === 'approve'
                    ? `✓ Connected! ${pendingAction.contact.name} has been notified.`
                    : '✓ Request declined and removed.'}
                </p>
              ) : pendingAction.action === 'approve' ? (
                <>
                  <p className="text-sm text-gray-400">
                    {actionName
                      ? <>You'll appear as <strong className="text-white">{actionName}</strong> to{' '}<strong className="text-white">{pendingAction.contact.name}</strong>.</>
                      : <>Enter your display name so{' '}<strong className="text-white">{pendingAction.contact.name}</strong>{' '}knows who accepted.</>
                    }
                  </p>
                  <div>
                    <label className="text-xs text-gray-400 mb-1.5 block">Your display name</label>
                    <input
                      value={actionName}
                      onChange={e => setActionName(e.target.value)}
                      onKeyDown={e => { if (e.key === 'Enter') handleApprove(); }}
                      placeholder="e.g. Bob"
                      autoFocus={!actionName}
                      className="w-full bg-gray-700 border border-gray-600 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-green-500"
                    />
                  </div>
                  <button
                    onClick={handleApprove}
                    disabled={!actionName.trim() || actioning}
                    className="w-full bg-green-600 hover:bg-green-500 disabled:opacity-50 py-2.5 rounded-xl text-sm font-medium transition-colors"
                  >
                    {actioning ? 'Approving…' : 'Approve & Connect'}
                  </button>
                </>
              ) : (
                <>
                  <p className="text-sm text-gray-400">
                    Decline <strong className="text-white">{pendingAction.contact.name}</strong>'s request.
                    They will be notified automatically.
                  </p>
                  <button
                    onClick={handleDecline}
                    disabled={actioning}
                    className="w-full bg-red-600 hover:bg-red-500 disabled:opacity-50 py-2.5 rounded-xl text-sm font-medium transition-colors"
                  >
                    {actioning ? 'Declining…' : 'Decline Request'}
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default MessengerPage;
