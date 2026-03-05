import React, { useEffect, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';
import { writeText } from '@tauri-apps/api/clipboard';

// ── Types ─────────────────────────────────────────────────────────────────────

interface Contact {
  address: string;
  name: string;
  ed25519_pubkey: string;
  kyber_pubkey: string;
  shared_key_hex: string;
  status: string;     // "pending_out" | "pending_in" | "approved"
  added_at: number;
  endpoint: string;
}

interface Message {
  id: string;
  from: string;
  to: string;
  content: string;
  message_type: string;  // "text" | "file_bundle" | "decrypt_key"
  timestamp: number;
  outgoing: boolean;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmtTime(ts: number): string {
  return new Date(ts * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
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

// ── Main page ─────────────────────────────────────────────────────────────────

const MessengerPage: React.FC = () => {
  // Core state
  const [contacts, setContacts]     = useState<Contact[]>([]);
  const [selected, setSelected]     = useState<Contact | null>(null);
  const [messages, setMessages]     = useState<Message[]>([]);
  const [msgInput, setMsgInput]     = useState('');
  const [sending, setSending]       = useState(false);
  const [sendError, setSendError]   = useState('');

  // "Share My Card" modal
  const [showMyCard, setShowMyCard]         = useState(false);
  const [myCardName, setMyCardName]         = useState('');
  const [myCard, setMyCard]                 = useState('');
  const [generatingCard, setGeneratingCard] = useState(false);
  const [copied, setCopied]                 = useState(false);

  // "Add Contact" modal
  const [showAdd, setShowAdd]     = useState(false);
  const [addBundle, setAddBundle] = useState('');
  const [addMyName, setAddMyName] = useState('');
  const [addMsg, setAddMsg]       = useState('');
  const [adding, setAdding]       = useState(false);

  // Approve / Decline flow
  const [pendingAction, setPendingAction] = useState<{
    contact: Contact;
    action: 'approve' | 'decline';
  } | null>(null);
  const [actionName, setActionName] = useState('');
  const [actioning, setActioning]   = useState(false);
  const [actionDone, setActionDone] = useState(false);

  const msgEndRef = useRef<HTMLDivElement>(null);
  const [importedIds, setImportedIds] = useState<Set<string>>(new Set());

  // P2P connectivity status
  interface P2pStatus { upnp: string; upnp_error: string | null; public_endpoint: string; p2p_port: number; }
  const [p2pStatus, setP2pStatus] = useState<P2pStatus | null>(null);

  // ── Data loaders ─────────────────────────────────────────────────────────

  async function loadContacts() {
    try {
      const cs = await invoke<Contact[]>('get_contacts');
      setContacts(cs);
    } catch (e) {
      console.error('get_contacts', e);
    }
  }

  async function loadMessages(addr: string) {
    try {
      const ms = await invoke<Message[]>('get_messages', { contactAddr: addr });
      setMessages(ms);
    } catch (e) {
      console.error('get_messages', e);
    }
  }

  // ── Real-time P2P event listeners ─────────────────────────────────────────

  // Keep a ref to `selected` so the event handlers inside useEffect can see the
  // latest value without stale closure issues.
  const selectedRef = useRef<Contact | null>(null);
  useEffect(() => { selectedRef.current = selected; }, [selected]);

  useEffect(() => {
    invoke<P2pStatus>('get_p2p_status').then(setP2pStatus).catch(() => {});
    const unlistenP2p = listen('ego://p2p-status-changed', () => {
      invoke<P2pStatus>('get_p2p_status').then(setP2pStatus).catch(() => {});
    });
    return () => { unlistenP2p.then(fn => fn()); };
  }, []);

  useEffect(() => {
    loadContacts();

    const unlisteners: Promise<() => void>[] = [
      // B receives A's contact request
      listen<Contact>('ego://contact-request', () => { loadContacts(); }),

      // A receives B's approval
      listen<Contact>('ego://contact-approved', (event) => {
        loadContacts();
        if (event.payload.address === selectedRef.current?.address) {
          loadMessages(event.payload.address);
        }
      }),

      // A receives B's decline
      listen('ego://contact-declined', () => { loadContacts(); }),

      // Incoming chat message delivered by P2P server
      listen<Message>('ego://message-received', (event) => {
        const msg = event.payload;
        // Refresh messages if the chat with the sender (or recipient) is open
        const cur = selectedRef.current;
        if (cur && (msg.from === cur.address || msg.to === cur.address)) {
          loadMessages(cur.address);
        }
      }),
    ];

    return () => { unlisteners.forEach(p => p.then(fn => fn())); };
  }, []);  // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (selected) loadMessages(selected.address);
    else setMessages([]);
  }, [selected]);

  useEffect(() => {
    msgEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // ── Handlers ─────────────────────────────────────────────────────────────

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
      setActionDone(true);
      await loadContacts();
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
      setTimeout(() => closePendingAction(), 1200);
    } catch (e: any) {
      console.error('decline_contact_request', e);
    } finally {
      setActioning(false);
    }
  }

  async function handleSend(msgType: string = 'text') {
    if (!selected || !msgInput.trim()) return;
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
      // Reload local outgoing message immediately
      await loadMessages(selected.address);
    } catch (e: any) {
      setSendError(String(e));
      setMsgInput(text); // restore input on error
    } finally {
      setSending(false);
    }
  }

  async function handleDeleteContact(addr: string) {
    if (!window.confirm('Remove this contact?')) return;
    try {
      await invoke('delete_contact', { contactAddr: addr });
      if (selected?.address === addr) setSelected(null);
      await loadContacts();
    } catch (e) { console.error(e); }
  }

  function closePendingAction() {
    setPendingAction(null);
    setActionName('');
    setActioning(false);
    setActionDone(false);
  }

  // ── Partitioned contacts ──────────────────────────────────────────────────

  const approvedContacts   = contacts.filter(c => c.status === 'approved');
  const pendingInContacts  = contacts.filter(c => c.status === 'pending_in');
  const pendingOutContacts = contacts.filter(c => c.status === 'pending_out');

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="flex flex-col h-screen bg-gray-900 text-white overflow-hidden">

      {/* ── P2P connectivity banner ── */}
      {p2pStatus?.upnp === 'failed' && (
        <div className="bg-yellow-900/80 border-b border-yellow-600/40 px-4 py-2 flex items-start gap-2 shrink-0">
          <span className="text-yellow-400 shrink-0 mt-0.5">⚠️</span>
          <div className="text-xs text-yellow-200 leading-relaxed">
            <strong>Cross-network messaging may not work.</strong> UPnP port mapping failed — peers on other networks can't reach you.
            Fix: forward <strong>TCP port {p2pStatus.p2p_port}</strong> to your local machine in your router settings.
          </div>
        </div>
      )}
      {p2pStatus?.upnp === 'ok' && (
        <div className="bg-green-900/40 border-b border-green-700/30 px-4 py-1.5 shrink-0">
          <span className="text-xs text-green-400">✓ Internet P2P active — reachable at {p2pStatus.public_endpoint}</span>
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
              onClick={() => { setShowMyCard(true); setMyCard(''); setMyCardName(''); }}
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
                      <div className="text-xs text-gray-400 font-mono">{truncAddr(c.address)}</div>
                    </div>
                  </div>
                  <div className="flex gap-1.5">
                    <button
                      onClick={() => {
                        setPendingAction({ contact: c, action: 'approve' });
                        setActionName('');
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
              className="flex items-center gap-3 px-4 py-3 opacity-50"
            >
              <div className="w-9 h-9 rounded-full bg-gray-600 flex items-center justify-center text-base shrink-0">
                ⏳
              </div>
              <div className="min-w-0 flex-1">
                <div className="text-sm text-gray-300 truncate">{c.name}</div>
                <div className="text-xs text-gray-500 mt-0.5">Waiting for approval…</div>
              </div>
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
            <div className="px-6 py-3 border-b border-gray-700 flex items-center justify-between shrink-0">
              <div className="flex items-center gap-3">
                <div className="w-9 h-9 rounded-full bg-gradient-to-br from-purple-500 to-pink-600 flex items-center justify-center text-sm font-bold shrink-0">
                  {(selected.name || '?').charAt(0).toUpperCase()}
                </div>
                <div>
                  <div className="font-semibold text-sm">{selected.name}</div>
                  <div className="text-xs text-gray-400 font-mono">{truncAddr(selected.address)}</div>
                </div>
              </div>
              <button
                onClick={() => handleDeleteContact(selected.address)}
                className="px-3 py-1.5 text-xs text-red-400 hover:bg-red-500/10 rounded-lg transition-colors"
              >
                Remove
              </button>
            </div>

            {/* Messages */}
            <div className="flex-1 overflow-y-auto px-6 py-4 space-y-2">
              {messages.length === 0 && (
                <div className="text-center text-gray-500 text-sm py-12">
                  <div className="text-3xl mb-2">🔐</div>
                  No messages yet — send an encrypted message below.
                </div>
              )}
              {messages.map(m => {
                const isFileBundle = m.message_type === 'file_bundle';
                const imported = importedIds.has(m.id);
                return (
                  <div key={m.id} className={`flex ${m.outgoing ? 'justify-end' : 'justify-start'}`}>
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
                      {isFileBundle ? (
                        <div className="space-y-2">
                          <div className="text-xs font-mono break-all text-purple-200 bg-black/20 rounded-lg px-2 py-1.5 max-h-20 overflow-hidden">
                            {m.content.slice(0, 60)}…
                          </div>
                          {!m.outgoing && (
                            <button
                              onClick={async () => {
                                const parts = m.content.trim().split(':');
                                if (parts.length < 5) return;
                                const [, cid, key_nonce_hex, name64, from_address] = parts;
                                let display_name = cid.slice(0, 12);
                                try { display_name = decodeURIComponent(escape(atob(name64))); } catch {}
                                try {
                                  await invoke('import_shared_file', {
                                    bundle: { cid, key_nonce_hex, display_name, from_address },
                                  });
                                  setImportedIds(s => new Set([...s, m.id]));
                                } catch (e) { console.error(e); }
                              }}
                              disabled={imported}
                              className={`w-full text-xs py-1.5 rounded-lg font-medium transition ${
                                imported
                                  ? 'bg-green-700/50 text-green-300 cursor-default'
                                  : 'bg-purple-600 hover:bg-purple-500 text-white'
                              }`}
                            >
                              {imported ? '✓ Imported to Storage' : '📥 Import File'}
                            </button>
                          )}
                        </div>
                      ) : (
                        <p className="text-sm break-all whitespace-pre-wrap">{m.content}</p>
                      )}
                      <p className={`text-xs mt-1 text-right ${m.outgoing ? 'text-blue-200' : 'text-gray-400'}`}>
                        {fmtTime(m.timestamp)}
                      </p>
                    </div>
                  </div>
                );
              })}
              <div ref={msgEndRef} />
            </div>

            {sendError && (
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
              <div className="flex gap-2">
                <input
                  value={msgInput}
                  onChange={e => setMsgInput(e.target.value)}
                  onKeyDown={e => {
                    if (e.key === 'Enter' && !e.shiftKey) {
                      e.preventDefault();
                      handleSend('text');
                    }
                  }}
                  placeholder="Type a message… press Enter to send"
                  className="flex-1 bg-gray-700 border border-gray-600 rounded-xl px-4 py-2.5 text-sm focus:outline-none focus:border-blue-500"
                />
                <button
                  onClick={() => handleSend('text')}
                  disabled={sending || !msgInput.trim()}
                  className="px-5 py-2.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-50 rounded-xl text-sm font-medium transition-colors"
                >
                  {sending ? '…' : 'Send'}
                </button>
              </div>
              <div className="flex gap-2">
                <button
                  onClick={() => handleSend('file_bundle')}
                  disabled={!msgInput.trim() || sending}
                  className="text-xs px-3 py-1.5 bg-gray-700 hover:bg-gray-600 disabled:opacity-40 rounded-lg transition-colors"
                  title="Paste an egoshare1:… bundle above, then click this"
                >
                  📎 Send as File Bundle
                </button>
                <button
                  onClick={() => handleSend('decrypt_key')}
                  disabled={!msgInput.trim() || sending}
                  className="text-xs px-3 py-1.5 bg-gray-700 hover:bg-gray-600 disabled:opacity-40 rounded-lg transition-colors"
                >
                  🔑 Send as Decrypt Key
                </button>
              </div>
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
                  onClick={() => { setShowMyCard(true); setMyCard(''); setMyCardName(''); }}
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

      </div>{/* end flex-1 row */}

      {/* ── Share My Card modal ── */}
      {showMyCard && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
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
              {myCard && (
                <div className="space-y-2">
                  <div className="text-xs text-green-400 font-medium">✓ Share this with your contact:</div>
                  <div className="bg-gray-900 rounded-xl p-3 text-xs font-mono break-all text-gray-300 max-h-28 overflow-y-auto">
                    {myCard}
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
              )}
            </div>
          </div>
        </div>
      )}

      {/* ── Add Contact modal ── */}
      {showAdd && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
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

      {/* ── Approve / Decline modal ── */}
      {pendingAction && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
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
                    Enter your display name so{' '}
                    <strong className="text-white">{pendingAction.contact.name}</strong>{' '}
                    knows who accepted.
                  </p>
                  <div>
                    <label className="text-xs text-gray-400 mb-1.5 block">Your display name</label>
                    <input
                      value={actionName}
                      onChange={e => setActionName(e.target.value)}
                      onKeyDown={e => { if (e.key === 'Enter') handleApprove(); }}
                      placeholder="e.g. Bob"
                      autoFocus
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
