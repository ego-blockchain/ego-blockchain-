import React, { useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';

interface PostView {
  id: string;
  from: string;
  name: string;
  body: string;
  ts: number;
  mine: boolean;
  edited: boolean;
  change_until: number | null;
  removal_votes: number;
  my_vote: boolean;
  removed_until: number | null;
}

interface ChatFeed {
  me: string;
  my_name: string;
  my_removed_until: number | null;
  threshold: number;
  ban_days: number;
  posts: PostView[];
  oldest: number | null;
}

const MAX_BODY = 500;
const MAX_NAME = 24;
const PAGE = 200;

function shortAddr(a: string): string {
  return a.length > 18 ? `${a.slice(0, 10)}…${a.slice(-6)}` : a;
}

function ago(ts: number): string {
  const s = Math.max(0, Math.floor(Date.now() / 1000) - ts);
  if (s < 60) return 'just now';
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86_400) return `${Math.floor(s / 3600)}h ago`;
  return new Date(ts * 1000).toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
}

function day(ts: number): string {
  return new Date(ts * 1000).toLocaleDateString(undefined, { day: 'numeric', month: 'long', year: 'numeric' });
}

function hue(addr: string): number {
  let h = 0;
  for (let i = 0; i < addr.length; i++) h = (h * 31 + addr.charCodeAt(i)) % 360;
  return h;
}

function errorText(e: unknown): string {
  if (typeof e === 'string') {
    return e.replace(/^(Invalid input|Wallet error|Database error|Network error|Operation not permitted|Resource not found): /, '');
  }
  return 'Something went wrong. Try again.';
}

function Avatar({ addr, name }: { addr: string; name: string }) {
  const letter = (name.trim()[0] ?? addr.slice(5, 6)).toUpperCase();
  return (
    <div
      className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold text-white shrink-0"
      style={{ background: `hsl(${hue(addr)} 45% 38%)` }}
      aria-hidden
    >
      {letter}
    </div>
  );
}

function minutesLeft(until: number): number {
  return Math.max(1, Math.ceil((until - Date.now() / 1000) / 60));
}

function Message({
  post,
  threshold,
  banDays,
  onChanged,
}: {
  post: PostView;
  threshold: number;
  banDays: number;
  onChanged: () => void;
}) {
  const [mode, setMode] = useState<'view' | 'vote' | 'edit' | 'delete'>('view');
  const [text, setText] = useState(post.body);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const who = post.name || shortAddr(post.from);
  const canChange = post.mine && post.change_until != null && post.change_until > Date.now() / 1000;
  const rowRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (mode !== 'view') rowRef.current?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }, [mode]);

  async function run(cmd: string, args: Record<string, unknown>) {
    setBusy(true);
    setError('');
    try {
      await invoke(cmd, args);
      setMode('view');
      onChanged();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  function close() {
    setMode('view');
    setError('');
    setText(post.body);
  }

  const action = 'px-2 py-0.5 rounded-md text-[11px] bg-gray-800 border border-gray-700 text-gray-300';

  return (
    <div ref={rowRef} className={`group relative flex gap-3 px-3 py-2.5 rounded-xl ${post.mine ? 'bg-purple-500/10' : 'hover:bg-gray-800/40'}`}>
      <Avatar addr={post.from} name={post.name} />
      <div className="flex-1 min-w-0">
        <div className="flex items-baseline gap-x-2 flex-wrap">
          <span className={`text-sm font-semibold text-white ${post.name ? '' : 'font-mono'}`} title={post.from}>{who}</span>
          {post.name && <span className="text-[11px] font-mono text-gray-500" title={post.from}>{shortAddr(post.from)}</span>}
          <span className="text-[11px] text-gray-500">{ago(post.ts)}{post.edited ? ' · edited' : ''}</span>
          {!post.mine && post.removal_votes > 0 && (
            <span
              title={`${post.removal_votes} of ${threshold} removal votes`}
              className="text-[10px] px-1.5 rounded border border-red-500/30 text-red-300 bg-red-500/10"
            >
              {post.removal_votes}/{threshold} to remove
            </span>
          )}
        </div>

        {mode === 'view' && !post.mine && (
          <button
            onClick={() => setMode('vote')}
            disabled={post.my_vote}
            className={`absolute right-2 top-2 ${action} hover:text-red-300 disabled:hover:text-gray-300 opacity-0 group-hover:opacity-100 focus:opacity-100 transition-opacity`}
          >
            {post.my_vote ? 'You voted to remove' : 'Vote to remove'}
          </button>
        )}
        {mode === 'view' && canChange && (
          <div
            className="absolute right-2 top-2 flex gap-1 opacity-0 group-hover:opacity-100 focus-within:opacity-100 transition-opacity"
            title={`You can change this for ${minutesLeft(post.change_until!)} more minutes`}
          >
            <button onClick={() => { setText(post.body); setMode('edit'); }} className={`${action} hover:text-white`}>Edit</button>
            <button onClick={() => setMode('delete')} className={`${action} hover:text-red-300`}>Delete</button>
          </div>
        )}

        {mode === 'edit' ? (
          <div className="mt-1 space-y-2">
            <textarea
              id={`dao-chat-edit-${post.id}`}
              value={text}
              maxLength={MAX_BODY}
              rows={3}
              autoFocus
              onChange={e => setText(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'Escape') close();
                if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); run('dao_chat_edit', { postId: post.id, postTs: post.ts, body: text }); }
              }}
              className="w-full resize-none px-3 py-2 rounded-lg bg-gray-800 border border-gray-700 text-sm text-white focus:outline-none focus:border-purple-500"
            />
            {error && <p className="text-xs text-red-300">{error}</p>}
            <div className="flex items-center gap-2">
              <button onClick={close} className="px-3 py-1.5 rounded-lg text-xs text-gray-300 bg-gray-800 hover:bg-gray-700">Cancel</button>
              <button
                onClick={() => run('dao_chat_edit', { postId: post.id, postTs: post.ts, body: text })}
                disabled={busy || !text.trim() || text.trim() === post.body}
                className="px-3 py-1.5 rounded-lg text-xs font-medium text-white bg-purple-600 hover:bg-purple-500 disabled:opacity-50"
              >
                {busy ? 'Saving…' : 'Save'}
              </button>
              {post.change_until != null && (
                <span className="text-[11px] text-gray-500">{minutesLeft(post.change_until)} min left to edit</span>
              )}
            </div>
          </div>
        ) : (
          <p className="text-sm text-gray-200 whitespace-pre-wrap break-words mt-0.5">{post.body}</p>
        )}

        {mode === 'delete' && (
          <div className="mt-2 p-3 rounded-lg border border-red-500/30 bg-red-500/10 space-y-2">
            <p className="text-xs text-red-200">Delete this message? It disappears for everyone.</p>
            {error && <p className="text-xs text-red-300">{error}</p>}
            <div className="flex gap-2">
              <button onClick={close} className="px-3 py-1.5 rounded-lg text-xs text-gray-300 bg-gray-800 hover:bg-gray-700">Cancel</button>
              <button
                onClick={() => run('dao_chat_delete', { postId: post.id, postTs: post.ts })}
                disabled={busy}
                className="px-3 py-1.5 rounded-lg text-xs font-medium text-white bg-red-600 hover:bg-red-500 disabled:opacity-50"
              >
                {busy ? 'Deleting…' : 'Delete'}
              </button>
            </div>
          </div>
        )}

        {mode === 'vote' && (
          <div className="mt-2 p-3 rounded-lg border border-red-500/30 bg-red-500/10 space-y-2">
            <p className="text-xs text-red-200">
              Vote to remove {who}? {threshold} votes within {banDays} days remove them from the chat for {banDays} days.
              A vote can't be taken back.
            </p>
            {error && <p className="text-xs text-red-300">{error}</p>}
            <div className="flex gap-2">
              <button onClick={close} className="px-3 py-1.5 rounded-lg text-xs text-gray-300 bg-gray-800 hover:bg-gray-700">Cancel</button>
              <button
                onClick={() => run('dao_chat_vote', { target: post.from })}
                disabled={busy}
                className="px-3 py-1.5 rounded-lg text-xs font-medium text-white bg-red-600 hover:bg-red-500 disabled:opacity-50"
              >
                {busy ? 'Voting…' : 'Vote to remove'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default function CommunityChat() {
  const [feed, setFeed] = useState<ChatFeed | null>(null);
  const [older, setOlder] = useState<PostView[]>([]);
  const [olderDone, setOlderDone] = useState(false);
  const [draft, setDraft] = useState('');
  const [sending, setSending] = useState(false);
  const [error, setError] = useState('');
  const [editing, setEditing] = useState(false);
  const [nameDraft, setNameDraft] = useState('');
  const [nameError, setNameError] = useState('');
  const listRef = useRef<HTMLDivElement>(null);
  const stickToBottom = useRef(true);

  const load = useCallback(async () => {
    try {
      setFeed(await invoke<ChatFeed>('dao_chat_feed', { before: null }));
    } catch {}
  }, []);

  useEffect(() => {
    load();
    invoke('dao_chat_sync').catch(() => {});
    const un = listen('ego://dao-chat', () => load());
    const timer = setInterval(load, 20_000);
    return () => {
      un.then(f => f());
      clearInterval(timer);
    };
  }, [load]);

  useLayoutEffect(() => {
    const el = listRef.current;
    if (el && stickToBottom.current) el.scrollTop = el.scrollHeight;
  }, [feed]);

  function onScroll() {
    const el = listRef.current;
    if (el) stickToBottom.current = el.scrollHeight - el.scrollTop - el.clientHeight < 80;
  }

  async function loadOlder() {
    const oldest = older[0]?.ts ?? feed?.oldest;
    if (oldest == null) return;
    try {
      const page = await invoke<ChatFeed>('dao_chat_feed', { before: oldest });
      setOlder(prev => [...page.posts, ...prev]);
      if (page.posts.length === 0 || page.oldest == null) setOlderDone(true);
    } catch {}
  }

  async function send() {
    const text = draft.trim();
    if (!text || sending) return;
    setSending(true);
    setError('');
    try {
      await invoke('dao_chat_post', { body: text });
      setDraft('');
      stickToBottom.current = true;
      await load();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setSending(false);
    }
  }

  async function saveName() {
    setNameError('');
    try {
      await invoke<string>('dao_chat_set_name', { name: nameDraft });
      setEditing(false);
      await load();
    } catch (e) {
      setNameError(errorText(e));
    }
  }

  const posts = [...older, ...(feed?.posts ?? [])];
  const removedUntil = feed?.my_removed_until ?? null;
  const showOlder = !olderDone && (feed?.posts.length ?? 0) >= PAGE - 10;

  return (
    <div className="flex-1 min-h-0 flex flex-col">
      <div className="px-4 pt-3 pb-2.5 border-b border-gray-800 space-y-1.5">
        <div className="flex items-center gap-2">
          <span className="w-2 h-2 rounded-full bg-green-400" aria-hidden />
          <p className="text-sm font-semibold text-white">Community chat</p>
          <span className="text-[11px] text-gray-500">public</span>
        </div>
        {editing ? (
          <div className="flex items-center gap-2">
            <input
              id="dao-chat-name"
              value={nameDraft}
              maxLength={MAX_NAME}
              autoFocus
              onChange={e => setNameDraft(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') saveName(); if (e.key === 'Escape') setEditing(false); }}
              placeholder="Your name in the chat"
              className="flex-1 min-w-0 px-3 py-1.5 rounded-lg bg-gray-800 border border-gray-700 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-purple-500"
            />
            <button onClick={saveName} className="px-3 py-1.5 rounded-lg text-xs font-medium text-white bg-purple-600 hover:bg-purple-500">Save</button>
            <button onClick={() => setEditing(false)} className="px-3 py-1.5 rounded-lg text-xs text-gray-300 bg-gray-800 hover:bg-gray-700">Cancel</button>
          </div>
        ) : (
          <div className="flex items-center gap-2 text-xs text-gray-400">
            <span className="truncate">
              You appear as <span className="text-white font-medium">{feed?.my_name || (feed?.me ? shortAddr(feed.me) : '…')}</span>
            </span>
            <button
              onClick={() => { setNameDraft(feed?.my_name ?? ''); setNameError(''); setEditing(true); }}
              className="shrink-0 text-purple-300 hover:text-purple-200"
            >
              {feed?.my_name ? 'Change name' : 'Set a name'}
            </button>
          </div>
        )}
        {nameError && <p className="text-xs text-red-400">{nameError}</p>}
        {feed && (
          <p className="text-[11px] leading-snug text-gray-500">
            Everyone on Ego can read this. {feed.threshold} removal votes within {feed.ban_days} days remove someone for {feed.ban_days} days.
          </p>
        )}
      </div>

      <div ref={listRef} onScroll={onScroll} className="flex-1 min-h-0 overflow-y-auto px-2 py-2 space-y-0.5">
        {showOlder && (
          <div className="flex justify-center pb-2">
            <button onClick={loadOlder} className="text-xs text-purple-300 hover:text-purple-200">Show older messages</button>
          </div>
        )}
        {feed && posts.length === 0 && (
          <div className="h-full flex flex-col items-center justify-center text-center gap-2">
            <p className="text-sm text-gray-400">No messages yet.</p>
            <p className="text-xs text-gray-500">Say hello. Everyone on the network will see it.</p>
          </div>
        )}
        {posts.map(p => (
          <Message key={p.id} post={p} threshold={feed?.threshold ?? 5} banDays={feed?.ban_days ?? 14} onChanged={load} />
        ))}
      </div>

      <div className="px-3 py-3 border-t border-gray-800">
        {removedUntil ? (
          <p className="text-sm text-red-300">
            Community votes removed you from the chat until {day(removedUntil)}.
          </p>
        ) : (
          <>
            <div className="flex items-end gap-2">
              <textarea
                id="dao-chat-draft"
                value={draft}
                maxLength={MAX_BODY}
                rows={2}
                onChange={e => setDraft(e.target.value)}
                onKeyDown={e => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); } }}
                placeholder="Message everyone…"
                className="flex-1 resize-none px-3 py-2 rounded-xl bg-gray-800 border border-gray-700 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-purple-500"
              />
              <button
                onClick={send}
                disabled={sending || !draft.trim()}
                className="px-4 py-2 rounded-xl text-sm font-medium text-white bg-purple-600 hover:bg-purple-500 disabled:opacity-40"
              >
                {sending ? 'Sending…' : 'Send'}
              </button>
            </div>
            <div className="flex justify-between mt-1">
              <span className="text-[11px] text-red-400">{error}</span>
              <span className="text-[11px] text-gray-500 shrink-0">{draft.length}/{MAX_BODY}</span>
            </div>
          </>
        )}
      </div>
    </div>
  );
}
