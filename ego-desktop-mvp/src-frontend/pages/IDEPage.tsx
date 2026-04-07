import { useState, useEffect, useRef, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { useTheme } from '../App';
import { RPC_URL } from '../config';
import Editor, { loader } from '@monaco-editor/react';
import * as monaco from 'monaco-editor';
import editorWorker from 'monaco-editor/esm/vs/editor/editor.worker?worker';
import { invoke } from '@tauri-apps/api/tauri';

(self as any).MonacoEnvironment = {
  getWorker() { return new editorWorker(); },
};
loader.config({ monaco });
import { open as dialogOpen } from '@tauri-apps/api/dialog';
import { readDir, readTextFile, writeTextFile, createDir, type FileEntry } from '@tauri-apps/api/fs';

interface ProjectFile {
  name: string;
  content: string;
  language: string;
}

interface Project {
  name: string;
  files: Record<string, ProjectFile>;
}

interface CompileResult {
  success: boolean;
  wasm_hex?: string;
  size?: number;
  error?: string;
}

interface DeployResult {
  contract_address: string;
}

interface ConsoleLog {
  ts: string;
  level: 'info' | 'error' | 'success';
  msg: string;
}

type RightTab = 'build' | 'deploy' | 'abi' | 'preview';
type DeployNetwork = 'testnet' | 'mainnet';

const TEMPLATES = [
  {
    name: 'EGO-20 Token',
    icon: '🪙',
    description: 'Fungible token with mint, burn and supply tracking',
    files: {
      'src/main.urego': `// EGO-20 Fungible Token\n// Uses u64 for all amounts (1 EGOC = 1_000_000 uEGOC)\ncontract MyToken {\n    pub fn init(supply: u64) {\n        storage.set("supply", supply);\n        storage.set("minted", 0);\n        storage.set("burned", 0);\n    }\n\n    pub fn mint(amount: u64) {\n        let minted: u64 = storage.get_u64("minted");\n        let supply: u64 = storage.get_u64("supply");\n        assert(minted + amount <= supply, "exceeds supply");\n        storage.set("minted", minted + amount);\n        events.emit("minted", amount);\n    }\n\n    pub fn burn(amount: u64) {\n        let minted: u64 = storage.get_u64("minted");\n        let burned: u64 = storage.get_u64("burned");\n        assert(minted - burned >= amount, "insufficient");\n        storage.set("burned", burned + amount);\n        events.emit("burned", amount);\n    }\n\n    pub fn total_supply() -> u64 {\n        return storage.get_u64("supply");\n    }\n\n    pub fn circulating() -> u64 {\n        let minted: u64 = storage.get_u64("minted");\n        let burned: u64 = storage.get_u64("burned");\n        return minted - burned;\n    }\n}`,
      'frontend/index.html': `<!DOCTYPE html>\n<html>\n<head><title>My Token dApp</title>\n<style>body{font-family:sans-serif;max-width:600px;margin:40px auto;background:#0f0f1a;color:white;}input,button{padding:8px 12px;border-radius:8px;border:1px solid #333;background:#1a1a2e;color:white;margin:4px;}button{background:#7c3aed;cursor:pointer;border:none;}</style>\n</head>\n<body>\n<h1>🪙 My Token</h1>\n<p>Deploy the contract and call <code>init(supply)</code> to set up your token.</p>\n<p>Use <code>mint(amount)</code> and <code>burn(amount)</code> to manage supply.</p>\n</body>\n</html>`,
      'ego.toml': `[project]\nname = "my-token"\nversion = "0.1.0"\nstandard = "EGO-20"\n\n[network]\ntestnet = "https://rpc.egoblockchain.com"\n`,
    },
  },
  {
    name: 'Hello World',
    icon: '👋',
    description: 'Minimal counter contract to get started',
    files: {
      'src/main.urego': `// Hello World — your first Ego contract\ncontract HelloWorld {\n    pub fn init() {\n        storage.set("visits", 0);\n    }\n\n    pub fn visit() {\n        let v: u64 = storage.get_u64("visits");\n        storage.set("visits", v + 1);\n        emit Visited { count: v + 1 };\n    }\n\n    pub fn get_visits() -> u64 {\n        return storage.get_u64("visits");\n    }\n}`,
      'frontend/index.html': `<!DOCTYPE html>\n<html>\n<head><title>Hello World dApp</title>\n<style>body{font-family:sans-serif;max-width:500px;margin:60px auto;background:#0f0f1a;color:white;text-align:center;}button{padding:10px 16px;border-radius:10px;background:#7c3aed;color:white;border:none;cursor:pointer;font-weight:bold;margin:6px;}</style>\n</head>\n<body>\n<h1>👋 Hello World</h1>\n<p>Deploy the contract, call <code>init()</code>, then <code>visit()</code> to increment the counter.</p>\n<p>Read the count with <code>get_visits()</code>.</p>\n</body>\n</html>`,
      'ego.toml': `[project]\nname = "hello-world"\nversion = "0.1.0"\n\n[network]\ntestnet = "https://rpc.egoblockchain.com"\n`,
    },
  },
  {
    name: 'Escrow',
    icon: '🤝',
    description: 'Lock an amount with release or refund',
    files: {
      'src/main.urego': `// Simple Escrow Contract\n// Status: 0 = active, 1 = released, 2 = refunded\ncontract Escrow {\n    pub fn init(amount: u64, deadline: u64) {\n        storage.set("amount", amount);\n        storage.set("deadline", deadline);\n        storage.set("released", 0);\n        storage.set("refunded", 0);\n    }\n\n    pub fn release() {\n        let released: u64 = storage.get_u64("released");\n        let refunded: u64 = storage.get_u64("refunded");\n        assert(released == 0, "already released");\n        assert(refunded == 0, "already refunded");\n        storage.set("released", 1);\n        let amt: u64 = storage.get_u64("amount");\n        emit Released { amount: amt };\n    }\n\n    pub fn refund() {\n        let released: u64 = storage.get_u64("released");\n        let refunded: u64 = storage.get_u64("refunded");\n        assert(released == 0, "already released");\n        assert(refunded == 0, "already refunded");\n        storage.set("refunded", 1);\n        let amt: u64 = storage.get_u64("amount");\n        emit Refunded { amount: amt };\n    }\n\n    pub fn get_amount() -> u64 {\n        return storage.get_u64("amount");\n    }\n\n    pub fn get_status() -> u64 {\n        let r: u64 = storage.get_u64("released");\n        let f: u64 = storage.get_u64("refunded");\n        if r == 1 {\n            return 1;\n        } else {\n            if f == 1 {\n                return 2;\n            } else {\n                return 0;\n            }\n        }\n    }\n}`,
      'ego.toml': `[project]\nname = "escrow"\nversion = "0.1.0"\n\n[network]\ntestnet = "https://rpc.egoblockchain.com"\n`,
    },
  },
  {
    name: 'DAO Vote',
    icon: '🗳️',
    description: 'Simple on-chain yes/no voting',
    files: {
      'src/main.urego': `// Simple DAO Voting\n// active: 1 = open, 0 = closed\n// get_winner: 1 = yes wins, 0 = no wins / tied\ncontract SimpleDAO {\n    pub fn init() {\n        storage.set("yes_votes", 0);\n        storage.set("no_votes", 0);\n        storage.set("active", 1);\n    }\n\n    pub fn vote_yes() {\n        let active: u64 = storage.get_u64("active");\n        assert(active == 1, "voting closed");\n        let yes: u64 = storage.get_u64("yes_votes");\n        storage.set("yes_votes", yes + 1);\n        events.emit("voted", 1);\n    }\n\n    pub fn vote_no() {\n        let active: u64 = storage.get_u64("active");\n        assert(active == 1, "voting closed");\n        let no: u64 = storage.get_u64("no_votes");\n        storage.set("no_votes", no + 1);\n        events.emit("voted", 0);\n    }\n\n    pub fn close() {\n        storage.set("active", 0);\n        events.emit("closed", 0);\n    }\n\n    pub fn get_yes() -> u64 {\n        return storage.get_u64("yes_votes");\n    }\n\n    pub fn get_no() -> u64 {\n        return storage.get_u64("no_votes");\n    }\n\n    pub fn get_winner() -> u64 {\n        let yes: u64 = storage.get_u64("yes_votes");\n        let no: u64 = storage.get_u64("no_votes");\n        if yes > no {\n            return 1;\n        } else {\n            return 0;\n        }\n    }\n}`,
      'ego.toml': `[project]\nname = "dao-vote"\nversion = "0.1.0"\nstandard = "EGO-8"\n\n[network]\ntestnet = "https://rpc.egoblockchain.com"\n`,
    },
  },
];

function getLanguage(filename: string): string {
  const ext = filename.split('.').pop()?.toLowerCase() ?? '';
  switch (ext) {
    case 'urego': return 'rust';
    case 'html': return 'html';
    case 'js': return 'javascript';
    case 'ts': return 'typescript';
    case 'toml': return 'ini';
    default: return 'plaintext';
  }
}

function getFileIcon(filename: string): string {
  const ext = filename.split('.').pop()?.toLowerCase() ?? '';
  switch (ext) {
    case 'urego': return '📄';
    case 'html': return '🌐';
    case 'js':
    case 'ts': return '📜';
    case 'toml': return '⚙️';
    default: return '📄';
  }
}

function nowTs(): string {
  return new Date().toLocaleTimeString('en-US', { hour12: false });
}

function encodeInitArgs(raw: string): string {
  const s = raw.trim();
  if (!s) return '';

  if (s.startsWith('0x') || s.startsWith('0X')) return s.slice(2);

  if (/^[0-9a-fA-F]+$/.test(s) && s.length % 2 === 0) return s;

  const parts = s.split(/\s+/);
  if (parts.every(p => /^\d+$/.test(p))) {
    return parts.map(p => {
      const n = BigInt(p);
      const bytes = new Uint8Array(8);
      let rem = n;
      for (let i = 0; i < 8; i++) { bytes[i] = Number(rem & 0xffn); rem >>= 8n; }
      return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
    }).join('');
  }
  return s;
}

function extractABI(source: string): string[] {
  const matches = [...source.matchAll(/pub fn (\w+)\s*\(([^)]*)\)(?:\s*->\s*([^{]+))?/g)];
  return matches.map((m) => {
    const name = m[1];
    const args = m[2].trim();
    const ret = m[3]?.trim();
    return ret ? `${name}(${args}) → ${ret}` : `${name}(${args})`;
  });
}

function buildProjectFromTemplate(tpl: (typeof TEMPLATES)[number]): Project {
  const files: Record<string, ProjectFile> = {};
  for (const [path, content] of Object.entries(tpl.files)) {
    files[path] = { name: path.split('/').pop()!, content, language: getLanguage(path) };
  }
  return { name: tpl.name, files };
}

const STORAGE_KEY = 'ego-ide-projects';
const MAX_IMPORT_FILES = 200;

/** Strip path-traversal segments so user input can't escape the project root. */
function sanitizeFilePath(p: string): string {
  return p
    .split('/')
    .filter(seg => seg !== '..' && seg !== '.' && seg.trim() !== '')
    .join('/');
}

function loadProjects(): Record<string, Project> {
  try {
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw) return JSON.parse(raw) as Record<string, Project>;
  } catch {

  }
  return {};
}

function saveProjects(projects: Record<string, Project>): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(projects));
  } catch (e) {
    console.error('[IDE] Failed to save projects to localStorage:', e);
  }
}

interface DeleteConfirmProps {
  path: string;
  onConfirm: () => void;
  onCancel: () => void;
}

function DeleteConfirm({ path, onConfirm, onCancel }: DeleteConfirmProps) {
  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
      <div className="bg-gray-800 border border-gray-600 rounded-xl shadow-2xl p-5 w-80 space-y-4">
        <div className="text-white font-semibold text-sm">Delete file?</div>
        <div className="text-gray-400 text-xs font-mono break-all bg-gray-900 rounded px-2 py-1.5">
          {path}
        </div>
        <div className="text-gray-400 text-xs">This cannot be undone.</div>
        <div className="flex gap-2 justify-end">
          <button
            onClick={onCancel}
            className="px-4 py-1.5 bg-gray-700 hover:bg-gray-600 text-white text-xs rounded-lg transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={onConfirm}
            className="px-4 py-1.5 bg-red-600 hover:bg-red-500 text-white text-xs rounded-lg transition-colors"
          >
            Delete
          </button>
        </div>
      </div>
    </div>
  );
}

interface FileTreeProps {
  project: Project;
  activeFile: string | null;
  onSelect: (path: string) => void;
  onDelete: (path: string) => void;
  onDeleteFolder: (folder: string) => void;
  onNewFile: (filename: string) => void;
  onNewFolder: (filename: string) => void;
  onMoveFile: (from: string, to: string) => void;
  onMoveFolder: (fromFolder: string, toFolder: string) => void;
  onCopyFile: (from: string, to: string) => void;
  onCopyFolder: (fromFolder: string, toFolder: string) => void;
  onRenameFile: (oldPath: string, newPath: string) => void;
  onRenameFolder: (oldFolder: string, newFolder: string) => void;
}

interface ClipboardItem { path: string; isFolder: boolean; op: 'cut' | 'copy' }

interface CtxMenu { x: number; y: number; path: string }

interface InlineState { mode: 'file' | 'folder'; target: string | null; val: string }

function IconNewFile({ size = 14 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="currentColor">
      <path d="M9 1H4a1 1 0 0 0-1 1v12a1 1 0 0 0 1 1h8a1 1 0 0 0 1-1V5L9 1zm0 1.5L11.5 5H9V2.5zM4 14V2h4v4h4v8H4z"/>
      <path d="M7.5 7.5v2H5.5v1h2v2h1v-2h2v-1h-2v-2z"/>
    </svg>
  );
}
function IconNewFolder({ size = 14 }: { size?: number }) {
  return (
    <svg width={size} height={size} viewBox="0 0 16 16" fill="currentColor">
      <path d="M14.5 3H7.707L6.854 2.146A.5.5 0 0 0 6.5 2h-5a.5.5 0 0 0-.5.5v11a.5.5 0 0 0 .5.5h13a.5.5 0 0 0 .5-.5v-10A.5.5 0 0 0 14.5 3zM14 13H2V3h4.293l.853.854A.5.5 0 0 0 7.5 4H14v9z"/>
      <path d="M8.5 7.5v2H6.5v1h2v2h1v-2h2v-1h-2v-2z"/>
    </svg>
  );
}

function FileTree({ project, activeFile, onSelect, onDelete, onDeleteFolder, onNewFile, onNewFolder, onMoveFile, onMoveFolder, onCopyFile, onCopyFolder, onRenameFile, onRenameFolder }: FileTreeProps) {
  const { theme } = useTheme();
  const L = theme === 'light';
  const [openFolders, setOpenFolders] = useState<Record<string, boolean>>({});
  const [inline,   setInline]  = useState<InlineState | null>(null);
  const [ctxMenu,  setCtxMenu] = useState<CtxMenu | null>(null);
  const [clipboard,  setClipboard]  = useState<ClipboardItem | null>(null);
  const [renaming,   setRenaming]   = useState<{ path: string; isFolder: boolean; val: string } | null>(null);
  const [dropTarget, setDropTarget] = useState<string | null>(null);
  const [dragGhost,  setDragGhost]  = useState<{ x: number; y: number; label: string; isFolder: boolean } | null>(null);
  const dragRef      = useRef<{ path: string; isFolder: boolean; startX: number; startY: number; active: boolean } | null>(null);
  const dropRef      = useRef<string | null>(null);
  const inlineRef = useRef<HTMLInputElement>(null);
  const renameRef = useRef<HTMLInputElement>(null);
  const ctxRef    = useRef<HTMLDivElement>(null);

  const grouped: Record<string, string[]> = {};
  for (const path of Object.keys(project.files)) {
    const folder = path.includes('/') ? path.split('/')[0] : '';
    if (!grouped[folder]) grouped[folder] = [];
    grouped[folder].push(path);
  }
  const folderKeys = Object.keys(grouped).filter(f => f !== '').sort();
  const rootFiles  = grouped[''] ?? [];

  useEffect(() => {
    setOpenFolders(prev => {
      const next = { ...prev };
      let changed = false;
      for (const f of folderKeys) {
        if (!(f in next)) { next[f] = true; changed = true; }
      }
      return changed ? next : prev;
    });

  }, [project.files]);

  useEffect(() => {
    if (inline) setTimeout(() => inlineRef.current?.focus(), 30);
  }, [inline?.mode, inline?.target]);

  useEffect(() => {
    if (renaming) setTimeout(() => renameRef.current?.focus(), 30);
  }, [renaming?.path]);

  useEffect(() => {
    if (!ctxMenu) return;
    function handle(e: MouseEvent) {
      if (ctxRef.current && !ctxRef.current.contains(e.target as Node)) setCtxMenu(null);
    }
    document.addEventListener('mousedown', handle);
    return () => document.removeEventListener('mousedown', handle);
  }, [ctxMenu]);

  function openFileInline(targetFolder: string) {
    setCtxMenu(null);
    setInline({ mode: 'file', target: targetFolder, val: targetFolder ? `${targetFolder}/` : '' });
    if (targetFolder) setOpenFolders(prev => ({ ...prev, [targetFolder]: true }));
  }

  function openFolderInline() {
    setCtxMenu(null);
    setInline({ mode: 'folder', target: null, val: '' });
  }

  function commitInline() {
    if (!inline) return;
    const val = inline.val.trim();
    if (val) {
      if (inline.mode === 'file') {
        onNewFile(val);
      } else {

        const name = val.replace(/[/\\]/g, '').trim();
        if (name) onNewFolder(`${name}/main.urego`);
      }
    }
    setInline(null);
  }

  function cancelInline() { setInline(null); }

  function startRename(path: string, isFolder: boolean) {
    setCtxMenu(null);
    const val = isFolder ? path : path.split('/').pop()!;
    setRenaming({ path, isFolder, val });
  }

  function commitRename() {
    if (!renaming) return;
    const val = renaming.val.trim();
    if (!val) { setRenaming(null); return; }
    if (renaming.isFolder) {
      if (val !== renaming.path) onRenameFolder(renaming.path, val);
    } else {
      const dir = renaming.path.includes('/') ? renaming.path.split('/').slice(0, -1).join('/') : '';
      const newPath = dir ? `${dir}/${val}` : val;
      if (newPath !== renaming.path) onRenameFile(renaming.path, newPath);
    }
    setRenaming(null);
  }

  function cancelRename() { setRenaming(null); }

  useEffect(() => {
    function onMove(e: MouseEvent) {
      const d = dragRef.current;
      if (!d) return;
      if (!d.active && Math.hypot(e.clientX - d.startX, e.clientY - d.startY) < 5) return;
      d.active = true;

      const el = document.elementFromPoint(e.clientX, e.clientY);
      const zone = el?.closest('[data-drop-zone]') as HTMLElement | null;
      const target = zone ? (zone.dataset.dropZone ?? null) : null;
      dropRef.current = target;
      setDropTarget(target);
      setDragGhost({ x: e.clientX, y: e.clientY, label: d.isFolder ? d.path : d.path.split('/').pop()!, isFolder: d.isFolder });
      document.body.style.cursor = 'grabbing';
    }
    function onUp() {
      const d = dragRef.current;
      const target = dropRef.current;
      if (d?.active && target !== null) {
        if (d.isFolder) {
          if (d.path !== target) onMoveFolder(d.path, target);
        } else {
          const filename = d.path.split('/').pop()!;
          const to = target ? `${target}/${filename}` : filename;
          if (d.path !== to) onMoveFile(d.path, to);
        }
      }
      dragRef.current  = null;
      dropRef.current  = null;
      setDragGhost(null);
      setDropTarget(null);
      document.body.style.cursor = '';
    }
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup',   onUp);
    return () => {
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup',   onUp);
    };
  }, []);

  function startDrag(e: React.MouseEvent, path: string, isFolder: boolean) {
    if ((e.target as HTMLElement).tagName === 'INPUT') return;
    e.preventDefault();
    dragRef.current = { path, isFolder, startX: e.clientX, startY: e.clientY, active: false };
  }

  function cutItem(path: string, isFolder: boolean) {
    setClipboard({ path, isFolder, op: 'cut' });
    setCtxMenu(null);
  }

  function copyItem(path: string, isFolder: boolean) {
    setClipboard({ path, isFolder, op: 'copy' });
    setCtxMenu(null);
  }

  function pasteInto(targetFolder: string) {
    if (!clipboard) return;
    setCtxMenu(null);
    const { path, isFolder, op } = clipboard;
    if (isFolder) {
      if (op === 'cut') { onMoveFolder(path, targetFolder); setClipboard(null); }
      else              { onCopyFolder(path, targetFolder); }
    } else {
      const filename = path.split('/').pop()!;
      const to = targetFolder ? `${targetFolder}/${filename}` : filename;
      if (op === 'cut') { onMoveFile(path, to); setClipboard(null); }
      else              { onCopyFile(path, to); }
    }
  }

  function InlineRow({ indented }: { indented: boolean }) {
    if (!inline) return null;
    return (
      <div className={`flex items-center gap-1.5 py-[3px] pr-2 border-l-2 border-blue-500 bg-blue-600/10 ${indented ? 'pl-6' : 'pl-3'}`}>
        <span className="text-[10px] shrink-0 text-gray-400">
          {inline.mode === 'file' ? '📄' : '📁'}
        </span>
        <input
          ref={inlineRef}
          value={inline.val}
          onChange={e => setInline(prev => prev ? { ...prev, val: e.target.value } : null)}
          onKeyDown={e => {
            if (e.key === 'Enter')  { e.preventDefault(); commitInline(); }
            if (e.key === 'Escape') { e.preventDefault(); cancelInline(); }
          }}
          onBlur={cancelInline}
          placeholder={
            inline.mode === 'folder' ? 'folder-name'
              : inline.target        ? `${inline.target}/filename`
              : 'filename.urego'
          }
          className="flex-1 min-w-0 bg-gray-800 border border-blue-500 rounded px-1.5 py-0.5 text-[11px] text-white placeholder-gray-600 focus:outline-none"
        />
        <span className="text-[9px] text-gray-600 shrink-0">↵</span>
      </div>
    );
  }

  return (
    <div className={`w-48 border-r flex flex-col text-xs select-none shrink-0 ${L ? 'bg-gray-50 border-gray-300' : 'bg-gray-900 border-gray-700'}`}>

      {}
      <div className={`group flex items-center gap-0.5 px-2 border-b h-8 shrink-0 ${L ? 'border-gray-300' : 'border-gray-700'}`}>
        <span className={`uppercase tracking-wider text-[10px] font-semibold truncate flex-1 pl-1 ${L ? 'text-gray-600' : 'text-gray-400'}`}>
          {project.name}
        </span>
        <div className="opacity-0 group-hover:opacity-100 flex items-center transition-opacity shrink-0">
          <button onClick={() => openFileInline('')}  className={`p-1 rounded ${L ? 'text-gray-500 hover:text-gray-900 hover:bg-gray-200' : 'text-gray-400 hover:text-white hover:bg-gray-700'}`} title="New File"><IconNewFile /></button>
          <button onClick={openFolderInline}           className={`p-1 rounded ${L ? 'text-gray-500 hover:text-gray-900 hover:bg-gray-200' : 'text-gray-400 hover:text-white hover:bg-gray-700'}`} title="New Folder"><IconNewFolder /></button>
        </div>
      </div>

      {}
      <div
        className="flex-1 overflow-y-auto pb-2"
        data-drop-zone=""
      >
        {}
        {inline?.mode === 'folder' && InlineRow({ indented: false })}

        {}
        {folderKeys.map(folder => {
          const isOpen = openFolders[folder] !== false;
          const isDrop = dropTarget === folder && dragRef.current?.path !== folder;

          return (
            <div
              key={folder}
              data-drop-zone={folder}
            >
              {}
              <div
                role="button"
                onMouseDown={e => startDrag(e, folder, true)}
                onClick={() => { if (!dragGhost) setOpenFolders(prev => ({ ...prev, [folder]: !isOpen })); }}
                onContextMenu={e => { e.preventDefault(); setCtxMenu({ x: e.clientX, y: e.clientY, path: `${folder}/` }); }}
                className={`flex items-center gap-1.5 px-2 py-[4px] cursor-grab transition-colors ${
                  isDrop ? 'bg-blue-500/20 text-blue-200 ring-1 ring-blue-400/50' : L ? 'text-gray-700 hover:bg-gray-200' : 'text-gray-300 hover:bg-gray-700/50'
                } ${clipboard?.path === folder && clipboard.isFolder && clipboard.op === 'cut' ? 'opacity-40' : ''}`}
              >
                {}
                <svg
                  width="9" height="9" viewBox="0 0 9 9" fill="currentColor"
                  className={`shrink-0 text-gray-500 transition-transform duration-150 ${isOpen ? 'rotate-90' : 'rotate-0'}`}
                >
                  <path d="M2.5 1.5l4 3-4 3z"/>
                </svg>
                {}
                <svg width="13" height="13" viewBox="0 0 16 16" fill="currentColor"
                  className={`shrink-0 transition-colors ${isDrop ? 'text-blue-400' : 'text-yellow-400/80'}`}
                >
                  <path d="M14.5 3H7.707L6.854 2.146A.5.5 0 0 0 6.5 2h-5a.5.5 0 0 0-.5.5v11a.5.5 0 0 0 .5.5h13a.5.5 0 0 0 .5-.5v-10A.5.5 0 0 0 14.5 3zM14 13H2V3h4.293l.853.854A.5.5 0 0 0 7.5 4H14v9z"/>
                </svg>
                {renaming?.path === folder && renaming.isFolder ? (
                  <input
                    ref={renameRef}
                    value={renaming.val}
                    onChange={e => setRenaming(prev => prev ? { ...prev, val: e.target.value } : null)}
                    onKeyDown={e => {
                      if (e.key === 'Enter')  { e.preventDefault(); commitRename(); }
                      if (e.key === 'Escape') { e.preventDefault(); cancelRename(); }
                    }}
                    onBlur={cancelRename}
                    onClick={e => e.stopPropagation()}
                    className="flex-1 min-w-0 bg-gray-800 border border-blue-500 rounded px-1 py-0 text-[11px] text-white focus:outline-none"
                  />
                ) : (
                  <span className="truncate text-[11px] flex-1">{folder}</span>
                )}
                {isDrop && <span className="shrink-0 text-[9px] text-blue-400 bg-blue-900/50 rounded px-1">drop</span>}
              </div>

              {}
              {isOpen && (
                <>
                  {}
                  {inline?.mode === 'file' && inline.target === folder && InlineRow({ indented: true })}

                  {grouped[folder]?.map(path => {
                    const label = path.split('/').pop()!;
                    const isActive = path === activeFile;
                    return (
                      <div
                        key={path}
                        onMouseDown={e => startDrag(e, path, false)}
                        onClick={() => { if (!dragGhost) onSelect(path); }}
                        onContextMenu={e => { e.preventDefault(); e.stopPropagation(); setCtxMenu({ x: e.clientX, y: e.clientY, path }); }}
                        className={`flex items-center gap-1.5 pl-6 py-[3px] pr-2 cursor-grab transition-colors ${
                          isActive ? 'bg-blue-600/25 text-blue-300' : L ? 'text-gray-700 hover:bg-gray-200' : 'text-gray-300 hover:bg-gray-700/40'
                        } ${clipboard?.path === path && clipboard.op === 'cut' ? 'opacity-40' : ''}`}
                        title={path}
                      >
                        <span className="text-[11px] shrink-0">{getFileIcon(label)}</span>
                        {renaming?.path === path && !renaming.isFolder ? (
                          <input
                            ref={renameRef}
                            value={renaming.val}
                            onChange={e => setRenaming(prev => prev ? { ...prev, val: e.target.value } : null)}
                            onKeyDown={e => {
                              if (e.key === 'Enter')  { e.preventDefault(); commitRename(); }
                              if (e.key === 'Escape') { e.preventDefault(); cancelRename(); }
                            }}
                            onBlur={cancelRename}
                            onClick={e => e.stopPropagation()}
                            className="flex-1 min-w-0 bg-gray-800 border border-blue-500 rounded px-1 py-0 text-[11px] text-white focus:outline-none"
                          />
                        ) : (
                          <span className="truncate flex-1 text-[11px]">{label}</span>
                        )}
                      </div>
                    );
                  })}
                </>
              )}
            </div>
          );
        })}

        {}
        {(rootFiles.length > 0 || (inline?.mode === 'file' && inline.target === '')) && (
          <div className={dropTarget === '' && dragRef.current ? 'bg-blue-600/10 rounded mx-0.5' : ''}>
            {inline?.mode === 'file' && inline.target === '' && InlineRow({ indented: false })}
            {rootFiles.map(path => {
              const isActive = path === activeFile;
              return (
                <div
                  key={path}
                  onMouseDown={e => startDrag(e, path, false)}
                  onClick={() => { if (!dragGhost) onSelect(path); }}
                  onContextMenu={e => { e.preventDefault(); e.stopPropagation(); setCtxMenu({ x: e.clientX, y: e.clientY, path }); }}
                  className={`flex items-center gap-1.5 pl-3 py-[3px] pr-2 cursor-grab transition-colors ${
                    isActive ? 'bg-blue-600/25 text-blue-300' : L ? 'text-gray-700 hover:bg-gray-200' : 'text-gray-300 hover:bg-gray-700/40'
                  } ${clipboard?.path === path && clipboard.op === 'cut' ? 'opacity-40' : ''}`}
                  title={path}
                >
                  <span className="text-[11px] shrink-0">{getFileIcon(path)}</span>
                  {renaming?.path === path && !renaming.isFolder ? (
                    <input
                      ref={renameRef}
                      value={renaming.val}
                      onChange={e => setRenaming(prev => prev ? { ...prev, val: e.target.value } : null)}
                      onKeyDown={e => {
                        if (e.key === 'Enter')  { e.preventDefault(); commitRename(); }
                        if (e.key === 'Escape') { e.preventDefault(); cancelRename(); }
                      }}
                      onBlur={cancelRename}
                      onClick={e => e.stopPropagation()}
                      className="flex-1 min-w-0 bg-gray-800 border border-blue-500 rounded px-1 py-0 text-[11px] text-white focus:outline-none"
                    />
                  ) : (
                    <span className="truncate flex-1 text-[11px]">{path}</span>
                  )}
                </div>
              );
            })}
          </div>
        )}
      </div>

      {}
      {dragGhost && (
        <div
          style={{ position: 'fixed', left: dragGhost.x + 14, top: dragGhost.y + 4, pointerEvents: 'none', zIndex: 9999 }}
          className="flex items-center gap-1.5 bg-gray-700 border border-blue-500 rounded px-2 py-1 text-[11px] text-white shadow-xl opacity-90"
        >
          <span>{dragGhost.isFolder ? '📁' : '📄'}</span>
          <span>{dragGhost.label}</span>
        </div>
      )}

      {}
      {ctxMenu && (
        <div
          ref={ctxRef}
          className="fixed z-50 bg-gray-800 border border-gray-600 rounded-lg shadow-2xl py-1 min-w-[172px] text-xs"
          style={{ top: ctxMenu.y, left: ctxMenu.x }}
        >
          {}
          {!ctxMenu.path.endsWith('/') && (
            <>
              <button className="w-full text-left px-3 py-1.5 text-gray-200 hover:bg-gray-700 flex items-center gap-2.5"
                onClick={() => { onSelect(ctxMenu.path); setCtxMenu(null); }}>
                <span>📄</span> Open
              </button>
              <button className="w-full text-left px-3 py-1.5 text-gray-200 hover:bg-gray-700 flex items-center gap-2.5"
                onClick={() => startRename(ctxMenu.path, false)}>
                <span>✏️</span> Rename
              </button>
              <div className="my-1 border-t border-gray-700" />
              <button className="w-full text-left px-3 py-1.5 text-gray-200 hover:bg-gray-700 flex items-center gap-2.5"
                onClick={() => cutItem(ctxMenu.path, false)}>
                <span>✂️</span> Cut
              </button>
              <button className="w-full text-left px-3 py-1.5 text-gray-200 hover:bg-gray-700 flex items-center gap-2.5"
                onClick={() => copyItem(ctxMenu.path, false)}>
                <span>📋</span> Copy
              </button>
              {clipboard && (
                <button className="w-full text-left px-3 py-1.5 text-blue-300 hover:bg-gray-700 flex items-center gap-2.5"
                  onClick={() => {
                    const dir = ctxMenu.path.includes('/') ? ctxMenu.path.split('/').slice(0, -1).join('/') : '';
                    pasteInto(dir);
                  }}>
                  <span>📌</span> Paste Here
                </button>
              )}
              <div className="my-1 border-t border-gray-700" />
              <button className="w-full text-left px-3 py-1.5 text-red-400 hover:bg-gray-700 flex items-center gap-2.5"
                onClick={() => { onDelete(ctxMenu.path); setCtxMenu(null); }}>
                <span>🗑️</span> Delete
              </button>
            </>
          )}

          {}
          {ctxMenu.path.endsWith('/') && (() => {
            const f = ctxMenu.path.slice(0, -1);
            const isOpen = openFolders[f] !== false;
            return (
              <>
                <div className="px-3 py-1.5 text-[10px] text-gray-500 font-semibold uppercase tracking-wider border-b border-gray-700 flex items-center gap-1.5">
                  <svg width="11" height="11" viewBox="0 0 16 16" fill="currentColor" className="text-yellow-400/70">
                    <path d="M14.5 3H7.707L6.854 2.146A.5.5 0 0 0 6.5 2h-5a.5.5 0 0 0-.5.5v11a.5.5 0 0 0 .5.5h13a.5.5 0 0 0 .5-.5v-10A.5.5 0 0 0 14.5 3zM14 13H2V3h4.293l.853.854A.5.5 0 0 0 7.5 4H14v9z"/>
                  </svg>
                  {f}
                </div>
                <button className="w-full text-left px-3 py-1.5 text-gray-200 hover:bg-gray-700 flex items-center gap-2.5"
                  onClick={() => openFileInline(f)}>
                  <IconNewFile size={12} /> New File Here
                </button>
                <button className="w-full text-left px-3 py-1.5 text-gray-200 hover:bg-gray-700 flex items-center gap-2.5"
                  onClick={openFolderInline}>
                  <IconNewFolder size={12} /> New Folder Here
                </button>
                <button className="w-full text-left px-3 py-1.5 text-gray-200 hover:bg-gray-700 flex items-center gap-2.5"
                  onClick={() => startRename(f, true)}>
                  <span>✏️</span> Rename Folder
                </button>
                <div className="my-1 border-t border-gray-700" />
                <button className="w-full text-left px-3 py-1.5 text-gray-200 hover:bg-gray-700 flex items-center gap-2.5"
                  onClick={() => cutItem(f, true)}>
                  <span>✂️</span> Cut Folder
                </button>
                <button className="w-full text-left px-3 py-1.5 text-gray-200 hover:bg-gray-700 flex items-center gap-2.5"
                  onClick={() => copyItem(f, true)}>
                  <span>📋</span> Copy Folder
                </button>
                {clipboard && (
                  <button className="w-full text-left px-3 py-1.5 text-blue-300 hover:bg-gray-700 flex items-center gap-2.5"
                    onClick={() => pasteInto(f)}>
                    <span>📌</span> Paste Into Folder
                  </button>
                )}
                <div className="my-1 border-t border-gray-700" />
                <button
                  className="w-full text-left px-3 py-1.5 text-gray-400 hover:bg-gray-700 flex items-center gap-2.5"
                  onClick={() => { setOpenFolders(prev => ({ ...prev, [f]: !isOpen })); setCtxMenu(null); }}
                >
                  <svg width="9" height="9" viewBox="0 0 9 9" fill="currentColor" className={`transition-transform ${isOpen ? 'rotate-90' : ''}`}>
                    <path d="M2.5 1.5l4 3-4 3z"/>
                  </svg>
                  {isOpen ? 'Collapse Folder' : 'Expand Folder'}
                </button>
                <div className="my-1 border-t border-gray-700" />
                <button
                  className="w-full text-left px-3 py-1.5 text-red-400 hover:bg-gray-700 flex items-center gap-2.5"
                  onClick={() => { onDeleteFolder(f); setCtxMenu(null); }}
                >
                  <span>🗑️</span> Delete Folder
                </button>
              </>
            );
          })()}
        </div>
      )}
    </div>
  );
}

interface RightPanelProps {
  tab: RightTab;
  onTabChange: (t: RightTab) => void;
  compiling: boolean;
  compileResult: CompileResult | null;
  deployResult: DeployResult | null;
  dryRunResult: string | null;
  deploying: boolean;
  deployNetwork: DeployNetwork;
  nodeUrl: string;
  initArgs: string;
  activeFile: string | null;
  currentContent: string;
  onCompile: () => void;
  onDeploy: () => void;
  onDryRun: () => void;
  onNetworkChange: (n: DeployNetwork) => void;
  onNodeUrlChange: (v: string) => void;
  onInitArgsChange: (v: string) => void;
  onNavigate: (path: string, state?: any) => void;
}

const TESTNET_RPC = 'https://rpc.egoblockchain.com';

function RightPanel({
  tab, onTabChange, compiling, compileResult, deployResult, dryRunResult, deploying,
  deployNetwork, nodeUrl, initArgs, activeFile, currentContent,
  onCompile, onDeploy, onDryRun, onNetworkChange, onNodeUrlChange, onInitArgsChange, onNavigate,
}: RightPanelProps) {
  const { theme } = useTheme();
  const L = theme === 'light';
  const tabs: { key: RightTab; label: string }[] = [
    { key: 'build', label: 'Build' },
    { key: 'deploy', label: 'Deploy' },
    { key: 'abi', label: 'ABI' },
    { key: 'preview', label: 'Preview' },
  ];

  const abiFunctions = currentContent ? extractABI(currentContent) : [];
  const isHtml = activeFile?.endsWith('.html') ?? false;

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text).catch(() => {});
  };

  return (
    <div className={`w-72 border-l flex flex-col shrink-0 ${L ? 'bg-gray-100 border-gray-300' : 'bg-gray-800 border-gray-700'}`}>
      {}
      <div className={`flex border-b shrink-0 ${L ? 'border-gray-300' : 'border-gray-700'}`}>
        {tabs.map((t) => (
          <button
            key={t.key}
            onClick={() => onTabChange(t.key)}
            className={`flex-1 py-2 text-xs font-medium transition-colors ${
              tab === t.key
                ? L ? 'text-gray-900 border-b-2 border-blue-500 bg-white' : 'text-white border-b-2 border-blue-500 bg-gray-750'
                : L ? 'text-gray-500 hover:text-gray-800' : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div className={`flex-1 min-h-0 ${tab === 'preview' ? 'overflow-hidden p-0' : 'overflow-y-auto p-3'}`}>
        {}
        {tab === 'build' && (
          <div className="space-y-4">
            <button
              onClick={onCompile}
              disabled={compiling}
              className="w-full py-3 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white rounded-lg font-semibold text-sm flex items-center justify-center gap-2 transition-colors"
            >
              {compiling ? (
                <>
                  <span className="animate-spin">⚙️</span>
                  Compiling...
                </>
              ) : (
                '🔨 Compile'
              )}
            </button>

            {compileResult && (
              <div
                className={`rounded-lg p-3 text-sm ${
                  compileResult.success
                    ? 'bg-green-900/30 border border-green-700 text-green-300'
                    : 'bg-red-900/30 border border-red-700 text-red-300'
                }`}
              >
                {compileResult.success ? (
                  <div className="space-y-1">
                    <div className="font-semibold">✓ Compile success</div>
                    <div className="text-xs">
                      WASM: {((compileResult.size ?? 0) / 1024).toFixed(1)} KB
                    </div>
                    <div className="text-xs text-gray-400">RU estimate: ~50,000</div>
                  </div>
                ) : (
                  <div className="space-y-1">
                    <div className="font-semibold">✗ Compile failed</div>
                    <div className="text-xs font-mono break-all">{compileResult.error}</div>
                  </div>
                )}
              </div>
            )}

            {!compileResult && (
              <div className="text-xs text-gray-500 text-center py-4">
                Open a .urego file and click Compile
              </div>
            )}
          </div>
        )}

        {}
        {tab === 'deploy' && (
          <div className="space-y-3">
            {}
            <div>
              <div className="text-xs text-gray-400 font-semibold uppercase tracking-wider mb-1.5">Network</div>
              <div className="flex rounded-lg overflow-hidden border border-gray-600">
                <button
                  onClick={() => onNetworkChange('testnet')}
                  className={`flex-1 py-2 text-xs font-semibold transition-colors ${
                    deployNetwork === 'testnet'
                      ? 'bg-green-700/60 text-green-200 border-r border-green-600'
                      : 'bg-gray-700/40 text-gray-400 hover:text-gray-200 border-r border-gray-600'
                  }`}
                >
                  🧪 Testnet
                </button>
                <button
                  onClick={() => onNetworkChange('mainnet')}
                  className={`flex-1 py-2 text-xs font-semibold transition-colors ${
                    deployNetwork === 'mainnet'
                      ? 'bg-purple-700/60 text-purple-200'
                      : 'bg-gray-700/40 text-gray-400 hover:text-gray-200'
                  }`}
                >
                  🌐 Mainnet
                </button>
              </div>
            </div>

            {}
            {deployNetwork === 'testnet' ? (
              <div className="bg-green-900/20 border border-green-700/50 rounded-lg px-3 py-2 space-y-0.5">
                <div className="text-xs text-green-400 font-semibold">✓ Testnet — Free deployment</div>
                <div className="text-[11px] text-green-700">No EGOC spent. Use this to test your contract before going live.</div>
                <div className="text-[10px] text-gray-500 font-mono mt-0.5">{TESTNET_RPC}</div>
              </div>
            ) : (
              <div className="bg-yellow-900/20 border border-yellow-700/50 rounded-lg px-3 py-2 space-y-0.5">
                <div className="text-xs text-yellow-400 font-semibold">⚠ Mainnet — Costs EGOC</div>
                <div className="text-[11px] text-yellow-700">Estimated fee: ~0.01 EGOC. This deploys a real contract on-chain.</div>
              </div>
            )}

            {}
            <div className={`text-xs rounded px-2 py-1.5 ${compileResult?.success ? 'text-green-400 bg-green-900/20' : 'text-gray-500 bg-gray-700/30'}`}>
              {compileResult?.success
                ? `✓ WASM ready — ${((compileResult.size ?? 0) / 1024).toFixed(1)} KB`
                : '⚙ Compile first before deploying'}
            </div>

            {}
            {deployNetwork === 'mainnet' && (
              <div>
                <label className="text-xs text-gray-400 block mb-1">Node URL</label>
                <input
                  value={nodeUrl}
                  onChange={(e) => onNodeUrlChange(e.target.value)}
                  className="w-full bg-gray-700 text-white text-xs px-2 py-1.5 rounded border border-gray-600 focus:outline-none focus:border-blue-500"
                />
              </div>
            )}

            {}
            <div>
              <label className="text-xs text-gray-400 block mb-1">Init Args <span className="text-gray-600">(optional)</span></label>
              <input
                value={initArgs}
                onChange={(e) => onInitArgsChange(e.target.value)}
                placeholder="e.g. 1000000  or  0x40420f00…"
                className="w-full bg-gray-700 text-white text-xs px-2 py-1.5 rounded border border-gray-600 focus:outline-none focus:border-blue-500"
              />
            </div>

            {}
            <button
              onClick={onDryRun}
              disabled={!compileResult?.success}
              className="w-full py-2 bg-gray-700 hover:bg-gray-600 disabled:bg-gray-700/40 disabled:text-gray-600 text-gray-300 rounded-lg text-xs font-medium flex items-center justify-center gap-2 transition-colors border border-gray-600"
            >
              🔬 Dry Run <span className="text-gray-500">(local simulation, no network)</span>
            </button>

            {}
            <button
              onClick={onDeploy}
              disabled={deploying || !compileResult?.success}
              className={`w-full py-3 disabled:bg-gray-600 text-white rounded-lg font-semibold text-sm flex items-center justify-center gap-2 transition-colors ${
                deployNetwork === 'testnet'
                  ? 'bg-green-700 hover:bg-green-600'
                  : 'bg-purple-600 hover:bg-purple-500'
              }`}
            >
              {deploying ? (
                <><span className="animate-spin">🚀</span> Deploying...</>
              ) : deployNetwork === 'testnet' ? (
                '🧪 Deploy to Testnet (Free)'
              ) : (
                '🚀 Deploy to Mainnet'
              )}
            </button>

            {}
            {dryRunResult && (
              <div className="bg-blue-900/20 border border-blue-700/50 rounded-lg p-3 space-y-1">
                <div className="text-xs text-blue-400 font-semibold">🔬 Dry Run — Simulated</div>
                <div className="text-[11px] text-gray-400">Simulated address (no real deployment):</div>
                <button
                  onClick={() => copyToClipboard(dryRunResult)}
                  className="w-full text-left font-mono text-xs bg-gray-900 rounded px-2 py-1 text-blue-300 hover:bg-gray-700 transition-colors break-all"
                  title="Click to copy"
                >
                  {dryRunResult}
                </button>
                <div className="text-[10px] text-gray-500">No EGOC spent · No on-chain state · Click to copy</div>
              </div>
            )}

            {}
            {deployResult && (
              <div className={`border rounded-xl p-3 space-y-3 ${deployNetwork === 'testnet' ? 'bg-green-900/20 border-green-700/60' : 'bg-purple-900/20 border-purple-700/60'}`}>
                {/* Header */}
                <div className="flex items-center gap-2">
                  <div className={`text-xs font-semibold ${deployNetwork === 'testnet' ? 'text-green-400' : 'text-purple-300'}`}>✓ Deployed!</div>
                  {deployNetwork === 'testnet' && (
                    <span className="text-[10px] font-bold px-1.5 py-0.5 rounded bg-green-800/60 text-green-300 border border-green-700/50">TESTNET</span>
                  )}
                </div>

                {/* Address */}
                <div>
                  <div className="text-[10px] text-gray-400 mb-1">Contract Address</div>
                  <button
                    onClick={() => copyToClipboard(deployResult.contract_address)}
                    className="w-full text-left font-mono text-xs bg-gray-900 rounded-lg px-2 py-1.5 text-green-300 hover:bg-gray-700 transition-colors break-all"
                    title="Click to copy"
                  >
                    {deployResult.contract_address}
                  </button>
                  <div className="text-[10px] text-gray-600 mt-0.5">Click address to copy</div>
                </div>

                {/* What can I do now? */}
                <div className="border-t border-gray-700/50 pt-2 space-y-1.5">
                  <div className="text-[10px] text-gray-400 font-semibold uppercase tracking-wide">What's next?</div>

                  <button
                    onClick={() => onNavigate('/contracts', { address: deployResult.contract_address, abi: abiFunctions })}
                    className="w-full flex items-center gap-2 px-2.5 py-2 rounded-lg bg-blue-600/20 hover:bg-blue-600/40 border border-blue-600/40 transition text-left"
                  >
                    <span className="text-sm">⚡</span>
                    <div>
                      <div className="text-xs font-semibold text-blue-300">Interact with Contract</div>
                      <div className="text-[10px] text-gray-400">Call functions, read state</div>
                    </div>
                    <span className="ml-auto text-blue-400 text-xs">→</span>
                  </button>

                  <button
                    onClick={() => onNavigate('/explorer', { search: deployResult.contract_address })}
                    className="w-full flex items-center gap-2 px-2.5 py-2 rounded-lg bg-gray-700/40 hover:bg-gray-700/70 border border-gray-600/40 transition text-left"
                  >
                    <span className="text-sm">🔍</span>
                    <div>
                      <div className="text-xs font-semibold text-gray-200">View in Explorer</div>
                      <div className="text-[10px] text-gray-400">See transactions & events</div>
                    </div>
                    <span className="ml-auto text-gray-400 text-xs">→</span>
                  </button>

                  {abiFunctions.length > 0 && (
                    <div className="mt-1">
                      <div className="text-[10px] text-gray-500 mb-1">Available functions:</div>
                      <div className="space-y-0.5 max-h-28 overflow-y-auto">
                        {abiFunctions.map((fn, i) => (
                          <div key={i} className="font-mono text-[10px] text-purple-300 bg-gray-900/60 rounded px-2 py-0.5 truncate">
                            {fn}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        )}

        {}
        {tab === 'abi' && (
          <div className="space-y-2">
            <div className="text-xs text-gray-400 font-semibold uppercase tracking-wider mb-3">
              Public Functions
            </div>
            {activeFile?.endsWith('.urego') ? (
              abiFunctions.length > 0 ? (
                abiFunctions.map((sig, i) => (
                  <button
                    key={i}
                    onClick={() => copyToClipboard(sig)}
                    className="w-full text-left font-mono text-xs bg-gray-700/50 hover:bg-gray-700 border border-gray-600 hover:border-blue-500 rounded px-2 py-1.5 text-blue-300 transition-colors"
                    title="Click to copy"
                  >
                    {sig}
                  </button>
                ))
              ) : (
                <div className="text-xs text-gray-500 py-4 text-center">
                  No public functions found
                </div>
              )
            ) : (
              <div className="text-xs text-gray-500 py-4 text-center">
                Open a .urego file to see its interface
              </div>
            )}
          </div>
        )}

        {}
        {tab === 'preview' && (
          <div className="h-full flex flex-col">
            {isHtml ? (
              <>
                <div className="text-xs text-gray-400 px-3 py-2 shrink-0 border-b border-gray-700">Live Preview</div>
                <iframe
                  srcDoc={currentContent}
                  sandbox="allow-scripts"
                  className="flex-1 bg-white w-full"
                  title="dApp Preview"
                />
              </>
            ) : (
              <div className="text-xs text-gray-500 py-4 text-center">
                Open an .html file to preview your dApp frontend
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}

interface TemplateModalProps {
  onClose: () => void;
  onSelect: (tpl: (typeof TEMPLATES)[number]) => void;
}

function TemplateModal({ onClose, onSelect }: TemplateModalProps) {
  return (
    <div className="fixed inset-0 bg-black/70 z-50 flex items-center justify-center p-6">
      <div className="bg-gray-800 rounded-xl border border-gray-600 w-full max-w-2xl max-h-[80vh] flex flex-col shadow-2xl">
        <div className="flex items-center justify-between p-4 border-b border-gray-700">
          <h2 className="text-white font-semibold">Contract Templates</h2>
          <button onClick={onClose} className="text-gray-400 hover:text-white text-xl leading-none">×</button>
        </div>
        <div className="overflow-y-auto p-4 grid grid-cols-2 gap-3">
          {TEMPLATES.map((tpl) => (
            <button
              key={tpl.name}
              onClick={() => { onSelect(tpl); onClose(); }}
              className="text-left bg-gray-700/50 hover:bg-gray-700 border border-gray-600 hover:border-blue-500 rounded-xl p-4 transition-colors"
            >
              <div className="text-2xl mb-2">{tpl.icon}</div>
              <div className="text-white font-medium text-sm">{tpl.name}</div>
              <div className="text-gray-400 text-xs mt-1">{tpl.description}</div>
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}

interface NewProjectModalProps {
  onConfirm: (name: string) => void;
  onCancel: () => void;
}

function NewProjectModal({ onConfirm, onCancel }: NewProjectModalProps) {
  const [name, setName] = useState('');
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    setTimeout(() => inputRef.current?.focus(), 50);
  }, []);

  function submit() {
    const trimmed = name.trim();
    if (trimmed) onConfirm(trimmed);
  }

  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
      <div className="bg-gray-800 border border-gray-600 rounded-xl shadow-2xl p-5 w-80 space-y-4">
        <div className="text-white font-semibold text-sm">New Project</div>
        <input
          ref={inputRef}
          value={name}
          onChange={(e) => setName(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === 'Enter') submit();
            if (e.key === 'Escape') onCancel();
          }}
          placeholder="Project name"
          className="w-full bg-gray-900 border border-gray-600 rounded-lg px-3 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
        />
        <div className="flex gap-2 justify-end">
          <button
            onClick={onCancel}
            className="px-4 py-1.5 bg-gray-700 hover:bg-gray-600 text-white text-xs rounded-lg transition-colors"
          >
            Cancel
          </button>
          <button
            onClick={submit}
            disabled={!name.trim()}
            className="px-4 py-1.5 bg-blue-600 hover:bg-blue-500 disabled:opacity-40 text-white text-xs rounded-lg transition-colors"
          >
            Create
          </button>
        </div>
      </div>
    </div>
  );
}

export default function IDEPage() {
  const navigate = useNavigate();
  const { theme } = useTheme();
  const L = theme === 'light'; // shorthand: L = light mode
  const [projects, setProjects] = useState<Record<string, Project>>({});
  const [activeProject, setActiveProject] = useState<string | null>(null);
  const [activeFile, setActiveFile] = useState<string | null>(null);
  const [openTabs, setOpenTabs] = useState<string[]>([]);
  const MAX_TABS = 3;
  function addTab(path: string, active?: string) {
    setOpenTabs(prev => {
      if (prev.includes(path)) return prev;
      if (prev.length < MAX_TABS) return [...prev, path];
      // evict oldest tab that isn't currently active
      const evictIdx = prev.findIndex(t => t !== (active ?? path));
      const next = [...prev];
      next.splice(evictIdx === -1 ? 0 : evictIdx, 1);
      return [...next, path];
    });
  }
  const [compiling, setCompiling] = useState(false);
  const [compileResult, setCompileResult] = useState<CompileResult | null>(null);
  const [deployResult, setDeployResult] = useState<DeployResult | null>(null);
  const [dryRunResult, setDryRunResult] = useState<string | null>(null);
  const [deploying, setDeploying] = useState(false);
  const [deployNetwork, setDeployNetwork] = useState<DeployNetwork>('testnet');
  const [consoleLogs, setConsoleLogs] = useState<ConsoleLog[]>([]);
  const [rightTab, setRightTab] = useState<RightTab>('build');
  const [showTemplates, setShowTemplates] = useState(false);
  const [showNewProject, setShowNewProject] = useState(false);
  const [deleteConfirmPath, setDeleteConfirmPath] = useState<string | null>(null);
  const [nodeUrl, setNodeUrl] = useState(RPC_URL);
  const [initArgs, setInitArgs] = useState('');
  const [consoleOpen,   setConsoleOpen]   = useState(true);
  const [consoleHeight, setConsoleHeight] = useState(140);
  const [sidebarOpen,   setSidebarOpen]   = useState(true);
  const [fileMenuOpen,  setFileMenuOpen]  = useState(false);
  const fileMenuRef = useRef<HTMLDivElement>(null);
  const consoleRef      = useRef<HTMLDivElement>(null);
  const saveTimerRef    = useRef<ReturnType<typeof setTimeout> | null>(null);

  const editorRef       = useRef<any>(null);
  const consoleResizeRef = useRef<{ startY: number; startH: number } | null>(null);

  useEffect(() => {
    let loaded = loadProjects();
    if (Object.keys(loaded).length === 0) {
      const helloTpl = TEMPLATES.find((t) => t.name === 'Hello World')!;
      const proj = buildProjectFromTemplate(helloTpl);
      loaded = { [proj.name]: proj };
      saveProjects(loaded);
    } else {

      const legacyMarkers = ['storage_set_str', 'storage_get_str', 'emit MessageSet(', 'emit Transfer(', 'emit EscrowCreated(', 'emit Proposed(', 'address_to_str(', 'u64_to_str(', 'caller()', 'require(', 'zero_address('];
      let migrated = false;
      for (const tpl of TEMPLATES) {
        const proj = loaded[tpl.name];
        if (!proj) continue;
        for (const [path, tplContent] of Object.entries(tpl.files)) {
          if (!path.endsWith('.urego')) continue;
          const existing = proj.files[path]?.content ?? '';
          if (legacyMarkers.some((m) => existing.includes(m))) {
            proj.files[path] = { name: path.split('/').pop()!, content: tplContent, language: 'rust' };
            migrated = true;
          }
        }
      }
      if (migrated) saveProjects(loaded);
    }
    setProjects(loaded);
    const firstKey = Object.keys(loaded)[0];
    setActiveProject(firstKey);
    const firstFile = Object.keys(loaded[firstKey].files)[0] ?? null;
    setActiveFile(firstFile);
    if (firstFile) setOpenTabs([firstFile]);
  }, []);

  useEffect(() => {
    if (consoleRef.current) {
      consoleRef.current.scrollTop = consoleRef.current.scrollHeight;
    }
  }, [consoleLogs]);

  useEffect(() => {
    function onMove(e: MouseEvent) {
      const r = consoleResizeRef.current;
      if (!r) return;
      const dy = r.startY - e.clientY;
      setConsoleHeight(Math.max(28, Math.min(600, r.startH + dy)));
    }
    function onUp() { consoleResizeRef.current = null; }
    document.addEventListener('mousemove', onMove);
    document.addEventListener('mouseup', onUp);
    return () => {
      document.removeEventListener('mousemove', onMove);
      document.removeEventListener('mouseup', onUp);
    };
  }, []);

  useEffect(() => {
    if (!fileMenuOpen) return;
    function handleClickOutside(e: MouseEvent) {
      if (fileMenuRef.current && !fileMenuRef.current.contains(e.target as Node)) {
        setFileMenuOpen(false);
      }
    }
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, [fileMenuOpen]);

  const addLog = useCallback((level: ConsoleLog['level'], msg: string) => {
    setConsoleLogs((prev) => {
      const next = [...prev, { ts: nowTs(), level, msg }];
      return next.length > 500 ? next.slice(next.length - 500) : next;
    });
  }, []);

  const currentProject = activeProject ? projects[activeProject] : null;
  const currentFile = currentProject && activeFile ? currentProject.files[activeFile] : null;
  const currentContent = currentFile?.content ?? '';

  const handleEditorChange = useCallback(
    (value: string | undefined) => {
      if (!activeProject || !activeFile || value === undefined) return;
      if (saveTimerRef.current) clearTimeout(saveTimerRef.current);
      saveTimerRef.current = setTimeout(() => {
        setProjects((prev) => {
          const updated = {
            ...prev,
            [activeProject]: {
              ...prev[activeProject],
              files: {
                ...prev[activeProject].files,
                [activeFile]: {
                  ...prev[activeProject].files[activeFile],
                  content: value,
                },
              },
            },
          };
          saveProjects(updated);
          return updated;
        });
      }, 500);
    },
    [activeProject, activeFile]
  );

  function createNewProject(name: string) {
    const proj: Project = {
      name,
      files: {
        'src/main.urego': {
          name: 'main.urego',
          content: '// New Ego Contract\ncontract MyContract {\n\n}',
          language: 'rust',
        },
        'ego.toml': {
          name: 'ego.toml',
          content: `[project]\nname = "${name.toLowerCase().replace(/\s+/g, '-')}"\nversion = "0.1.0"\n\n[network]\ntestnet = "https://rpc.egoblockchain.com"\n`,
          language: 'ini',
        },
      },
    };
    setProjects((prev) => {
      const updated = { ...prev, [name]: proj };
      saveProjects(updated);
      return updated;
    });
    setActiveProject(name);
    setActiveFile('src/main.urego');
    setOpenTabs(['src/main.urego']);
    setCompileResult(null);
    setDeployResult(null);
    addLog('info', `Created project "${name}"`);
  }

  function loadTemplate(tpl: (typeof TEMPLATES)[number]) {
    const proj = buildProjectFromTemplate(tpl);
    const key = proj.name;
    setProjects((prev) => {
      const updated = { ...prev, [key]: proj };
      saveProjects(updated);
      return updated;
    });
    setActiveProject(key);
    const firstTplFile = Object.keys(proj.files)[0] ?? null;
    setActiveFile(firstTplFile);
    setOpenTabs(firstTplFile ? [firstTplFile] : []);
    setCompileResult(null);
    setDeployResult(null);
    addLog('info', `Loaded template "${tpl.name}"`);
  }

  function handleNewFile(filename: string) {
    if (!activeProject) return;
    const safe = sanitizeFilePath(filename);
    if (!safe) return;
    setProjects((prev) => {
      const updated = {
        ...prev,
        [activeProject]: {
          ...prev[activeProject],
          files: {
            ...prev[activeProject].files,
            [safe]: {
              name: safe.split('/').pop()!,
              content: '',
              language: getLanguage(safe),
            },
          },
        },
      };
      saveProjects(updated);
      return updated;
    });
    setActiveFile(safe);
    addTab(safe, activeFile ?? undefined);
    addLog('info', `Created file "${safe}"`);
  }

  function handleNewFolder(firstFilePath: string) {
    handleNewFile(firstFilePath);
  }

  function handleMoveFolder(fromFolder: string, toFolder: string) {
    if (!activeProject || fromFolder === toFolder) return;
    setProjects((prev) => {
      const files = { ...prev[activeProject].files };
      const newFiles: typeof files = {};
      for (const [path, file] of Object.entries(files)) {
        if (path.startsWith(`${fromFolder}/`)) {
          const filename = path.slice(fromFolder.length + 1);
          const newPath = toFolder ? `${toFolder}/${filename}` : filename;
          newFiles[newPath] = { ...file, name: file.name };
        } else {
          newFiles[path] = file;
        }
      }
      const updated = { ...prev, [activeProject]: { ...prev[activeProject], files: newFiles } };
      saveProjects(updated);
      return updated;
    });
    setActiveFile(prev => {
      if (!prev?.startsWith(`${fromFolder}/`)) return prev;
      const filename = prev.slice(fromFolder.length + 1);
      return toFolder ? `${toFolder}/${filename}` : filename;
    });
    setOpenTabs(prev => prev.map(t => {
      if (!t.startsWith(`${fromFolder}/`)) return t;
      const filename = t.slice(fromFolder.length + 1);
      return toFolder ? `${toFolder}/${filename}` : filename;
    }));
    addLog('info', `Moved folder "${fromFolder}/" → "${toFolder || 'root'}"`);
  }

  function handleMoveFile(from: string, to: string) {
    if (!activeProject || from === to) return;
    setProjects((prev) => {
      const files = { ...prev[activeProject].files };
      const file = files[from];
      if (!file) return prev;
      delete files[from];
      files[to] = { ...file, name: to.split('/').pop()! };
      const updated = { ...prev, [activeProject]: { ...prev[activeProject], files } };
      saveProjects(updated);
      return updated;
    });
    if (activeFile === from) setActiveFile(to);
    setOpenTabs(prev => prev.map(t => t === from ? to : t));
    addLog('info', `Moved "${from}" → "${to}"`);
  }

  function handleDeleteFolder(folder: string) {
    if (!activeProject) return;
    setProjects((prev) => {
      const files = { ...prev[activeProject].files };
      const toDelete = Object.keys(files).filter(p => p.startsWith(`${folder}/`));
      for (const p of toDelete) delete files[p];
      const updated = { ...prev, [activeProject]: { ...prev[activeProject], files } };
      saveProjects(updated);
      return updated;
    });
    setOpenTabs(prev => {
      const next = prev.filter(t => !t.startsWith(`${folder}/`));
      if (activeFile?.startsWith(`${folder}/`)) {
        setActiveFile(next[next.length - 1] ?? null);
      }
      return next;
    });
    addLog('info', `Deleted folder "${folder}/"`);
  }

  function handleCopyFile(from: string, to: string) {
    if (!activeProject) return;
    setProjects((prev) => {
      const files = { ...prev[activeProject].files };
      const file = files[from];
      if (!file) return prev;

      let dest = to;
      if (files[dest]) {
        const dot = dest.lastIndexOf('.');
        dest = dot > 0 ? `${dest.slice(0, dot)}_copy${dest.slice(dot)}` : `${dest}_copy`;
      }
      files[dest] = { ...file, name: dest.split('/').pop()! };
      const updated = { ...prev, [activeProject]: { ...prev[activeProject], files } };
      saveProjects(updated);
      return updated;
    });
    addLog('info', `Copied "${from}" → "${to}"`);
  }

  function handleCopyFolder(fromFolder: string, toFolder: string) {
    if (!activeProject) return;
    setProjects((prev) => {
      const files = { ...prev[activeProject].files };
      for (const [path, file] of Object.entries(files)) {
        if (!path.startsWith(`${fromFolder}/`)) continue;
        const filename = path.slice(fromFolder.length + 1);
        const newPath = toFolder ? `${toFolder}/${filename}` : filename;
        if (!files[newPath]) files[newPath] = { ...file, name: file.name };
      }
      const updated = { ...prev, [activeProject]: { ...prev[activeProject], files } };
      saveProjects(updated);
      return updated;
    });
    addLog('info', `Copied folder "${fromFolder}/" → "${toFolder || 'root'}"`);
  }

  function handleRenameFile(oldPath: string, newPath: string) {
    if (!activeProject || oldPath === newPath) return;
    const safeNew = sanitizeFilePath(newPath);
    if (!safeNew) return;
    setProjects((prev) => {
      const files = { ...prev[activeProject].files };
      const file = files[oldPath];
      if (!file) return prev;
      delete files[oldPath];
      files[safeNew] = { ...file, name: safeNew.split('/').pop()! };
      const updated = { ...prev, [activeProject]: { ...prev[activeProject], files } };
      saveProjects(updated);
      return updated;
    });
    if (activeFile === oldPath) setActiveFile(safeNew);
    setOpenTabs(prev => prev.map(t => t === oldPath ? safeNew : t));
    addLog('info', `Renamed "${oldPath}" → "${safeNew}"`);
  }

  function handleRenameFolder(oldFolder: string, newFolder: string) {
    if (!activeProject || oldFolder === newFolder) return;
    setProjects((prev) => {
      const files = { ...prev[activeProject].files };
      const updated_files: typeof files = {};
      for (const [path, file] of Object.entries(files)) {
        if (path.startsWith(`${oldFolder}/`)) {
          const newPath = `${newFolder}/${path.slice(oldFolder.length + 1)}`;
          updated_files[newPath] = { ...file, name: file.name };
        } else {
          updated_files[path] = file;
        }
      }
      const updated = { ...prev, [activeProject]: { ...prev[activeProject], files: updated_files } };
      saveProjects(updated);
      return updated;
    });
    setActiveFile(prev => prev?.startsWith(`${oldFolder}/`) ? prev.replace(`${oldFolder}/`, `${newFolder}/`) : prev);
    setOpenTabs(prev => prev.map(t => t.startsWith(`${oldFolder}/`) ? t.replace(`${oldFolder}/`, `${newFolder}/`) : t));
    addLog('info', `Renamed folder "${oldFolder}" → "${newFolder}"`);
  }

  function handleDeleteFile(path: string) {
    setDeleteConfirmPath(path);
  }

  function confirmDelete() {
    if (!activeProject || !deleteConfirmPath) return;
    const path = deleteConfirmPath;
    setDeleteConfirmPath(null);
    setProjects((prev) => {
      const files = { ...prev[activeProject].files };
      delete files[path];
      const updated = { ...prev, [activeProject]: { ...prev[activeProject], files } };
      saveProjects(updated);
      return updated;
    });
    setOpenTabs(prev => {
      const next = prev.filter(t => t !== path);
      if (activeFile === path) {
        setActiveFile(next[next.length - 1] ?? null);
      }
      return next;
    });
    addLog('info', `Deleted file "${path}"`);
  }

  async function compile() {
    if (!activeFile?.endsWith('.urego')) {
      addLog('error', 'Open a .urego file to compile');
      return;
    }
    setCompiling(true);
    setCompileResult(null);
    addLog('info', `Compiling ${activeFile}...`);
    try {
      const result = await invoke<{ wasm_hex: string; size: number }>('compile_urego', {
        source: currentContent,
      });
      setCompileResult({ success: true, wasm_hex: result.wasm_hex, size: result.size });
      addLog('success', `✓ Compiled ${activeFile} (${(result.size / 1024).toFixed(1)} KB WASM)`);
      setRightTab('deploy');
    } catch (e: unknown) {
      const msg = String(e);
      setCompileResult({ success: false, error: msg });
      addLog('error', `✗ ${msg}`);
    } finally {
      setCompiling(false);
    }
  }

  function dryRun() {
    if (!compileResult?.success || !compileResult.wasm_hex) {
      addLog('error', 'Compile successfully before dry run');
      return;
    }

    const seed = (compileResult.wasm_hex.slice(0, 32) + (activeProject ?? '')).split('').reduce(
      (acc, c) => (acc * 31 + c.charCodeAt(0)) >>> 0, 0x5EED
    );
    const hex = seed.toString(16).padStart(8, '0') + compileResult.wasm_hex.slice(-24);
    const simAddr = `egot1sim${hex}`;
    setDryRunResult(simAddr);
    setDeployResult(null);
    addLog('info', `🔬 Dry run complete — simulated address: ${simAddr}`);
    addLog('info', `   No network call made, no EGOC spent.`);
  }

  async function deploy() {
    if (!compileResult?.success || !compileResult.wasm_hex) {
      addLog('error', 'Compile successfully before deploying');
      return;
    }
    const targetUrl = deployNetwork === 'testnet' ? TESTNET_RPC : nodeUrl;
    setDeploying(true);
    setDryRunResult(null);
    addLog('info', `Deploying to ${deployNetwork === 'testnet' ? 'Testnet' : 'Mainnet'} (${targetUrl})...`);
    try {
      let abiSource = currentContent;
      if (!activeFile?.endsWith('.urego') && currentProject) {
        const mainFile = currentProject.files['src/main.urego'];
        if (mainFile) abiSource = mainFile.content;
      }
      const result = await invoke<{ contract_address: string }>('deploy_contract', {
        args: {
          wasm_hex:      compileResult.wasm_hex,
          init_args_hex: encodeInitArgs(initArgs),
          name:          activeProject || '',
          abi:           extractABI(abiSource),
          node_url:      targetUrl,
        },
      });
      setDeployResult(result);
      addLog('success', `✓ Deployed on ${deployNetwork === 'testnet' ? 'Testnet (free)' : 'Mainnet'}: ${result.contract_address}`);
    } catch (e: unknown) {
      addLog('error', `✗ Deploy failed: ${String(e)}`);
    } finally {
      setDeploying(false);
    }
  }

  async function flattenEntries(
    entries: FileEntry[],
    rootPath: string,
  ): Promise<{ rel: string; full: string }[]> {
    const result: { rel: string; full: string }[] = [];
    for (const entry of entries) {
      if (entry.children) {
        const nested = await flattenEntries(entry.children, rootPath);
        result.push(...nested);
      } else if (entry.path) {

        const norm = entry.path.replace(/\\/g, '/');
        const base = rootPath.replace(/\\/g, '/').replace(/\/$/, '');
        const rel  = norm.startsWith(base + '/') ? norm.slice(base.length + 1) : norm.split('/').pop()!;
        result.push({ rel, full: entry.path });
      }
    }
    return result;
  }

  async function handleOpenProjectFromDisk() {
    const chosen = await dialogOpen({ directory: true, multiple: false, title: 'Open Project Folder' });
    if (!chosen || typeof chosen !== 'string') return;

    const projectName = chosen.replace(/\\/g, '/').split('/').pop() || 'Imported Project';
    addLog('info', `Importing project "${projectName}"…`);

    try {
      const entries = await readDir(chosen, { recursive: true });
      const flat    = await flattenEntries(entries, chosen);

      if (flat.length > MAX_IMPORT_FILES) {
        addLog('error', `Project has ${flat.length} files — import is capped at ${MAX_IMPORT_FILES}. Open a smaller folder.`);
        return;
      }

      const files: Record<string, ProjectFile> = {};
      for (const { rel, full } of flat) {
        try {
          const content = await readTextFile(full);
          const safeRel = sanitizeFilePath(rel);
          if (safeRel) files[safeRel] = { name: safeRel.split('/').pop()!, content, language: getLanguage(safeRel) };
        } catch {
          // skip unreadable / binary files silently
        }
      }

      if (Object.keys(files).length === 0) {
        addLog('error', 'No readable files found in that folder.');
        return;
      }

      setProjects(prev => {
        const updated = { ...prev, [projectName]: { name: projectName, files } };
        saveProjects(updated);
        return updated;
      });
      setActiveProject(projectName);
      const firstFile = Object.keys(files).find(f => f.endsWith('.urego')) ?? Object.keys(files)[0] ?? null;
      setActiveFile(firstFile);
      setOpenTabs(firstFile ? [firstFile] : []);
      setCompileResult(null);
      setDeployResult(null);
      addLog('success', `✓ Imported "${projectName}" — ${Object.keys(files).length} files`);
    } catch (e) {
      addLog('error', `Import failed: ${String(e)}`);
    }
  }

  async function handleSaveProjectToDisk() {
    if (!currentProject) return;

    const destDir = await dialogOpen({ directory: true, multiple: false, title: 'Choose Save Location' });
    if (!destDir || typeof destDir !== 'string') return;

    const sep   = destDir.includes('\\') ? '\\' : '/';
    const root  = `${destDir}${sep}${currentProject.name}`;

    try {
      await createDir(root, { recursive: true });
      for (const [filePath, file] of Object.entries(currentProject.files)) {
        const parts   = filePath.split('/');
        const fileDir = parts.length > 1 ? `${root}${sep}${parts.slice(0, -1).join(sep)}` : root;
        await createDir(fileDir, { recursive: true });
        await writeTextFile(`${fileDir}${sep}${parts[parts.length - 1]}`, file.content);
      }
      addLog('success', `✓ Project saved to ${root}`);
    } catch (e) {
      addLog('error', `Save failed: ${String(e)}`);
    }
  }

  async function handleSaveCurrentFile() {
    if (!currentFile || !activeFile) return;
    const destDir = await dialogOpen({ directory: true, multiple: false, title: 'Save File To…' });
    if (!destDir || typeof destDir !== 'string') return;
    const sep      = destDir.includes('\\') ? '\\' : '/';
    const filename = activeFile.split('/').pop()!;
    try {
      await writeTextFile(`${destDir}${sep}${filename}`, currentFile.content);
      addLog('success', `✓ Saved ${filename} to disk`);
    } catch (e) {
      addLog('error', `Save failed: ${String(e)}`);
    }
  }

  return (
    <div className={`h-full flex flex-col overflow-hidden ${L ? 'bg-white' : 'bg-gray-900'}`}>
      {}
      <div className={`shrink-0 flex items-center gap-2 px-3 py-2 border-b ${L ? 'bg-gray-100 border-gray-300' : 'bg-gray-800 border-gray-700'}`}>
        {}
        <button
          onClick={() => setSidebarOpen(v => !v)}
          title={sidebarOpen ? 'Hide file tree' : 'Show file tree'}
          className={`p-1 rounded transition-colors ${L ? 'text-gray-500 hover:text-gray-900 hover:bg-gray-200' : 'text-gray-400 hover:text-white hover:bg-gray-700'}`}
        >
          <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
            <path d="M1 2h14v1H1zm0 5h10v1H1zm0 5h14v1H1z"/>
            {sidebarOpen && <path d="M13 5l3 3-3 3V5z" className="text-blue-400" fill="currentColor"/>}
          </svg>
        </button>
        <span className={`font-semibold text-sm ${L ? 'text-gray-900' : 'text-white'}`}>dApp IDE</span>
        <span className={L ? 'text-gray-400' : 'text-gray-600'}>|</span>
        {}
        <select
          value={activeProject ?? ''}
          onChange={(e) => {
            const key = e.target.value;
            setActiveProject(key);
            const firstFile = Object.keys(projects[key]?.files ?? {})[0] ?? null;
            setActiveFile(firstFile);
            setOpenTabs(firstFile ? [firstFile] : []);
            setCompileResult(null);
            setDeployResult(null);
          }}
          className={`text-xs px-2 py-1 rounded border focus:outline-none focus:border-blue-500 ${L ? 'bg-white text-gray-800 border-gray-300' : 'bg-gray-700 text-white border-gray-600'}`}
        >
          {Object.keys(projects).map((k) => (
            <option key={k} value={k}>{k}</option>
          ))}
        </select>
        <div className="flex gap-2 ml-auto items-center">
          {}
          <button
            onClick={() => editorRef.current?.trigger('kbd', 'undo', null)}
            title="Undo (Ctrl+Z)"
            className={`px-2 py-1 text-xs rounded border transition-colors flex items-center gap-1 ${L ? 'bg-white hover:bg-gray-100 text-gray-700 border-gray-300' : 'bg-gray-700 hover:bg-gray-600 text-white border-gray-600'}`}
          >
            <svg width="11" height="11" viewBox="0 0 16 16" fill="currentColor"><path d="M2.5 6H9a4 4 0 0 1 0 8H5v-1.5h4a2.5 2.5 0 0 0 0-5H2.5l2 2-1 1L0 8l3.5-3.5 1 1-2 .5z"/></svg>
            Undo
          </button>
          {/* File menu dropdown */}
          <div className="relative" ref={fileMenuRef}>
            <button
              onClick={() => setFileMenuOpen(v => !v)}
              className={`px-3 py-1 text-xs rounded border transition-colors flex items-center gap-1 ${L ? 'bg-white hover:bg-gray-100 text-gray-700 border-gray-300' : 'bg-gray-700 hover:bg-gray-600 text-white border-gray-600'}`}
            >
              File
              <svg width="9" height="9" viewBox="0 0 9 9" fill="currentColor" className={`transition-transform ${fileMenuOpen ? 'rotate-180' : ''}`}>
                <path d="M1 2.5l3.5 4 3.5-4z"/>
              </svg>
            </button>
            {fileMenuOpen && (
              <div className={`absolute right-0 top-full mt-1 z-50 rounded-lg border shadow-xl py-1 min-w-[170px] ${L ? 'bg-white border-gray-300' : 'bg-gray-800 border-gray-600'}`}>
                <button
                  onClick={() => { setFileMenuOpen(false); setShowNewProject(true); }}
                  className={`w-full text-left px-3 py-2 text-xs flex items-center gap-2.5 transition-colors ${L ? 'text-gray-700 hover:bg-gray-100' : 'text-gray-200 hover:bg-gray-700'}`}
                >
                  <span>📄</span> New Project
                </button>
                <button
                  onClick={() => { setFileMenuOpen(false); handleOpenProjectFromDisk(); }}
                  className={`w-full text-left px-3 py-2 text-xs flex items-center gap-2.5 transition-colors ${L ? 'text-gray-700 hover:bg-gray-100' : 'text-gray-200 hover:bg-gray-700'}`}
                >
                  <span>📁</span> Open Folder…
                </button>
                <button
                  onClick={() => { setFileMenuOpen(false); setShowTemplates(true); }}
                  className={`w-full text-left px-3 py-2 text-xs flex items-center gap-2.5 transition-colors ${L ? 'text-gray-700 hover:bg-gray-100' : 'text-gray-200 hover:bg-gray-700'}`}
                >
                  <span>🧩</span> Templates
                </button>
                <div className={`my-1 border-t ${L ? 'border-gray-200' : 'border-gray-700'}`} />
                <button
                  onClick={() => { setFileMenuOpen(false); handleSaveProjectToDisk(); }}
                  disabled={!currentProject}
                  className={`w-full text-left px-3 py-2 text-xs flex items-center gap-2.5 transition-colors disabled:opacity-40 ${L ? 'text-gray-700 hover:bg-gray-100' : 'text-gray-200 hover:bg-gray-700'}`}
                >
                  <span>💾</span> Save Project…
                </button>
                <button
                  onClick={() => { setFileMenuOpen(false); handleSaveCurrentFile(); }}
                  disabled={!currentFile}
                  className={`w-full text-left px-3 py-2 text-xs flex items-center gap-2.5 transition-colors disabled:opacity-40 ${L ? 'text-gray-700 hover:bg-gray-100' : 'text-gray-200 hover:bg-gray-700'}`}
                >
                  <span>⬇</span> Save File…
                </button>
              </div>
            )}
          </div>
          <button
            onClick={compile}
            disabled={compiling}
            className="px-3 py-1 bg-blue-600 hover:bg-blue-500 disabled:bg-gray-600 text-white text-xs rounded transition-colors font-medium"
          >
            {compiling ? '⚙️ Compiling…' : '🔨 Compile'}
          </button>
          <button
            onClick={deploy}
            disabled={deploying || !compileResult?.success}
            className="px-3 py-1 bg-purple-600 hover:bg-purple-500 disabled:bg-gray-600 text-white text-xs rounded transition-colors font-medium"
          >
            {deploying ? '🚀 Deploying…' : '🚀 Deploy'}
          </button>
        </div>
      </div>

      {}
      <div className="flex-1 flex min-h-0">
        {}
        {currentProject && sidebarOpen && (
          <FileTree
            project={currentProject}
            activeFile={activeFile}
            onSelect={(path) => {
              setActiveFile(path);
              addTab(path, activeFile ?? undefined);
              setCompileResult(null);
            }}
            onDelete={handleDeleteFile}
            onDeleteFolder={handleDeleteFolder}
            onNewFile={handleNewFile}
            onNewFolder={handleNewFolder}
            onMoveFile={handleMoveFile}
            onMoveFolder={handleMoveFolder}
            onCopyFile={handleCopyFile}
            onCopyFolder={handleCopyFolder}
            onRenameFile={handleRenameFile}
            onRenameFolder={handleRenameFolder}
          />
        )}

        {}
        <div className="flex-1 min-w-0 flex flex-col">
          {}
          <div className={`shrink-0 flex items-center border-b overflow-x-auto min-h-[32px] ${L ? 'bg-gray-50 border-gray-300' : 'bg-gray-900 border-gray-700'}`}>
            {openTabs.map(tabPath => {
              const label    = tabPath.split('/').pop()!;
              const isActive = tabPath === activeFile;
              return (
                <div
                  key={tabPath}
                  onClick={() => { setActiveFile(tabPath); setCompileResult(null); }}
                  className={`flex items-center gap-1.5 px-3 py-1.5 border-r cursor-pointer shrink-0 group transition-colors ${L ? 'border-gray-300' : 'border-gray-700'} ${
                    isActive
                      ? L ? 'bg-white text-gray-900 border-t-2 border-t-blue-500' : 'bg-gray-800 text-white border-t-2 border-t-blue-500'
                      : L ? 'text-gray-500 hover:bg-white hover:text-gray-800' : 'text-gray-400 hover:bg-gray-800/60 hover:text-gray-200'
                  }`}
                >
                  <span className="text-[11px]">{getFileIcon(label)}</span>
                  <span className="text-xs">{label}</span>
                  <button
                    onClick={e => {
                      e.stopPropagation();
                      setOpenTabs(prev => {
                        const next = prev.filter(t => t !== tabPath);
                        if (activeFile === tabPath) setActiveFile(next[next.length - 1] ?? null);
                        return next;
                      });
                    }}
                    className="opacity-0 group-hover:opacity-100 ml-1 text-gray-500 hover:text-white text-[11px] leading-none rounded hover:bg-gray-600 w-4 h-4 flex items-center justify-center transition-all"
                    title="Close tab"
                  >
                    ×
                  </button>
                </div>
              );
            })}
          </div>
          <div className="flex-1 min-h-0">
            {currentFile ? (
              <Editor
                key={`${activeProject}::${activeFile}`}
                height="100%"
                theme={L ? 'vs' : 'vs-dark'}
                language={currentFile.language}
                value={currentFile.content}
                onChange={handleEditorChange}
                onMount={(editor) => { editorRef.current = editor; }}
                options={{
                  fontSize: 13,
                  minimap: { enabled: false },
                  wordWrap: 'on',
                  lineNumbers: 'on',
                  scrollBeyondLastLine: false,
                  automaticLayout: true,
                  padding: { top: 8 },
                }}
              />
            ) : (
              <div className={`h-full flex items-center justify-center text-sm ${L ? 'bg-white text-gray-400' : 'text-gray-500'}`}>
                <div className="text-center space-y-2">
                  <div className="text-4xl">📄</div>
                  <div>Select a file or create a new project</div>
                  <button
                    onClick={() => setShowTemplates(true)}
                    className="mt-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white text-xs rounded-lg transition-colors"
                  >
                    Browse Templates
                  </button>
                </div>
              </div>
            )}
          </div>
        </div>

        {}
        <RightPanel
          tab={rightTab}
          onTabChange={setRightTab}
          compiling={compiling}
          compileResult={compileResult}
          deployResult={deployResult}
          dryRunResult={dryRunResult}
          deploying={deploying}
          deployNetwork={deployNetwork}
          nodeUrl={nodeUrl}
          initArgs={initArgs}
          activeFile={activeFile}
          currentContent={currentContent}
          onCompile={compile}
          onDeploy={deploy}
          onDryRun={dryRun}
          onNetworkChange={setDeployNetwork}
          onNodeUrlChange={setNodeUrl}
          onInitArgsChange={setInitArgs}
          onNavigate={navigate}
        />
      </div>

      {}
      <div
        className={`shrink-0 flex flex-col ${L ? 'bg-gray-50' : 'bg-black'}`}
        style={{ height: consoleOpen ? consoleHeight : 28 }}
      >
        {}
        {consoleOpen && (
          <div
            onMouseDown={e => { e.preventDefault(); consoleResizeRef.current = { startY: e.clientY, startH: consoleHeight }; }}
            className={`h-1 cursor-ns-resize shrink-0 transition-colors ${L ? 'bg-gray-300 hover:bg-blue-400' : 'bg-gray-700 hover:bg-blue-500'}`}
            title="Drag to resize"
          />
        )}
        <div className={`flex items-center justify-between px-3 py-1 border-b shrink-0 ${L ? 'border-gray-300' : 'border-gray-800'}`}>
          <button
            onClick={() => setConsoleOpen((v) => !v)}
            className={`text-xs font-mono flex items-center gap-1 ${L ? 'text-gray-600 hover:text-gray-900' : 'text-gray-400 hover:text-white'}`}
          >
            <span>{consoleOpen ? '▼' : '▶'}</span>
            <span>Console</span>
            {consoleLogs.length > 0 && (
              <span className={`rounded px-1 ml-1 ${L ? 'bg-gray-200 text-gray-600' : 'bg-gray-700 text-gray-300'}`}>{consoleLogs.length}</span>
            )}
          </button>
          {consoleOpen && (
            <div className="flex items-center gap-3">
              <span className={`text-[10px] ${L ? 'text-gray-400' : 'text-gray-600'}`}>drag top edge to resize</span>
              <button
                onClick={() => setConsoleLogs([])}
                className={`text-xs ${L ? 'text-gray-500 hover:text-gray-900' : 'text-gray-500 hover:text-white'}`}
              >
                Clear
              </button>
            </div>
          )}
        </div>
        {consoleOpen && (
          <div ref={consoleRef} className="flex-1 overflow-y-auto">
            {consoleLogs.length === 0 ? (
              <div className={`px-3 py-1 font-mono text-xs ${L ? 'text-gray-400' : 'text-gray-600'}`}>Ready.</div>
            ) : (
              consoleLogs.map((log, i) => (
                <div
                  key={i}
                  className={`px-3 py-0.5 font-mono text-xs ${
                    log.level === 'error'
                      ? 'text-red-500'
                      : log.level === 'success'
                      ? 'text-green-600'
                      : L ? 'text-gray-600' : 'text-gray-400'
                  }`}
                >
                  <span className={L ? 'text-gray-400' : 'text-gray-600'}>[{log.ts}]</span> {log.msg}
                </div>
              ))
            )}
          </div>
        )}
      </div>

      {}
      {showTemplates && (
        <TemplateModal onClose={() => setShowTemplates(false)} onSelect={loadTemplate} />
      )}

      {showNewProject && (
        <NewProjectModal
          onConfirm={(name) => { setShowNewProject(false); createNewProject(name); }}
          onCancel={() => setShowNewProject(false)}
        />
      )}

      {deleteConfirmPath && (
        <DeleteConfirm
          path={deleteConfirmPath}
          onConfirm={confirmDelete}
          onCancel={() => setDeleteConfirmPath(null)}
        />
      )}
    </div>
  );
}
