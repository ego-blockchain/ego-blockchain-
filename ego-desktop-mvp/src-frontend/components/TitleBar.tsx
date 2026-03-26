import React, { useState } from 'react';
import { appWindow } from '@tauri-apps/api/window';
import { open as openUrl } from '@tauri-apps/api/shell';
import { writeText } from '@tauri-apps/api/clipboard';
import qrcode from 'qrcode-generator';

// ── Replace with your Stripe Payment Link once created ──────────────────────
const STRIPE_DONATE_URL = 'https://buy.stripe.com/dRm6oHfhy4eF8oad8897G00';

function makeQR(text: string): string {
  const qr = qrcode(0, 'M');
  qr.addData(text);
  qr.make();
  return qr.createDataURL(3, 0);
}

const CRYPTO = [
  {
    id: 'btc',
    label: 'Bitcoin',
    symbol: 'BTC',
    color: '#f7931a',
    address: 'bc1qaqx0xf9sv0ktmtcxlzzh7t7kf59nwu8c0vlqhg',
    icon: '₿',
  },
  {
    id: 'usdt',
    label: 'USDT (Ethereum)',
    symbol: 'USDT',
    color: '#26a17b',
    address: '0xD4f2B1fA44668B806290A4c3CB758ABb7EF35C64',
    icon: '₮',
  },
  {
    id: 'ada',
    label: 'Cardano',
    symbol: 'ADA',
    color: '#0033ad',
    address: 'addr1qyp35j52jw8tmg85wvll3p5krsgkpttxa65kxav4mc56g73fmcra587acj9n8zsqm8u55zvumpff3mrkt9865jswu4gql452dd',
    icon: '₳',
  },
];

const DonateModal: React.FC<{ onClose: () => void }> = ({ onClose }) => {
  const [copied, setCopied] = useState<string | null>(null);
  const [qrFor, setQrFor]   = useState<string | null>(null);

  async function copy(id: string, address: string) {
    await writeText(address);
    setCopied(id);
    setTimeout(() => setCopied(null), 2000);
  }

  return (
    <div
      className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-[9999] p-4"
      onClick={e => { if (e.target === e.currentTarget) onClose(); }}
    >
      <div className="bg-gray-800 border border-gray-700 rounded-2xl w-full max-w-md shadow-2xl overflow-hidden">
        {/* Header */}
        <div className="bg-gradient-to-r from-purple-600/30 to-pink-600/20 px-6 py-5 border-b border-gray-700">
          <div className="flex items-center justify-between">
            <div>
              <h2 className="text-lg font-bold">Support Ego Blockchain ❤️</h2>
              <p className="text-xs text-gray-400 mt-0.5">Your support keeps this project alive</p>
            </div>
            <button onClick={onClose} className="text-gray-400 hover:text-white text-xl leading-none">✕</button>
          </div>
        </div>

        <div className="p-5 space-y-3">
          {/* Crypto addresses */}
          {CRYPTO.map(c => (
            <div key={c.id} className="bg-gray-900/60 rounded-xl border border-gray-700/50 overflow-hidden">
              <div className="flex items-center gap-3 px-4 py-3">
                <div
                  className="w-9 h-9 rounded-lg flex items-center justify-center text-lg font-bold shrink-0"
                  style={{ background: c.color + '22', color: c.color }}
                >
                  {c.icon}
                </div>
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-semibold">{c.label}</div>
                  <div className="font-mono text-[10px] text-gray-400 truncate">{c.address}</div>
                </div>
                <div className="flex items-center gap-1 shrink-0">
                  <button
                    onClick={() => setQrFor(qrFor === c.id ? null : c.id)}
                    className="text-xs text-gray-400 hover:text-white px-2 py-1 rounded-lg hover:bg-gray-700 transition"
                    title="Show QR"
                  >
                    ⬛
                  </button>
                  <button
                    onClick={() => copy(c.id, c.address)}
                    className={`text-xs px-3 py-1 rounded-lg transition font-medium ${
                      copied === c.id
                        ? 'bg-green-600/30 text-green-400'
                        : 'bg-gray-700 hover:bg-gray-600 text-gray-300'
                    }`}
                  >
                    {copied === c.id ? '✓ Copied' : 'Copy'}
                  </button>
                </div>
              </div>
              {qrFor === c.id && (
                <div className="border-t border-gray-700/50 px-4 py-3 flex flex-col items-center gap-2">
                  <img src={makeQR(c.address)} alt={`${c.symbol} QR`} className="w-36 h-36 rounded-lg" style={{ imageRendering: 'pixelated' }} />
                  <p className="text-[10px] text-gray-500 font-mono text-center break-all">{c.address}</p>
                </div>
              )}
            </div>
          ))}

          {/* Stripe — card & Apple Pay */}
          <button
            onClick={() => openUrl(STRIPE_DONATE_URL).catch(() => {})}
            className="w-full flex items-center justify-center gap-3 bg-gradient-to-r from-blue-600 to-indigo-600 hover:from-blue-500 hover:to-indigo-500 text-white rounded-xl py-3 font-semibold text-sm transition shadow-lg"
          >
            <span className="text-base">💳</span>
            <span>Donate with Card or Apple Pay</span>
            <span className="text-xs opacity-70">via Stripe ↗</span>
          </button>

          <p className="text-center text-xs text-gray-600">
            Thank you for supporting decentralized technology 🙏
          </p>
        </div>
      </div>
    </div>
  );
};

const TitleBar: React.FC = () => {
  const [showDonate, setShowDonate] = useState(false);

  return (
    <>
      <div
        className="flex items-center h-9 bg-gray-900 border-b border-gray-800 shrink-0 select-none"
        style={{ WebkitUserSelect: 'none' }}
      >
        {/* Traffic lights */}
        <div className="flex items-center gap-[6px] pl-3 pr-4 group">
          <button
            onClick={() => appWindow.hide()}
            className="w-3 h-3 rounded-full flex items-center justify-center transition-opacity"
            style={{ backgroundColor: '#ff5f57' }}
            title="Hide to tray"
          >
            <svg className="w-[7px] h-[7px] opacity-0 group-hover:opacity-100 transition-opacity" viewBox="0 0 10 10" fill="none">
              <path d="M2 2l6 6M8 2l-6 6" stroke="#820005" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
          </button>

          <button
            onClick={() => appWindow.minimize()}
            className="w-3 h-3 rounded-full flex items-center justify-center transition-opacity"
            style={{ backgroundColor: '#ffbd2e' }}
            title="Minimize"
          >
            <svg className="w-[7px] h-[7px] opacity-0 group-hover:opacity-100 transition-opacity" viewBox="0 0 10 10" fill="none">
              <path d="M2 5h6" stroke="#9d5800" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
          </button>

          <button
            onClick={() => appWindow.toggleMaximize()}
            className="w-3 h-3 rounded-full flex items-center justify-center transition-opacity"
            style={{ backgroundColor: '#28c840' }}
            title="Maximize"
          >
            <svg className="w-[7px] h-[7px] opacity-0 group-hover:opacity-100 transition-opacity" viewBox="0 0 10 10" fill="none">
              <path d="M2 5h6M5 2v6" stroke="#0a5516" strokeWidth="1.5" strokeLinecap="round" />
            </svg>
          </button>
        </div>

        {/* Drag region + title */}
        <div data-tauri-drag-region className="flex-1 h-full flex items-center justify-center">
          <span className="text-xs text-gray-500 font-medium pointer-events-none">Ego Desktop</span>
        </div>

        {/* Donate button */}
        <div className="pr-3 shrink-0">
          <button
            onClick={() => setShowDonate(true)}
            className="flex items-center gap-1.5 px-2.5 py-1 rounded-lg bg-pink-600/20 hover:bg-pink-600/40 text-pink-400 hover:text-pink-300 text-xs font-medium transition"
          >
            ❤️ Donate
          </button>
        </div>
      </div>

      {showDonate && <DonateModal onClose={() => setShowDonate(false)} />}
    </>
  );
};

export default TitleBar;
