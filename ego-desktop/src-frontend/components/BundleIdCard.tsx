import React, { useEffect, useState } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import qrcode from 'qrcode-generator';

function qrFor(text: string): string {
  if (!text) return '';
  try {
    const qr = qrcode(0, 'M');
    qr.addData(text);
    qr.make();
    return qr.createDataURL(3, 0);
  } catch {
    return '';
  }
}

const BundleIdCard: React.FC = () => {
  const [card, setCard] = useState('');
  const [problem, setProblem] = useState('');
  const [copied, setCopied] = useState(false);
  const [showQr, setShowQr] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [renewing, setRenewing] = useState(false);

  async function load() {
    try {
      setCard(await invoke<string>('get_my_contact_bundle', {}));
      setProblem('');
    } catch (e) {
      setProblem(String(e));
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function copy() {
    if (!card) return;
    await navigator.clipboard.writeText(card);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  }

  async function renew() {
    setRenewing(true);
    try {
      await invoke('revoke_contact_bundle');
      setConfirming(false);
      await load();
    } catch (e) {
      setProblem(String(e));
    } finally {
      setRenewing(false);
    }
  }

  return (
    <div className="bg-gray-800 rounded-2xl border border-gray-700 overflow-hidden">
      <div className="px-5 py-4 border-b border-gray-700">
        <h3 className="font-semibold">Bundle ID</h3>
        <div className="text-xs text-gray-400 mt-0.5">
          Give it to someone so they can add you in Messenger. Your phone shows the same one.
        </div>
      </div>
      <div className="px-5 py-4 space-y-3">
        {card ? (
          <div className="bg-gray-900 rounded-xl p-3 font-mono text-xs text-gray-300 break-all select-all max-h-24 overflow-y-auto">
            {card}
          </div>
        ) : (
          <div className="bg-gray-900 rounded-xl p-3 text-xs text-gray-500">
            {problem || 'Loading…'}
          </div>
        )}
        {showQr && card && (
          <div className="flex justify-center">
            <img src={qrFor(card)} alt="Bundle ID QR code" className="rounded-lg bg-white p-2" />
          </div>
        )}
        <div className="flex gap-2 flex-wrap">
          <button
            onClick={copy}
            disabled={!card}
            className="bg-blue-600 hover:bg-blue-500 disabled:opacity-40 px-4 py-2 rounded-xl text-xs font-medium transition-colors"
          >
            {copied ? '✓ Copied' : 'Copy'}
          </button>
          <button
            onClick={() => setShowQr(v => !v)}
            disabled={!card}
            className="bg-gray-700 hover:bg-gray-600 disabled:opacity-40 px-4 py-2 rounded-xl text-xs font-medium transition-colors"
          >
            {showQr ? 'Hide QR code' : 'Show QR code'}
          </button>
          {!confirming && (
            <button
              onClick={() => setConfirming(true)}
              disabled={!card}
              className="text-xs text-gray-400 hover:text-red-400 px-2 transition-colors"
            >
              Delete and make a new one
            </button>
          )}
        </div>
        {confirming && (
          <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-xl p-3 space-y-2">
            <p className="text-xs text-yellow-300">
              Anyone holding the old Bundle ID can no longer send you a contact request. Contacts you already have keep working.
              Your phone switches to the new one within a few minutes.
            </p>
            <div className="flex gap-2">
              <button
                onClick={renew}
                disabled={renewing}
                className="bg-red-600 hover:bg-red-500 disabled:opacity-40 px-4 py-2 rounded-xl text-xs font-medium transition-colors"
              >
                {renewing ? 'Making a new one…' : 'Delete and make a new one'}
              </button>
              <button
                onClick={() => setConfirming(false)}
                className="bg-gray-700 hover:bg-gray-600 px-4 py-2 rounded-xl text-xs font-medium transition-colors"
              >
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

export default BundleIdCard;
