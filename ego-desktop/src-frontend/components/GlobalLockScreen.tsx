import React, { useState, useEffect, useCallback } from 'react';
import { invoke } from '@tauri-apps/api/tauri';
import { listen } from '@tauri-apps/api/event';
import { appWindow } from '@tauri-apps/api/window';

export function GlobalLockScreen({ children }: { children: React.ReactNode }) {
  const [isLocked, setIsLocked] = useState(true);
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const [hasPin, setHasPin] = useState(false);

  const [showResetPassword, setShowResetPassword] = useState(false);
  const [resetPhraseWords, setResetPhraseWords]   = useState<string[]>(Array(24).fill(''));
  const [resetNewPwd, setResetNewPwd]             = useState('');
  const [resetNewPwd2, setResetNewPwd2]           = useState('');
  const [resetPwdError, setResetPwdError]         = useState('');
  const [resetPwdBusy, setResetPwdBusy]           = useState(false);
  const [resetSuccess, setResetSuccess]           = useState('');

  const checkLock = useCallback(async () => {
    try {
      const status = await invoke<{ has_pin: boolean }>('get_password_status');
      setHasPin(status.has_pin);
      if (status.has_pin) {
        if (sessionStorage.getItem('ego-unlocked') === 'true') {
          setIsLocked(false);
        } else {
          setIsLocked(true);
        }
      } else {
        setIsLocked(false);
      }
    } catch (e) {
      setIsLocked(false);
    }
  }, []);

  useEffect(() => {
    checkLock();
    const unlisten = listen('ego://app-locked', () => {
      sessionStorage.removeItem('ego-unlocked');
      checkLock();
      setPassword('');
      setError('');
    });
    return () => { unlisten.then(f => f()); };
  }, [checkLock]);

  async function handleUnlock(e: React.FormEvent) {
    e.preventDefault();
    setLoading(true);
    setError('');
    try {
      const ok = await invoke<boolean>('verify_password', { password });
      if (ok) {
        sessionStorage.setItem('ego-unlocked', 'true');
        setIsLocked(false);
        setPassword('');
      } else {
        setError('Incorrect password');
      }
    } catch (err: any) {
      setError(String(err).replace(/^.*Error:/, '').trim());
    } finally {
      setLoading(false);
    }
  }

  async function handleResetPasswordWithRecovery() {
    setResetPwdError('');
    setResetSuccess('');
    const phrase = resetPhraseWords.map(w => w.trim().toLowerCase()).filter(Boolean);
    if (phrase.length !== 24) {
      setResetPwdError('Enter all 24 recovery words.');
      return;
    }
    if (resetNewPwd.length < 8) {
      setResetPwdError('New password must be at least 8 characters.');
      return;
    }
    if (resetNewPwd !== resetNewPwd2) {
      setResetPwdError('Passwords do not match.');
      return;
    }
    setResetPwdBusy(true);
    try {
      await invoke('reset_password_with_recovery_phrase', {
        recoveryPhrase: phrase,
        newPassword:    resetNewPwd,
      });
      setResetSuccess('✅ Password reset successfully! You can now log in.');
      setTimeout(() => {
        setShowResetPassword(false);
        setResetPhraseWords(Array(24).fill(''));
        setResetNewPwd('');
        setResetNewPwd2('');
        setResetSuccess('');
      }, 3000);
    } catch (e: any) {
      setResetPwdError(String(e).replace(/^.*Error:/, '').trim());
    } finally {
      setResetPwdBusy(false);
    }
  }

  const handlePastePhrase = (e: React.ClipboardEvent<HTMLInputElement>) => {
    const pastedText = e.clipboardData.getData('text');
    const words = pastedText.trim().split(/[\s,]+/).filter(Boolean);
    if (words.length === 24) {
      e.preventDefault();
      setResetPhraseWords(words.map(w => w.toLowerCase()));
    }
  };

  if (!hasPin || !isLocked) return <>{children}</>;

  return (
    <div className="fixed inset-0 z-[99999] flex items-center justify-center bg-gray-900/90 backdrop-blur-xl">
      <form onSubmit={handleUnlock} className="relative bg-gray-800 p-8 rounded-3xl shadow-2xl border border-gray-700 max-w-sm w-full text-center">
        <button
          type="button"
          onClick={() => appWindow.close()}
          className="absolute top-5 right-5 text-gray-500 hover:text-white transition-colors text-xl leading-none"
          title="Close App"
        >
          ✕
        </button>
        <div className="w-16 h-16 bg-blue-500/20 text-blue-400 rounded-full flex items-center justify-center mx-auto mb-5 text-2xl">🔒</div>
        <h2 className="text-2xl font-bold text-white mb-2">Ego Desktop Locked</h2>
        <p className="text-sm text-gray-400 mb-6">Enter your password to continue.</p>
        <input type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="Password" autoFocus className="w-full bg-gray-900 border border-gray-600 rounded-xl px-4 py-3 text-white mb-4 outline-none focus:border-blue-500 transition" />
        {error && <div className="text-red-400 text-sm mb-4 font-semibold">{error}</div>}
        <button type="submit" disabled={loading || !password} className="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-3.5 rounded-xl transition disabled:opacity-50 mb-3">{loading ? 'Unlocking...' : 'Unlock'}</button>
        
        <button type="button" onClick={() => setShowResetPassword(true)} className="text-xs text-blue-400 hover:text-blue-300 transition">
          Forgot password? Reset with recovery phrase
        </button>
      </form>

      {showResetPassword && (
        <div className="absolute inset-0 flex items-center justify-center bg-gray-900/90 backdrop-blur-xl p-4 z-50">
          <div className="bg-gray-800 p-6 w-full max-w-2xl border border-gray-700 shadow-2xl rounded-3xl max-h-[90vh] overflow-y-auto relative text-left">
            <button onClick={() => setShowResetPassword(false)} className="absolute top-6 right-6 text-gray-400 hover:text-white transition-colors text-xl leading-none">✕</button>
            <h2 className="text-xl font-bold text-white mb-4">Reset Password</h2>
            <div className="bg-blue-500/10 border border-blue-500/30 rounded-xl px-4 py-3 text-xs text-blue-300 mb-5 leading-relaxed">
              Enter your 24-word recovery phrase exactly as you wrote it down when you created the wallet.
              Each word in its own box, lowercase, in order. Then choose a new password.
            </div>
            
            <div className="grid grid-cols-4 gap-2 mb-5">
              {resetPhraseWords.map((w, i) => (
                <div key={i} className="relative">
                  <span className="absolute left-2 top-1/2 -translate-y-1/2 text-[10px] text-gray-500">{i + 1}.</span>
                  <input
                    type="text"
                    value={w}
                    onPaste={handlePastePhrase}
                    onChange={e => {
                      const v = e.target.value.toLowerCase().trim();
                      setResetPhraseWords(prev => prev.map((x, j) => j === i ? v : x));
                    }}
                    className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-lg pl-7 pr-2 py-2 text-xs font-mono outline-none transition text-white"
                  />
                </div>
              ))}
            </div>

            <div className="space-y-3">
              <input type="password" value={resetNewPwd} onChange={e => setResetNewPwd(e.target.value)} placeholder="New password (min 8 chars)" className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none transition text-white" />
              <input type="password" value={resetNewPwd2} onChange={e => setResetNewPwd2(e.target.value)} onKeyDown={e => e.key === 'Enter' && !resetPwdBusy && handleResetPasswordWithRecovery()} placeholder="Confirm new password" className="w-full bg-gray-900 border border-gray-700 focus:border-blue-500 rounded-xl px-4 py-3 text-sm outline-none transition text-white" />
              
              {resetPwdError && (
                <div className="text-xs px-3 py-2 rounded-lg bg-red-500/20 text-red-400">{resetPwdError}</div>
              )}
              {resetSuccess && (
                <div className="text-xs px-3 py-2 rounded-lg bg-green-500/20 text-green-400">{resetSuccess}</div>
              )}
              
              <button
                onClick={handleResetPasswordWithRecovery}
                disabled={resetPwdBusy}
                className="w-full bg-blue-600 hover:bg-blue-500 disabled:opacity-40 py-3 rounded-xl font-semibold text-sm transition text-white mt-2"
              >
                {resetPwdBusy ? 'Verifying & saving...' : 'Reset Password'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}