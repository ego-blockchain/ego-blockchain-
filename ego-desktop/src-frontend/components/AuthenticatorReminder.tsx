import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { totpEnabled } from '../lib/totp';

const SNOOZE_KEY = 'ego-totp-reminder-until';
const SNOOZE_DAYS = 7;

const AuthenticatorReminder: React.FC = () => {
  const [show, setShow] = useState(false);
  const navigate = useNavigate();

  useEffect(() => {
    let alive = true;
    const check = async () => {
      const until = Number(localStorage.getItem(SNOOZE_KEY) || 0);
      if (until > Date.now()) {
        if (alive) setShow(false);
        return;
      }
      const on = await totpEnabled();
      if (alive) setShow(!on);
    };
    check();
    const timer = setInterval(check, 30 * 60 * 1000);
    const onWake = () => { if (document.visibilityState === 'visible') check(); };
    const onChange = () => { check(); };
    document.addEventListener('visibilitychange', onWake);
    window.addEventListener('ego-totp-changed', onChange);
    return () => {
      alive = false;
      clearInterval(timer);
      document.removeEventListener('visibilitychange', onWake);
      window.removeEventListener('ego-totp-changed', onChange);
    };
  }, []);

  if (!show) return null;

  return (
    <div className="bg-amber-500/10 border-b border-amber-500/30 px-5 py-3 flex items-center gap-3">
      <span className="text-lg shrink-0">🛡</span>
      <div className="min-w-0 flex-1">
        <div className="text-sm font-semibold text-amber-200">Protect your wallet with an authenticator app</div>
        <div className="text-xs text-gray-400">
          Payments, shielding and showing your keys will also need a 6-digit code from your phone. Google Authenticator works; setup takes a minute.
        </div>
      </div>
      <button
        onClick={() => navigate('/settings')}
        className="shrink-0 bg-amber-600 hover:bg-amber-500 px-4 py-1.5 rounded-xl text-xs font-semibold transition-colors"
      >
        Set up
      </button>
      <button
        onClick={() => {
          localStorage.setItem(SNOOZE_KEY, String(Date.now() + SNOOZE_DAYS * 86_400_000));
          setShow(false);
        }}
        className="shrink-0 text-xs text-gray-400 hover:text-white px-2"
      >
        Later
      </button>
    </div>
  );
};

export default AuthenticatorReminder;
