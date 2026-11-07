import React from 'react';
import { PASSWORD_RULES } from '../lib/password';

const PasswordRules: React.FC<{ value: string }> = ({ value }) => (
  <div className="grid grid-cols-2 gap-x-3 gap-y-0.5 mt-1.5">
    {PASSWORD_RULES.map(r => {
      const ok = r.ok(value);
      return (
        <div key={r.label} className={`text-[11px] ${ok ? 'text-green-400' : 'text-gray-500'}`}>
          {ok ? '✓' : '○'} {r.label}
        </div>
      );
    })}
  </div>
);

export default PasswordRules;
