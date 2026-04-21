import React, { useState, useCallback } from 'react';

interface ConfirmState {
  message: string;
  detail?: string;
  confirmLabel?: string;
  resolve: (value: boolean) => void;
}

export function useConfirm() {
  const [state, setState] = useState<ConfirmState | null>(null);

  const confirm = useCallback((
    message: string,
    options?: { detail?: string; confirmLabel?: string },
  ): Promise<boolean> => {
    return new Promise(resolve => {
      setState({ message, detail: options?.detail, confirmLabel: options?.confirmLabel, resolve });
    });
  }, []);

  const handleConfirm = () => { state?.resolve(true);  setState(null); };
  const handleCancel  = () => { state?.resolve(false); setState(null); };

  const ConfirmDialog = state ? (
    <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-[200] p-4 backdrop-blur-sm">
      <div className="bg-gray-800 rounded-2xl w-full max-w-sm border border-gray-700 shadow-2xl p-6 space-y-4">
        <p className="text-sm font-semibold text-white">{state.message}</p>
        {state.detail && (
          <p className="text-xs text-gray-400">{state.detail}</p>
        )}
        <div className="flex gap-3 justify-end pt-1">
          <button
            onClick={handleCancel}
            className="px-4 py-2 rounded-xl bg-gray-700 hover:bg-gray-600 text-sm transition"
          >
            Cancel
          </button>
          <button
            onClick={handleConfirm}
            className="px-4 py-2 rounded-xl bg-red-600 hover:bg-red-500 text-sm font-semibold transition"
          >
            {state.confirmLabel ?? 'Confirm'}
          </button>
        </div>
      </div>
    </div>
  ) : null;

  return { confirm, ConfirmDialog };
}
