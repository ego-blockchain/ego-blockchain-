import { invoke } from '@tauri-apps/api/tauri';

export type TotpAction = 'send' | 'reveal' | 'pin' | 'export';

export interface TotpAsk {
  action: TotpAction;
  password: boolean;
  code: boolean;
  resolve: (ok: boolean) => void;
}

let asker: ((ask: TotpAsk) => void) | null = null;

export function registerTotpAsker(fn: ((ask: TotpAsk) => void) | null) {
  asker = fn;
}

export async function totpEnabled(): Promise<boolean> {
  try {
    const s = await invoke<{ enabled: boolean }>('totp_status');
    return s.enabled;
  } catch {
    return false;
  }
}

export async function requireConfirm(action: TotpAction): Promise<boolean> {
  let status = { password: false, code: false };
  try {
    status = await invoke<{ password: boolean; code: boolean }>('confirm_status');
  } catch {
    return false;
  }
  const password = status.password && action !== 'reveal';
  const code = status.code;
  if (!password && !code) return true;
  const ask = asker;
  if (!ask) return false;
  return new Promise<boolean>(resolve => ask({ action, password, code, resolve }));
}

export const requireTotp = requireConfirm;
