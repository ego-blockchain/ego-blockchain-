type Shape = (data: Record<string, unknown>) => unknown;

const accountsOf: Shape = data => (data.accounts as string[]) ?? [];
const txHashOf: Shape = data => data.tx_hash;
const signatureOf: Shape = data => data.signature;

function reply(_reqId: string, detail: { result?: unknown; error?: string }) {
  window.dispatchEvent(new CustomEvent('EGO_RESPONSE', { detail: { ...detail, _reqId } }));
}

window.addEventListener('EGO_REQUEST', async (event: Event) => {
  const e = event as CustomEvent<{
    method: string;
    params?: unknown[];
    _reqId: string;
  }>;
  const { method, params = [], _reqId } = e.detail ?? ({} as { method: string; params?: unknown[]; _reqId: string });
  if (typeof method !== 'string' || typeof _reqId !== 'string') return;

  let msgType: string;
  let payload: Record<string, unknown> = {};
  let shape: Shape;

  switch (method) {
    case 'ego_requestAccounts':
    case 'eth_requestAccounts':
      msgType = 'EGO_DAPP_CONNECT';
      shape = accountsOf;
      break;

    case 'eth_accounts':
    case 'ego_accounts':
    case 'ego_getAccounts':
      msgType = 'EGO_DAPP_ACCOUNTS';
      shape = accountsOf;
      break;

    case 'eth_chainId':
    case 'ego_chainId':
      reply(_reqId, { result: '0x1' });
      return;

    case 'eth_sendTransaction':
    case 'ego_sendTransaction': {
      msgType = 'EGO_DAPP_SEND_TX';
      shape = txHashOf;
      const txParam = (params[0] ?? {}) as Record<string, unknown>;
      const amount = method === 'ego_sendTransaction' && txParam.amount_egoc !== undefined
        ? Number(txParam.amount_egoc)
        : Number(txParam.value ?? 0) / 1e18;
      payload = {
        to: typeof txParam.to === 'string' ? txParam.to : '',
        amount_egoc: amount,
        memo: typeof txParam.memo === 'string' ? txParam.memo : typeof txParam.data === 'string' ? txParam.data : '',
      };
      break;
    }

    case 'ego_callContract': {
      msgType = 'EGO_DAPP_CALL_CONTRACT';
      shape = txHashOf;
      const p0 = (params[0] ?? {}) as Record<string, unknown>;
      payload = {
        contractAddr: p0.contractAddr ?? p0.to ?? '',
        entrypoint:   p0.entrypoint ?? '',
        callArgs:     p0.callArgs ?? p0.args ?? '',
      };
      break;
    }

    case 'personal_sign':
    case 'ego_sign':
    case 'ego_signMessage': {
      msgType = 'EGO_DAPP_SIGN';
      shape = signatureOf;
      payload = { message: typeof params[0] === 'string' ? params[0] : '' };
      break;
    }

    case 'wallet_switchEthereumChain':
      reply(_reqId, { result: null });
      return;

    default:
      reply(_reqId, { error: `Unsupported method: ${method}` });
      return;
  }

  try {
    const response = await chrome.runtime.sendMessage({ type: msgType, payload });
    if (response?.success) {
      reply(_reqId, { result: shape((response.data ?? {}) as Record<string, unknown>) });
    } else {
      reply(_reqId, { error: response?.error ?? 'Unknown error' });
    }
  } catch (err: unknown) {
    reply(_reqId, { error: (err as Error).message });
  }
});

// Inject the page provider as an EXTERNAL script (web_accessible_resource) so it
// runs in the page's MAIN world without an inline <script>, which strict-CSP
// pages (e.g. Google) block.
const script = document.createElement('script');
script.src = chrome.runtime.getURL('inject.js');
script.onload = () => script.remove();
(document.head || document.documentElement).appendChild(script);
