window.addEventListener('EGO_REQUEST', async (event: Event) => {
  const e = event as CustomEvent<{
    method: string;
    params?: unknown[];
    _reqId: string;
  }>;
  const { method, params = [], _reqId } = e.detail;

  let msgType: string;
  let payload: Record<string, unknown> = {};

  switch (method) {
    case 'ego_requestAccounts':
    case 'eth_requestAccounts':
    case 'eth_accounts':
      msgType = 'EGO_GET_ACCOUNTS';
      break;

    case 'eth_chainId':
    case 'ego_chainId':
      window.dispatchEvent(new CustomEvent('EGO_RESPONSE', {
        detail: { result: '0x1', _reqId },
      }));
      return;

    case 'eth_sendTransaction':
    case 'ego_sendTransaction': {
      msgType = 'EGO_SEND_TX';
      const txParam = (params[0] ?? {}) as Record<string, unknown>;
      payload = {
        to: txParam.to ?? '',
        amount_egoc: Number(txParam.value ?? 0) / 1e18,
        memo: (txParam.data as string) ?? '',
      };
      break;
    }

    case 'personal_sign':
    case 'ego_sign': {
      msgType = 'EGO_SIGN_MESSAGE';
      payload = { message: params[0] ?? '' };
      break;
    }

    case 'wallet_switchEthereumChain':
      window.dispatchEvent(new CustomEvent('EGO_RESPONSE', {
        detail: { result: null, _reqId },
      }));
      return;

    default:
      window.dispatchEvent(new CustomEvent('EGO_RESPONSE', {
        detail: { error: `Unsupported method: ${method}`, _reqId },
      }));
      return;
  }

  try {
    const response = await chrome.runtime.sendMessage({ type: msgType, payload });
    if (response?.success) {
      window.dispatchEvent(new CustomEvent('EGO_RESPONSE', {
        detail: { result: response.data, _reqId },
      }));
    } else {
      window.dispatchEvent(new CustomEvent('EGO_RESPONSE', {
        detail: { error: response?.error ?? 'Unknown error', _reqId },
      }));
    }
  } catch (err: unknown) {
    window.dispatchEvent(new CustomEvent('EGO_RESPONSE', {
      detail: { error: (err as Error).message, _reqId },
    }));
  }
});

// Inject the page provider as an EXTERNAL script (web_accessible_resource) so it
// runs in the page's MAIN world without an inline <script>, which strict-CSP
// pages (e.g. Google) block.
const script = document.createElement('script');
script.src = chrome.runtime.getURL('inject.js');
script.onload = () => script.remove();
(document.head || document.documentElement).appendChild(script);
