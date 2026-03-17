/**
 * Ego Wallet — Content Script
 *
 * Injects the window.ego provider into every page by appending
 * an inline <script> tag. This avoids CSP issues with external scripts
 * while still running in the page's JS context (not isolated world).
 *
 * Communication path:
 *   page ↔ CustomEvents (EGO_REQUEST / EGO_RESPONSE)
 *   content ↔ chrome.runtime.sendMessage ↔ background
 */

// ── Bridge: page → background via postMessage relay ──────────────────────────

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

// ── Inject window.ego provider into page context ──────────────────────────────

const scriptContent = `
(function() {
  if (window.ego && window.ego.isEgoWallet) return;

  var _listeners = {};
  var _pendingRequests = {};

  window.addEventListener('EGO_RESPONSE', function(e) {
    var detail = e.detail;
    var reqId = detail._reqId;
    if (reqId && _pendingRequests[reqId]) {
      var cb = _pendingRequests[reqId];
      delete _pendingRequests[reqId];
      if (detail.error) {
        cb.reject(new Error(detail.error));
      } else {
        cb.resolve(detail.result);
      }
    }
  });

  function egoRequest(args) {
    return new Promise(function(resolve, reject) {
      var reqId = Math.random().toString(36).slice(2) + Date.now();
      _pendingRequests[reqId] = { resolve: resolve, reject: reject };
      window.dispatchEvent(new CustomEvent('EGO_REQUEST', {
        detail: { method: args.method, params: args.params || [], _reqId: reqId }
      }));
    });
  }

  var egoProvider = {
    isEgoWallet: true,
    isMetaMask: false,
    chainId: '0x1',
    networkVersion: '1',
    selectedAddress: null,

    request: egoRequest,

    enable: function() {
      return egoRequest({ method: 'ego_requestAccounts' });
    },

    send: function(methodOrPayload, callbackOrParams) {
      if (typeof methodOrPayload === 'string') {
        if (typeof callbackOrParams === 'function') {
          egoRequest({ method: methodOrPayload }).then(function(r) {
            callbackOrParams(null, { result: r });
          }).catch(function(e) {
            callbackOrParams(e, null);
          });
        } else {
          return egoRequest({ method: methodOrPayload, params: callbackOrParams });
        }
      } else if (methodOrPayload && methodOrPayload.method) {
        return egoRequest(methodOrPayload);
      }
    },

    sendAsync: function(payload, callback) {
      egoRequest(payload).then(function(result) {
        callback(null, { id: payload.id, jsonrpc: '2.0', result: result });
      }).catch(function(err) {
        callback(err, null);
      });
    },

    on: function(event, handler) {
      if (!_listeners[event]) _listeners[event] = [];
      _listeners[event].push(handler);
      return egoProvider;
    },

    removeListener: function(event, handler) {
      if (_listeners[event]) {
        _listeners[event] = _listeners[event].filter(function(h) { return h !== handler; });
      }
      return egoProvider;
    },

    emit: function(event) {
      var args = Array.prototype.slice.call(arguments, 1);
      var handlers = _listeners[event] || [];
      handlers.forEach(function(h) { h.apply(null, args); });
    },
  };

  Object.defineProperty(window, 'ego', {
    value: egoProvider,
    writable: false,
    configurable: false,
  });

  // EVM dApp compatibility
  if (!window.ethereum) {
    Object.defineProperty(window, 'ethereum', {
      value: egoProvider,
      writable: true,
      configurable: true,
    });
  }

  window.dispatchEvent(new Event('ego#initialized'));
  if (window.ethereum === egoProvider) {
    window.dispatchEvent(new Event('ethereum#initialized'));
  }
})();
`;

const script = document.createElement('script');
script.textContent = scriptContent;
(document.head || document.documentElement).appendChild(script);
script.remove();
