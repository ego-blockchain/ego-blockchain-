// Injected into the page's MAIN world as an EXTERNAL script (declared as a
// web_accessible_resource) so it works under strict CSP — an inline <script>
// would be blocked by pages like Google. Exposes window.ego (and window.ethereum
// for EVM dApp compatibility). Talks to the content-script bridge via window
// CustomEvents (EGO_REQUEST / EGO_RESPONSE), which cross the isolated/main world.
(function () {
  const w = window as any;
  if (w.ego && w.ego.isEgoWallet) return;

  const _listeners: Record<string, Function[]> = {};
  const _pendingRequests: Record<string, { resolve: (v: unknown) => void; reject: (e: unknown) => void }> = {};

  window.addEventListener('EGO_RESPONSE', function (e: Event) {
    const detail = (e as CustomEvent).detail;
    const reqId = detail && detail._reqId;
    if (reqId && _pendingRequests[reqId]) {
      const cb = _pendingRequests[reqId];
      delete _pendingRequests[reqId];
      if (detail.error) cb.reject(new Error(detail.error));
      else cb.resolve(detail.result);
    }
  });

  function egoRequest(args: { method: string; params?: unknown[] }) {
    return new Promise(function (resolve, reject) {
      const reqId = Math.random().toString(36).slice(2) + Date.now();
      _pendingRequests[reqId] = { resolve, reject };
      window.dispatchEvent(new CustomEvent('EGO_REQUEST', {
        detail: { method: args.method, params: args.params || [], _reqId: reqId },
      }));
    });
  }

  const egoProvider: any = {
    isEgoWallet: true,
    isMetaMask: false,
    chainId: '0x1',
    networkVersion: '1',
    selectedAddress: null,

    request: egoRequest,

    enable: function () {
      return egoRequest({ method: 'ego_requestAccounts' });
    },

    send: function (methodOrPayload: any, callbackOrParams: any) {
      if (typeof methodOrPayload === 'string') {
        if (typeof callbackOrParams === 'function') {
          egoRequest({ method: methodOrPayload }).then(function (r) {
            callbackOrParams(null, { result: r });
          }).catch(function (e) {
            callbackOrParams(e, null);
          });
        } else {
          return egoRequest({ method: methodOrPayload, params: callbackOrParams });
        }
      } else if (methodOrPayload && methodOrPayload.method) {
        return egoRequest(methodOrPayload);
      }
    },

    sendAsync: function (payload: any, callback: any) {
      egoRequest(payload).then(function (result) {
        callback(null, { id: payload.id, jsonrpc: '2.0', result: result });
      }).catch(function (err) {
        callback(err, null);
      });
    },

    on: function (event: string, handler: Function) {
      if (!_listeners[event]) _listeners[event] = [];
      _listeners[event].push(handler);
      return egoProvider;
    },

    removeListener: function (event: string, handler: Function) {
      if (_listeners[event]) {
        _listeners[event] = _listeners[event].filter(function (h) { return h !== handler; });
      }
      return egoProvider;
    },

    emit: function (event: string) {
      const args = Array.prototype.slice.call(arguments, 1);
      const handlers = _listeners[event] || [];
      handlers.forEach(function (h) { h.apply(null, args); });
    },
  };

  Object.defineProperty(window, 'ego', {
    value: egoProvider,
    writable: false,
    configurable: false,
  });

  // EVM dApp compatibility
  if (!w.ethereum) {
    Object.defineProperty(window, 'ethereum', {
      value: egoProvider,
      writable: true,
      configurable: true,
    });
  }

  window.dispatchEvent(new Event('ego#initialized'));
  if (w.ethereum === egoProvider) {
    window.dispatchEvent(new Event('ethereum#initialized'));
  }
})();
