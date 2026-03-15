/**
 * EGO-25 WalletConnect SDK
 *
 * Connects web dApps to Ego wallets via QR code + encrypted relay.
 * Specification: eips/EGO-25.md
 *
 * Cryptography used:
 *   - Kyber-768 KEM for session key establishment (post-quantum)
 *   - AES-256-GCM for session message encryption
 *   - Ed25519 for transaction signing (handled by the wallet, not this SDK)
 */

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/** An active wallet connection session. */
export interface EgoSession {
  /** 32-byte hex topic that uniquely identifies this session. */
  topic: string;
  /** Wallet account addresses approved for this session. */
  accounts: string[];
  /** Chain ID the session is scoped to. */
  chainId: number;
  /** WebSocket relay URL used for this session. */
  relay: string;
  /** Human-readable dApp name shown to the user. */
  dappName: string;
  /** dApp origin URL. */
  dappUrl: string;
  /** Unix timestamp (seconds) when the session expires. */
  expiresAt: number;
}

/** A signing/send request sent from dApp to wallet. */
export interface EgoRequest {
  /** Unique request identifier within the session. */
  id: number;
  /** RPC method name (e.g., "ego_signTransaction"). */
  method: string;
  /** Method parameters. */
  params: unknown[];
}

/** Successful response returned by the wallet. */
export interface EgoResponse {
  id: number;
  result: unknown;
}

/** Error response returned by the wallet on rejection or failure. */
export interface EgoError {
  id: number;
  /** 4001 = user rejection; 4100 = unauthorized; 4900 = disconnected. */
  code: number;
  message: string;
}

/** Transaction object for ego_signTransaction / ego_sendTransaction. */
export interface EgoTx {
  /** Recipient address in Ego bech32 format. */
  to: string;
  /** Value in uEGOC (1 EGOC = 1,000,000 uEGOC). */
  value: number;
  /** Hex-encoded calldata. Empty string for simple transfers. */
  data: string;
  /** Optional nonce override; wallet fills in automatically if omitted. */
  nonce?: number;
  /** Resource Unit limit for execution. */
  gasLimit?: number;
}

/** Options for initializing EgoWalletConnect. */
export interface EgoWalletConnectOptions {
  /** WebSocket relay URL. Defaults to the public Ego relay. */
  relay?: string;
  /** Session duration in seconds. Defaults to 7 days. */
  sessionTtlSeconds?: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const DEFAULT_RELAY = 'wss://relay.ego-blockchain.io';
const DEFAULT_SESSION_TTL = 7 * 24 * 60 * 60; // 7 days in seconds
const PROTOCOL_VERSION = 'wc1';

// ---------------------------------------------------------------------------
// EgoWalletConnect (dApp-side SDK)
// ---------------------------------------------------------------------------

/**
 * Main class for dApp-side wallet connection.
 *
 * Usage:
 * ```ts
 * const wc = new EgoWalletConnect({ relay: 'wss://relay.ego-blockchain.io' });
 * const { uri, topic } = wc.connect('EgoSwap', 'https://swap.ego-blockchain.io');
 * // Display `uri` as a QR code; wait for session_approve...
 * const accounts = await wc.waitForSession(topic);
 * const result = await wc.request(topic, 'ego_signTransaction', [tx]);
 * ```
 */
export class EgoWalletConnect {
  private relay: string;
  private sessionTtl: number;
  private sessions: Map<string, EgoSession> = new Map();
  private pendingRequests: Map<number, { resolve: (v: unknown) => void; reject: (e: unknown) => void }> = new Map();
  private requestCounter = 0;

  constructor(options: EgoWalletConnectOptions = {}) {
    this.relay = options.relay ?? DEFAULT_RELAY;
    this.sessionTtl = options.sessionTtlSeconds ?? DEFAULT_SESSION_TTL;
  }

  // -------------------------------------------------------------------------
  // Connection
  // -------------------------------------------------------------------------

  /**
   * Generate a QR code URI for wallet connection.
   *
   * The returned `uri` should be displayed as a QR code. The wallet scans it,
   * connects to the relay, and sends a `session_propose` message. Call
   * `waitForSession(topic)` to await approval.
   *
   * @param dappName  Human-readable name shown to the user in the wallet.
   * @param dappUrl   URL of the dApp (for display only).
   * @returns         `{ uri, topic }` — show `uri` as QR; use `topic` to track the session.
   */
  connect(dappName: string, dappUrl: string): { uri: string; topic: string } {
    const topicBytes = crypto.getRandomValues(new Uint8Array(32));
    const topic = bytesToHex(topicBytes);
    const relayB64 = btoa(this.relay);

    // In production, dApp would generate a real Kyber-768 key pair here and
    // include the public key in the URI. The stub omits the real KEM.
    const dappPubkeyHex = bytesToHex(crypto.getRandomValues(new Uint8Array(32))); // placeholder

    const uri = `ego:${PROTOCOL_VERSION}:${topic}:${relayB64}:${dappPubkeyHex}`;

    // Store minimal pending session metadata so we can populate it on approval.
    this.sessions.set(topic, {
      topic,
      accounts: [],
      chainId: 1,
      relay: this.relay,
      dappName,
      dappUrl,
      expiresAt: Math.floor(Date.now() / 1000) + this.sessionTtl,
    });

    return { uri, topic };
  }

  /**
   * Wait for a wallet to approve a session proposal.
   *
   * Resolves with the approved account list when `session_approve` arrives.
   * Rejects if `session_reject` arrives or the timeout expires.
   *
   * NOTE: In this stub implementation, connection to the relay WebSocket is
   * simulated. A production implementation would open a real WebSocket
   * connection, subscribe to `topic`, and handle incoming messages.
   *
   * @param topic    The session topic returned by `connect()`.
   * @param timeoutMs  How long to wait before giving up (default 120s).
   */
  async waitForSession(topic: string, timeoutMs = 120_000): Promise<string[]> {
    const session = this.sessions.get(topic);
    if (!session) {
      throw new Error(`No pending session for topic: ${topic}`);
    }

    // Stub: in production this would subscribe to the relay WebSocket and
    // resolve when a session_approve message arrives.
    console.log(`[EgoWC] Waiting for wallet approval on topic ${topic.slice(0, 8)}...`);
    console.log(`[EgoWC] QR relay: ${this.relay} | timeout: ${timeoutMs}ms`);

    // Production implementation outline:
    // 1. Open WebSocket to `this.relay`
    // 2. Send: { type: "subscribe", topic }
    // 3. Wait for: { type: "message", topic, message: <encrypted session_approve> }
    // 4. Decrypt with session_key (derived from Kyber KEM)
    // 5. Parse session_approve → update session.accounts, session.chainId
    // 6. Resolve with accounts

    return session.accounts;
  }

  // -------------------------------------------------------------------------
  // RPC Requests
  // -------------------------------------------------------------------------

  /**
   * Send a JSON-RPC request to the connected wallet and await the response.
   *
   * @param topic   Session topic identifying which wallet to send to.
   * @param method  RPC method (e.g., `"ego_signTransaction"`).
   * @param params  Method parameters.
   * @returns       The `result` field from the wallet's `ego_response`.
   *
   * @throws        If the wallet returns `ego_error` or the session is not found.
   */
  async request(topic: string, method: string, params: unknown[]): Promise<unknown> {
    const session = this.sessions.get(topic);
    if (!session) {
      throw new Error(`No active session for topic: ${topic}`);
    }
    if (Date.now() / 1000 > session.expiresAt) {
      this.sessions.delete(topic);
      throw new Error(`Session expired for topic: ${topic}`);
    }

    const id = ++this.requestCounter;
    const request: EgoRequest = { id, method, params };

    // In production: encrypt `request` with session_key (AES-256-GCM),
    // publish to relay on `topic`, and await the matching ego_response/ego_error.
    console.log(`[EgoWC] → ${method} (id=${id})`, JSON.stringify(params));

    // Stub: return null for all methods.
    // Production implementation would:
    // 1. Serialise request to JSON
    // 2. Encrypt with AES-256-GCM (session_key)
    // 3. Publish to relay: { type: "publish", topic, message: <nonce_hex + ciphertext_hex> }
    // 4. Wait for ego_response / ego_error with matching id
    // 5. Decrypt and return result or throw EgoError
    return null;
  }

  /** Convenience: request the wallet's account addresses. */
  async getAccounts(topic: string): Promise<string[]> {
    const result = await this.request(topic, 'ego_getAccounts', []);
    return result as string[];
  }

  /** Convenience: ask the wallet to sign a transaction (does NOT broadcast). */
  async signTransaction(topic: string, tx: EgoTx): Promise<string> {
    const result = await this.request(topic, 'ego_signTransaction', [tx]);
    return (result as { signature_hex: string }).signature_hex;
  }

  /** Convenience: ask the wallet to sign and broadcast a transaction. */
  async sendTransaction(topic: string, tx: EgoTx): Promise<string> {
    const result = await this.request(topic, 'ego_sendTransaction', [tx]);
    return (result as { tx_hash: string }).tx_hash;
  }

  /**
   * Sign a message (raw bytes or EGO-17 typed data).
   *
   * @param message  Hex string of the message bytes, or an EGO-17 typed data object.
   */
  async signMessage(topic: string, message: string | Record<string, unknown>): Promise<string> {
    const result = await this.request(topic, 'ego_signMessage', [message]);
    return (result as { signature_hex: string }).signature_hex;
  }

  /** Ask the wallet to switch to a different chain. */
  async switchChain(topic: string, chainId: number): Promise<boolean> {
    const result = await this.request(topic, 'ego_switchChain', [chainId]);
    return (result as { success: boolean }).success;
  }

  // -------------------------------------------------------------------------
  // Session management
  // -------------------------------------------------------------------------

  /** Disconnect and remove a session. */
  disconnect(topic: string): void {
    if (!this.sessions.has(topic)) return;
    this.sessions.delete(topic);
    // In production: publish a session_delete message to the relay so the
    // wallet can clean up its side.
    console.log(`[EgoWC] Disconnected topic ${topic.slice(0, 8)}...`);
  }

  /** Return all active (non-expired) sessions. */
  getSessions(): EgoSession[] {
    const now = Math.floor(Date.now() / 1000);
    const active: EgoSession[] = [];
    for (const [topic, session] of this.sessions) {
      if (session.expiresAt > now) {
        active.push(session);
      } else {
        this.sessions.delete(topic); // lazy cleanup
      }
    }
    return active;
  }

  /** Return a single session by topic, or undefined if not found / expired. */
  getSession(topic: string): EgoSession | undefined {
    const session = this.sessions.get(topic);
    if (!session) return undefined;
    if (Math.floor(Date.now() / 1000) > session.expiresAt) {
      this.sessions.delete(topic);
      return undefined;
    }
    return session;
  }

  /** Disconnect all active sessions. */
  disconnectAll(): void {
    for (const topic of this.sessions.keys()) {
      this.disconnect(topic);
    }
  }
}

// ---------------------------------------------------------------------------
// EgoWalletPairing (wallet-side SDK)
// ---------------------------------------------------------------------------

/**
 * Wallet-side counterpart to EgoWalletConnect.
 *
 * The wallet application uses this class to:
 * 1. Parse a `ego:wc1:...` URI scanned from a QR code.
 * 2. Establish the encrypted session with the dApp.
 * 3. Receive and respond to signing requests.
 *
 * This is a skeleton implementation; the real implementation lives in the
 * Rust crate `crates/ego-walletconnect/` for the Ego Desktop wallet.
 */
export class EgoWalletPairing {
  private activeSessions: Map<string, EgoSession> = new Map();
  private requestHandler?: (req: EgoRequest, topic: string) => Promise<unknown>;

  /**
   * Parse a `ego:wc1:...` URI and extract connection parameters.
   *
   * @param uri  The URI string from the QR code.
   * @returns    Parsed connection parameters.
   * @throws     If the URI is malformed or uses an unsupported version.
   */
  static parseUri(uri: string): { topic: string; relay: string; dappPubkeyHex: string } {
    if (!uri.startsWith('ego:wc1:')) {
      throw new Error(`Unsupported URI scheme: expected ego:wc1:, got: ${uri.slice(0, 16)}`);
    }
    const parts = uri.slice('ego:wc1:'.length).split(':');
    if (parts.length < 3) {
      throw new Error('Malformed ego:wc1 URI — expected topic:relay_b64:pubkey');
    }
    const [topic, relayB64, dappPubkeyHex] = parts;
    let relay: string;
    try {
      relay = atob(relayB64);
    } catch {
      throw new Error('Malformed relay URL in QR code (invalid base64)');
    }
    return { topic, relay, dappPubkeyHex };
  }

  /**
   * Register a handler that is called whenever the dApp sends a request.
   *
   * The handler receives the request and the topic, and must return the result
   * or throw to send an error response.
   *
   * @param handler  Async function: `(req, topic) => result`
   */
  onRequest(handler: (req: EgoRequest, topic: string) => Promise<unknown>): void {
    this.requestHandler = handler;
  }

  /**
   * Pair with a dApp by processing a scanned `ego:wc1:...` URI.
   *
   * In production this would:
   * 1. Parse the URI.
   * 2. Connect to the relay WebSocket.
   * 3. Run Kyber KEM to derive the session key.
   * 4. Send `session_propose`.
   * 5. Await `session_approve`.
   * 6. Begin listening for requests.
   *
   * @param uri       URI from the QR code.
   * @param accounts  Wallet accounts to expose to the dApp.
   * @param chainId   Chain ID for this session.
   * @returns         The established session.
   */
  async pair(uri: string, accounts: string[], chainId = 1): Promise<EgoSession> {
    const { topic, relay, dappPubkeyHex: _dappPubkeyHex } = EgoWalletPairing.parseUri(uri);

    console.log(`[EgoWallet] Pairing with topic ${topic.slice(0, 8)}... via ${relay}`);

    // Stub session — production would complete Kyber KEM and await dApp approval.
    const session: EgoSession = {
      topic,
      accounts,
      chainId,
      relay,
      dappName: 'Unknown dApp',
      dappUrl: '',
      expiresAt: Math.floor(Date.now() / 1000) + DEFAULT_SESSION_TTL,
    };

    this.activeSessions.set(topic, session);
    return session;
  }

  /** Reject an incoming signing request. */
  async reject(topic: string, requestId: number, reason = 'User rejected'): Promise<void> {
    const error: EgoError = { id: requestId, code: 4001, message: reason };
    // In production: encrypt and publish ego_error to relay on `topic`.
    console.log(`[EgoWallet] Rejected request ${requestId} on topic ${topic.slice(0, 8)}:`, reason);
    void error; // suppress unused warning in stub
  }

  /** Return all active sessions known to this wallet instance. */
  getSessions(): EgoSession[] {
    return Array.from(this.activeSessions.values());
  }

  /** Terminate a session from the wallet side. */
  disconnect(topic: string): void {
    this.activeSessions.delete(topic);
    console.log(`[EgoWallet] Disconnected topic ${topic.slice(0, 8)}...`);
  }
}

// ---------------------------------------------------------------------------
// Utility helpers
// ---------------------------------------------------------------------------

/** Encode a Uint8Array to a lowercase hex string. */
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

/** Decode a hex string to a Uint8Array. */
export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('Odd-length hex string');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// Default export
// ---------------------------------------------------------------------------

export default EgoWalletConnect;
