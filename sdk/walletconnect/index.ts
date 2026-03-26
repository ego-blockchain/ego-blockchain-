export interface EgoSession {

  topic: string;

  accounts: string[];

  chainId: number;

  relay: string;

  dappName: string;

  dappUrl: string;

  expiresAt: number;
}

export interface EgoRequest {

  id: number;

  method: string;

  params: unknown[];
}

export interface EgoResponse {
  id: number;
  result: unknown;
}

export interface EgoError {
  id: number;

  code: number;
  message: string;
}

export interface EgoTx {

  to: string;

  value: number;

  data: string;

  nonce?: number;

  gasLimit?: number;
}

export interface EgoWalletConnectOptions {

  relay?: string;

  sessionTtlSeconds?: number;
}

const DEFAULT_RELAY = 'wss://relay.ego-blockchain.io';
const DEFAULT_SESSION_TTL = 7 * 24 * 60 * 60;
const PROTOCOL_VERSION = 'wc1';

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

  connect(dappName: string, dappUrl: string): { uri: string; topic: string } {
    const topicBytes = crypto.getRandomValues(new Uint8Array(32));
    const topic = bytesToHex(topicBytes);
    const relayB64 = btoa(this.relay);

    const dappPubkeyHex = bytesToHex(crypto.getRandomValues(new Uint8Array(32)));

    const uri = `ego:${PROTOCOL_VERSION}:${topic}:${relayB64}:${dappPubkeyHex}`;

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

  async waitForSession(topic: string, timeoutMs = 120_000): Promise<string[]> {
    const session = this.sessions.get(topic);
    if (!session) {
      throw new Error(`No pending session for topic: ${topic}`);
    }

    console.log(`[EgoWC] Waiting for wallet approval on topic ${topic.slice(0, 8)}...`);
    console.log(`[EgoWC] QR relay: ${this.relay} | timeout: ${timeoutMs}ms`);

    return session.accounts;
  }

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

    console.log(`[EgoWC] → ${method} (id=${id})`, JSON.stringify(params));

    return null;
  }

  async getAccounts(topic: string): Promise<string[]> {
    const result = await this.request(topic, 'ego_getAccounts', []);
    return result as string[];
  }

  async signTransaction(topic: string, tx: EgoTx): Promise<string> {
    const result = await this.request(topic, 'ego_signTransaction', [tx]);
    return (result as { signature_hex: string }).signature_hex;
  }

  async sendTransaction(topic: string, tx: EgoTx): Promise<string> {
    const result = await this.request(topic, 'ego_sendTransaction', [tx]);
    return (result as { tx_hash: string }).tx_hash;
  }

  async signMessage(topic: string, message: string | Record<string, unknown>): Promise<string> {
    const result = await this.request(topic, 'ego_signMessage', [message]);
    return (result as { signature_hex: string }).signature_hex;
  }

  async switchChain(topic: string, chainId: number): Promise<boolean> {
    const result = await this.request(topic, 'ego_switchChain', [chainId]);
    return (result as { success: boolean }).success;
  }

  disconnect(topic: string): void {
    if (!this.sessions.has(topic)) return;
    this.sessions.delete(topic);

    console.log(`[EgoWC] Disconnected topic ${topic.slice(0, 8)}...`);
  }

  getSessions(): EgoSession[] {
    const now = Math.floor(Date.now() / 1000);
    const active: EgoSession[] = [];
    for (const [topic, session] of this.sessions) {
      if (session.expiresAt > now) {
        active.push(session);
      } else {
        this.sessions.delete(topic);
      }
    }
    return active;
  }

  getSession(topic: string): EgoSession | undefined {
    const session = this.sessions.get(topic);
    if (!session) return undefined;
    if (Math.floor(Date.now() / 1000) > session.expiresAt) {
      this.sessions.delete(topic);
      return undefined;
    }
    return session;
  }

  disconnectAll(): void {
    for (const topic of this.sessions.keys()) {
      this.disconnect(topic);
    }
  }
}

export class EgoWalletPairing {
  private activeSessions: Map<string, EgoSession> = new Map();
  private requestHandler?: (req: EgoRequest, topic: string) => Promise<unknown>;

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

  onRequest(handler: (req: EgoRequest, topic: string) => Promise<unknown>): void {
    this.requestHandler = handler;
  }

  async pair(uri: string, accounts: string[], chainId = 1): Promise<EgoSession> {
    const { topic, relay, dappPubkeyHex: _dappPubkeyHex } = EgoWalletPairing.parseUri(uri);

    console.log(`[EgoWallet] Pairing with topic ${topic.slice(0, 8)}... via ${relay}`);

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

  async reject(topic: string, requestId: number, reason = 'User rejected'): Promise<void> {
    const error: EgoError = { id: requestId, code: 4001, message: reason };

    console.log(`[EgoWallet] Rejected request ${requestId} on topic ${topic.slice(0, 8)}:`, reason);
    void error;
  }

  getSessions(): EgoSession[] {
    return Array.from(this.activeSessions.values());
  }

  disconnect(topic: string): void {
    this.activeSessions.delete(topic);
    console.log(`[EgoWallet] Disconnected topic ${topic.slice(0, 8)}...`);
  }
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join('');
}

export function hexToBytes(hex: string): Uint8Array {
  if (hex.length % 2 !== 0) throw new Error('Odd-length hex string');
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  }
  return bytes;
}

export default EgoWalletConnect;
