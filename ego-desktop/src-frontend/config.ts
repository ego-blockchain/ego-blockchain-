export const RELAY_P2P       = '/dns4/EgoRelay.egoblockchain.com/tcp/4001/p2p/12D3KooWPj6m7jzmVyMh1zWrsoux3YiVs9j2HwsjrFXzDcqAGGz4';
export const RPC_URL         = 'https://rpc.egoblockchain.com';
export const EXPLORER_URL    = 'https://egoblockchain.com/egoscan';
export const txUrl = (hash: string, height?: number | null) =>
  `${EXPLORER_URL}?tx=${encodeURIComponent(hash)}${height != null ? `&h=${height}` : ''}`;
export const blockUrl = (height: number) => `${EXPLORER_URL}?block=${height}`;
export const addressUrl = (address: string) => `${EXPLORER_URL}?address=${encodeURIComponent(address)}`;
export const searchUrl = (q: string) => `${EXPLORER_URL}?q=${encodeURIComponent(q)}`;
export const BOOTSTRAP_PEER  = '/dns4/rpc.egoblockchain.com/tcp/9000/p2p/12D3KooWMNRh7dJePAgtaZiwFCTisevVJQ5E52SpPqQqUPbHpJ72';
