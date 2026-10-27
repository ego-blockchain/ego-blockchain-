import { createLibp2p } from 'libp2p'
import { webRTCDirect } from '@libp2p/webrtc'
import { multiaddr } from '@multiformats/multiaddr'

export const PROTOCOL = '/ego/rpc/1'
export const GATEWAY_LIST = 'https://rpc.egoblockchain.com/gateways'

const SHA2_256 = 0x12
const DIGEST_BYTES = 32

function hexBytes(hex) {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}

function base64url(bytes) {
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function webrtcAddress(gateway) {
  const m = /^https:\/\/(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})\/rpc$/.exec(gateway?.endpoint ?? '')
  if (!m || !/^[0-9a-f]{64}$/.test(gateway?.cert_sha256 ?? '')) {
    throw new Error('That is not an entry from the Ego gateway list.')
  }
  const multihash = new Uint8Array(2 + DIGEST_BYTES)
  multihash[0] = SHA2_256
  multihash[1] = DIGEST_BYTES
  multihash.set(hexBytes(gateway.cert_sha256), 2)
  return `/ip4/${m[1]}/udp/${m[2]}/webrtc-direct/certhash/u${base64url(multihash)}`
}

export async function listGateways(url = GATEWAY_LIST) {
  const res = await fetch(url)
  if (!res.ok) throw new Error(`The gateway list answered ${res.status}.`)
  const body = await res.json()
  return Array.isArray(body) ? body : body.gateways ?? []
}

function frameReader(stream) {
  const chunks = stream[Symbol.asyncIterator]()
  let buffered = new Uint8Array(0)
  return async function read(n) {
    while (buffered.length < n) {
      const { value, done } = await chunks.next()
      if (done) throw new Error('The gateway closed the connection.')
      const chunk = value instanceof Uint8Array ? value : value.subarray()
      const joined = new Uint8Array(buffered.length + chunk.length)
      joined.set(buffered)
      joined.set(chunk, buffered.length)
      buffered = joined
    }
    const out = buffered.slice(0, n)
    buffered = buffered.slice(n)
    return out
  }
}

export async function connect(target, { timeoutMs = 15000, dialerVersion } = {}) {
  const address = typeof target === 'string' ? target : webrtcAddress(target)
  const node = await createLibp2p({
    transports: [webRTCDirect(dialerVersion ? { dialerVersion } : {})],
    connectionGater: { denyDialMultiaddr: () => false }
  })
  let stream
  try {
    stream = await node.dialProtocol(multiaddr(address), PROTOCOL, { signal: AbortSignal.timeout(timeoutMs) })
  } catch (e) {
    await node.stop()
    throw new Error(`Could not reach the gateway over WebRTC (${e.message}).`)
  }
  const read = frameReader(stream)
  const encoder = new TextEncoder()
  const decoder = new TextDecoder()
  let nextId = 0
  let queue = Promise.resolve()

  async function exchange(method, params) {
    const body = encoder.encode(JSON.stringify({ jsonrpc: '2.0', id: ++nextId, method, params }))
    const frame = new Uint8Array(4 + body.length)
    new DataView(frame.buffer).setUint32(0, body.length)
    frame.set(body, 4)
    if (!stream.send(frame)) await stream.onDrain()
    const length = new DataView((await read(4)).buffer).getUint32(0)
    const reply = JSON.parse(decoder.decode(await read(length)))
    if (reply.error) throw Object.assign(new Error(reply.error.message), { code: reply.error.code })
    return reply.result
  }

  return {
    address,
    call(method, params = {}) {
      const result = queue.then(() => exchange(method, params))
      queue = result.catch(() => {})
      return result
    },
    async close() {
      await stream.close().catch(() => {})
      await node.stop()
    }
  }
}

export async function connectAny(gateways, options) {
  const errors = []
  for (const g of gateways) {
    try {
      return await connect(g, options)
    } catch (e) {
      errors.push(`${g.endpoint}: ${e.message}`)
    }
  }
  throw new Error(`No gateway answered over WebRTC.\n${errors.join('\n')}`)
}
