import { connect, connectAny, listGateways, webrtcAddress } from '../src/index.js'

const args = process.argv.slice(2)
const versionFlag = args.find((a) => a.startsWith('--v'))
const dialerVersion = versionFlag ? Number(versionFlag.slice(3)) : undefined
const [endpoint, certSha256] = args.filter((a) => !a.startsWith('--'))

const started = Date.now()
const client = endpoint
  ? await connect({ endpoint, cert_sha256: certSha256 }, { dialerVersion })
  : await connectAny(await listGateways(), { dialerVersion })
console.log(`connected${dialerVersion ? ` as WebRTC Direct v${dialerVersion}` : ''} to ${client.address} in ${Date.now() - started} ms`)

const listed = await client.call('gateway.list')
console.log(`gateway.list: ${listed.gateways.length} gateway(s)`)

const again = await Promise.all([client.call('gateway.list'), client.call('gateway.list')])
console.log(`two queued calls on one stream: ${again.map((r) => r.gateways.length).join(', ')}`)

try {
  await client.call('no.such.method')
} catch (e) {
  console.log(`unknown method refused: ${e.code} ${e.message}`)
}

if (endpoint) {
  console.log(`address derived from the list entry: ${webrtcAddress({ endpoint, cert_sha256: certSha256 })}`)
}
await client.close()
console.log('ok')
