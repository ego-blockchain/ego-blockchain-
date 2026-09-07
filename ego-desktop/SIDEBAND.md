# Running without the internet

There are two separate things here, and most people need the first one.

## 1. Local mesh, on hardware you already own

Your laptop has a radio in it: WiFi. Two or more machines on the same WiFi
network find each other over mDNS and dial each other directly, with no router
uplink, no relay and no internet at all. One machine can create the network as a
hotspot; nobody needs an ISP.

Two nodes are enough to finalise blocks. The BFT floor is exactly two, so a pair
of laptops in the same room is a working chain, while a single machine on its
own deliberately halts rather than producing a fork nobody else can reconcile.

By default a node still reaches for the public relay, the bootstrap anchor and
the price oracle. On a cut-off network that is pointless, and on a censored one
it is worse than pointless: those requests identify the machine as running Ego
before it has sent anything. To stop all of it:

```
EGO_OFFLINE=1
```

Peers are then found only by mDNS on the local network, or named explicitly in
`EGO_DIRECT_PEERS`. Nothing is dialled outside it.

The rule is enforced where packets leave, not at each place that builds a peer
list. Every send and every dial checks the address, and anything that is not a
private range is refused: `127.x`, `10.x`, `192.168.x`, `172.16-31.x`,
`169.254.x` and IPv6 loopback are allowed, while any DNS name and any relay
circuit address is not.

That distinction matters. The first version of this gated the relay and oracle
call sites, and nodes still dialled the public relay, because endpoints also
arrive from peer announcements and cached contacts. One stale circuit address
learned from a peer was enough. A check at the egress point cannot be bypassed
by a path nobody remembered to gate.

Note the corollary: in this mode a node cannot reach the wider network even if
the connection comes back. It is for a machine that should stay local, not a
machine that is temporarily offline.

The limit is range. WiFi reaches tens of metres indoors and a few hundred
outdoors, so this is a building or a street, not a city. That is a property of
the radio in a laptop, not of the software.

## 2. Sideband transports, for when nothing is in WiFi range

Where even a local mesh has nobody to talk to, a transaction can travel over a
LoRa mesh, an HF radio link, a satellite downlink, or a USB stick carried
between two machines. This needs hardware, and it is off by default.

```
EGO_SIDEBAND_SPOOL=1
```

Note what this does and does not do. It carries a **signed transaction** to
somebody who can reach the network. It does not carry consensus: an isolated
node cannot mine, because it cannot reach quorum alone. So a transaction sent
this way waits in a mempool until it arrives somewhere connected. Two people who
are both cut off cannot settle between themselves over radio, but they can over
the local mesh in part 1.

## Why this is safe to accept from a stranger

A transaction authenticates itself. Every frame that arrives is reassembled and
then handed to `verify_incoming_tx`, the same validation gossip uses. Signature,
nonce, balance and fee are all checked before anything enters the mempool.

An untrusted relay can therefore **drop** your transaction or **delay** it. It
cannot forge one, alter one, or replay an old one. That is what makes it
acceptable for a transaction to spend three hours crossing an HF hop and arrive
via a radio operator you have never met.

## How it moves

`%APPDATA%/EgoDesktop/sideband/`

```
inbox/    frames arriving from the outside, consumed and deleted
outbox/   frames waiting to be transmitted
```

A frame is a small JSON file. A signed Ego transaction is roughly 4 KB, most of
it the Dilithium public key and signature, so it does not fit in a single LoRa
or APRS frame. Transactions are split into 200-byte chunks with a CRC over the
whole message, and reassembled at the far end. Frames may arrive out of order.
Missing frames are tracked so a peer can be asked for just the gaps.

Anything that can move files between two `sideband` directories is a valid
transport. A USB stick needs no code at all.

## Losing frames

A transaction is 21 frames. If any one of them is lost the whole thing silently
never reassembles, which on a link bad enough to need a sync word is not a rare
event.

So the receiver notices. A partial message that has heard nothing for two
minutes is assumed to be missing frames rather than merely slow, and the
receiver sends back a repeat request naming exactly the sequence numbers it
lacks. The sender keeps its frames for an hour and serves only those, so a
transaction that lost three frames costs three frames to repair rather than
another 21.

It gives up after three attempts. A message that cannot be completed expires on
its own rather than being chased forever.

The answering side is capped too, and for a reason that matters more than
bandwidth. A repeat request is a few bytes; the answer can be twenty frames.
Answering means keying the transmitter, and on these links transmitting is what
gets a person located. An unbounded responder would let anyone within earshot
make your radio transmit on demand. So a given message is repaired at most six
times, after which further requests for it are ignored.

Two minutes is deliberately patient. Asking sooner spends the little bandwidth
there is on frames that were already on their way.

**This needs a link you can transmit on.** A receive-only station cannot ask for
anything. Where the far side cannot answer, the sending bridge should transmit
each frame more than once instead:

```
python sideband-bridge.py --port COM3 --repeat 3
```

That is the only defence against loss a one-way link has. Duplicates cost the
receiver nothing, since a frame it already holds simply overwrites itself.

## Bridging to real hardware

`sideband-bridge.py` reads and writes the spool over a serial port, for a LoRa
module, a KISS TNC, or an SDR with a soundcard modem.

```
python sideband-bridge.py --port COM3 --baud 9600
python sideband-bridge.py --port /dev/ttyUSB0 --receive-only
```

`--receive-only` never transmits. Use it for a satellite downlink, and read the
next section before using anything else.

On the wire each frame is a sync word, a length, a CRC32, then the payload. The
sync word exists because a radio link drops bytes and a bare length prefix
cannot recover from that: one lost byte shifts every length field after it and
the stream never recovers. The receiver hunts for the sync word instead, and the
CRC throws away anything that survives a false match.

Check the framing without any hardware:

```
python sideband-bridge.py --self-test
```

That covers frames split across reads, leading noise, a dropped byte mid-stream,
a corrupted payload, a sync word occurring inside a payload, and buffer growth
under pure noise.

`--loopback` goes further and feeds your own outbox back into your own inbox
through the real wire format, which exercises the spool plumbing end to end. It
is not a network; frames return to the node that sent them.

**No part of this has been tested against real radio hardware.** The framing,
reassembly and ingest are covered by tests. Whether a given LoRa module or TNC
passes these bytes through unmodified at your chosen baud rate is not something
the tests can tell you.

## Before you transmit

Receiving is passive and undetectable. **Transmitting is not.**

Note that repair makes a receiving node transmit: asking for a lost frame is
itself a transmission. If you are running receive-only this never happens, and
lost frames simply cost you the transaction.

A transmitter can be located by direction finding, usually to a building and
sometimes to a room. If you are in a place where using this at all is the reason
you need it, that risk is the whole problem, and it is not one the software can
solve for you.

Run receive-only, and hand outbound transactions to someone else or move them
physically on a USB stick through the same spool directory. Both work with no
transmitter of your own.

Separately, transmitting on most of these bands requires a licence in most
countries, and the frequency, power and duty cycle that are legal vary. That is
your responsibility, not the software's.

## Timing

A transaction handed to a sideband transport stays valid for **24 hours**
(`MAX_SIDEBAND_TX_AGE_SECS`), rather than the 30 minutes an internet transaction
gets. Nonce sequencing, not the clock, is what prevents replay.

If your wallet has been offline long enough that the account nonce has moved on
without you, the transaction will be rejected on arrival as invalid. Sending
from one wallet on two devices at once will do this.

There is no way for the far end to tell you, because a one-way link has no
return path. The wallet therefore warns you **before** signing, once its view of
the chain is more than an hour old, and names the transaction number it is about
to use. If you have been genuinely offline and this is your only device, that
number is correct and you can send. A node that rejects a transaction for this
reason logs it as a stale view rather than as a bad transaction, so whoever
operates the receiving end can tell the difference and pass word back.

## When it is used

Automatically, when a transaction is submitted and no internet peer is
reachable. A sideband link carries a few hundred bytes per second at best, so
nothing is mirrored onto it while gossip is working.

If you believe your connection is censored rather than absent, so gossip appears
to succeed but nothing ever confirms, the wallet offers **Also send over radio**
on a submitted transaction to push it out by hand.
