# Offline transaction transport

Ego transactions normally travel over libp2p gossip. Where the internet is
throttled, filtered or absent, they can travel over something else instead: a
LoRa mesh, an HF radio link, a satellite downlink, or a USB stick carried
between two machines.

This is off by default.

```
EGO_SIDEBAND_SPOOL=1
```

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
