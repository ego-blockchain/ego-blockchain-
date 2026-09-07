#!/usr/bin/env python3
"""
Bridge the Ego sideband spool to any radio.

The node never talks to hardware. It writes frames to sideband/outbox/ and reads
them from sideband/inbox/. This script is the only piece that knows what carries
them, so supporting a new radio means editing the framing here, not touching the
node.

Works with anything exposing a serial port: LoRa modules (RYLR896, E32), KISS
TNCs for VHF packet, HF modems, or an SDR frontend.

    pip install pyserial
    python sideband-bridge.py --port COM5 --baud 9600

For a receive-only satellite downlink, pass --receive-only so nothing is
transmitted. On an HF link where transmitting is a physical risk, that flag is
the difference between listening and being locatable.

To exercise the framing without any hardware:

    python sideband-bridge.py --self-test
    python sideband-bridge.py --loopback
"""

import argparse
import binascii
import os
import pathlib
import sys
import time

try:
    import serial  # type: ignore
except ImportError:
    serial = None

FRAME_SUFFIX = ".frame"
POLL_SECONDS = 0.5

# A radio link loses bytes. A bare length prefix cannot recover from that: one
# dropped byte shifts every subsequent length field and the stream stays garbage
# from then on, permanently. So each frame is introduced by a sync word the
# receiver can hunt for, and carries a CRC so a frame that survives a false sync
# is discarded rather than handed to the node.
SYNC = b"\xE6\x07\xA5\x5A"
HEADER_LEN = len(SYNC) + 2 + 4
MAX_FRAME = 4096


def spool_root() -> pathlib.Path:
    if os.name == "nt":
        base = pathlib.Path(os.environ["APPDATA"]) / "EgoDesktop"
    elif sys.platform == "darwin":
        base = pathlib.Path.home() / "Library" / "Application Support" / "EgoDesktop"
    else:
        base = pathlib.Path.home() / ".local" / "share" / "EgoDesktop"
    return pathlib.Path(os.environ.get("EGO_DATA_DIR", base)) / "sideband"


def encode_frame(payload: bytes) -> bytes:
    if not payload or len(payload) > MAX_FRAME:
        raise ValueError("payload of %d bytes is out of range" % len(payload))
    crc = binascii.crc32(payload) & 0xFFFFFFFF
    return SYNC + len(payload).to_bytes(2, "big") + crc.to_bytes(4, "big") + payload


class FrameReader:
    """Turns a lossy byte stream back into whole frames.

    Holds a buffer, hunts for the sync word, and drops what precedes it. A frame
    whose CRC does not match is discarded and the hunt resumes one byte past the
    bad sync, so a sync word appearing inside a payload cannot wedge the stream.
    """

    def __init__(self) -> None:
        self.buf = bytearray()
        self.dropped = 0

    def feed(self, chunk: bytes) -> None:
        self.buf.extend(chunk)
        # Bound the buffer so a stream of noise cannot exhaust memory.
        limit = (MAX_FRAME + HEADER_LEN) * 4
        if len(self.buf) > limit:
            self.dropped += len(self.buf) - limit
            del self.buf[: len(self.buf) - limit]

    def frames(self):
        while True:
            start = self.buf.find(SYNC)
            if start < 0:
                # Keep only a possible partial sync word at the tail.
                if len(self.buf) > len(SYNC):
                    self.dropped += len(self.buf) - len(SYNC)
                    del self.buf[: -len(SYNC)]
                return
            if start > 0:
                self.dropped += start
                del self.buf[:start]
            if len(self.buf) < HEADER_LEN:
                return

            length = int.from_bytes(self.buf[len(SYNC):len(SYNC) + 2], "big")
            crc = int.from_bytes(self.buf[len(SYNC) + 2:HEADER_LEN], "big")
            if length == 0 or length > MAX_FRAME:
                del self.buf[:1]
                self.dropped += 1
                continue
            if len(self.buf) < HEADER_LEN + length:
                return

            payload = bytes(self.buf[HEADER_LEN:HEADER_LEN + length])
            if (binascii.crc32(payload) & 0xFFFFFFFF) == crc:
                del self.buf[: HEADER_LEN + length]
                yield payload
            else:
                # False sync, or a corrupted frame. Either way resume the hunt
                # past this sync word rather than trusting its length field.
                del self.buf[:1]
                self.dropped += 1


def write_inbox(inbox: pathlib.Path, payload: bytes, seq: int) -> None:
    """Write beside the target then rename, so the node never reads a
    half-written frame."""
    tmp = inbox / ("rx-%08d%s.tmp" % (seq, FRAME_SUFFIX))
    tmp.write_bytes(payload)
    tmp.rename(inbox / ("rx-%08d%s" % (seq, FRAME_SUFFIX)))


def self_test() -> int:
    """Exercise the framing against the failures a radio link actually produces."""
    failures = []

    def check(name, ok):
        print(("  ok    " if ok else "  FAIL  ") + name)
        if not ok:
            failures.append(name)

    r = FrameReader()
    r.feed(encode_frame(b"hello") + encode_frame(b"world"))
    check("two frames back to back", list(r.frames()) == [b"hello", b"world"])

    r = FrameReader()
    wire = encode_frame(b"A" * 200)
    got = []
    for i in range(0, len(wire), 7):
        r.feed(wire[i:i + 7])
        got = list(r.frames())
    check("a frame split across many reads", got == [b"A" * 200])

    r = FrameReader()
    r.feed(b"\x00\x11garbage before the frame" + encode_frame(b"payload"))
    check("leading noise is skipped", list(r.frames()) == [b"payload"])

    r = FrameReader()
    wire = bytearray(encode_frame(b"first frame") + encode_frame(b"second frame"))
    del wire[6]
    r.feed(bytes(wire))
    check("resynchronises after a dropped byte", list(r.frames()) == [b"second frame"])

    r = FrameReader()
    wire = bytearray(encode_frame(b"corrupt me please"))
    wire[-1] ^= 0xFF
    r.feed(bytes(wire) + encode_frame(b"good one"))
    check("a corrupted payload is rejected, the next is not", list(r.frames()) == [b"good one"])

    r = FrameReader()
    inner = SYNC + b" sync word inside the payload"
    r.feed(encode_frame(inner))
    check("a sync word inside a payload is handled", list(r.frames()) == [inner])

    r = FrameReader()
    for _ in range(2000):
        r.feed(b"\xE6\x07\xA5\x5A\xFF\xFF")
        list(r.frames())
    check("noise does not grow the buffer without bound",
          len(r.buf) <= (MAX_FRAME + HEADER_LEN) * 4)

    r = FrameReader()
    r.feed(encode_frame(b"x" * MAX_FRAME))
    check("a maximum size frame round trips", list(r.frames()) == [b"x" * MAX_FRAME])

    r = FrameReader()
    tx = b'{"v":1,"msg_id":42,"seq":0,"total":21,"crc":123,"payload":[1,2,3]}'
    r.feed(encode_frame(tx))
    check("a real sideband frame round trips", list(r.frames()) == [tx])

    print("")
    if failures:
        print("%d check(s) failed" % len(failures))
        return 1
    print("all framing checks passed")
    return 0


def loopback(root: pathlib.Path) -> int:
    """Move the outbox into our own inbox through the real wire format.

    This proves the spool plumbing and the framing end to end with no hardware.
    It is not a network: frames come straight back to the node that sent them.
    """
    inbox, outbox = root / "inbox", root / "outbox"
    inbox.mkdir(parents=True, exist_ok=True)
    outbox.mkdir(parents=True, exist_ok=True)
    print("loopback on %s" % root)
    print("frames written to the outbox are encoded, decoded and delivered to the inbox")

    reader = FrameReader()
    seq = 0
    try:
        while True:
            for path in sorted(outbox.glob("*" + FRAME_SUFFIX)):
                try:
                    reader.feed(encode_frame(path.read_bytes()))
                    path.unlink()
                except Exception as exc:
                    print("loopback failed on %s: %s" % (path.name, exc), file=sys.stderr)
                    break
            for payload in reader.frames():
                seq += 1
                write_inbox(inbox, payload, seq)
                print("looped %d bytes" % len(payload))
            time.sleep(POLL_SECONDS)
    except KeyboardInterrupt:
        print("\nstopped")
        return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", help="serial device, e.g. COM5 or /dev/ttyUSB0")
    ap.add_argument("--baud", type=int, default=9600)
    ap.add_argument("--receive-only", action="store_true",
                    help="never transmit; for satellite downlink or when TX is unsafe")
    ap.add_argument("--self-test", action="store_true",
                    help="check the framing against dropped and corrupted bytes, then exit")
    ap.add_argument("--loopback", action="store_true",
                    help="feed the outbox back into the inbox through the real wire format")
    args = ap.parse_args()

    if args.self_test:
        return self_test()

    root = spool_root()
    if args.loopback:
        return loopback(root)

    if not args.port:
        ap.error("--port is required unless --self-test or --loopback is given")
    if serial is None:
        print("pyserial is required:  pip install pyserial", file=sys.stderr)
        return 1

    inbox, outbox = root / "inbox", root / "outbox"
    inbox.mkdir(parents=True, exist_ok=True)
    outbox.mkdir(parents=True, exist_ok=True)
    print("spool: %s" % root)
    print("radio: %s @ %d%s" % (args.port, args.baud,
                                "  (receive only)" if args.receive_only else ""))

    link = serial.Serial(args.port, args.baud, timeout=0.2)
    reader = FrameReader()
    seq = 0
    last_dropped = 0

    while True:
        if not args.receive_only:
            for path in sorted(outbox.glob("*" + FRAME_SUFFIX)):
                try:
                    body = path.read_bytes()
                    link.write(encode_frame(body))
                    link.flush()
                except Exception as exc:
                    print("tx failed %s: %s" % (path.name, exc), file=sys.stderr)
                    break
                # Only after the bytes are out, so a write that throws leaves the
                # frame in the outbox to be retried.
                path.unlink()
                print("tx %s (%d bytes)" % (path.name, len(body)))

        try:
            chunk = link.read(link.in_waiting or 1)
        except Exception as exc:
            print("rx failed: %s" % exc, file=sys.stderr)
            chunk = b""

        if chunk:
            reader.feed(chunk)
            for payload in reader.frames():
                seq += 1
                write_inbox(inbox, payload, seq)
                print("rx %d bytes" % len(payload))

        if reader.dropped != last_dropped:
            print("resync: discarded %d stray bytes" % (reader.dropped - last_dropped))
            last_dropped = reader.dropped

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())
