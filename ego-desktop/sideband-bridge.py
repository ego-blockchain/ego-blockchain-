#!/usr/bin/env python3
"""
Bridge the Ego sideband spool to any radio.

The node never talks to hardware. It writes frames to sideband/outbox/ and reads
them from sideband/inbox/. This script is the only piece that knows what carries
them, so supporting a new radio means editing two functions here, not touching
the node.

Works with anything exposing a serial port: LoRa modules (RYLR896, E32),
KISS TNCs for VHF packet, HF modems, or an SDR frontend.

    pip install pyserial
    python sideband_bridge_example.py --port COM5 --baud 9600

For a receive-only satellite downlink, pass --receive-only so nothing is
transmitted. On an HF link where transmitting is a physical risk, that flag is
the difference between listening and being locatable.
"""

import argparse
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


def spool_root() -> pathlib.Path:
    if os.name == "nt":
        base = pathlib.Path(os.environ["APPDATA"]) / "EgoDesktop"
    elif sys.platform == "darwin":
        base = pathlib.Path.home() / "Library" / "Application Support" / "EgoDesktop"
    else:
        base = pathlib.Path.home() / ".local" / "share" / "EgoDesktop"
    return pathlib.Path(os.environ.get("EGO_DATA_DIR", base)) / "sideband"


def send_over_radio(link, payload: bytes) -> None:
    """One frame out. Length-prefixed so the far side can find frame boundaries
    in a stream that may drop bytes."""
    link.write(len(payload).to_bytes(2, "big") + payload)
    link.flush()


def read_from_radio(link) -> bytes | None:
    """One frame in, or None if nothing complete is waiting."""
    header = link.read(2)
    if len(header) < 2:
        return None
    length = int.from_bytes(header, "big")
    if length == 0 or length > 4096:
        return None
    body = link.read(length)
    return body if len(body) == length else None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", required=True, help="serial device, e.g. COM5 or /dev/ttyUSB0")
    ap.add_argument("--baud", type=int, default=9600)
    ap.add_argument("--receive-only", action="store_true",
                    help="never transmit; for satellite downlink or when TX is unsafe")
    args = ap.parse_args()

    if serial is None:
        print("pyserial is required:  pip install pyserial", file=sys.stderr)
        return 1

    root = spool_root()
    inbox, outbox = root / "inbox", root / "outbox"
    inbox.mkdir(parents=True, exist_ok=True)
    outbox.mkdir(parents=True, exist_ok=True)
    print(f"spool: {root}")
    print(f"radio: {args.port} @ {args.baud}" + ("  (receive only)" if args.receive_only else ""))

    link = serial.Serial(args.port, args.baud, timeout=1)
    seq = 0

    while True:
        if not args.receive_only:
            for path in sorted(outbox.glob(f"*{FRAME_SUFFIX}")):
                try:
                    send_over_radio(link, path.read_bytes())
                    path.unlink()
                    print(f"tx {path.name}")
                except Exception as exc:
                    print(f"tx failed {path.name}: {exc}", file=sys.stderr)
                    break

        try:
            payload = read_from_radio(link)
        except Exception as exc:
            print(f"rx failed: {exc}", file=sys.stderr)
            payload = None

        if payload:
            seq += 1
            # Write beside the target then rename, so the node never reads a
            # half-written frame.
            tmp = inbox / f"rx-{seq:08d}{FRAME_SUFFIX}.tmp"
            tmp.write_bytes(payload)
            tmp.rename(inbox / f"rx-{seq:08d}{FRAME_SUFFIX}")
            print(f"rx {len(payload)} bytes")

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())
