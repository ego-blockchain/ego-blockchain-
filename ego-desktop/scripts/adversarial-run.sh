#!/usr/bin/env bash
#
# Run a small testnet with one deliberately dishonest validator in it.
#
# Every defence in consensus is written against an attacker nobody has ever
# run. This starts N honest nodes and one that cheats in a named way, then
# checks the two things that matter: the honest nodes refuse what the attacker
# sends, and they keep making blocks without it.
#
#   ./adversarial-run.sh                        # sweep every behaviour
#   ./adversarial-run.sh tamper-merkle-root     # just one
#   HONEST=4 SECONDS=180 ./adversarial-run.sh   # bigger, longer
#
# Behaviours: tamper-merkle-root, inflate-coinbase, forge-system-transfer,
# forge-signature, equivocate, double-vote, withhold-votes, malformed-gossip.
#
# Each node gets its own data directory under a scratch root, so this never
# touches a real wallet or chain. The scratch root is wiped at the start of
# every run.
#
# What a pass means: the honest nodes logged a rejection of the attacker's
# work, and their chain height rose while the attacker was running. What a
# failure means: either they accepted something they should not have, or they
# stopped making progress because of it. Both are findings.

set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
SCRATCH="${SCRATCH:-${TMPDIR:-/tmp}/ego-adversarial}"
HONEST="${HONEST:-3}"
SECONDS_PER_CASE="${SECONDS:-90}"
BASE_PORT="${BASE_PORT:-47600}"

ALL_BEHAVIOURS=(
  tamper-merkle-root
  inflate-coinbase
  forge-system-transfer
  forge-signature
  equivocate
  double-vote
  withhold-votes
  malformed-gossip
)

if [ $# -gt 0 ]; then
  BEHAVIOURS=("$@")
else
  BEHAVIOURS=("${ALL_BEHAVIOURS[@]}")
fi

BIN="$ROOT/src-tauri/target/release/ego-desktop"
[ -x "$BIN" ] || BIN="$ROOT/src-tauri/target/release/ego-desktop.exe"
[ -x "$BIN" ] || BIN="$ROOT/src-tauri/target/debug/ego-desktop"
[ -x "$BIN" ] || BIN="$ROOT/src-tauri/target/debug/ego-desktop.exe"

if [ ! -x "$BIN" ]; then
  echo "No ego-desktop binary. Build one first:"
  echo "  (cd '$ROOT/src-tauri' && cargo build --release)"
  exit 1
fi
echo "binary:  $BIN"
echo "scratch: $SCRATCH"
echo "honest:  $HONEST"
echo

PIDS=()

stop_all() {
  for pid in "${PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" 2>/dev/null
  done
  PIDS=()
  wait 2>/dev/null
}
trap 'stop_all; exit 130' INT TERM

# Start one node. $1 is its name, $2 its EGO_ADVERSARY value (empty = honest).
start_node() {
  local name="$1" adversary="${2:-}" dir="$SCRATCH/$name"
  mkdir -p "$dir"
  (
    export EGO_DATA_DIR="$dir"
    export EGO_INVARIANTS=strict      # a violation must stop the node loudly
    export EGO_SHIELDED_POOL_HEIGHT=0 # exercise the shielded rules too
    export RUST_LOG="${RUST_LOG:-ego_desktop=info,warn}"
    [ -n "$adversary" ] && export EGO_ADVERSARY="$adversary"
    exec "$BIN" >"$dir/node.log" 2>&1
  ) &
  PIDS+=($!)
}

# The height an honest node reached, read back from its log.
height_of() {
  grep -oE 'block #[0-9]+' "$1" 2>/dev/null | grep -oE '[0-9]+' | sort -n | tail -1
}

overall=0

for behaviour in "${BEHAVIOURS[@]}"; do
  echo "── $behaviour ──────────────────────────────────────────────"
  rm -rf "$SCRATCH"
  mkdir -p "$SCRATCH"

  for i in $(seq 1 "$HONEST"); do
    start_node "honest$i" ""
  done
  start_node "attacker" "$behaviour"

  # Let them find each other and produce blocks.
  for _ in $(seq 1 "$SECONDS_PER_CASE"); do sleep 1; done

  before_stop_heights=()
  for i in $(seq 1 "$HONEST"); do
    before_stop_heights+=("$(height_of "$SCRATCH/honest$i/node.log")")
  done
  stop_all

  # 1. Did any honest node accept something it should not have?
  violated=0
  for i in $(seq 1 "$HONEST"); do
    if grep -q "Invariant. VIOLATED" "$SCRATCH/honest$i/node.log" 2>/dev/null; then
      echo "  FAIL  honest$i recorded an invariant violation"
      grep -m3 "Invariant. VIOLATED" "$SCRATCH/honest$i/node.log" | sed 's/^/        /'
      violated=1
    fi
  done

  # 2. Did they refuse the attacker's work? Withholding votes and malformed
  #    gossip produce no rejection line by design, so only the behaviours that
  #    actually send something invalid are required to be logged.
  rejected=0
  case "$behaviour" in
    withhold-votes|malformed-gossip) rejected=1 ;;
    *)
      for i in $(seq 1 "$HONEST"); do
        if grep -qE "rejected|Rejected|refused|invalid" "$SCRATCH/honest$i/node.log" 2>/dev/null; then
          rejected=1
          break
        fi
      done
      ;;
  esac
  [ "$rejected" -eq 1 ] || echo "  FAIL  no honest node logged a rejection of the attacker's work"

  # 3. Did the honest majority keep making progress?
  progressed=0
  for h in "${before_stop_heights[@]}"; do
    if [ -n "$h" ] && [ "$h" -gt 0 ] 2>/dev/null; then
      progressed=1
      break
    fi
  done
  [ "$progressed" -eq 1 ] || echo "  FAIL  the honest nodes made no blocks while the attacker was running"

  if [ "$violated" -eq 0 ] && [ "$rejected" -eq 1 ] && [ "$progressed" -eq 1 ]; then
    echo "  pass  refused the attack and kept making blocks"
  else
    overall=1
    echo "  logs: $SCRATCH/honest*/node.log"
  fi
  echo
done

if [ "$overall" -eq 0 ]; then
  echo "All behaviours refused."
else
  echo "At least one behaviour was not handled. Read the logs above."
fi
exit "$overall"
