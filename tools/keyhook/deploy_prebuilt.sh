#!/bin/bash
#
# deploy_prebuilt.sh — Deploy a PRE-BUILT keyhook.so and capture session keys.
#
# Use this when the host has no arm-linux-gnueabihf-gcc (e.g. macOS / Pi gone).
# Build keyhook.so first via the OrbStack cross-compiler:
#   docker run --rm -v "$PWD":/work -w /work debian:bookworm bash -c \
#     'apt-get update -qq && apt-get install -y -qq gcc-arm-linux-gnueabihf && \
#      arm-linux-gnueabihf-gcc -DKEYHOOK_QUIET=1 -marm -fomit-frame-pointer -O2 \
#      -shared -fPIC -o keyhook.so keyhook.c'
#   ( -marm -fomit-frame-pointer is REQUIRED: Debian's cross-gcc defaults to
#     Thumb-2 where r7 is the frame pointer and the read() syscall asm needs r7. )
#
# Then:  ./deploy_prebuilt.sh [bridge_ip]     (default 10.1.10.141)
#
# WARNING: this restarts lorabrd → the sensor RE-HANDSHAKES (new session keys).
# Only run it when you can immediately take a session-synced sensor RAM dump.
set -e

GW_IP="${1:-10.1.10.141}"
GW_USER="ubnt"
GW_PASS="zaLsHMDA7IdjmVhR1sFyODonQPfZ6h"
SSH="sshpass -p '$GW_PASS' ssh -o StrictHostKeyChecking=accept-new $GW_USER@$GW_IP"
SCP="sshpass -p '$GW_PASS' scp -O -o StrictHostKeyChecking=accept-new"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

[ -f "$SCRIPT_DIR/keyhook.so" ] || { echo "ERROR: keyhook.so not built — see header"; exit 1; }
echo "=== SuperLink Session Key Capture (pre-built hook) ==="
echo "Gateway: $GW_USER@$GW_IP   keyhook.so: $(file -b "$SCRIPT_DIR/keyhook.so")"
echo

# lorabrd is a procd service. Its invocation is fixed (from /etc/init.d/lorabr):
#   chrt -r 50 /usr/sbin/lorabrd --syslog /etc/persistent/cfg/lorabr.json
# procd respawns it on a bare `killall`, so we must `/etc/init.d/lorabr stop`
# first (that disables respawn). The bridge's busybox has NO nohup/setsid, so we
# detach the hooked process with a `( ... & )` subshell (orphan to init).
LORABRD='chrt -r 50 /usr/sbin/lorabrd --syslog /etc/persistent/cfg/lorabr.json'

echo "[1/3] Deploying pre-built keyhook.so..."
eval $SCP "$SCRIPT_DIR/keyhook.so" "$GW_USER@$GW_IP:/tmp/keyhook.so"

echo "[2/3] Stop procd service + launch hooked lorabrd..."
eval $SSH "'
  chmod +x /tmp/keyhook.so; rm -f /tmp/keyhook.log /tmp/lorabrd_hooked.log
  /etc/init.d/lorabr stop 2>/dev/null; sleep 1; killall -9 lorabrd 2>/dev/null; sleep 1
  ( LD_PRELOAD=/tmp/keyhook.so KEYHOOK_OUT=/tmp/keyhook.log $LORABRD </dev/null >/tmp/lorabrd_hooked.log 2>&1 & )
  sleep 2; echo \"  hooked lorabrd pid: \$(pidof lorabrd || echo FAILED)\"
'"

echo "  Waiting for sensor re-handshake (up to 55s)..."
for i in $(seq 1 55); do
    sleep 1
    KEY_COUNT=$(eval $SSH "grep -c '^KEY=' /tmp/keyhook.log 2>/dev/null" 2>/dev/null || echo "0")
    if [ "$KEY_COUNT" -ge 2 ]; then echo "  Captured $KEY_COUNT KEY= lines!"; break; fi
    printf "."
done
echo

echo "[3/3] Captured session keys:"
eval $SSH "grep -E '^(SHARED|KEY|OUT)=' /tmp/keyhook.log 2>/dev/null | sort -u"
echo
echo "Full log on bridge: /tmp/keyhook.log  (scp it to captures/live/)"
echo "The hooked lorabrd is orphaned to init and NOT procd-managed — if it dies,"
echo "the bridge loses LoRa until you restore. To restore the clean service"
echo "(this RE-HANDSHAKES → new session key):"
echo "  ssh $GW_USER@$GW_IP 'killall -9 lorabrd; /etc/init.d/lorabr start'"
