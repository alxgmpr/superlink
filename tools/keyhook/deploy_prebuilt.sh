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

echo "[1/4] Deploying pre-built keyhook.so..."
eval $SCP "$SCRIPT_DIR/keyhook.so" "$GW_USER@$GW_IP:/tmp/keyhook.so"
eval $SSH "chmod +x /tmp/keyhook.so && rm -f /tmp/keyhook.log"

echo "[2/4] Stopping lorabrd..."
LORABRD_CMD=$(eval $SSH "cat /proc/\$(pidof lorabrd)/cmdline 2>/dev/null | tr '\0' ' '" 2>/dev/null || echo "/usr/sbin/lorabrd")
eval $SSH "killall lorabrd 2>/dev/null" || true
sleep 1
echo "  Original command: $LORABRD_CMD"

echo "[3/4] Restarting lorabrd with LD_PRELOAD hook..."
eval $SSH "cd /tmp && LD_PRELOAD=/tmp/keyhook.so KEYHOOK_OUT=/tmp/keyhook.log nohup $LORABRD_CMD > /tmp/lorabrd_hooked.log 2>&1 &"
echo "  Waiting for sensor reconnect (up to 30s)..."
for i in $(seq 1 30); do
    sleep 1
    KEY_COUNT=$(eval $SSH "grep -c '^KEY=' /tmp/keyhook.log 2>/dev/null" 2>/dev/null || echo "0")
    if [ "$KEY_COUNT" -ge 2 ]; then echo "  Captured $KEY_COUNT keys!"; break; fi
    printf "."
done
echo

echo "[4/4] Captured session keys:"
eval $SSH "cat /tmp/keyhook.log 2>/dev/null"
echo
echo "To restore: ssh $GW_USER@$GW_IP 'killall lorabrd; /etc/init.d/lorabr start'"
