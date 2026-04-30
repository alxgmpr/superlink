#!/bin/bash
#
# capture_key.sh — Capture SuperLink session keys from a USL Gateway
#
# Cross-compiles the LD_PRELOAD hook, deploys to gateway, restarts lorabrd
# with the hook, waits for a sensor to connect, and prints the session key.
#
# Usage:
#   ./capture_key.sh [gateway_ip]
#
# Prerequisites:
#   - arm-linux-gnueabihf-gcc (install: sudo apt install gcc-arm-linux-gnueabihf)
#   - sshpass (install: sudo apt install sshpass)
#   - Gateway SSH must be enabled (see docs/protocol/crypto_keys_captured.md)
#
set -e

GW_IP="${1:-10.1.1.141}"
GW_USER="ubnt"
GW_PASS="zaLsHMDA7IdjmVhR1sFyODonQPfZ6h"
SSH="sshpass -p '$GW_PASS' ssh -o StrictHostKeyChecking=accept-new $GW_USER@$GW_IP"
SCP="sshpass -p '$GW_PASS' scp -o StrictHostKeyChecking=accept-new"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=== SuperLink Session Key Capture ==="
echo "Gateway: $GW_USER@$GW_IP"
echo

# Step 1: Cross-compile
echo "[1/5] Cross-compiling keyhook.so for armv7l..."
# QUIET=1 disables the memcpy/send/recv hooks; without it the binary SIGSEGVs on lorabrd startup
arm-linux-gnueabihf-gcc -DKEYHOOK_QUIET=1 -shared -fPIC -o "$SCRIPT_DIR/keyhook.so" "$SCRIPT_DIR/keyhook.c"
echo "  Built keyhook.so ($(wc -c < "$SCRIPT_DIR/keyhook.so") bytes)"

# Step 2: Deploy to gateway
echo "[2/5] Deploying to gateway..."
eval $SCP -O "$SCRIPT_DIR/keyhook.so" "$GW_USER@$GW_IP:/tmp/keyhook.so"
eval $SSH "chmod +x /tmp/keyhook.so && rm -f /tmp/keyhook.log"
echo "  Deployed to /tmp/keyhook.so"

# Step 3: Find lorabrd PID and its command line
echo "[3/5] Stopping lorabrd..."
LORABRD_CMD=$(eval $SSH "cat /proc/\$(pidof lorabrd)/cmdline 2>/dev/null | tr '\0' ' '" 2>/dev/null || echo "/bin/lorabrd")
eval $SSH "killall lorabrd 2>/dev/null" || true
sleep 1
echo "  Original command: $LORABRD_CMD"

# Step 4: Restart with hook
echo "[4/5] Restarting lorabrd with LD_PRELOAD hook..."
eval $SSH "cd /tmp && LD_PRELOAD=/tmp/keyhook.so KEYHOOK_OUT=/tmp/keyhook.log nohup $LORABRD_CMD > /tmp/lorabrd_hooked.log 2>&1 &"
echo "  Waiting for sensor reconnect (up to 30s)..."

for i in $(seq 1 30); do
    sleep 1
    KEY_COUNT=$(eval $SSH "grep -c '^KEY=' /tmp/keyhook.log 2>/dev/null" 2>/dev/null || echo "0")
    if [ "$KEY_COUNT" -ge 2 ]; then
        echo "  Captured $KEY_COUNT keys!"
        break
    fi
    printf "."
done
echo

# Step 5: Extract keys
echo "[5/5] Captured session keys:"
echo
eval $SSH "cat /tmp/keyhook.log 2>/dev/null"
echo
echo "=== Keys for superlink-sniff ==="
eval $SSH "grep '^KEY=' /tmp/keyhook.log 2>/dev/null" | while read line; do
    key="${line#KEY=}"
    echo "  superlink-sniff --key $key"
done
echo
echo "Keys saved on gateway at /tmp/keyhook.log"
echo "To restore original lorabrd: ssh $GW_USER@$GW_IP 'killall lorabrd; /bin/lorabrd &'"
