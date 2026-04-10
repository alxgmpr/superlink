#!/bin/bash
# Deploy SuperLink sniffer to RPi and optionally run it
set -e

PI_HOST="alex@corecell.local"
PI_KEY="$HOME/.ssh/id_ed25519_pi"
PI_DIR="~/superlink"

echo "Syncing to $PI_HOST..."
scp -i "$PI_KEY" -r superlink superlink-sniff "$PI_HOST:$PI_DIR/"
ssh -i "$PI_KEY" "$PI_HOST" "chmod +x $PI_DIR/superlink-sniff"

if [ "$1" = "run" ]; then
    shift
    echo "Starting sniffer..."
    ssh -t -i "$PI_KEY" "$PI_HOST" "cd $PI_DIR && ~/superlink-venv/bin/python3 superlink-sniff $*"
else
    echo "Deployed. Run with: ./deploy.sh run [--key HEX] [--mac MAC]"
fi
