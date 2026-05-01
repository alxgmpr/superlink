#!/bin/bash
# Deploy SuperLink package to RPi (SX1302 concentrator) and optionally run.
#
# Usage:
#   ./deploy.sh                      # rsync only — no run
#   ./deploy.sh run sniff [args]     # deploy + run superlink-sniff (CLI/passive)
#   ./deploy.sh run gw    [args]     # deploy + run superlink-gw    (state machine)
#
# `run` without a target defaults to sniff for backward compatibility.

set -e

PI_HOST="alex@corecell.local"
PI_KEY="$HOME/.ssh/id_ed25519_pi"
PI_DIR="~/superlink"

echo "Syncing to $PI_HOST..."
scp -i "$PI_KEY" -r superlink superlink-sniff superlink-gw "$PI_HOST:$PI_DIR/"
ssh -i "$PI_KEY" "$PI_HOST" "chmod +x $PI_DIR/superlink-sniff $PI_DIR/superlink-gw"

if [ "$1" = "run" ]; then
    shift
    target="${1:-sniff}"
    case "$target" in
        sniff|gw) shift ;;
        *)
            # Backward-compat: if first arg after `run` is a flag (--key, ...)
            # rather than sniff/gw, treat the target as `sniff` and forward.
            target="sniff"
            ;;
    esac
    case "$target" in
        sniff) entry="superlink-sniff" ;;
        gw)    entry="superlink-gw" ;;
    esac
    echo "Starting $entry on $PI_HOST..."
    ssh -t -i "$PI_KEY" "$PI_HOST" "cd $PI_DIR && ~/superlink-venv/bin/python3 $entry $*"
else
    echo "Deployed. Run with:"
    echo "    ./deploy.sh run sniff [--key HEX] [--mac MAC]"
    echo "    ./deploy.sh run gw    [--gw-mac MAC]"
fi
