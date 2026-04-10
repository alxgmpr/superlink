#!/bin/bash
# Setup script for SuperLink sniffer on RPi with SX1302 CoreCell
set -e

echo "=== Installing system packages ==="
sudo apt-get update
sudo apt-get install -y libsodium-dev python3-venv

echo "=== Creating Python venv ==="
cd ~
python3 -m venv superlink-venv
source ~/superlink-venv/bin/activate
pip install pysodium

echo "=== Building libloragw.so ==="
cd ~/sx1302_hal
make clean all
cd libloragw && make libloragw.so

echo "=== Verifying ==="
python3 -c "
import ctypes, os
lib = ctypes.CDLL(os.path.expanduser('~/sx1302_hal/libloragw/libloragw.so'))
ver = lib.lgw_version_info
ver.restype = ctypes.c_char_p
print(f'HAL version: {ver().decode()}')
"
python3 -c "import pysodium; print(f'pysodium OK: {pysodium.crypto_stream_KEYBYTES} byte keys')"

echo "=== Done ==="
