#!/usr/bin/env bash
# Continuous SRAM capture DURING a firmware update — to catch decrypted firmware
# in transit. The bootloader must produce plaintext to program flash, and the
# ~96 KB image exceeds the 64 KB SRAM, so it's decrypted chunk-by-chunk in SRAM.
# During an update the CPU is continuously busy (RX/decrypt/flash), so the SWD
# debug port stays up and attach lands easily — we just dump over and over and
# grep the pile for plaintext firmware.
#
# Run this while `superlink-gw --ota-push <file>` is actively transferring
# (sensor requesting chunks). Ctrl-C when the transfer ends.
#
# Usage: tools/sensor_swd/ota_capture.sh [seconds]   (default 180)
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DUR="${1:-180}"
OUTDIR=/tmp/otadumps
mkdir -p "$OUTDIR"; rm -f "$OUTDIR"/*.bin
if ! ioreg -p IOUSB 2>/dev/null | grep -qi "j-link"; then
  echo "!! No J-Link on USB." >&2; exit 1
fi
JL=/tmp/ota_dump.jlink
END=$(( $(date +%s) + DUR )); n=0; caught=0
echo "[*] continuous SRAM capture for ${DUR}s -> $OUTDIR (dump while the update transfers)"
while [ "$(date +%s)" -lt "$END" ]; do
  n=$((n+1))
  f="$OUTDIR/d$(printf '%04d' "$n").bin"
  printf 'halt\nsavebin %s 0x20000000 0x10000\ngo\nexit\n' "$f" > "$JL"
  /usr/local/bin/JLinkExe -device Cortex-M4 -if SWD -speed 1000 \
      -autoconnect 1 -ExitOnError 1 -CommanderScript "$JL" >/dev/null 2>&1
  if [ -f "$f" ] && [ "$(stat -f%z "$f" 2>/dev/null)" = "65536" ]; then
    caught=$((caught+1))
    [ $((caught % 10)) -eq 0 ] && echo "    captured $caught dumps ($(date +%H:%M:%S))"
  else
    rm -f "$f"
  fi
done
echo "[*] done: $caught/$n dumps captured in $OUTDIR"
echo "[*] scanning for decrypted-firmware fragments..."
uv run --with cryptography python "$HERE/fw_fragment_scan.py" "$OUTDIR"/*.bin
