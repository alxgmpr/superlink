#!/usr/bin/env bash
# Live SWD keystore extraction from the paired SuperLink motion sensor.
#
# Proves live-keystore extraction: attach to the RUNNING sensor with no reset,
# dump SRAM, and confirm the CURRENT committed addDevice.key is resident.
#
# PREREQUISITES (all must be true or this thrashes):
#   1. J-Link probe plugged into the Mac AND wired to the sensor J3 SWD pads
#      (SWDIO=PA13, SWCLK=PA14, GND; NRST=pad44 left FLOATING — we never reset).
#      Sanity: `system_profiler SPUSBDataType | grep -i segger` must show it.
#   2. On the Pi: `superlink-gw --reconnect --keep-awake` RUNNING, so the sensor
#      CPU never deep-sleeps and the SWD debug port stays live (this is what
#      prevents J-Link's connect-under-reset fallback).
#
# Usage:  tools/sensor_swd/live_dump.sh
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
DUMP=/tmp/sensor_sram_live.bin
PI=alex@sx1302.local
PIKEY="$HOME/.ssh/id_ed25519_pi"

# 0. Fail fast if the probe isn't even connected.
if ! system_profiler SPUSBDataType 2>/dev/null | grep -qi segger; then
  echo "!! No SEGGER J-Link on USB. Plug the probe into the Mac first." >&2
  exit 1
fi

# 1. Pull the live committed addDevice.key from the Pi (the ground-truth target).
echo "[*] fetching live committed key from $PI:/tmp/superlink_adopt.json"
KEY="$(ssh -i "$PIKEY" -o ConnectTimeout=6 "$PI" 'cat /tmp/superlink_adopt.json' \
        | python3 -c 'import sys,json; print(json.load(sys.stdin)["primary"])')"
echo "[*] live primary addDevice.key = $KEY"

# 2. Attach WITHOUT reset and dump all 64 KB SRAM. Generic Cortex-M4 device +
#    no `r` in the script = plain attach. Reading 64 KB @1000 kHz is <1s.
#    IMPORTANT: --keep-awake keeps the sensor RF-alive but the STM32WLE5 still
#    drops into STOP between the ~1s PING slots, powering down the SWD-AP. A
#    single attach almost always misses. We HAMMER attach until one shot lands
#    in an active window (empirically ~170 shots / ~70s; a fresh power-cycle's
#    boot-init window is the easiest catch). A failed attach is harmless here:
#    NRST is unwired (RESET pin floats high), so the under-reset fallback can't
#    actually pull reset — the sensor keeps its adoption.
rm -f "$DUMP"
echo "[*] hammering attach (no reset) until a wake window is caught -> $DUMP"
END=$(( $(date +%s) + 180 )); n=0
while [ "$(date +%s)" -lt "$END" ]; do
  n=$((n+1))
  /usr/local/bin/JLinkExe -device Cortex-M4 -if SWD -speed 1000 \
      -autoconnect 1 -ExitOnError 1 \
      -CommanderScript "$HERE/attach_dump.jlink" >/tmp/jlink_attempt.log 2>&1
  if [ -f "$DUMP" ] && [ "$(stat -f%z "$DUMP" 2>/dev/null)" = "65536" ]; then
    echo "[*] caught on attempt $n"; break
  fi
  [ $((n % 20)) -eq 0 ] && echo "    ...$n attempts, still trying (power-cycle the sensor to help)"
done
[ -f "$DUMP" ] || { echo "!! no dump after $n attempts — check SWD wiring (SWDIO=PA13, SWCLK=PA14, GND) and that --keep-awake is running" >&2; exit 1; }

# 3. Grep the dump for the live key -> proves live keystore extraction over SWD.
echo "[*] searching dump for the live key"
uv run --with cryptography python "$HERE/analyze_ram.py" "$DUMP" --key "$KEY"
