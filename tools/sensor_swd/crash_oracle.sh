#!/usr/bin/env bash
# SWD crash oracle for RF write-fuzzing. Hammer-attaches the running sensor (no
# reset) and reads the Cortex-M4 fault status registers. A nonzero CFSR/HFSR
# means a malicious frame faulted the core; BFAR/MMFAR give the faulting address.
#
# Run this RIGHT AFTER a --write-fuzz / --ota-evil-offset batch, while the sensor
# is still awake (keep it awake with --keep-awake, or power-cycle to catch a
# boot window — the attach loop will land in an active window).
#
# Usage: tools/sensor_swd/crash_oracle.sh
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
if ! ioreg -p IOUSB 2>/dev/null | grep -qi "j-link"; then
  echo "!! No J-Link on USB. Plug the probe in." >&2; exit 1
fi
LOG=/tmp/fault_check.log
echo "[*] hammering attach to read fault registers (power-cycle to help)..."
END=$(( $(date +%s) + 120 )); n=0
while [ "$(date +%s)" -lt "$END" ]; do
  n=$((n+1))
  /usr/local/bin/JLinkExe -device Cortex-M4 -if SWD -speed 1000 \
      -autoconnect 1 -ExitOnError 1 \
      -CommanderScript "$HERE/fault_check.jlink" >"$LOG" 2>&1
  if grep -q "E000ED28" "$LOG"; then
    echo "[*] attached on attempt $n"; break
  fi
done
if ! grep -q "E000ED28" "$LOG"; then
  echo "!! never caught an awake window in $n attempts" >&2; exit 1
fi

# Parse the mem32 reads (format: "E000ED28 = 00000000").
val() { grep -i "^$1" "$LOG" | head -1 | sed -E 's/.*=[[:space:]]*//; s/[^0-9A-Fa-f].*//'; }
CFSR=$(val E000ED28); HFSR=$(val E000ED2C); MMFAR=$(val E000ED34); BFAR=$(val E000ED38); SHCSR=$(val E000ED24)
echo "---------------------------------------------"
echo " CFSR  (fault flags)  = 0x${CFSR:-????????}"
echo " HFSR  (hardfault)    = 0x${HFSR:-????????}"
echo " MMFAR (MM addr)      = 0x${MMFAR:-????????}"
echo " BFAR  (busfault addr)= 0x${BFAR:-????????}"
echo " SHCSR (handler state)= 0x${SHCSR:-????????}"
echo "---------------------------------------------"
if [ -n "${CFSR:-}" ] && [ "$CFSR" != "00000000" ]; then
  echo ">>> FAULT DETECTED (CFSR nonzero). If CFSR bit7(MMARVALID)/bit15(BFARVALID)"
  echo "    is set, MMFAR/BFAR above is the faulting address — that's the OOB target."
elif [ -n "${HFSR:-}" ] && [ "$HFSR" != "00000000" ]; then
  echo ">>> HARDFAULT (HFSR nonzero, CFSR clear — likely escalated/forced)."
else
  echo "    No fault latched. Either the write was silent (diff SRAM via live_dump.sh)"
  echo "    or the sensor already reset (regs cleared on reset)."
fi
