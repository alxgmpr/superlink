# SuperLink adoption-commit — fresh-session handoff

## ✅ SOLVED 2026-07-23 — adoption commits end-to-end (merged to main)
This handoff is now historical. The sensor commits and holds an operational
session. Root cause was the **`0x63` ACK sequencing** (must echo the sensor's
`0x54` ADOPT_RESPONSE `seq_hi` and set `seq_lo = acked+1`) plus the **dual-key
reconnect** (fallbackKey transport + primary `addDevice.key` KDF context, rotated
only on observing adopted-form `0x40`). See `docs/protocol/adoption_commit_mechanism.md`
and the decoded transcript. The app-layer memory-disclosure sweeps
(PROPERTY_REQUEST / message-id / PING) all ran clean/negative on fw 1.1.1.

## ⚠️ UPDATE 2026-07-22 — the reference capture has been fully decoded

The single reference capture was decoded at BOTH the controller↔bridge JSON-RPC
layer AND the LoRa-plaintext layer (the WS frames turned out to be plaintext JSON,
not deflate). Results in **`docs/protocol/adoption_commit_mechanism.md`** and the
annotated transcript **`captures/live/bridge_adopt_fresh_pass2_DECODED.txt`**.
Headlines that supersede parts of this doc below:

- **Ratchet/rotation-counter theory (Prime suspect #1) is REFUTED.** Protect's
  `deviceAdopt.ts` uses `r=randomBytes(32)`, `o=randomBytes(32)` for the ADOPT
  ephemerals — no seed, no counter. The sensor has nothing monotonic to validate,
  and ECDH symmetry makes our addDevice.key match the sensor's. Do NOT keep
  chasing a persistent ratchet.
- **`c5923a86…` = `LORA_DEVICE_DEFAULT_ADOPTION_KEY`, a global Protect constant**,
  not a per-device factory secret. The controller literally sends
  `addDevice{key:"c5923a86…"}` to start adoption.
- **The commit is a re-handshake under two derived keys, not a confirm frame.**
  The `0x63 0100` is just the MAC-layer ACK of the sensor's 0x54 ADOPT_RESPONSE.
  Post-adoption the `0x62/0x42` handshake is XSalsa20'd with the **fallbackKey**;
  the operational session key uses the **primary** addDevice.key as KDF context.
  Our gateway uses `pairing_key` for those handshake frames (gateway.py
  434/467/479/583) → the reconnect can't complete. That is the first genuinely
  new, evidence-backed lead. See the mechanism doc for the exact fix + the still-
  open commit-trigger question (our `0x63` ACK framing).

The original notes below remain for context; treat the "Prime suspects" and the
"post-ADOPT_RESPONSE frame" framing as partly superseded.

## Mission
Make our Pi/SX1302 gateway (`superlink-gw`) get a **factory-reset SuperLink sensor
to COMMIT adoption** to us, the way the real UniFi bridge does. Once the sensor
commits, everything downstream already works (rotated-key operational session +
PROPERTY_REQUEST memory-disclosure sweep are built, tested, and verified against
ground truth). Commit is the one blocker.

## The wall (current failure signature — consistent across 4 attempts)
Our gateway:
1. Completes the pairing handshake `0x40→0x62→0x42→0x62` with KDF context
   `c5923a86…`; the 0x42 inner blob decrypts to the sensor's own MAC → session
   key is correct.
2. Sends `ADOPT_REQUEST` (msgId 0x02), receives a valid `ADOPT_RESPONSE`
   (msgId 0x03) with the sensor's device pubkeys, derives `addDevice.key`.
3. Sends the commit ack, then rotates its KDF context to `addDevice.key`.
4. **Sensor goes silent ~24 s (it accepts our frames), then comes back
   UNADOPTED** — discovery `01ae94 NN 00000000` (no networkId trailer), and
   re-handshakes using its OWN `c5923a86` context (NOT our `addDevice.key`), so
   our rotated context yields a garbage inner MAC. The sensor NEVER emits the
   adopted-form discovery `01ae94 8N 0000048f`.

So the ADOPT round-trip completes cleanly but the sensor **refuses to commit**.

## Ground truth we DID nail (verified — don't re-derive)
- **Session-key KDF**: `blake2b32(shared || gw_pub || sensor_pub || CONTEXT)`.
  - CONTEXT = `c5923a86e166e4bf3f8959643ff1c245f986115ec34946ded0b87dc0d7bd38db`
    (factory per-device key; survives factory reset) **pre-adoption**.
  - CONTEXT = `addDevice.key` **post-adoption**. Verified EXACT: our
    `derive_session_key` reproduces the bridge's operational key `9432ba8e…`
    from `captures/live/bridge_pair_keyhook_20260722.log`. (test_crypto:
    `test_operational_session_key_matches_bridge_ground_truth`)
- **addDevice.key** = `E(eph_priv, dev_pub)` =
  `blake2b32(X25519(eph_priv,dev_pub) || base*eph_priv || dev_pub || H)`,
  `H = 70be68514ce7b81328d9f3215855c5675336ea88a08a728df7fce95cc8970a59`.
  Because of ECDH symmetry this MATCHES what the sensor computes regardless of
  whether `eph_priv` is random — so a key mismatch is NOT the commit blocker.
- **The commit decision + addDevice.key are computed by the CONTROLLER
  (UniFi Protect `service.js`), not by `lorabrd`.** A fresh-adoption keyhook of
  `lorabrd` shows only 2 scalarmults (the handshake DH); no `E()` on the bridge.
- **Message IDs** (Protect webpack module 41118): 01 REQUEST_STATUS_RESPONSE,
  02 ADOPT_REQUEST, 03 ADOPT_RESPONSE, 04 PING_REQ, 05 PING_RSP, 06 REBOOT,
  07 FACTORY_RESET, 08 LOCATE, 09 DEVICE_INFO_REQUEST, 0a DEVICE_INFO_REPORT,
  0b PROPERTY_REQUEST, 0c PROPERTY_REPORT, 0e PROPERTY_SET, 15/16/17 FIRMWARE_*.
  Property IDs in module 17695 (1..42 with holes at 18 and >42).
- **Discovery encodes adoption state**: unadopted = `01ae94 NN 00000000`
  (no networkId), adopted = `01ae94 8N 0000048f` (byte3 high bit + networkId
  0x048f=1167).

## The real bridge's fresh-adoption flow (ground truth, byte-exact)
From `captures/live/bridge_adopt_fresh_pass2_20260722.log`, interleaved UL/DL
(bodies MIC-stripped). `-->` = bridge→sensor DL, `<--` = sensor→bridge UL:
```
<-- 0x40 disc  01ae94 NN 00000000            (unadopted discovery, byte3 rolls)
-->  0x62 conn 0101 <gwpub>...               ConnRsp        \
<-- 0x42 chal  010201 <senspub>...           challenge       | handshake, ctx c5923a86
-->  0x62 conn 0103 <enc-inner>              ChallengeRsp    /  session key K1
<-- 0x53 mgmt  0100
-->  0x74 setup 02 <tag> <gwpub><gwfbpub> 0000048f   ADOPT_REQUEST   <-- answers the 0x53 DIRECTLY
<-- 0x54 data  03 <tag> <devpub><devfbpub>          ADOPT_RESPONSE
-->  0x63 data  0100                                 REQUEST_STATUS_RESPONSE(OK)
<-- 0x40 disc  01ae94 80 0000048f            *** COMMITTED ***
      … then reconnect handshake(s) with CONTEXT=addDevice.key …
-->  0x74 DEVICE_INFO_REQUEST 0937
<-- 0x44 DEVICE_INFO_REPORT   0a…
-->  0x74 PROPERTY_SET  0e <tag> 0d 00 01 2c   (REPORT_INTERVAL=300)  \ post-commit
-->  0x74 PROPERTY_SET  0e <tag> 15 00 01      (TAMPER_CONFIG=1)       | config —
-->  0x74 PROPERTY_SET  0e <tag> 10 00 01      (ENTRY_CONFIG=1)        / NOT part of commit
```
Key facts: **no** pre-commit DEVICE_INFO/PROPERTY exchange; the `0e … 0d 00 01 2c`
that earlier RE (and my commit 93584a9) mistook for the "confirm" is actually a
**PROPERTY_SET(REPORT_INTERVAL=300)** sent post-commit during config.

## What I tried and it did NOT commit (do not repeat)
1. 3-frame `09/0b/09` burst after ADOPT_RESPONSE.
2. Single `0e NN 0d 00 01 2c` "confirm" (it's really PROPERTY_SET; misidentified).
3. `0x63 01 00` commit-ack (matches the bridge byte-for-byte) — still no commit.
4. **Minimal flow**: answer `0x53` with ADOPT_REQUEST directly, no pre-commit
   `09`/`0b`, then `0x63 01 00`, then rotate context — still no commit.
All four produced a valid ADOPT round-trip and the exact same failure signature.
Conclusion: **the commit is NOT gated by the post-ADOPT_RESPONSE LoRa frame.**
Our frames now match the bridge's; the sensor still won't commit. The differentiator
is something else.

## Prime suspects (unexplored — start here)
1. **The ADOPT is a two-way ECDH RATCHET tied to the sensor's PERSISTENT state**
   (see memory `grant_replay_layered_failure`). The controller likely derives the
   ADOPT ephemerals `r`,`o` from a per-device persistent seed/rotation-counter,
   and the sensor VALIDATES the ADOPT against its own stored rotation state —
   committing only if the ratchet advances correctly. Our random ephemerals make
   `addDevice.key` still match (ECDH), but the sensor may reject the *ratchet
   step*. **READ Protect `deviceAdopt.ts`**: how are `r`/`o` generated? Is there a
   `removeDevice`+`addDevice` sequence, a rotation counter, or a persisted
   `key`/`fallbackKey` fed back in?
2. **A controller-side value we don't provide.** The commit (adopted-form 0x40)
   happens on LoRa right after `0x63 0100`, so it should be LoRa-observable — but
   maybe the *content* of an earlier frame (the ADOPT_REQUEST, or the handshake
   challenge echo) must carry a specific persistent value.
3. **Byte-exact multi-capture diff.** We only have ONE clean fresh-adoption
   recording. **Capture several** (see below) and diff them to separate
   session-varying fields (ephemerals, session keys, nonces, tags) from anything
   CONSTANT or MONOTONIC across adoptions of the same sensor — a constant/counter
   is the ratchet fingerprint. Also capture OUR gateway's failed attempt
   (decrypted) and diff every field against the bridge's success.
4. **Firmware.** The commit-validation logic lives in the sensor (STM32WLE5,
   RDP1-locked — hard to dump) and the adoption logic in Protect `service.js`.
   `lorabrd` is just a relay. If the ratchet theory doesn't crack it from
   captures, trace `deviceAdopt.ts` fully and/or attempt the sensor extraction
   path (separate effort; RDP1 → EMFI).

## FIRST STEP for the new session: gather several pairing recordings
Deploy the keyhook on the real bridge and capture N (≥3–5) **fresh** adoptions.
```
# bridge access (FORCE password auth; scp needs -O; SSH is disabled on bridge
# reset — re-enable via Protect web UI PATCH {"isSshEnabled":true}, console 10.1.1.1)
export SSHPASS='zaLsHMDA7IdjmVhR1sFyODonQPfZ6h'
SSHOPT='-o PreferredAuthentications=password -o PubkeyAuthentication=no -o StrictHostKeyChecking=accept-new'
BR=ubnt@10.1.10.141

# deploy + start hooked lorabrd (prebuilt hook already in repo)
sshpass -e scp -O $SSHOPT tools/keyhook/keyhook.so $BR:/tmp/keyhook.so
sshpass -e ssh $SSHOPT $BR 'chmod +x /tmp/keyhook.so; /etc/init.d/lorabr stop; sleep 1; killall -9 lorabrd; sleep 1; ( LD_PRELOAD=/tmp/keyhook.so KEYHOOK_OUT=/tmp/keyhook.log chrt -r 50 /usr/sbin/lorabrd --syslog /etc/persistent/cfg/lorabr.json </dev/null >/tmp/lorabrd_hooked.log 2>&1 & ); sleep 2; pidof lorabrd'

# For EACH recording: clear log, then FORGET the device in Protect + FACTORY-RESET
# the sensor + RE-ADD it (a genuine first-adoption; a "re-adopt" of a known device
# is only a reconnect — verify each capture has >2 scalarmults? NO: the E() runs in
# the CONTROLLER, so the bridge log shows only 2 scalarmults even for a true fresh
# adoption. Instead verify freshness by the write-side JSON showing adopted:false →
# ADOPT_RSP → adopted:true.)
sshpass -e ssh $SSHOPT $BR ': > /tmp/keyhook.log'      # clear before each pass
# ...trigger the fresh adoption in the UniFi UI...
sshpass -e scp -O $SSHOPT $BR:/tmp/keyhook.log captures/live/bridge_adopt_freshN_$(date +%Y%m%d).log

# restore clean bridge when done (this RE-HANDSHAKES the sensor):
sshpass -e ssh $SSHOPT $BR 'killall -9 lorabrd; /etc/init.d/lorabr start'
```
Decoding a capture (the WS JSON-RPC is permessage-deflate; `tools/keyhook/ssl_decode.py`
is meant to inflate it but currently returns 0 records — FIX IT, it's the fastest
path to the controller's adoption commands). For LoRa frames, extract libsodium
`FUNC=stream` blocks: DL plaintext = `PHASE=pre IN=`, UL plaintext = `PHASE=post OUT=`,
strip the 4-byte MIC prefix; nonce = `[mctrl][dctrl][mac6][seqhi][seqlo][13×00][ctr]`.

## Infrastructure / contacts
- **Repo**: `/Users/alex/superlink` (Mac). Branch `property-request-sweeper`
  (5 commits this session: a8ff4de sweeper, 93584a9/4e873dc/f9545e1/acbb943
  adoption attempts — the last two are the current best-guess flow but DO NOT
  commit; treat them as suspect, not gospel). Commits NOT pushed (push was
  blocked by the auto classifier).
- **Pi gateway (SX1302 concentrator)**: `ssh -i ~/.ssh/id_ed25519_pi alex@sx1302.local`
  (password also `alex`). Python `~/superlink-venv/bin/python3`. Package at
  `~/superlink/`. Concentrator working: SPI + I2C enabled, `sx1302_hal` built,
  `libloragw.so` hand-linked with `-fPIC`, `~/sx1302_hal/tools/reset_lgw.sh`
  rewritten to use `pinctrl` (sysfs GPIO dead on kernel 6.18). Deploy: `scp`
  the `superlink/*.py`. Run:
  `cd ~/superlink && ~/superlink-venv/bin/python3 -u superlink-gw --mac AA:BB:CC:DD:EE:01 --kdf-context c5923a86e166e4bf3f8959643ff1c245f986115ec34946ded0b87dc0d7bd38db --sweep --verbose`
- **Real bridge (runs `lorabrd`)**: `ubnt@10.1.10.141`, password
  `zaLsHMDA7IdjmVhR1sFyODonQPfZ6h`. FORCE password auth (old keys cause a
  3-strike lockout). `scp` needs `-O`. lorabrd:
  `chrt -r 50 /usr/sbin/lorabrd --syslog /etc/persistent/cfg/lorabr.json`,
  procd `/etc/init.d/lorabr`. Bridge MAC `9041B23483DC`. Busybox lacks
  nohup/setsid/strace/tcpdump. Bridge is currently CLEAN (keyhook removed).
  SSH disabled on every bridge reset → re-enable from the Protect web UI
  (`fetch('/proxy/protect/api/bridges',{credentials:'include'})` → csrf →
  `PATCH …/nvr {"isSshEnabled":true}`); console UCG-Fiber `10.1.1.1`.
- **Sensor**: MAC `90:41:B2:2E:9A:53`, AcSiP ST50HE = STM32WLE5, **RDP1 locked**.
  Factory context `c5923a86…`, pairing key
  `47be3dffb41ea35749c9290e6d2124e6b3e3842ab4e443bd0ac41eda045c2dbe`,
  networkId `0x048f`. It is a **sleepy battery device** — repeated failed
  pairings push it into discovery backoff/sleep; factory-reset to wake it.
- **Binary Ninja MCP**: `firmware/analysis/up-sense-link/rootfs/bin/lorabrd.bndb`
  (text base `0x10000`, no PIE, RAs map directly).
- **Protect firmware**: `firmware/dumps/UNVR-5.0.16-9d351dce.bin`, squashfs at
  offset 15240517 (`0xE88D45`, zstd). `service.js` (5.3 MB webpack) at
  `usr/share/unifi-protect/app/service.js` (+`.map`, 3160 source paths).
  Adoption code: module 41118 (`helpers/applicationLayer/messages.ts`),
  `subscribers/deviceAdopt.ts` (kdf_E + addDevice), 96443 (key exchange).
  Extract: `unsquashfs -o 15240517 -d DEST UNVR-5.0.16-9d351dce.bin usr/share/unifi-protect/app/service.js{,.map}`.

## Captures (`captures/live/`)
- **`bridge_adopt_fresh_pass2_20260722.log`** — THE reference: a real fresh
  adoption that COMMITS. keyhook of `lorabrd`.
- `bridge_pair_keyhook_20260722.log` — operational reconnect (already-adopted).
- `bridge_adopt_pass1_20260722.log` — a "re-adopt" that was only a reconnect.
- `bridge_pair5/6/7_*_20260421.log` — older keyhook captures (session keys differ).

## Relevant memories (auto-loaded index in MEMORY.md)
`next_session_pi_gw_state` (comprehensive, READ FIRST), `session_key_kdf`,
`class_b_grant`, `grant_replay_layered_failure` (the ratchet lead),
`property_request_read_primitive`, `ota_handler_not_in_lorabrd`,
`reference_bridge_tooling`, `sensor_st50he_teardown`.

## Definition of done
`superlink-gw` logs the sensor emitting adopted-form discovery
`01ae94 8N 0000048f` after our commit ack; then the operational reconnect
derives a session key with CONTEXT=addDevice.key whose 0x42 inner decrypt
matches the sensor MAC (not garbage); then `SWEEP device_info` / `SWEEP FINDING`
lines appear. That is a committed adoption + a live memory-disclosure sweep.
