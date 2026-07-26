#!/usr/bin/env python3
"""Hardware command probe: drive ONE application-layer command to an adopted
SuperLink sensor and capture/decode its response.

Loads the adopted DeviceRecord from the bridge store, re-handshakes when the
sensor next reconnects (0x40 -> 0x62 -> 0x42 -> ACTIVE), queues the chosen
command body on the sensor's 0x53 command window (re-arming with a fresh
non-zero tag until it lands), and logs every decoded response event
(DeviceInfoEvent / PropertyEvent / RawMessageEvent).

Only ONE process may own the SX1302 concentrator at a time — stop
superlink-bridged (and any other probe) before running this.

Examples (on the Pi):
  python3 -u command_probe.py device_info
  python3 -u command_probe.py property_request --ids 1,3,13
  python3 -u command_probe.py ping --data deadbeef
  python3 -u command_probe.py locate
  python3 -u command_probe.py reboot
  python3 -u command_probe.py property_set --id 14 --channel 0 --value 00
"""
import argparse
import logging
import sys
import time

sys.path.insert(0, "/home/alex/superlink")

from superlink import appmsg
from superlink.bridge.config import RuntimeConfig
from superlink.bridge.events import (
    DeviceInfoEvent, PropertyEvent, RawMessageEvent, DeviceStateEvent,
)
from superlink.bridge.profiles import ProfileRegistry
from superlink.bridge.session import DeviceSession
from superlink.bridge.store import JsonDeviceStore
from superlink.decoder import parse_frame
from superlink.hal import SX1302, BW_500KHZ

logging.basicConfig(level=logging.INFO,
                    format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("probe")


def build_body(spec: str, tag: int) -> bytes:
    """Build a command body from a spec string.

    spec forms (colon-separated args):
      locate
      reboot
      factory_reset
      device_info
      ping[:HEXDATA]
      property_request:1|3|13        (pipe-separated ids, decimal or 0x..)
      property_set:ID|CHANNEL|HEXVAL
    """
    parts = spec.split(":")
    cmd = parts[0]
    if cmd == "locate":
        return appmsg.encode_locate(tag)
    if cmd == "reboot":
        return appmsg.encode_reboot(tag)
    if cmd == "factory_reset":
        return appmsg.encode_factory_reset(tag)
    if cmd == "device_info":
        return appmsg.encode_device_info_request(tag)
    if cmd == "ping":
        data = bytes.fromhex(parts[1]) if len(parts) > 1 else b""
        return appmsg.encode_ping_request(tag, data)
    if cmd == "property_request":
        ids = [int(x, 0) for x in parts[1].split("|")]
        return appmsg.encode_property_request(ids, tag)
    if cmd == "property_set":
        pid, ch, val = parts[1].split("|")
        return appmsg.encode_property_set(
            [(int(pid, 0), int(ch, 0), bytes.fromhex(val))], tag)
    raise SystemExit(f"unknown command {cmd}")


def describe_event(ev) -> str | None:
    if isinstance(ev, DeviceInfoEvent):
        props = ", ".join(
            f"{appmsg.property_name(p['propertyId'])}"
            f"(id={p['propertyId']},ch={p['channelCount']},sz={p['valueSize']})"
            for p in ev.supported_properties)
        return (f"DEVICE_INFO_REPORT type=0x{ev.device_type:04x} "
                f"fw={'.'.join(map(str, ev.fw_version))} hw={ev.hw_revision} "
                f"anon={ev.anon_id.hex()} "
                f"supportedMsgIds={ev.supported_message_ids} "
                f"supportedProps=[{props}]")
    if isinstance(ev, PropertyEvent):
        val = ev.value if ev.decoded else ev.raw.hex()
        return (f"PROPERTY {ev.name}(id={ev.property_id},ch{ev.channel}) = "
                f"{val}{(' ' + ev.unit) if ev.unit else ''} raw={ev.raw.hex()}")
    if isinstance(ev, RawMessageEvent):
        return f"RAW msgId={ev.message_id} body={ev.body.hex()}"
    return None


def expected_response(spec: str, ev) -> bool:
    """True if `ev` looks like the response to command `spec`."""
    cmd = spec.split(":")[0]
    if cmd == "device_info":
        return isinstance(ev, DeviceInfoEvent)
    if cmd in ("property_request", "property_set"):
        return isinstance(ev, PropertyEvent)
    if cmd == "ping":
        return isinstance(ev, RawMessageEvent) and ev.message_id == 5
    # locate/reboot/factory_reset may reply with a status (msgId 1) or nothing.
    if isinstance(ev, RawMessageEvent) and ev.message_id == 1:
        return True
    return False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("commands",
                    help="comma-separated command specs run in sequence, e.g. "
                         "'device_info,property_request:1|3|13,ping:dead,locate'")
    ap.add_argument("--config", default="/home/alex/superlink/superlink_bridge.yaml")
    ap.add_argument("--retries", type=int, default=3,
                    help="times to fire each command across 0x53 windows")
    ap.add_argument("--per-cmd-timeout", type=float, default=45.0,
                    help="seconds to wait for a command's response before advancing")
    ap.add_argument("--timeout", type=float, default=1200.0,
                    help="overall wall-clock budget (also covers waiting for reconnect)")
    ap.add_argument("--beacon-interval", type=float, default=15.0,
                    help="seconds between gateway beacons that invite discovery")
    args = ap.parse_args()

    specs = [s for s in args.commands.split(",") if s]

    cfg = RuntimeConfig.load(args.config)
    recs = JsonDeviceStore(cfg.store_path).load_all()
    recs = [r for r in recs if r.adopted]
    if not recs:
        log.error("no adopted device in store %s", cfg.store_path)
        sys.exit(2)
    rec = recs[0]
    log.info("target=%s adopted=%s kdf_ctx=%s transport=%s sequence=%s",
             rec.mac.hex(), rec.adopted, rec.kdf_context[:8].hex(),
             rec.transport_key[:8].hex(), specs)

    # Short beacon interval so we actively invite a settled sensor to
    # re-discover (the real Ubiquiti bridge beacons continuously on 927.6 MHz;
    # a sensor that has lost its gateway waits for that invitation).
    sess = DeviceSession(rec, gw_mac=cfg.gw_mac, pairing_key=cfg.pairing_key,
                         profiles=ProfileRegistry.load(),
                         beacon_interval=args.beacon_interval)
    sess.start()

    hal = SX1302()
    hal.start()
    log.info("listening; sequence has %d command(s), awaiting reconnect...",
             len(specs))

    idx = 0                 # current spec
    tag = 0
    fired = 0               # times current spec fired
    spec_started_at = None  # when current spec became active-eligible
    results = {}            # spec -> True if response seen
    deadline = time.time() + args.timeout
    was_active = False
    try:
        while time.time() < deadline and idx < len(specs):
            for pkt in hal.receive():
                if not pkt.crc_ok:
                    continue
                fr = parse_frame(pkt.payload)
                if fr is None:
                    continue
                log.info("RX ch=%d dctrl=0x%02X seq=%02X.%02X state=%s",
                         pkt.ul_channel, fr.dctrl, fr.seq_hi, fr.seq_lo,
                         sess.state)
                frames, events = sess.feed(fr, pkt.ul_channel, time.monotonic())

                if sess.session_key is not None and not was_active:
                    was_active = True
                    spec_started_at = time.time()
                    log.info(">>> session ACTIVE (session_key derived) <<<")

                for ev in events:
                    desc = describe_event(ev)
                    if desc:
                        log.info("EVENT %s", desc)
                    if idx < len(specs) and expected_response(specs[idx], ev):
                        results[specs[idx]] = True
                        log.info("*** RESPONSE for '%s' — advancing ***",
                                 specs[idx])
                        idx += 1
                        fired = 0
                        spec_started_at = time.time()

                # Fire the current spec on a fresh 0x53 window once ACTIVE.
                if (sess.session_key is not None and idx < len(specs)
                        and not sess._pending_bodies and fired < args.retries):
                    tag = (tag % 0xFF) + 1
                    body = build_body(specs[idx], tag)
                    sess.queue_body(body)
                    fired += 1
                    log.info("queued '%s' attempt %d/%d tag=%d body=%s",
                             specs[idx], fired, args.retries, tag, body.hex())

                for f in frames:
                    try:
                        hal.send(f.freq_hz, f.data, bandwidth=BW_500KHZ,
                                 tx_timestamp_us=pkt.timestamp_us
                                 + cfg.downlink_delay_us,
                                 invert_pol=cfg.invert_iq)
                    except Exception as e:  # noqa: BLE001
                        log.warning("tx skip: %s", e)

            # Beacon on 927.6 MHz to invite a settled sensor to re-discover.
            bframes, _ = sess.tick(time.monotonic())
            for f in bframes:
                try:
                    hal.send(f.freq_hz, f.data, bandwidth=BW_500KHZ,
                             tx_timestamp_us=0, invert_pol=cfg.invert_iq)
                    log.info("beacon TX on %.1f MHz", f.freq_hz / 1e6)
                except Exception as e:  # noqa: BLE001
                    log.warning("beacon tx skip: %s", e)

            # Advance past a spec that exhausted retries and timed out waiting.
            if (was_active and idx < len(specs) and spec_started_at
                    and fired >= args.retries
                    and time.time() - spec_started_at > args.per_cmd_timeout):
                log.info("--- no response for '%s' after %d tries; advancing ---",
                         specs[idx], fired)
                results.setdefault(specs[idx], False)
                idx += 1
                fired = 0
                spec_started_at = time.time()
            time.sleep(0.01)
    finally:
        hal.stop()
        log.info("SEQUENCE DONE. results:")
        for s in specs:
            log.info("  %-40s %s", s,
                     "RESPONDED" if results.get(s) else "no-response/na")


if __name__ == "__main__":
    main()
