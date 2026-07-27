"""SuperLink bridge runtime daemon: owns the SX1302 HAL and drives BridgeCore."""
from __future__ import annotations
import csv
import logging
import queue
import time
from typing import Callable

from ..hal import BW_500KHZ
from .config import RuntimeConfig
from .core import BridgeCore, OutgoingFrame
from .events import (
    Event, DeviceDiscovered, DeviceStateEvent, PropertyEvent, DeviceInfoEvent,
    AdoptDevice,
)
from .profiles import ProfileRegistry
from .session import DeviceSession
from .store import DeviceStore, JsonDeviceStore

log = logging.getLogger("superlink.runtime")


class BridgeRuntime:
    def __init__(self, config: RuntimeConfig, hal, store: DeviceStore | None = None):
        self.config = config
        self.hal = hal
        self.profiles = ProfileRegistry.load()
        self.store = store if store is not None else JsonDeviceStore(config.store_path)
        self._sessions: dict[bytes, DeviceSession] = {}
        self._sinks: list[Callable[[Event], None]] = []
        self._stop = False
        self._csv_writer = None
        self._csv_file = None
        self._action_queue: queue.Queue = queue.Queue()
        self._tick_interval = 1.0
        self._last_tick = 0.0
        self.core = BridgeCore(self.store, self.profiles, self._session_factory,
                               auto_adopt=False)
        self.core.subscribe(self._on_event)

    def _session_factory(self, record) -> DeviceSession:
        s = DeviceSession(record, gw_mac=self.config.gw_mac,
                          pairing_key=self.config.pairing_key,
                          profiles=self.profiles,
                          link_lost_timeout=self.config.link_lost_timeout)
        self._sessions[record.mac] = s
        return s

    def add_event_sink(self, callback: Callable[[Event], None]) -> None:
        self._sinks.append(callback)

    def _on_event(self, event: Event) -> None:
        if isinstance(event, DeviceDiscovered):
            if self.config.is_allowed(event.mac):
                log.info("discovered %s — adopting", event.mac.hex())
                self.core.submit(AdoptDevice(mac=event.mac))
            else:
                log.info("discovered %s — not in allowlist, ignoring", event.mac.hex())
        elif isinstance(event, DeviceStateEvent) and event.state == "adopted":
            session = self._sessions.get(event.mac)
            if session is not None:
                self.store.save(session.to_record())
                log.info("persisted adopted device %s", event.mac.hex())
        elif isinstance(event, DeviceStateEvent) and event.state == "discovered":
            # A previously-adopted device re-advertised as unadopted (factory
            # reset). Drop the stale record so the fresh pair re-adopts cleanly.
            if any(r.mac == event.mac for r in self.store.load_all()):
                self.store.delete(event.mac)
                log.info("removed stale record for re-discovered %s",
                         event.mac.hex())
        elif isinstance(event, (PropertyEvent, DeviceInfoEvent)):
            self._log_and_csv(event)
        # Every event fans out to sinks (B's MQTT publisher attaches here).
        for sink in self._sinks:
            sink(event)

    def _log_and_csv(self, event: Event) -> None:
        if isinstance(event, PropertyEvent):
            log.info("%s %s[ch%d] = %s%s", event.mac.hex(), event.name,
                     event.channel, event.value if event.decoded else event.raw.hex(),
                     f" {event.unit}" if event.unit else "")
            if self._csv_writer is not None:
                self._csv_writer.writerow([
                    time.time(), event.mac.hex(), event.name, event.channel,
                    event.value if event.decoded else "", event.raw.hex(),
                    event.unit or "", event.decoded])
                self._csv_file.flush()

    # --- append these methods to BridgeRuntime ---

    def _schedule(self, frames, base_ts: int) -> None:
        for i, f in enumerate(frames):
            ts = base_ts + self.config.downlink_delay_us + i * self.config.burst_spacing_us
            try:
                self.hal.send(f.freq_hz, f.data, bandwidth=BW_500KHZ,
                              tx_timestamp_us=ts, invert_pol=self.config.invert_iq)
            except (ValueError, RuntimeError) as exc:
                log.warning("TX skipped (%d bytes): %s", len(f.data), exc)

    def submit_action(self, action) -> None:
        """Thread-safe: enqueue an action to be applied on the poll-loop thread."""
        self._action_queue.put(action)

    def default_mac(self) -> bytes | None:
        """The MAC a control command targets when none is given.

        Prefer the single adopted device in the store; fall back to a
        one-element adopt allowlist. Ambiguous (0 or >1) -> None, so the
        operator must name the device explicitly.
        """
        adopted = [r.mac for r in self.store.load_all() if getattr(r, "adopted", False)]
        if len(adopted) == 1:
            return adopted[0]
        allow = self.config.adopt
        if isinstance(allow, (set, frozenset)) and len(allow) == 1:
            return next(iter(allow))
        return None

    def _drain_actions(self) -> None:
        while True:
            try:
                action = self._action_queue.get_nowait()
            except queue.Empty:
                break
            self.core.submit(action)

    def poll_once(self, now: float) -> None:
        self._drain_actions()
        for pkt in self.hal.receive():
            if not pkt.crc_ok:
                continue
            frames = self.core.feed(pkt.payload, pkt.ul_channel, now)
            self._schedule(frames, base_ts=pkt.timestamp_us)

    def tick_if_due(self, now: float) -> None:
        """Call _maybe_tick at most once per _tick_interval seconds."""
        if now - self._last_tick >= self._tick_interval:
            self._last_tick = now
            self._maybe_tick(now)

    def _maybe_tick(self, now: float) -> None:
        # Housekeeping only (session timeouts). No RX packet to correlate, so any
        # frames go out best-effort/immediate.
        frames = self.core.tick(now)
        for f in frames:
            try:
                self.hal.send(f.freq_hz, f.data, bandwidth=BW_500KHZ,
                              tx_timestamp_us=0, invert_pol=self.config.invert_iq)
            except (ValueError, RuntimeError) as exc:
                log.warning("tick TX skipped: %s", exc)

    def stop(self) -> None:
        self._stop = True

    def run(self) -> None:
        if self.config.csv_path:
            self._csv_file = open(self.config.csv_path, "a", newline="")
            self._csv_writer = csv.writer(self._csv_file)
        self.hal.start()
        log.info("bridge runtime started (HAL %s)", self.hal.version())
        try:
            while not self._stop:
                now = time.monotonic()
                self.poll_once(now)
                self.tick_if_due(now)
                time.sleep(0.01)
        except KeyboardInterrupt:
            log.info("shutting down")
        finally:
            self.hal.stop()
            for mac, session in self._sessions.items():
                try:
                    self.store.save(session.to_record())
                except Exception:  # best-effort final flush
                    pass
            if self._csv_file:
                self._csv_file.close()


def build_runtime(config: RuntimeConfig, hal, store=None) -> BridgeRuntime:
    return BridgeRuntime(config, hal, store=store)


def start_control_socket_if_configured(runtime, config):
    """Start the operator control socket if config.control_socket is set."""
    if not config.control_socket:
        return None
    from .control import ControlSocket
    cs = ControlSocket(config.control_socket, submit=runtime.submit_action,
                       default_mac=runtime.default_mac)
    cs.start()
    return cs


def start_mqtt_if_configured(runtime, config, client=None):
    """Start the MQTT bridge if config.mqtt is set; return it (or None)."""
    if config.mqtt is None:
        return None
    from .mqtt import MqttBridge
    if client is None:
        import paho.mqtt.client as mqtt
        client = mqtt.Client()
    bridge = MqttBridge(config.mqtt, runtime, client)
    bridge.start()
    return bridge


def main(argv=None):
    import argparse
    from ..hal import SX1302
    parser = argparse.ArgumentParser(description="SuperLink bridge runtime daemon")
    parser.add_argument("--config", default="superlink_bridge.yaml",
                        help="path to YAML config")
    args = parser.parse_args(argv)
    config = RuntimeConfig.load(args.config)
    logging.basicConfig(level=getattr(logging, config.log_level, logging.INFO))
    runtime = build_runtime(config, SX1302())
    control = start_control_socket_if_configured(runtime, config)
    mqtt_bridge = start_mqtt_if_configured(runtime, config)
    try:
        runtime.run()
    finally:
        if mqtt_bridge is not None:
            mqtt_bridge.stop()
        if control is not None:
            control.stop()
