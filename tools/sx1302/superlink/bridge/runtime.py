"""SuperLink bridge runtime daemon: owns the SX1302 HAL and drives BridgeCore."""
from __future__ import annotations
import csv
import logging
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
        self.core = BridgeCore(self.store, self.profiles, self._session_factory,
                               auto_adopt=False)
        self.core.subscribe(self._on_event)

    def _session_factory(self, record) -> DeviceSession:
        s = DeviceSession(record, gw_mac=self.config.gw_mac,
                          pairing_key=self.config.pairing_key,
                          profiles=self.profiles)
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
