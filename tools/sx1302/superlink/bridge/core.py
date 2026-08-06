"""BridgeCore: pure multi-device orchestrator over DeviceSessions."""
from __future__ import annotations
import logging
from dataclasses import dataclass
from typing import Callable, Protocol

from ..decoder import parse_frame
from .events import (
    Event, Action, AdoptDevice, DeviceDiscovered, DeviceStateEvent,
    CommandStatus, DeviceRemoved, FactoryReset,
)
from .mapping import action_to_body
from .profiles import ProfileRegistry
from .store import DeviceStore, DeviceRecord

log = logging.getLogger("superlink.core")


@dataclass
class OutgoingFrame:
    data: bytes
    freq_hz: int
    channel: int


class SessionProtocol(Protocol):
    mac: bytes
    state: str
    def start(self, now: float) -> None: ...
    def feed(self, frame, channel: int, now: float,
             rssi: float | None = ..., snr: float | None = ...): ...
    def tick(self, now: float): ...
    def queue_body(self, body: bytes) -> None: ...


class BridgeCore:
    def __init__(self, store: DeviceStore, profiles: ProfileRegistry,
                 session_factory: Callable[[DeviceRecord], SessionProtocol],
                 auto_adopt: bool = False):
        self.store = store
        self.profiles = profiles
        self._factory = session_factory
        self.auto_adopt = auto_adopt
        self._sessions: dict[bytes, SessionProtocol] = {}
        # MACs whose session has already been start()ed. Core-owned sessions are
        # created IDLE (no keypair); they must be started — entering BEACONING
        # and generating a keypair — before a frame is dispatched or they are
        # ticked, or their state machine does nothing. Lazy-started on first
        # feed/tick since `now` is not available at construction/submit time.
        self._started: set[bytes] = set()
        self._discovered: dict[bytes, float] = {}
        self._subscribers: list[Callable[[Event], None]] = []
        # Running command messageTag. The sensor REJECTS tag 0 (a tag-0
        # FACTORY_RESET is silently ignored — no 0x74 ACK, no reset; verified
        # on hardware 2026-07-25). Real controllers use an incrementing non-zero
        # tag which the sensor echoes in its status reply. Start at 0 so the
        # first command uses tag 1.
        self._cmd_tag = 0
        # mac -> messageTag of a FACTORY_RESET awaiting its status reply. The
        # sensor answers in a later window, so the teardown is event-driven:
        # only a tag-matched status with code 0 removes the device.
        self._pending_reset: dict[bytes, int] = {}
        for record in store.load_all():
            self._sessions[record.mac] = session_factory(record)

    def subscribe(self, cb: Callable[[Event], None]) -> None:
        self._subscribers.append(cb)

    def _emit(self, events) -> None:
        for ev in events:
            for cb in self._subscribers:
                cb(ev)

    def _ensure_started(self, mac: bytes, session: SessionProtocol,
                        now: float) -> None:
        """Start a core-owned session exactly once (idempotent).

        Freshly built / store-restored sessions are IDLE with no keypair;
        start() moves them to BEACONING and generates the DH keypair. Guarded
        by `_started` so a session is never started twice — its keys are never
        regenerated and an already-ACTIVE/BEACONING session is never reset.
        """
        if mac not in self._started:
            self._started.add(mac)
            session.start(now)

    def feed(self, raw: bytes, channel: int, now: float,
             rssi: float | None = None, snr: float | None = None
             ) -> list[OutgoingFrame]:
        frame = parse_frame(raw)
        if frame is None:
            return []
        mac = frame.mac
        session = self._sessions.get(mac)
        if session is not None:
            self._ensure_started(mac, session, now)
            frames, events = session.feed(frame, channel, now, rssi=rssi, snr=snr)
            # _emit before _intercept: subscribers must see the CommandStatus
            # (and any event sharing its batch, e.g. a LinkSignal) before the
            # DeviceRemoved it triggers. Otherwise MqttBridge retracts the
            # device's topics and clears its guards first, then republishes
            # discovery/state for the very LinkSignal that arrives "after" —
            # a ghost entity nothing will ever retract.
            self._emit(events)
            self._intercept(events)
            return list(frames)
        if mac in self._discovered:
            return []  # already announced; awaiting AdoptDevice / auto_adopt
        self._discovered[mac] = now
        self._emit([DeviceDiscovered(mac=mac, channel=channel, first_seen=now),
                    DeviceStateEvent(mac=mac, state="discovered")])
        if self.auto_adopt:
            self._adopt(mac)
            session = self._sessions[mac]
            self._ensure_started(mac, session, now)
            frames, events = session.feed(frame, channel, now, rssi=rssi, snr=snr)
            self._emit(events)
            return list(frames)
        return []

    def _adopt(self, mac: bytes) -> None:
        self._discovered.pop(mac, None)
        record = DeviceRecord(mac=mac)
        self._sessions[mac] = self._factory(record)
        self._emit([DeviceStateEvent(mac=mac, state="adopting")])

    def _intercept(self, events) -> None:
        """Act on events before they reach subscribers.

        A FACTORY_RESET is confirmed by a REQUEST_STATUS_RESPONSE echoing the
        command's messageTag with status 0 — the same signal the real
        controller waits for before issuing removeDevice. Anything else (wrong
        tag, non-zero status) leaves the record alone: a stale record is
        recoverable, a wrongly-deleted one needs a physical re-pair.
        """
        for ev in events:
            if not isinstance(ev, CommandStatus):
                continue
            pending = self._pending_reset.get(ev.mac)
            if pending is None or ev.message_tag != pending:
                continue
            if ev.status_code != 0:
                log.warning("factory reset on %s failed: status=%d "
                            "(keeping device record)",
                            ev.mac.hex(), ev.status_code)
                self._pending_reset.pop(ev.mac, None)
                continue
            self._remove_device(ev.mac, "factory_reset")

    def _remove_device(self, mac: bytes, reason: str) -> None:
        """Forget a device entirely: session, start-state, and stored record."""
        self._sessions.pop(mac, None)
        self._started.discard(mac)
        self._discovered.pop(mac, None)
        self._pending_reset.pop(mac, None)
        self.store.delete(mac)
        log.info("removed device %s (%s)", mac.hex(), reason)
        self._emit([DeviceRemoved(mac=mac, reason=reason)])

    def tick(self, now: float) -> list[OutgoingFrame]:
        out: list[OutgoingFrame] = []
        for mac, session in list(self._sessions.items()):
            self._ensure_started(mac, session, now)
            frames, events = session.tick(now)
            out.extend(frames)
            self._emit(events)
            self._intercept(events)
        return out

    def submit(self, action: Action) -> None:
        if isinstance(action, AdoptDevice):
            if action.mac in self._discovered:
                self._adopt(action.mac)
            return
        session = self._sessions.get(action.mac)
        if session is None:
            return
        self._cmd_tag = (self._cmd_tag % 0xFF) + 1  # 1..255, never 0
        session.queue_body(
            action_to_body(action, self.profiles, tag=self._cmd_tag))
        # The tag space is shared across all devices and wraps at 255, so a
        # stale pending-reset tag could otherwise be "confirmed" by an
        # unrelated later command that happens to land on the same tag. Only
        # invalidate the pending reset when the new command actually reuses
        # its tag -- that's the one case an aliased status would wrongly
        # confirm it. A pending reset's status can take a full sensor window
        # (seconds to minutes) to arrive, so invalidating on *every* later
        # submit (a second button press, a Locate/Refresh) would silently
        # disarm a reset the sensor still goes on to perform.
        if self._pending_reset.get(action.mac) == self._cmd_tag:
            log.warning("pending factory reset on %s disarmed: tag %d reused "
                        "by a later command before its status arrived",
                        action.mac.hex(), self._cmd_tag)
            self._pending_reset.pop(action.mac)
        if isinstance(action, FactoryReset):
            self._pending_reset[action.mac] = self._cmd_tag
