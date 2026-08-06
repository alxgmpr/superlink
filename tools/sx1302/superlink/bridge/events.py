"""Typed events (core -> consumer) and actions (consumer -> core)."""
from __future__ import annotations
from dataclasses import dataclass, field

DEVICE_STATES = ("discovered", "adopting", "adopted", "active", "lost")


class Event:
    """Base class for all core-emitted events."""


class Action:
    """Base class for all consumer-submitted actions."""


@dataclass(frozen=True)
class DeviceDiscovered(Event):
    mac: bytes
    channel: int
    first_seen: float


@dataclass(frozen=True)
class PropertyEvent(Event):
    mac: bytes
    property_id: int
    name: str
    channel: int
    raw: bytes
    value: object | None
    unit: str | None
    decoded: bool


@dataclass(frozen=True)
class ButtonPressed(Event):
    """A discrete button press, derived from a monotonic last-press-uptime
    property (id19) advancing. Momentary: fires once per detected edge."""
    mac: bytes
    property_id: int
    name: str
    value: int


@dataclass(frozen=True)
class LinkSignal(Event):
    """Gateway-measured link quality for a received frame: RSSI in dBm and SNR
    in dB, straight off the SX1302 (real units, unlike the sensor's opaque id2)."""
    mac: bytes
    rssi_dbm: float
    snr: float


@dataclass(frozen=True)
class DeviceInfoEvent(Event):
    mac: bytes
    device_type: int
    fw_version: tuple[int, int, int]
    hw_revision: int
    anon_id: bytes
    supported_message_ids: list[int]
    supported_properties: list[dict]


@dataclass(frozen=True)
class DeviceStateEvent(Event):
    mac: bytes
    state: str


@dataclass(frozen=True)
class RawMessageEvent(Event):
    mac: bytes
    message_id: int
    body: bytes


@dataclass(frozen=True)
class CommandStatus(Event):
    """REQUEST_STATUS_RESPONSE (msgId 1): the sensor's reply to a command,
    echoing that command's messageTag. statusCode 0 = success.

    The reply arrives in a *later* window than the command it answers (a
    FACTORY_RESET goes out on 0x74; its status comes back on a subsequent
    0x54), so consumers must correlate on message_tag, not on ordering."""
    mac: bytes
    message_tag: int
    status_code: int


@dataclass(frozen=True)
class AdoptDevice(Action):
    mac: bytes


@dataclass(frozen=True)
class SetProperty(Action):
    mac: bytes
    name_or_id: str | int
    value: object


@dataclass(frozen=True)
class SetPropertyRaw(Action):
    mac: bytes
    property_id: int
    channel: int
    raw: bytes


@dataclass(frozen=True)
class RequestProperty(Action):
    mac: bytes
    ids: list[int]


@dataclass(frozen=True)
class RequestDeviceInfo(Action):
    mac: bytes


@dataclass(frozen=True)
class Locate(Action):
    mac: bytes


@dataclass(frozen=True)
class Reboot(Action):
    mac: bytes


@dataclass(frozen=True)
class FactoryReset(Action):
    mac: bytes


@dataclass(frozen=True)
class Ping(Action):
    mac: bytes
    data: bytes = b""
