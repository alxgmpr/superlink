"""Device registry persistence: interface + in-memory and JSON impls."""
from __future__ import annotations
import abc
import json
import os
from dataclasses import dataclass, asdict, fields


@dataclass
class DeviceRecord:
    mac: bytes
    device_type: int | None = None
    primary_key: bytes | None = None
    fallback_key: bytes | None = None
    kdf_context: bytes | None = None
    transport_key: bytes | None = None
    adopted: bool = False
    tx_seq_hi: int = 0
    tx_seq_lo: int = 0
    ul_counter_offset: int = 5
    last_seen: float = 0.0


_BYTES_FIELDS = ("mac", "primary_key", "fallback_key", "kdf_context", "transport_key")


def _to_json(rec: DeviceRecord) -> dict:
    d = asdict(rec)
    for k in _BYTES_FIELDS:
        d[k] = d[k].hex() if d[k] is not None else None
    return d


def _from_json(d: dict) -> DeviceRecord:
    allowed = {f.name for f in fields(DeviceRecord)}
    d = {k: v for k, v in d.items() if k in allowed}
    for k in _BYTES_FIELDS:
        if d.get(k) is not None:
            d[k] = bytes.fromhex(d[k])
    return DeviceRecord(**d)


class DeviceStore(abc.ABC):
    @abc.abstractmethod
    def load_all(self) -> list[DeviceRecord]: ...
    @abc.abstractmethod
    def save(self, record: DeviceRecord) -> None: ...
    @abc.abstractmethod
    def delete(self, mac: bytes) -> None: ...


class InMemoryDeviceStore(DeviceStore):
    def __init__(self):
        self._records: dict[bytes, DeviceRecord] = {}

    def load_all(self) -> list[DeviceRecord]:
        return list(self._records.values())

    def save(self, record: DeviceRecord) -> None:
        self._records[record.mac] = record

    def delete(self, mac: bytes) -> None:
        self._records.pop(mac, None)


class JsonDeviceStore(DeviceStore):
    def __init__(self, path: str):
        self.path = path

    def _read(self) -> dict[str, dict]:
        if not os.path.exists(self.path):
            return {}
        with open(self.path) as f:
            return json.load(f)

    def _write(self, data: dict[str, dict]) -> None:
        with open(self.path, "w") as f:
            json.dump(data, f, indent=2)

    def load_all(self) -> list[DeviceRecord]:
        return [_from_json(v) for v in self._read().values()]

    def save(self, record: DeviceRecord) -> None:
        data = self._read()
        data[record.mac.hex()] = _to_json(record)
        self._write(data)

    def delete(self, mac: bytes) -> None:
        data = self._read()
        data.pop(mac.hex(), None)
        self._write(data)
