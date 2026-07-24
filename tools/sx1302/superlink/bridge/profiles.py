"""Data-driven property decode/encode profiles."""
from __future__ import annotations
import os
import yaml

_INT_TYPES = {"u8": (1, False), "u16": (2, False),
              "u32": (4, False), "s16": (2, True)}
_DEFAULT_PATH = os.path.join(os.path.dirname(__file__), "profiles", "superlink.yaml")


class ProfileRegistry:
    def __init__(self, properties: dict, device_types: dict):
        self._props = {int(k): v for k, v in properties.items()}
        self._by_name = {v["name"]: int(k) for k, v in self._props.items()}
        self._device_types = device_types or {}

    @classmethod
    def load(cls, path: str | None = None) -> "ProfileRegistry":
        with open(path or _DEFAULT_PATH) as f:
            doc = yaml.safe_load(f)
        return cls(doc.get("properties", {}), doc.get("device_types", {}))

    def _entry(self, property_id: int, device_type: int | None):
        if device_type is not None:
            override = self._device_types.get(device_type, {}).get(property_id)
            if override:
                return override
        return self._props.get(property_id)

    def resolve_id(self, name_or_id: str | int) -> int:
        if isinstance(name_or_id, int):
            return name_or_id
        return self._by_name[name_or_id]  # KeyError if unknown

    def name(self, property_id: int) -> str:
        entry = self._props.get(property_id)
        return entry["name"] if entry else f"UNKNOWN_{property_id}"

    def decode(self, property_id: int, raw: bytes,
               device_type: int | None = None):
        entry = self._entry(property_id, device_type)
        if not entry or "type" not in entry:
            return None, None, False
        t = entry["type"]
        unit = entry.get("unit")
        if t == "bool":
            return (any(raw), unit, True)
        size, signed = _INT_TYPES[t]
        n = int.from_bytes(raw[:size], "big", signed=signed)
        if "scale" in entry:
            return (n * entry["scale"], unit, True)
        return (n, unit, True)

    def encode(self, name_or_id: str | int, value,
               device_type: int | None = None) -> tuple[int, bytes]:
        pid = self.resolve_id(name_or_id)
        entry = self._entry(pid, device_type)
        if not entry or "type" not in entry:
            raise KeyError(f"no encodable profile for property {name_or_id}")
        if entry.get("access", "r") != "rw":
            raise PermissionError(f"property {entry['name']} is read-only")
        t = entry["type"]
        if t == "bool":
            return pid, b"\x01" if value else b"\x00"
        size, signed = _INT_TYPES[t]
        n = round(value / entry["scale"]) if "scale" in entry else int(value)
        try:
            return pid, n.to_bytes(size, "big", signed=signed)
        except OverflowError as exc:
            raise ValueError(f"{value} out of range for {t}") from exc
