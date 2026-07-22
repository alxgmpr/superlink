"""PROPERTY_REQUEST sweep controller.

Drives a memory-disclosure fuzz of a paired SuperLink sensor: hand out
batches of property ids to probe via PROPERTY_REQUEST, then classify the
PROPERTY_REPORTs that come back. The high-value signal is an *undefined*
property id (one the firmware doesn't define, i.e. not in
appmsg.DEFINED_PROPERTY_IDS) that nonetheless returns bytes — a candidate
out-of-bounds read in the sensor's property dispatch.

Pure logic, no RF. The gateway state machine feeds it decoded reports and
pulls id batches to encode into DL frames.
"""

from __future__ import annotations

from . import appmsg


def parse_id_spec(spec: str) -> list[int]:
    """Parse a property-id selection into a sorted id list.

    Accepts "all" (0-255), "undefined" (0-255 minus firmware-defined ids), or
    a comma list of singles and inclusive ranges, e.g. "0,18,43-255".
    """
    spec = spec.strip().lower()
    if spec == "all":
        return list(range(256))
    if spec == "undefined":
        return sorted(set(range(256)) - appmsg.DEFINED_PROPERTY_IDS)
    ids: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            lo, hi = (int(x) for x in part.split("-", 1))
            rng = range(lo, hi + 1)
        else:
            rng = [int(part)]
        for i in rng:
            if not 0 <= i <= 255:
                raise ValueError(f"id {i} out of range 0-255")
            ids.append(i)
    return ids


class PropertySweep:
    def __init__(self, ids=None, batch_size: int = 8):
        # Default: probe the entire byte range (defined ids give a baseline,
        # undefined ids are the actual targets).
        self._queue = list(range(256)) if ids is None else list(ids)
        self.batch_size = batch_size
        self.sizes: dict = {}
        self.anonymous_device_id: bytes | None = None
        self.device_info: dict | None = None
        # Ids the *device* advertises supporting (subset of firmware-defined).
        # None until a DEVICE_INFO_REPORT is ingested.
        self.advertised: set | None = None
        self._probed: list[int] = []
        # propertyId -> {"value", "channel", "known"} for ids that answered.
        self.responses: dict[int, dict] = {}
        self.findings: list[dict] = []

    # ---- driving the sweep ----

    def next_batch(self) -> list[int]:
        """Return the next batch of ids to probe (marking them probed)."""
        batch = self._queue[:self.batch_size]
        self._queue = self._queue[self.batch_size:]
        self._probed.extend(batch)
        return batch

    def done(self) -> bool:
        return not self._queue

    def set_device_info(self, report: dict) -> None:
        """Record a decoded DEVICE_INFO_REPORT: value-size map + device id."""
        self.device_info = report
        self.sizes = appmsg.property_sizes(report)
        self.anonymous_device_id = report.get("anonymousDeviceId")
        self.advertised = {p["propertyId"]
                           for p in report.get("supportedProperties", [])}

    # ---- classifying responses ----

    def record_report(self, report: dict) -> None:
        """Ingest a decoded PROPERTY_REPORT and flag disclosures."""
        for prop in report.get("properties", []):
            pid = prop["propertyId"]
            value = prop.get("value", b"")
            self.responses[pid] = {
                "channel": prop.get("channel"),
                "value": value,
                "known": prop.get("known", True),
            }
            reasons = self._classify(pid, value)
            if reasons:
                self.findings.append({
                    "propertyId": pid,
                    "name": appmsg.property_name(pid),
                    "channel": prop.get("channel"),
                    "value": value,
                    "reasons": reasons,
                })

    def _classify(self, pid: int, value: bytes) -> list[str]:
        reasons = []
        if not value:
            return reasons
        if pid not in appmsg.DEFINED_PROPERTY_IDS:
            # Firmware doesn't define this id, yet it returned data — the
            # strongest out-of-bounds-read signal.
            reasons.append("undefined_property_id")
        elif self.advertised is not None and pid not in self.advertised:
            # A firmware-defined id the device did NOT advertise supporting,
            # yet it answered with data — weaker, but worth a look.
            reasons.append("unadvertised_property")
        return reasons

    # ---- reporting ----

    def summary(self) -> dict:
        return {
            "probed": len(self._probed),
            "remaining": len(self._queue),
            "responded": len(self.responses),
            "findings": len(self.findings),
        }
