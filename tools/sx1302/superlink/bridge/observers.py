"""RE sweep re-expressed as a BridgeCore event observer.

The PROPERTY_REQUEST / memory-disclosure sweep (``superlink.sweep``) was
originally driven inline by ``GatewaySession._ingest_app_report``. This adapter
re-expresses the *ingest* half of that coupling as a plain BridgeCore event
subscriber: decoded ``DeviceInfoEvent`` / ``PropertyEvent`` are forwarded to the
sweep controller via its public ``set_device_info`` / ``record_report`` methods.

The dicts handed to the sweep are shaped exactly like the decoded
``DEVICE_INFO_REPORT`` / ``PROPERTY_REPORT`` messages the sweep already consumes
(see ``superlink.sweep.PropertySweep``), so a real ``PropertySweep`` works
unchanged behind this observer.
"""
from __future__ import annotations

from .events import Event, PropertyEvent, DeviceInfoEvent


class SweepObserver:
    def __init__(self, core, sweep):
        self.core = core
        self.sweep = sweep

    def on_event(self, event: Event) -> None:
        if isinstance(event, DeviceInfoEvent):
            if hasattr(self.sweep, "set_device_info"):
                self.sweep.set_device_info({
                    "deviceType": event.device_type,
                    "fwVersion": event.fw_version,
                    "hardwareRevision": event.hw_revision,
                    "anonymousDeviceId": event.anon_id,
                    "supportedMessageIds": event.supported_message_ids,
                    "supportedProperties": event.supported_properties,
                })
        elif isinstance(event, PropertyEvent):
            if hasattr(self.sweep, "record_report"):
                self.sweep.record_report({"properties": [{
                    "propertyId": event.property_id,
                    "channel": event.channel,
                    "value": event.raw,
                    "known": event.decoded,
                }]})
