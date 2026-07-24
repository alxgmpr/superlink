"""Pure translation between application-layer messages and typed events/actions."""
from __future__ import annotations
from .. import appmsg
from .events import (
    Event, Action, PropertyEvent, DeviceInfoEvent, RawMessageEvent,
    SetProperty, SetPropertyRaw, RequestProperty, RequestDeviceInfo,
    Locate, Reboot, FactoryReset, Ping,
)
from .profiles import ProfileRegistry


def events_from_app_message(mac, body, profiles: ProfileRegistry,
                            sizes=None, device_type=None) -> list[Event]:
    if len(body) < 2:
        return []
    msg = appmsg.decode_message(body, sizes=sizes)
    msg_id = msg["messageId"]

    if msg_id == appmsg.MessageId.DEVICE_INFO_REPORT:
        return [DeviceInfoEvent(
            mac=mac, device_type=msg["deviceType"], fw_version=msg["fwVersion"],
            hw_revision=msg["hardwareRevision"], anon_id=msg["anonymousDeviceId"],
            supported_message_ids=msg["supportedMessageIds"],
            supported_properties=msg["supportedProperties"])]

    if msg_id in (appmsg.MessageId.PROPERTY_REPORT, appmsg.MessageId.PROPERTY_SET):
        out = []
        for p in msg["properties"]:
            pid, raw = p["propertyId"], p["value"]
            value, unit, decoded = profiles.decode(pid, raw, device_type)
            out.append(PropertyEvent(
                mac=mac, property_id=pid, name=profiles.name(pid),
                channel=p["channel"], raw=raw, value=value, unit=unit,
                decoded=decoded))
        return out

    return [RawMessageEvent(mac=mac, message_id=msg_id, body=bytes(body[2:]))]


def action_to_body(action: Action, profiles: ProfileRegistry,
                   tag: int = 0, device_type=None) -> bytes:
    if isinstance(action, SetProperty):
        pid, raw = profiles.encode(action.name_or_id, action.value, device_type)
        return appmsg.encode_property_set([(pid, 0, raw)], tag=tag)
    if isinstance(action, SetPropertyRaw):
        return appmsg.encode_property_set([(action.property_id, action.channel, action.raw)], tag=tag)
    if isinstance(action, RequestProperty):
        return appmsg.encode_property_request(action.ids, tag=tag)
    if isinstance(action, RequestDeviceInfo):
        return appmsg.encode_device_info_request(tag=tag)
    if isinstance(action, Ping):
        return appmsg.encode_ping_request(tag=tag, data=action.data)
    if isinstance(action, Locate):
        return appmsg.encode_locate(tag=tag)
    if isinstance(action, Reboot):
        return appmsg.encode_reboot(tag=tag)
    if isinstance(action, FactoryReset):
        return appmsg.encode_factory_reset(tag=tag)
    raise TypeError(f"{type(action).__name__} has no application-layer body")
