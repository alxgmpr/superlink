"""SuperLink application-layer message codec.

Ported from UniFi Protect (UNVR fw v5.0.16, webpack module 41118 =
helpers/applicationLayer/messages.ts, property ids from module 17695).
These messages are the *body* of the encrypted 0x74/0x54 LoRa frames.

Wire format:
    [1B messageId] [1B messageTag] [payload...]

Only the subset the gateway needs is implemented: the two probe encoders
(DEVICE_INFO_REQUEST, PROPERTY_REQUEST) and the report decoders we expect
back. PROPERTY_REQUEST does NOT validate ids — that is deliberate: sending
undefined property ids (0, 18, 43-255) to a paired sensor probes its
property dispatch for out-of-bounds reads (see docs / memory
property_request_read_primitive).
"""

from __future__ import annotations


# MessageId enum (module 41118).
class MessageId:
    REQUEST_STATUS_RESPONSE = 1
    ADOPT_REQUEST = 2
    ADOPT_RESPONSE = 3
    PING_REQUEST = 4
    PING_RESPONSE = 5
    REBOOT = 6
    FACTORY_RESET = 7
    LOCATE = 8
    DEVICE_INFO_REQUEST = 9
    DEVICE_INFO_REPORT = 10
    PROPERTY_REQUEST = 11
    PROPERTY_REPORT = 12
    PROPERTY_SET = 14
    FIRMWARE_UPDATE_START = 15
    FIRMWARE_CHUNK_REQUEST = 16
    FIRMWARE_CHUNK_RESPONSE = 17


# PropertyId enum (module 17695). Note the gaps: no 18, nothing above 42.
PROPERTY_NAMES = {
    1: "UPTIME", 2: "SIGNAL", 3: "BATTERY", 4: "LEAK_DETECTED",
    5: "LEAK_AUX_CONNECTED", 6: "LEAK_CONFIG", 7: "TEMPERATURE",
    8: "TEMPERATURE_CONFIG", 9: "HUMIDITY", 10: "HUMIDITY_CONFIG",
    11: "AMBIENT_LIGHT", 12: "AMBIENT_LIGHT_CONFIG", 13: "REPORT_INTERVAL",
    14: "LED_ENABLED", 15: "ENTRY_DETECTED", 16: "ENTRY_CONFIG",
    17: "FIRMWARE_VERSION", 19: "BUTTON_PRESSED", 20: "TAMPER_DETECTED",
    21: "TAMPER_CONFIG", 22: "TAMPER_CLEAR", 23: "MOTION_DETECTED",
    24: "MOTION_CONFIG", 25: "ACCELERATION", 26: "ACCELERATION_CONFIG",
    27: "SMOKE_STATUS", 28: "SMOKE_ALARM_SILENCE", 29: "SMOKE_TROUBLE_SILENCE",
    30: "SMOKE_TEST", 31: "SMOKE_REMOTE_STATUS", 32: "LED_FEEDBACK_CONFIG",
    33: "GLASS_BREAK_DETECTED", 34: "GLASS_BREAK_CLEAR", 35: "GLASS_BREAK_CONFIG",
    36: "ALARM_SOUND_CONTROL", 37: "ALARM_SOUND_CONFIG", 38: "ALARM_LIGHT_CONTROL",
    39: "ALARM_LIGHT_CONFIG", 40: "BUTTON_LONG_PRESSED",
    41: "BUTTON_DOUBLE_PRESSED", 42: "BUTTON_CONFIG",
}

# Ids the firmware defines. Anything outside this set is a probe candidate.
DEFINED_PROPERTY_IDS = frozenset(PROPERTY_NAMES)


class FirmwareChunkStatus:
    CONTINUE = 0
    ERROR = 1
    COMPLETED = 2


def property_name(property_id: int) -> str:
    """Human name for a property id, or UNKNOWN_<n> for undefined ids."""
    return PROPERTY_NAMES.get(property_id, f"UNKNOWN_{property_id}")


# ---- encoders ----

def encode_device_info_request(tag: int = 0) -> bytes:
    """DEVICE_INFO_REQUEST body: [9, tag]. No payload."""
    return bytes([MessageId.DEVICE_INFO_REQUEST, tag & 0xFF])


def encode_property_request(property_ids, tag: int = 0) -> bytes:
    """PROPERTY_REQUEST body: [11, tag, id...].

    Ids are written verbatim with no validation beyond byte range — this is
    the point (probe undefined ids). Raises ValueError only if an id does not
    fit in a byte.
    """
    ids = list(property_ids)
    for i in ids:
        if not 0 <= i <= 0xFF:
            raise ValueError(f"property id {i} out of byte range 0-255")
    return bytes([MessageId.PROPERTY_REQUEST, tag & 0xFF]) + bytes(ids)


# ---- decoders ----

def decode_message(body: bytes, sizes: dict | None = None) -> dict:
    """Decode an application-layer message body ([msgId][tag][payload]).

    Args:
        body: full message body including the 2-byte header.
        sizes: propertyId -> value size map (0 = dynamic length-prefixed),
            required to parse PROPERTY_REPORT / PROPERTY_SET. Obtain it from a
            DEVICE_INFO_REPORT via property_sizes().

    Returns a dict with at least messageId and messageTag.
    """
    if len(body) < 2:
        raise ValueError("message body too short for header")
    msg_id = body[0]
    tag = body[1]
    s = body[2:]
    base = {"messageId": msg_id, "messageTag": tag}

    if msg_id == MessageId.REQUEST_STATUS_RESPONSE:
        if len(s) < 1:
            raise ValueError("short REQUEST_STATUS_RESPONSE")
        return {**base, "statusCode": s[0]}

    if msg_id in (MessageId.PING_REQUEST, MessageId.PING_RESPONSE):
        return {**base, "data": bytes(s)}

    if msg_id == MessageId.DEVICE_INFO_REPORT:
        return {**base, **_decode_device_info_report(s)}

    if msg_id == MessageId.PROPERTY_REQUEST:
        return {**base, "propertyIds": list(s)}

    if msg_id in (MessageId.PROPERTY_REPORT, MessageId.PROPERTY_SET):
        return {**base, "properties": _decode_properties(s, sizes or {})}

    if msg_id == MessageId.FIRMWARE_CHUNK_REQUEST:
        if len(s) < 9:
            raise ValueError("short FIRMWARE_CHUNK_REQUEST")
        return {**base,
                "size": int.from_bytes(s[0:4], "big"),
                "offset": int.from_bytes(s[4:8], "big"),
                "status": s[8]}

    return {**base, "raw": bytes(s)}


def _decode_device_info_report(s: bytes) -> dict:
    if len(s) < 29:
        raise ValueError("short DEVICE_INFO_REPORT")
    e = 0

    def u16():
        nonlocal e
        v = int.from_bytes(s[e:e + 2], "big")
        e += 2
        return v

    device_type = u16()
    major = u16()
    minor = u16()
    patch = u16()
    build_id = format(int.from_bytes(s[e:e + 4], "big"), "x")
    e += 4
    hw_rev = s[e]
    e += 1
    anon_id = bytes(s[e:e + 16])
    e += 16

    msg_count = s[e]
    e += 1
    supported_msgs = list(s[e:e + msg_count])
    e += msg_count

    prop_count = s[e]
    e += 1
    props = []
    for _ in range(prop_count):
        props.append({
            "propertyId": s[e],
            "channelCount": s[e + 1],
            "valueSize": s[e + 2],
        })
        e += 3

    return {
        "deviceType": device_type,
        "fwVersion": (major, minor, patch),
        "fwBuildId": build_id,
        "hardwareRevision": hw_rev,
        "anonymousDeviceId": anon_id,
        "supportedMessageIds": supported_msgs,
        "supportedProperties": props,
    }


def _decode_properties(s: bytes, sizes: dict) -> list:
    """Parse a PROPERTY_REPORT/PROPERTY_SET value list.

    For ids present in `sizes` we honor the declared size (0 => dynamic,
    length-prefixed). For an id NOT in the map — the interesting fuzzing
    case — we cannot know its size, so we grab the rest of the buffer as an
    opaque value, mark it known=False, and stop.
    """
    out = []
    i = 0
    n = len(s)
    while i < n:
        if i + 2 > n:
            break
        prop_id = s[i]
        channel = s[i + 1]
        i += 2
        if prop_id in sizes:
            size = sizes[prop_id]
            if size == 0:  # dynamic
                if i >= n:
                    break
                vlen = s[i]
                i += 1
                value = bytes(s[i:i + vlen])
                i += vlen
            else:
                value = bytes(s[i:i + size])
                i += size
            out.append({"propertyId": prop_id, "channel": channel,
                        "value": value, "known": True})
        else:
            # Unknown id: capture remaining bytes raw and stop.
            out.append({"propertyId": prop_id, "channel": channel,
                        "value": bytes(s[i:]), "known": False})
            break
    return out


def property_sizes(device_info: dict) -> dict:
    """Build propertyId -> valueSize map from a decoded DEVICE_INFO_REPORT."""
    return {p["propertyId"]: p["valueSize"]
            for p in device_info.get("supportedProperties", [])}
