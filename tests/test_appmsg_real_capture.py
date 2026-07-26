"""Ground-truth decode of REAL controller<->bridge application-layer bodies.

Payloads lifted verbatim from captures/live/bridge_adopt_fresh_pass2_DECODED.txt
(the genuine UniFi Protect controller talking to sensor 90:41:B2:2E:9A:53 over
the Ubiquiti bridge). These are the plaintext bodies inside the encrypted LoRa
frames, exactly what our codec consumes — so decoding them correctly proves the
codec against the real implementation, not just against our own encoders.
"""
from superlink import appmsg

# JSON 64, BR->CTL, msgId 0x0a DEVICE_INFO_REPORT
DEVICE_INFO_REPORT = bytes.fromhex(
    "0A37AE940001000100010CB24D9D0452B4BA379A5749018003AB8809AC01FB"
    "03080F110E01010402010311010A0D01020E01012001011202061301040301"
    "041401011501011601010F0101100101")

# JSON 62, BR->CTL, msgId 0x0c PROPERTY_REPORT (device's spontaneous report)
PROPERTY_REPORT = bytes.fromhex("0C00010000000006020064DD080300590B7C00140001")

# JSON 66 CTL->BR PROPERTY_SET REPORT_INTERVAL=0x012c, JSON 74 BR->CTL readback
PROPERTY_SET_REQUEST = bytes.fromhex("0e380d00012c")
PROPERTY_REPORT_READBACK = bytes.fromhex("0C380D00012C")


def test_real_device_info_report_decodes():
    r = appmsg.decode_message(DEVICE_INFO_REPORT)
    assert r["messageId"] == appmsg.MessageId.DEVICE_INFO_REPORT
    assert r["messageTag"] == 0x37
    assert r["deviceType"] == 0xAE94        # entry sensor
    assert r["fwVersion"] == (1, 1, 1)      # v2 firmware 1.1.1
    assert r["fwBuildId"] == "cb24d9d"
    assert r["hardwareRevision"] == 4
    assert r["supportedMessageIds"] == [8, 15, 17]   # LOCATE, FW_UPDATE, PROPERTY_REQ
    # 14 properties; the entry-sensor signature (ENTRY/TAMPER/BUTTON) is present.
    names = {appmsg.property_name(p["propertyId"])
             for p in r["supportedProperties"]}
    assert {"UPTIME", "BATTERY", "ENTRY_DETECTED", "TAMPER_DETECTED",
            "BUTTON_PRESSED", "LED_ENABLED"} <= names


def test_real_property_report_decodes_with_learned_sizes():
    """The size map from the DEVICE_INFO_REPORT must parse the sensor's own
    PROPERTY_REPORT into clean, fully-known fixed-size values."""
    sizes = appmsg.property_sizes(appmsg.decode_message(DEVICE_INFO_REPORT))
    r = appmsg.decode_message(PROPERTY_REPORT, sizes=sizes)
    props = {p["propertyId"]: p for p in r["properties"]}
    assert all(p["known"] for p in r["properties"])
    assert set(props) == {1, 2, 3, 20}                       # UPTIME,SIGNAL,BATTERY,TAMPER
    assert props[1]["value"] == bytes.fromhex("00000006")    # UPTIME = 6s
    assert props[20]["value"] == b"\x01"                     # TAMPER_DETECTED = 1
    assert len(props[2]["value"]) == 3                       # SIGNAL, sz 3
    assert len(props[3]["value"]) == 4                       # BATTERY, sz 4


def test_real_property_set_readback_roundtrip():
    """A PROPERTY_SET(REPORT_INTERVAL=300) and the device's PROPERTY_REPORT
    read-back carry the same encoded value — the read-back-confirms pattern."""
    sizes = appmsg.property_sizes(appmsg.decode_message(DEVICE_INFO_REPORT))
    # The controller's PROPERTY_SET body encodes REPORT_INTERVAL(13) ch0 = 012c.
    assert appmsg.encode_property_set(
        [(13, 0, bytes.fromhex("012c"))], tag=0x38) == PROPERTY_SET_REQUEST
    # The device's read-back reports the same value.
    rb = appmsg.decode_message(PROPERTY_REPORT_READBACK, sizes=sizes)
    entry = rb["properties"][0]
    assert entry["propertyId"] == 13 and entry["value"] == bytes.fromhex("012c")
    assert int.from_bytes(entry["value"], "big") == 300      # seconds
