"""Tests for the PropertySweep controller."""
import pytest
from superlink.sweep import PropertySweep, parse_id_spec
from superlink import appmsg


def test_parse_id_spec_all():
    assert parse_id_spec("all") == list(range(256))


def test_parse_id_spec_undefined_excludes_defined():
    ids = parse_id_spec("undefined")
    assert 43 in ids and 0 in ids and 18 in ids   # undefined
    assert 1 not in ids and 42 not in ids          # defined
    assert ids == sorted(set(range(256)) - appmsg.DEFINED_PROPERTY_IDS)


def test_parse_id_spec_ranges_and_singles():
    assert parse_id_spec("1,2,5-8,255") == [1, 2, 5, 6, 7, 8, 255]


def test_parse_id_spec_rejects_out_of_range():
    with pytest.raises(ValueError):
        parse_id_spec("300")


def _device_info():
    return {
        "messageId": 10,
        "supportedProperties": [
            {"propertyId": 1, "channelCount": 1, "valueSize": 4},
            {"propertyId": 3, "channelCount": 1, "valueSize": 1},
        ],
        "anonymousDeviceId": bytes(range(16)),
    }


def test_next_batch_advances_and_exhausts():
    sw = PropertySweep(ids=[1, 2, 3, 4, 5], batch_size=2)
    assert sw.next_batch() == [1, 2]
    assert sw.next_batch() == [3, 4]
    assert sw.next_batch() == [5]
    assert sw.next_batch() == []
    assert sw.done()


def test_not_done_until_all_batches_handed_out():
    sw = PropertySweep(ids=[1, 2, 3], batch_size=8)
    assert not sw.done()
    assert sw.next_batch() == [1, 2, 3]
    assert sw.done()


def test_default_probes_full_byte_range():
    sw = PropertySweep()
    all_ids = []
    while (b := sw.next_batch()):
        all_ids.extend(b)
    assert all_ids == list(range(256))


def test_set_device_info_builds_size_map():
    sw = PropertySweep()
    sw.set_device_info(_device_info())
    assert sw.sizes == {1: 4, 3: 1}
    assert sw.anonymous_device_id == bytes(range(16))


def test_record_report_flags_undefined_id_with_data():
    """An undefined property id (43) returning bytes is the payoff — a
    candidate out-of-bounds read. It must be flagged."""
    sw = PropertySweep(ids=[43])
    sw.next_batch()
    report = appmsg.decode_message(
        bytes([0x0c, 0x00, 43, 0x00, 0xde, 0xad, 0xbe, 0xef]),
        sizes=sw.sizes,
    )
    sw.record_report(report)
    findings = sw.findings
    assert len(findings) == 1
    assert findings[0]["propertyId"] == 43
    assert findings[0]["value"] == bytes.fromhex("deadbeef")
    assert "undefined_property_id" in findings[0]["reasons"]


def test_record_report_defined_id_not_flagged():
    sw = PropertySweep(ids=[1])
    sw.set_device_info(_device_info())
    sw.next_batch()
    report = appmsg.decode_message(
        bytes([0x0c, 0x00, 1, 0x00, 0x00, 0x00, 0x01, 0x00]),
        sizes=sw.sizes,
    )
    sw.record_report(report)
    assert sw.findings == []
    # ...but the response is still recorded for the baseline.
    assert 1 in sw.responses


def test_record_report_flags_unadvertised_defined_id():
    """A firmware-defined id the device did NOT advertise, yet answered with
    data, is a weaker but real disclosure signal."""
    sw = PropertySweep(ids=[4])          # LEAK_DETECTED, not on a motion sensor
    sw.set_device_info(_device_info())   # advertises only {1, 3}
    sw.next_batch()
    report = appmsg.decode_message(
        bytes([0x0c, 0x00, 4, 0x00, 0x01]), sizes=sw.sizes)
    sw.record_report(report)
    assert len(sw.findings) == 1
    assert sw.findings[0]["reasons"] == ["unadvertised_property"]


def test_summary_counts():
    sw = PropertySweep(ids=[1, 43])
    sw.next_batch()
    sw.record_report(appmsg.decode_message(
        bytes([0x0c, 0x00, 1, 0x00, 0x2a]), sizes={}))
    sw.record_report(appmsg.decode_message(
        bytes([0x0c, 0x00, 43, 0x00, 0x99]), sizes={}))
    s = sw.summary()
    assert s["probed"] == 2
    assert s["responded"] == 2
    assert s["findings"] == 1
