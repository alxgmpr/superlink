import pytest
from superlink.bridge.config import RuntimeConfig, ADOPT_ALL, DEFAULT_PAIRING_KEY

YAML_LIST = """
gw_mac: "010203040506"
pairing_key: null
store_path: "devs.json"
adopt: ["9041b22e9a53", "AABBCCDDEEFF"]
downlink_delay_us: 900000
invert_iq: true
log:
  level: "DEBUG"
  csv: "events.csv"
"""

YAML_ALL = """
gw_mac: "010203040506"
adopt: all
"""


def _write(tmp_path, text):
    p = tmp_path / "c.yaml"
    p.write_text(text)
    return str(p)


def test_load_list(tmp_path):
    c = RuntimeConfig.load(_write(tmp_path, YAML_LIST))
    assert c.gw_mac == bytes.fromhex("010203040506")
    assert c.pairing_key == DEFAULT_PAIRING_KEY        # null -> default
    assert c.adopt == {bytes.fromhex("9041b22e9a53"), bytes.fromhex("aabbccddeeff")}
    assert c.downlink_delay_us == 900000
    assert c.burst_spacing_us == 500000                 # default
    assert c.invert_iq is True
    assert c.log_level == "DEBUG" and c.csv_path == "events.csv"


def test_is_allowed_list(tmp_path):
    c = RuntimeConfig.load(_write(tmp_path, YAML_LIST))
    assert c.is_allowed(bytes.fromhex("9041b22e9a53")) is True
    assert c.is_allowed(bytes.fromhex("001122334455")) is False


def test_adopt_all(tmp_path):
    c = RuntimeConfig.load(_write(tmp_path, YAML_ALL))
    assert c.adopt is ADOPT_ALL
    assert c.is_allowed(bytes.fromhex("001122334455")) is True


def test_bad_gw_mac(tmp_path):
    with pytest.raises(ValueError):
        RuntimeConfig.load(_write(tmp_path, 'gw_mac: "0102"\nadopt: all\n'))
