import pytest
from superlink.bridge.config import RuntimeConfig, ADOPT_ALL, DEFAULT_PAIRING_KEY
from superlink.bridge.control import DEFAULT_SOCKET_PATH

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


def test_control_socket_defaults_on(tmp_path):
    c = RuntimeConfig.load(_write(tmp_path, YAML_ALL))
    assert c.control_socket == DEFAULT_SOCKET_PATH


def test_control_socket_explicit_path(tmp_path):
    c = RuntimeConfig.load(_write(
        tmp_path, 'gw_mac: "010203040506"\nadopt: all\ncontrol_socket: "/tmp/x.sock"\n'))
    assert c.control_socket == "/tmp/x.sock"


def test_link_lost_timeout_default_and_override(tmp_path):
    c = RuntimeConfig.load(_write(tmp_path, YAML_ALL))
    assert c.link_lost_timeout == 60.0
    c2 = RuntimeConfig.load(_write(
        tmp_path, 'gw_mac: "010203040506"\nadopt: all\nlink_lost_timeout: 45\n'))
    assert c2.link_lost_timeout == 45.0


def test_watchdog_defaults_and_override(tmp_path):
    c = RuntimeConfig.load(_write(tmp_path, YAML_ALL))
    assert c.watchdog_timeout == 150.0
    assert c.watchdog_short_challenge_k == 3
    c2 = RuntimeConfig.load(_write(
        tmp_path, 'gw_mac: "010203040506"\nadopt: all\n'
                  'watchdog_timeout: 200\nwatchdog_short_challenge_k: 5\n'))
    assert c2.watchdog_timeout == 200.0
    assert c2.watchdog_short_challenge_k == 5


def test_control_socket_disabled(tmp_path):
    c = RuntimeConfig.load(_write(
        tmp_path, 'gw_mac: "010203040506"\nadopt: all\ncontrol_socket: null\n'))
    assert c.control_socket is None
