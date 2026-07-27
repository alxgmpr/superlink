"""Control-channel command parser + Unix-socket listener.

The control socket lets an operator inject application-layer commands into a
*running* superlink-bridged without killing it (which would drop the SX1302 and
red-light the sensor). parse_control_line() is the pure text->Action core; the
ControlSocket thread carries it over a Unix-domain socket.
"""
import os
import socket
import tempfile
import threading
import time

import pytest


@pytest.fixture
def sock_path():
    # AF_UNIX paths are capped at ~104 bytes on macOS; pytest's tmp_path is too
    # long, so bind under a short mkdtemp in /tmp.
    d = tempfile.mkdtemp(dir="/tmp")
    yield os.path.join(d, "s")
    try:
        os.rmdir(d)
    except OSError:
        pass

from superlink.bridge.control import parse_control_line, ControlSocket, send_command
from superlink.bridge.events import (
    RequestDeviceInfo, RequestProperty, SetProperty, SetPropertyRaw,
    Locate, Reboot, FactoryReset, Ping,
)

MAC = bytes.fromhex("9041B22E9A53")
OTHER = bytes.fromhex("AABBCCDDEE99")


# --- parser: each command form maps to the right Action -------------------

def test_device_info():
    assert parse_control_line("device_info", MAC) == RequestDeviceInfo(mac=MAC)


def test_locate():
    assert parse_control_line("locate", MAC) == Locate(mac=MAC)


def test_reboot():
    assert parse_control_line("reboot", MAC) == Reboot(mac=MAC)


def test_factory_reset():
    assert parse_control_line("factory_reset", MAC) == FactoryReset(mac=MAC)


def test_ping_no_data():
    assert parse_control_line("ping", MAC) == Ping(mac=MAC, data=b"")


def test_ping_with_hex_data():
    assert parse_control_line("ping deadbeef", MAC) == Ping(mac=MAC, data=b"\xde\xad\xbe\xef")


def test_property_request_single_id():
    assert parse_control_line("property_request 13", MAC) == RequestProperty(mac=MAC, ids=[13])


def test_property_request_multiple_ids():
    assert parse_control_line("property_request 1,3,13", MAC) == RequestProperty(mac=MAC, ids=[1, 3, 13])


def test_property_request_hex_ids():
    assert parse_control_line("property_request 0x0d", MAC) == RequestProperty(mac=MAC, ids=[13])


def test_property_set_raw():
    # GOAL 1's path: REPORT_INTERVAL id=13, channel 0, value 0x012c (300s).
    assert parse_control_line("property_set_raw 13 0 012c", MAC) == \
        SetPropertyRaw(mac=MAC, property_id=13, channel=0, raw=b"\x01\x2c")


def test_property_set_by_name():
    assert parse_control_line("property_set LED_ENABLED 1", MAC) == \
        SetProperty(mac=MAC, name_or_id="LED_ENABLED", value=1)


def test_explicit_mac_overrides_default():
    assert parse_control_line("locate mac=AABBCCDDEE99", MAC) == Locate(mac=OTHER)


def test_case_insensitive_command():
    assert parse_control_line("LOCATE", MAC) == Locate(mac=MAC)


def test_blank_line_raises():
    with pytest.raises(ValueError):
        parse_control_line("   ", MAC)


def test_unknown_command_raises():
    with pytest.raises(ValueError):
        parse_control_line("frobnicate", MAC)


def test_no_default_mac_and_no_explicit_raises():
    with pytest.raises(ValueError):
        parse_control_line("locate", None)


# --- ControlSocket: real Unix socket carries a line to the submit callback --

def test_control_socket_delivers_action(sock_path):
    path = sock_path
    got = []
    cs = ControlSocket(path, submit=got.append, default_mac=lambda: MAC)
    cs.start()
    try:
        resp = _send_line(path, "locate")
        # give the handler a moment to invoke submit
        deadline = time.time() + 2
        while not got and time.time() < deadline:
            time.sleep(0.01)
        assert got == [Locate(mac=MAC)]
        assert resp.startswith("OK")
    finally:
        cs.stop()


def test_control_socket_reports_parse_error(sock_path):
    path = sock_path
    got = []
    cs = ControlSocket(path, submit=got.append, default_mac=lambda: MAC)
    cs.start()
    try:
        resp = _send_line(path, "frobnicate")
        assert got == []
        assert resp.startswith("ERR")
    finally:
        cs.stop()


def test_control_socket_stop_removes_socket_file(sock_path):
    path = sock_path
    cs = ControlSocket(path, submit=lambda a: None, default_mac=lambda: MAC)
    cs.start()
    assert os.path.exists(path)
    cs.stop()
    assert not os.path.exists(path)


def test_send_command_client_round_trips(sock_path):
    path = sock_path
    got = []
    cs = ControlSocket(path, submit=got.append, default_mac=lambda: MAC)
    cs.start()
    try:
        resp = send_command(path, "reboot")
        deadline = time.time() + 2
        while not got and time.time() < deadline:
            time.sleep(0.01)
        assert got == [Reboot(mac=MAC)]
        assert resp.startswith("OK")
    finally:
        cs.stop()


def _send_line(path: str, line: str) -> str:
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.settimeout(2)
    c.connect(path)
    c.sendall((line + "\n").encode())
    data = c.recv(4096)
    c.close()
    return data.decode().strip()
