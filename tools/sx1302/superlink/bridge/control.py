"""Operator control channel: inject application-layer commands into a *running*
bridge daemon over a Unix-domain socket, without stopping it.

Killing superlink-bridged to run command_probe.py drops the SX1302 and
red-lights the sensor (only one process may own the concentrator). Instead the
daemon listens on a control socket; an operator sends a one-line command and the
parsed Action is handed to the runtime's thread-safe submit_action(), landing on
the sensor's next 0x53 window like any other command.

Line grammar (whitespace-separated tokens, one command per line):

    device_info                       -> RequestDeviceInfo
    ping [HEXDATA]                    -> Ping
    locate                            -> Locate
    reboot                           -> Reboot
    factory_reset                    -> FactoryReset
    property_request ID[,ID...]      -> RequestProperty   (ids decimal or 0x..)
    property_set NAME_OR_ID VALUE    -> SetProperty       (profile-encoded)
    property_set_raw ID CH HEXVAL    -> SetPropertyRaw    (verbatim bytes)

An optional `mac=<12hex>` token may appear anywhere to target a specific device;
otherwise the daemon's default MAC (the single adopted device) is used.
"""
from __future__ import annotations

import logging
import os
import socket
import threading
from typing import Callable

from .events import (
    Action, RequestDeviceInfo, RequestProperty, SetProperty, SetPropertyRaw,
    Locate, Reboot, FactoryReset, Ping,
)

log = logging.getLogger("superlink.control")

DEFAULT_SOCKET_PATH = "/tmp/superlink_bridge.sock"


def _parse_value(token: str):
    """property_set value: int if it parses as one (dec or 0x..), else the string."""
    try:
        return int(token, 0)
    except ValueError:
        return token


def parse_control_line(line: str, default_mac: bytes | None) -> Action:
    """Parse one control line into an Action. Raises ValueError on any bad input."""
    tokens = line.split()
    if not tokens:
        raise ValueError("empty command")

    # Pull out an optional mac=... token from anywhere in the line.
    mac = default_mac
    rest = []
    for tok in tokens:
        if tok.lower().startswith("mac="):
            try:
                mac = bytes.fromhex(tok[4:])
            except ValueError:
                raise ValueError(f"bad mac: {tok}")
            if len(mac) != 6:
                raise ValueError(f"mac must be 6 bytes, got {len(mac)}")
        else:
            rest.append(tok)

    cmd, args = rest[0].lower(), rest[1:]
    if mac is None:
        raise ValueError(f"no target device: pass mac=<12hex> ({cmd})")

    if cmd == "device_info":
        return RequestDeviceInfo(mac=mac)
    if cmd == "locate":
        return Locate(mac=mac)
    if cmd == "reboot":
        return Reboot(mac=mac)
    if cmd == "factory_reset":
        return FactoryReset(mac=mac)
    if cmd == "ping":
        data = bytes.fromhex(args[0]) if args else b""
        return Ping(mac=mac, data=data)
    if cmd == "property_request":
        if not args:
            raise ValueError("property_request needs at least one id")
        ids = [int(x, 0) for x in args[0].split(",")]
        return RequestProperty(mac=mac, ids=ids)
    if cmd == "property_set":
        if len(args) != 2:
            raise ValueError("usage: property_set NAME_OR_ID VALUE")
        return SetProperty(mac=mac, name_or_id=_parse_value(args[0]),
                           value=_parse_value(args[1]))
    if cmd == "property_set_raw":
        if len(args) != 3:
            raise ValueError("usage: property_set_raw ID CHANNEL HEXVAL")
        return SetPropertyRaw(mac=mac, property_id=int(args[0], 0),
                              channel=int(args[1], 0), raw=bytes.fromhex(args[2]))
    raise ValueError(f"unknown command: {cmd}")


def send_command(path: str, line: str, timeout: float = 3.0) -> str:
    """Client: send one command line to a running daemon's control socket and
    return its reply ("OK: ..." / "ERR: ...")."""
    c = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    c.settimeout(timeout)
    try:
        c.connect(path)
        c.sendall((line.rstrip("\n") + "\n").encode())
        return c.recv(4096).decode("utf-8", "replace").strip()
    finally:
        c.close()


class ControlSocket:
    """Unix-domain socket listener that feeds parsed commands to a submit callback.

    One connection = one command line. The listener replies "OK: <action>" or
    "ERR: <reason>" and closes. submit() runs on the listener thread; the runtime
    provides a thread-safe submit (its action queue), so commands hop safely to
    the poll-loop thread.
    """

    def __init__(self, path: str, submit: Callable[[Action], None],
                 default_mac: Callable[[], bytes | None]):
        self.path = path
        self._submit = submit
        self._default_mac = default_mac
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._stop = False

    def start(self) -> None:
        if os.path.exists(self.path):
            os.unlink(self.path)
        self._sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._sock.bind(self.path)
        self._sock.listen(4)
        self._sock.settimeout(0.5)
        self._thread = threading.Thread(target=self._serve, name="control-socket",
                                        daemon=True)
        self._thread.start()
        log.info("control socket listening at %s", self.path)

    def _serve(self) -> None:
        while not self._stop:
            try:
                conn, _ = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            with conn:
                try:
                    self._handle(conn)
                except Exception as exc:  # noqa: BLE001 — never let one client kill the listener
                    log.warning("control client error: %s", exc)

    def _handle(self, conn: socket.socket) -> None:
        conn.settimeout(2.0)
        data = conn.recv(4096)
        if not data:
            return
        line = data.decode("utf-8", "replace").splitlines()[0] if data else ""
        try:
            action = parse_control_line(line, self._default_mac())
        except ValueError as exc:
            conn.sendall(f"ERR: {exc}\n".encode())
            return
        self._submit(action)
        log.info("control: %s", action)
        conn.sendall(f"OK: {action}\n".encode())

    def stop(self) -> None:
        self._stop = True
        if self._thread is not None:
            self._thread.join(timeout=2.0)
        if self._sock is not None:
            self._sock.close()
            self._sock = None
        if os.path.exists(self.path):
            try:
                os.unlink(self.path)
            except OSError:
                pass


def main(argv=None):
    """CLI client: `python3 -m superlink.bridge.control send "<command line>"`."""
    import argparse
    ap = argparse.ArgumentParser(description="SuperLink bridge control client")
    ap.add_argument("action", choices=["send"], help="only 'send' for now")
    ap.add_argument("command", help="control command line, e.g. 'property_set_raw 13 0 012c'")
    ap.add_argument("--socket", default=DEFAULT_SOCKET_PATH)
    args = ap.parse_args(argv)
    print(send_command(args.socket, args.command))


if __name__ == "__main__":
    main()
