"""In-memory HAL double for runtime tests. Records sends; replays a queued inbox."""
from types import SimpleNamespace


def make_packet(payload: bytes, ul_channel: int = 1, timestamp_us: int = 1000,
                crc_ok: bool = True):
    """Minimal stand-in exposing the 4 attrs BridgeRuntime reads off an RxPacket."""
    return SimpleNamespace(payload=payload, ul_channel=ul_channel,
                           timestamp_us=timestamp_us, crc_ok=crc_ok)


class FakeHal:
    def __init__(self, inbox=None, fail_on_send_index=None):
        self.inbox = list(inbox or [])
        self.sent = []            # list of dicts
        self.started = False
        self.stopped = False
        self._fail_idx = fail_on_send_index
        self._send_calls = 0      # total send() invocations, including failures

    def start(self, *a, **k):
        self.started = True

    def stop(self):
        self.stopped = True

    def version(self):
        return "fake-hal"

    def receive(self):
        pkts, self.inbox = self.inbox, []
        return pkts

    def send(self, freq_hz, payload, bandwidth=None, tx_timestamp_us=0,
             invert_pol=False):
        idx = self._send_calls
        self._send_calls += 1
        if self._fail_idx is not None and idx == self._fail_idx:
            raise RuntimeError("simulated lgw_send failure")
        self.sent.append({"freq_hz": freq_hz, "payload": bytes(payload),
                          "tx_timestamp_us": tx_timestamp_us,
                          "invert_pol": invert_pol})
