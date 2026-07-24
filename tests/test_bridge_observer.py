from superlink.bridge.observers import SweepObserver
from superlink.bridge.events import PropertyEvent, DeviceInfoEvent

MAC = bytes.fromhex("9041B22E9A53")


class FakeSweep:
    def __init__(self):
        self.reports = []
        self.findings = []
        self.sizes = {}
        self.infos = []

    def record_report(self, report):
        self.reports.append(report)

    def set_device_info(self, report):
        self.infos.append(report)


class FakeCore:
    def __init__(self):
        self.submitted = []

    def submit(self, action):
        self.submitted.append(action)


def test_observer_forwards_property_events_to_sweep():
    core, sweep = FakeCore(), FakeSweep()
    obs = SweepObserver(core, sweep)
    obs.on_event(PropertyEvent(mac=MAC, property_id=3, name="BATTERY",
                               channel=0, raw=b"\x64", value=100, unit="%", decoded=True))
    assert len(sweep.reports) == 1


def test_observer_forwards_device_info_events_to_sweep():
    core, sweep = FakeCore(), FakeSweep()
    obs = SweepObserver(core, sweep)
    obs.on_event(DeviceInfoEvent(
        mac=MAC, device_type=0x1234, fw_version=(1, 1, 1), hw_revision=2,
        anon_id=b"\x00" * 8, supported_message_ids=[1, 2, 3],
        supported_properties=[{"propertyId": 3, "valueSize": 1}]))
    assert len(sweep.infos) == 1


def test_observer_ignores_unrelated_events():
    core, sweep = FakeCore(), FakeSweep()
    obs = SweepObserver(core, sweep)

    class Other:
        pass

    obs.on_event(Other())
    assert sweep.reports == []
    assert sweep.infos == []
