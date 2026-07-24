from superlink.bridge.store import DeviceRecord, InMemoryDeviceStore, JsonDeviceStore

MAC = bytes.fromhex("9041B22E9A53")


def _rec():
    return DeviceRecord(mac=MAC, device_type=0x0100,
                        primary_key=b"\x11" * 32, fallback_key=b"\x22" * 32,
                        adopted=True, tx_seq_hi=5, ul_counter_offset=5,
                        last_seen=123.0)


def test_inmemory_roundtrip():
    s = InMemoryDeviceStore()
    s.save(_rec())
    got = s.load_all()
    assert len(got) == 1 and got[0].mac == MAC and got[0].primary_key == b"\x11" * 32


def test_inmemory_save_is_upsert_and_delete():
    s = InMemoryDeviceStore()
    s.save(_rec())
    s.save(DeviceRecord(mac=MAC, device_type=0x0200))  # overwrite
    assert s.load_all()[0].device_type == 0x0200
    s.delete(MAC)
    assert s.load_all() == []


def test_json_roundtrip(tmp_path):
    path = str(tmp_path / "devices.json")
    s = JsonDeviceStore(path)
    s.save(_rec())
    reloaded = JsonDeviceStore(path).load_all()
    assert len(reloaded) == 1
    r = reloaded[0]
    assert r.mac == MAC and r.fallback_key == b"\x22" * 32 and r.adopted is True
