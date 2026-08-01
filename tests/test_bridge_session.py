"""Tests for the extracted DeviceSession (new bridge surface)."""
from superlink.bridge.session import DeviceSession
from superlink.bridge.core import OutgoingFrame
from superlink.bridge.store import DeviceRecord
from superlink.bridge.profiles import ProfileRegistry
from superlink.bridge.events import Event
from tests.fixtures.captured_frames import (
    SENSOR_MAC, DEFAULT_PAIRING_KEY, FRAME_36B_RAW,
)

GW_MAC = bytes.fromhex("0102030405")  # 5-byte gw mac used by gateway today


def _session():
    return DeviceSession(DeviceRecord(mac=SENSOR_MAC), gw_mac=GW_MAC,
                         pairing_key=DEFAULT_PAIRING_KEY,
                         profiles=ProfileRegistry.load())


def test_feed_returns_frames_and_events_tuple():
    from superlink.decoder import parse_frame
    s = _session()
    frame = parse_frame(FRAME_36B_RAW)   # real parsed SuperLinkFrame
    result = s.feed(frame, channel=1, now=1.0)
    assert isinstance(result, tuple) and len(result) == 2
    frames, events = result
    assert isinstance(frames, list) and isinstance(events, list)


def test_to_record_roundtrips_identity():
    s = _session()
    rec = s.to_record()
    assert rec.mac == SENSOR_MAC


def test_to_record_persists_learned_prop_sizes():
    s = _session()
    s._prop_sizes = {1: 4, 3: 4, 15: 1}
    assert s.to_record().prop_sizes == {1: 4, 3: 4, 15: 1}


def test_prop_sizes_restored_from_record():
    # A restart rebuilds sessions from the store; the learned property-size map
    # must come back so PROPERTY_REPORTs decode into typed events immediately,
    # rather than collapsing to a single opaque property until device info is
    # re-requested on the next reconnect.
    rec = DeviceRecord(mac=SENSOR_MAC, prop_sizes={1: 4, 7: 2})
    s = DeviceSession(rec, gw_mac=GW_MAC, pairing_key=DEFAULT_PAIRING_KEY,
                      profiles=ProfileRegistry.load())
    assert s._prop_sizes == {1: 4, 7: 2}


def test_beacon_emitted_on_tick_when_due_and_enabled():
    s = DeviceSession(DeviceRecord(mac=SENSOR_MAC), gw_mac=GW_MAC,
                      pairing_key=DEFAULT_PAIRING_KEY, profiles=ProfileRegistry.load(),
                      beacon_enabled=True)
    s.start(now=0.0)                    # enter BEACONING
    frames, _ = s.tick(now=1000.0)      # well past beacon_interval
    assert any(isinstance(f, OutgoingFrame) for f in frames)


def test_no_beacon_emitted_by_default():
    # The beacon frame format is unverified (dctrl stub); TX must stay off until
    # Track A captures the real beacon. Default sessions never emit one.
    s = _session()
    s.start(now=0.0)
    frames, _ = s.tick(now=1000.0)      # well past beacon_interval, but disabled
    assert frames == []


# --- v2 firmware support: discovery-ad recognition + version-aware KDF ctx ---

# Decrypted 0x40 discovery payloads. v1 firmware: 01 ae94 NN 00000000 (8B).
# v2 firmware: 02 ae94 NN 00000000 0002 (10B). The ae94 marker is stable across
# versions; the leading byte is the protocol version.
V1_DISCOVERY_PAYLOAD = bytes.fromhex("01ae940000000000")
V2_DISCOVERY_PAYLOAD = bytes.fromhex("02ae9431000000000002")


def test_is_discovery_ad_accepts_v1_and_v2():
    from superlink.bridge.session import is_discovery_ad
    assert is_discovery_ad(V1_DISCOVERY_PAYLOAD)
    assert is_discovery_ad(V2_DISCOVERY_PAYLOAD)


def test_is_discovery_ad_rejects_non_discovery():
    from superlink.bridge.session import is_discovery_ad
    assert not is_discovery_ad(None)
    assert not is_discovery_ad(b"")
    assert not is_discovery_ad(b"\x01\x02\x03")           # too short
    assert not is_discovery_ad(bytes.fromhex("01dead0000000000"))  # wrong marker
    assert not is_discovery_ad(bytes.fromhex("03ae940000000000"))  # unknown version


def test_initial_pairing_kdf_context_is_version_aware():
    from superlink.bridge.session import (
        initial_pairing_kdf_context, LORA_DEVICE_DEFAULT_ADOPTION_KEY,
    )
    # v1 firmware seeds the session KDF with the pairing key ...
    assert initial_pairing_kdf_context(
        V1_DISCOVERY_PAYLOAD, DEFAULT_PAIRING_KEY) == DEFAULT_PAIRING_KEY
    # ... v2 firmware seeds it with the global default adoption key.
    assert initial_pairing_kdf_context(
        V2_DISCOVERY_PAYLOAD, DEFAULT_PAIRING_KEY) == LORA_DEVICE_DEFAULT_ADOPTION_KEY


def test_default_adoption_key_value():
    from superlink.bridge.session import LORA_DEVICE_DEFAULT_ADOPTION_KEY
    assert LORA_DEVICE_DEFAULT_ADOPTION_KEY == bytes.fromhex(
        "c5923a86e166e4bf3f8959643ff1c245f986115ec34946ded0b87dc0d7bd38db")


def _craft_discovery_frame(payload: bytes):
    """Build a real encrypted 0x40 discovery frame (pairing key, counter 0)."""
    from superlink.decoder import build_frame, compute_mic, parse_frame
    header = bytes([0xE0, 0x40]) + SENSOR_MAC + bytes([0x00, 0x00])
    mic = compute_mic(header, payload)
    raw = build_frame(0xE0, 0x40, SENSOR_MAC, 0x00, 0x00, mic, payload,
                      DEFAULT_PAIRING_KEY, counter=0)
    return parse_frame(raw)


def test_v2_discovery_is_answered_with_connrsp():
    # The old payload[0]==0x01 gate silently dropped v2 discovery (leading 0x02),
    # so the gateway never replied. It must now answer with a ConnRsp.
    s = _session()
    s.start(now=0.0)
    frame = _craft_discovery_frame(V2_DISCOVERY_PAYLOAD)
    frames, _ = s.feed(frame, channel=1, now=1.0)
    assert any(isinstance(f, OutgoingFrame) for f in frames), \
        "v2 discovery should be answered with a ConnRsp"


def test_v2_discovery_selects_adoption_kdf_context():
    from superlink.bridge.session import LORA_DEVICE_DEFAULT_ADOPTION_KEY
    s = _session()
    s.start(now=0.0)
    s.feed(_craft_discovery_frame(V2_DISCOVERY_PAYLOAD), channel=1, now=1.0)
    assert s._kdf_context == LORA_DEVICE_DEFAULT_ADOPTION_KEY


def test_v1_discovery_keeps_pairing_key_kdf_context():
    s = _session()
    s.start(now=0.0)
    s.feed(_craft_discovery_frame(V1_DISCOVERY_PAYLOAD), channel=1, now=1.0)
    assert s._kdf_context == DEFAULT_PAIRING_KEY


def test_explicit_kdf_context_override_is_not_clobbered_by_version():
    # An operator-supplied --kdf-context must survive a v2 discovery.
    override = bytes(range(32))
    s = DeviceSession(DeviceRecord(mac=SENSOR_MAC), gw_mac=GW_MAC,
                      pairing_key=DEFAULT_PAIRING_KEY, kdf_context=override,
                      profiles=ProfileRegistry.load())
    s.start(now=0.0)
    s.feed(_craft_discovery_frame(V2_DISCOVERY_PAYLOAD), channel=1, now=1.0)
    assert s._kdf_context == override


# --- commit observation emits a persistable "adopted" state event ---

# Adopted-form v2 discovery: non-zero networkId trailer (0x048f) is the reliable
# commit discriminator (unadopted-form carries 00000000).
ADOPTED_DISCOVERY_PAYLOAD = bytes.fromhex("02ae94950000048f0002")


def test_commit_observed_emits_adopted_state_event():
    """When the sensor commits (adopted-form 0x40 while _adopt_pending), the
    session must EMIT DeviceStateEvent(state="adopted") so the runtime persists
    the rotated addDevice keys to disk. Without this event the commit rotates
    keys in memory but nothing writes them out until a graceful SIGINT — a
    restart in between loses the keys."""
    from superlink.bridge.events import DeviceStateEvent
    s = _session()
    s.start(now=0.0)
    # Stage a pending-commit: ADOPT round-trip done, keys stashed, awaiting the
    # adopted-form 0x40 that signals the sensor committed.
    s._adopt_pending = True
    s._adopted = False
    s._derived_addDevice_key = bytes(range(32))
    s._derived_addDevice_fb_key = bytes(range(32, 64))

    _, events = s.feed(_craft_discovery_frame(ADOPTED_DISCOVERY_PAYLOAD),
                       channel=1, now=1.0)

    assert s._adopted is True                                  # rotation happened
    adopted_evs = [e for e in events
                   if isinstance(e, DeviceStateEvent) and e.state == "adopted"]
    assert adopted_evs, "commit must emit a DeviceStateEvent(state='adopted')"
    assert adopted_evs[0].mac == SENSOR_MAC


def test_no_adopted_event_without_commit():
    """A plain (unadopted-form / already-adopted) discovery must not spuriously
    emit an 'adopted' state event — only the actual commit transition does."""
    from superlink.bridge.events import DeviceStateEvent
    s = _session()
    s.start(now=0.0)
    _, events = s.feed(_craft_discovery_frame(V2_DISCOVERY_PAYLOAD),
                       channel=1, now=1.0)
    assert not [e for e in events
                if isinstance(e, DeviceStateEvent) and e.state == "adopted"]


# --- telemetry-liveness timeout: ACTIVE -> BEACONING on silence ----------------

def _active_data_session(link_lost_timeout=60.0):
    from superlink.bridge.session import State
    s = DeviceSession(DeviceRecord(mac=SENSOR_MAC, adopted=True), gw_mac=GW_MAC,
                      pairing_key=DEFAULT_PAIRING_KEY, profiles=ProfileRegistry.load(),
                      link_lost_timeout=link_lost_timeout)
    s.start(now=0.0)
    s._state = State.ACTIVE
    s.session_key = bytes(range(32))
    s.sensor_mac = SENSOR_MAC
    s._adopted = True
    s._last_data_rx = 0.0
    return s


def _data_frame_0x54():
    from superlink.decoder import SuperLinkFrame
    return SuperLinkFrame(mctrl=0xE0, dctrl=0x54, mac=SENSOR_MAC, seq_hi=0x10,
                          seq_lo=0x00, encrypted=b"", direction="UL",
                          frame_type="data", payload=None)


def test_active_drops_to_beaconing_after_link_lost_timeout():
    from superlink.bridge.session import State
    from superlink.bridge.events import DeviceStateEvent
    s = _active_data_session(link_lost_timeout=60.0)
    frames, events = s.tick(now=61.0)            # 61s of silence > 60s timeout
    assert s._state == State.BEACONING
    assert s.session_key is None
    assert any(isinstance(e, DeviceStateEvent) and e.state == "lost" for e in events)


def _craft_data_frame(session_key, seq_hi=0x10, counter=5,
                      payload=b"\x0c\x00\x0f\x00\x01"):
    """A real 0x54 data frame the session can decrypt+MIC-verify under
    `session_key` (so `_scan_data_counter` finds `counter`)."""
    from superlink.decoder import build_frame, compute_mic, parse_frame
    header = bytes([0xE0, 0x54]) + SENSOR_MAC + bytes([seq_hi, 0x00])
    mic = compute_mic(header, payload)
    raw = build_frame(0xE0, 0x54, SENSOR_MAC, seq_hi, 0x00, mic, payload,
                      session_key, counter=counter)
    return parse_frame(raw)


def test_data_frame_refreshes_liveness():
    # A DECODABLE data frame (MIC verifies under the session key) is the liveness
    # heartbeat — it must keep the link alive.
    from superlink.bridge.session import State
    s = _active_data_session(link_lost_timeout=60.0)
    s.feed(_craft_data_frame(s.session_key), channel=1, now=50.0)  # real telemetry
    s.tick(now=100.0)                                  # only 50s since data
    assert s._state == State.ACTIVE                    # still healthy


def test_queued_command_pushed_on_telemetry_window():
    # The real controller delivers config/commands in-session as DL 0x74 right
    # after a UL frame, not gated on the sensor's rare 0x53 reconnect poll. A
    # queued body must go out on a telemetry (0x54) window too.
    s = _active_data_session()
    s._adopted = True
    s.queue_body(b"\x0e\x01\x10\x00\x01")               # PROPERTY_SET ENTRY_CONFIG=1
    frames, _ = s.feed(_craft_data_frame(s.session_key), channel=3, now=6.0)
    assert any(isinstance(f, OutgoingFrame) for f in frames), \
        "a queued command must be pushed on a 0x54 telemetry window"
    assert s._pending_bodies == [], "the body must be drained once sent"


def _button_report_frame(session_key, uptime, seq_hi=0x10, counter=5):
    # PROPERTY_REPORT(12) tag0, BUTTON_PRESSED(19) ch0 = u32 uptime.
    payload = bytes([12, 0, 19, 0]) + uptime.to_bytes(4, "big")
    return _craft_data_frame(session_key, seq_hi=seq_hi, counter=counter,
                             payload=payload)


def test_button_press_edge_surfaces_through_session():
    from superlink.bridge.events import ButtonPressed
    s = _active_data_session()
    s._prop_sizes = {19: 4}
    # Baseline sighting: no press yet.
    _, evs = s.feed(_button_report_frame(s.session_key, 1000, seq_hi=0x10,
                                         counter=5), channel=1, now=6.0)
    assert not any(isinstance(e, ButtonPressed) for e in evs)
    # Uptime advances -> a press edge surfaces.
    _, evs = s.feed(_button_report_frame(s.session_key, 1500, seq_hi=0x11,
                                         counter=6), channel=1, now=7.0)
    assert any(isinstance(e, ButtonPressed) and e.property_id == 19 for e in evs)


def test_decoded_telemetry_emits_link_signal_rssi():
    from superlink.bridge.events import LinkSignal
    s = _active_data_session()
    _, evs = s.feed(_craft_data_frame(s.session_key), channel=1, now=6.0,
                    rssi=-42.5, snr=9.0)
    sig = [e for e in evs if isinstance(e, LinkSignal)]
    assert sig and sig[0].mac == SENSOR_MAC
    assert sig[0].rssi_dbm == -42.5 and sig[0].snr == 9.0


def test_no_link_signal_without_rssi():
    # No RSSI supplied (e.g. legacy path) -> no LinkSignal, no crash.
    from superlink.bridge.events import LinkSignal
    s = _active_data_session()
    _, evs = s.feed(_craft_data_frame(s.session_key), channel=1, now=6.0)
    assert not any(isinstance(e, LinkSignal) for e in evs)


def test_no_command_pushed_without_queue():
    # No queued body -> a telemetry frame must NOT emit a spurious DL command.
    s = _active_data_session()
    s._adopted = True
    frames, _ = s.feed(_craft_data_frame(s.session_key), channel=3, now=6.0)
    assert not any(isinstance(f, OutgoingFrame) for f in frames)


def test_undecodable_data_does_not_refresh_liveness():
    # The stale-until-manual-restart trap: a drifted/dead session where the sensor
    # still emits 0x54s that no longer decrypt. Raw dctrl must NOT count as
    # liveness, or the link never times out to BEACONING to answer the reconnect.
    from superlink.bridge.session import State
    s = _active_data_session(link_lost_timeout=60.0)
    wrong_key = bytes(range(1, 33))                    # != s.session_key
    garbage = _craft_data_frame(wrong_key)             # 0x54 that won't MIC-verify
    s.feed(garbage, channel=1, now=50.0)
    s.tick(now=61.0)                                   # 61s since last DECODED data
    assert s._state == State.BEACONING                 # timed out despite the 0x54


def test_discovery_0x40_does_not_refresh_liveness():
    # A reconnecting sensor sends 0x40s, NOT telemetry. Those must not keep the
    # link "alive" — otherwise an ACTIVE session ignoring 0x40 strands it forever.
    from superlink.bridge.session import State
    s = _active_data_session(link_lost_timeout=60.0)
    s.feed(_craft_discovery_frame(ADOPTED_DISCOVERY_PAYLOAD), channel=1, now=50.0)
    s.tick(now=61.0)                                    # 61s since last DATA
    assert s._state == State.BEACONING                 # timed out despite the 0x40


def test_lost_timeout_preserves_pending_bodies():
    s = _active_data_session(link_lost_timeout=60.0)
    s.queue_body(b"\x08\x01")                          # a LOCATE-ish body
    s.tick(now=61.0)
    assert s._pending_bodies == [b"\x08\x01"]


# --- factory-reset auto-re-adopt ---------------------------------------------

UNADOPTED_DISCOVERY_PAYLOAD = bytes.fromhex("02ae9406000000000002")  # zero networkId


def test_unadopted_discovery_on_adopted_session_triggers_readopt():
    from superlink.bridge.session import State
    from superlink.bridge.events import DeviceStateEvent
    s = _active_data_session()
    s._derived_addDevice_key = bytes(range(32))
    frames, events = s.feed(_craft_discovery_frame(UNADOPTED_DISCOVERY_PAYLOAD),
                            channel=1, now=5.0)
    assert s._adopted is False, "factory-reset sensor must clear adoption"
    assert s._state == State.BEACONING
    assert any(isinstance(e, DeviceStateEvent) and e.state == "discovered"
               for e in events)


# --- reconnect-storm backoff -------------------------------------------------

def _storm_to_backoff(s, link_lost_timeout=10.0):
    """Drive 3 lost transitions (as re-handshakes would) to trip the storm guard."""
    from superlink.bridge.session import State
    for t in (11.0, 22.0, 33.0):
        s._state = State.ACTIVE
        s.session_key = bytes(range(32))
        s._last_data_rx = t - 11.0
        s.tick(now=t)


def test_reconnect_storm_triggers_backoff():
    from superlink.bridge.core import OutgoingFrame
    s = _active_data_session(link_lost_timeout=10.0)
    _storm_to_backoff(s)
    # A fresh discovery in BEACONING must be ignored (backing off).
    frames, _ = s.feed(_craft_discovery_frame(ADOPTED_DISCOVERY_PAYLOAD),
                       channel=1, now=34.0)
    assert not any(isinstance(f, OutgoingFrame) for f in frames), \
        "during backoff a 0x40 must not be answered with a ConnRsp"


def test_backoff_clears_after_cooldown():
    from superlink.bridge.core import OutgoingFrame
    s = _active_data_session(link_lost_timeout=10.0)
    _storm_to_backoff(s)
    # After the 60s cooldown, discovery is answered again.
    frames, _ = s.feed(_craft_discovery_frame(ADOPTED_DISCOVERY_PAYLOAD),
                       channel=1, now=34.0 + 61.0)
    assert any(isinstance(f, OutgoingFrame) for f in frames)


# --- _prop_sizes learned from DEVICE_INFO_REPORT enables PROPERTY_REPORT decode ---

def _device_info_body(props):
    """Minimal DEVICE_INFO_REPORT body ([10, tag] + fields + supported props).

    props: list of (propertyId, channelCount, valueSize).
    """
    body = bytes([10, 0])                     # msgId, tag
    body += (0x0007).to_bytes(2, "big")       # deviceType
    body += (1).to_bytes(2, "big")            # fw major
    body += (1).to_bytes(2, "big")            # fw minor
    body += (1).to_bytes(2, "big")            # fw patch
    body += (0xABCD1234).to_bytes(4, "big")   # buildId
    body += bytes([2])                        # hardwareRevision
    body += bytes(16)                         # anonymousDeviceId
    body += bytes([0])                        # supportedMessageIds count = 0
    body += bytes([len(props)])               # supportedProperties count
    for pid, ch_count, vsize in props:
        body += bytes([pid, ch_count, vsize])
    return body


# --- watchdog: recover a stuck link that link-lost re-handshake can't fix -----
#
# After link-lost drops ACTIVE -> BEACONING, a sensor sometimes gets stuck sending
# 2-byte "resume" 0x42 ConnChallenges the bridge can't complete (logged
# "ConnectionChallenge too short"), so telemetry never resumes. The only known
# recovery is a clean bridge restart, which rebuilds the session from the record
# with a FRESH DH keypair. The watchdog reproduces that restart in-process: after
# a deep-silence timeout OR repeated short-0x42 rejections, it re-arms the session
# (new keypair, back to BEACONING) while preserving adoption/keys.

def _stuck_beaconing_session(watchdog_timeout=150.0, watchdog_short_challenge_k=3,
                             link_lost_timeout=60.0):
    """An adopted session already dropped to BEACONING (post link-lost) and
    silent since t=0 — i.e. the stuck state the watchdog must recover."""
    from superlink.bridge.session import State
    s = DeviceSession(DeviceRecord(mac=SENSOR_MAC, adopted=True), gw_mac=GW_MAC,
                      pairing_key=DEFAULT_PAIRING_KEY, profiles=ProfileRegistry.load(),
                      link_lost_timeout=link_lost_timeout,
                      watchdog_timeout=watchdog_timeout,
                      watchdog_short_challenge_k=watchdog_short_challenge_k)
    s.start(now=0.0)                       # BEACONING, keypair generated
    s._state = State.BEACONING
    s.session_key = None
    s.sensor_mac = SENSOR_MAC
    s._adopted = True
    s._last_data_rx = 0.0
    return s


def _craft_short_challenge_frame():
    """A 2-byte 'resume' 0x42 ConnChallenge (the stuck-state signature), encrypted
    with the transport key (pairing key for an un-rotated session)."""
    from superlink.decoder import build_frame, compute_mic, parse_frame
    payload = b"\x01\x00"
    header = bytes([0xE0, 0x42]) + SENSOR_MAC + bytes([0x00, 0x00])
    mic = compute_mic(header, payload)
    raw = build_frame(0xE0, 0x42, SENSOR_MAC, 0x00, 0x00, mic, payload,
                      DEFAULT_PAIRING_KEY, counter=0)
    return parse_frame(raw)


def test_short_resume_0x42_answered_with_connrsp():
    # inner_type-0 0x42 (2-byte `01 00`) is the sensor's reconnect request
    # (firmware sub_524ac case 0 -> sub_51742 answers with a ConnRsp, inner_type 1).
    # The bridge must answer it with a 0x62 ConnRsp — same as a 0x40 discovery —
    # instead of dead-ending it as "too short" (which strands the sensor).
    s = _stuck_beaconing_session(watchdog_timeout=0.0)
    frames, events = s.feed(_craft_short_challenge_frame(), channel=1, now=5.0)
    assert any(f.data[1] == 0x62 for f in frames), \
        "short inner_type-0 0x42 resume must be answered with a 0x62 ConnRsp"


def test_watchdog_rearms_after_deep_silence():
    from superlink.bridge.session import State
    s = _stuck_beaconing_session(watchdog_timeout=150.0)
    old_pubkey = s._pubkey
    frames, events = s.tick(now=151.0)          # silent 151s > watchdog_timeout
    assert s._state == State.BEACONING
    assert s.session_key is None
    assert s._pubkey != old_pubkey, "watchdog must generate a fresh DH keypair"


def test_watchdog_does_not_rearm_before_timeout():
    s = _stuck_beaconing_session(watchdog_timeout=150.0)
    old_pubkey = s._pubkey
    s.tick(now=149.0)                            # still under the timeout
    assert s._pubkey == old_pubkey, "no re-arm before the watchdog timeout"


def test_watchdog_preserves_adoption_and_keys():
    s = _stuck_beaconing_session(watchdog_timeout=150.0)
    s._derived_addDevice_key = bytes(range(32))
    s._derived_addDevice_fb_key = bytes(range(32, 64))
    s._kdf_context = s._derived_addDevice_key
    s._transport_key = s._derived_addDevice_fb_key
    s._prop_sizes = {1: 4, 15: 1}
    s.tick(now=151.0)
    assert s._adopted is True
    assert s._derived_addDevice_key == bytes(range(32))
    assert s._derived_addDevice_fb_key == bytes(range(32, 64))
    assert s._kdf_context == bytes(range(32))
    assert s._transport_key == bytes(range(32, 64))
    assert s._prop_sizes == {1: 4, 15: 1}


def test_watchdog_rearm_self_rate_limits():
    # Re-arm resets the silence clock, so a follow-up tick must not re-arm again.
    s = _stuck_beaconing_session(watchdog_timeout=150.0)
    s.tick(now=151.0)
    pubkey_after_rearm = s._pubkey
    s.tick(now=152.0)
    assert s._pubkey == pubkey_after_rearm


def test_watchdog_disabled_when_timeout_zero():
    s = _stuck_beaconing_session(watchdog_timeout=0.0)
    old_pubkey = s._pubkey
    s.tick(now=100000.0)
    assert s._pubkey == old_pubkey, "watchdog_timeout=0 disables the silence trigger"


def test_repeated_short_challenge_triggers_rearm():
    from superlink.bridge.session import State
    s = _stuck_beaconing_session(watchdog_timeout=0.0,  # isolate the short-0x42 path
                                 watchdog_short_challenge_k=3)
    old_pubkey = s._pubkey
    for _ in range(3):
        s.feed(_craft_short_challenge_frame(), channel=1, now=5.0)
    frames, events = s.tick(now=6.0)
    assert s._pubkey != old_pubkey, \
        "3 short 0x42 rejections must escalate to a watchdog re-arm"
    assert s._state == State.BEACONING


def test_short_challenge_count_below_threshold_does_not_rearm():
    s = _stuck_beaconing_session(watchdog_timeout=0.0, watchdog_short_challenge_k=3)
    old_pubkey = s._pubkey
    for _ in range(2):                           # only 2 < k
        s.feed(_craft_short_challenge_frame(), channel=1, now=5.0)
    s.tick(now=6.0)
    assert s._pubkey == old_pubkey


def test_short_challenge_tally_resets_on_decoded_telemetry():
    # Decoded telemetry on a live session proves the link recovered — clear any
    # short-0x42 tally so a later isolated resume attempt doesn't trip the watchdog.
    s = _active_data_session()                       # ACTIVE, session_key set
    s._short_challenge_count = 2
    s.feed(_craft_data_frame(s.session_key), channel=1, now=6.0)
    assert s._short_challenge_count == 0


def _frame_with_payload(payload):
    from superlink.decoder import SuperLinkFrame
    return SuperLinkFrame(mctrl=0xE0, dctrl=0x54, mac=SENSOR_MAC,
                          seq_hi=0x10, seq_lo=0x00, encrypted=b"",
                          direction="UL", frame_type="data", payload=payload)


def test_device_info_report_populates_prop_sizes():
    """Observing a DEVICE_INFO_REPORT must record propertyId->valueSize so later
    PROPERTY_REPORT/SET frames decode against the correct fixed sizes instead of
    falling back to opaque 'grab the rest' parsing."""
    s = _session()
    s._adopted = True                          # _observe only runs when adopted
    s._observe(_frame_with_payload(
        _device_info_body([(13, 1, 2), (3, 1, 1)])), channel=1)
    assert s._prop_sizes == {13: 2, 3: 1}


def test_property_report_decodes_with_learned_sizes():
    """After learning sizes from DEVICE_INFO_REPORT, a two-property
    PROPERTY_REPORT must decode into two PropertyEvents (each value taking its
    declared size). Without the sizes, id 13 would swallow the rest of the
    buffer and only one property would surface."""
    from superlink.bridge.events import PropertyEvent
    s = _session()
    s._adopted = True
    s._observe(_frame_with_payload(
        _device_info_body([(13, 1, 2), (3, 1, 1)])), channel=1)

    # PROPERTY_REPORT: id13 ch0 = 003c (2B), id3 ch0 = 64 (1B).
    report = bytes([12, 0]) + bytes([13, 0, 0x00, 0x3c]) + bytes([3, 0, 0x64])
    events = s._observe(_frame_with_payload(report), channel=1)
    prop_evs = [e for e in events if isinstance(e, PropertyEvent)]
    assert [e.property_id for e in prop_evs] == [13, 3]
    assert prop_evs[0].raw == b"\x00\x3c"
    assert prop_evs[1].raw == b"\x64"
