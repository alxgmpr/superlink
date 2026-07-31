"""Runtime configuration for the SuperLink bridge daemon."""
from __future__ import annotations
from dataclasses import dataclass, field
import yaml

# Documented Ubiquiti factory-default pairing key (docs/protocol/crypto_and_pairing.md).
DEFAULT_PAIRING_KEY = bytes.fromhex(
    "47be3dffb41ea35749c9290e6d2124e6b3e3842ab4e443bd0ac41eda045c2dbe"
)

ADOPT_ALL = object()  # sentinel: adopt any discovered device


@dataclass
class MqttConfig:
    host: str
    port: int = 1883
    username: str | None = None
    password: str | None = None
    base_topic: str = "superlink"
    discovery_prefix: str = "homeassistant"
    tls: bool = False


@dataclass
class RuntimeConfig:
    gw_mac: bytes
    pairing_key: bytes = DEFAULT_PAIRING_KEY
    store_path: str = "superlink_devices.json"
    adopt: object = field(default_factory=set)   # set[bytes] or ADOPT_ALL
    downlink_delay_us: int = 1_000_000
    burst_spacing_us: int = 500_000
    invert_iq: bool = False
    log_level: str = "INFO"
    csv_path: str | None = None
    mqtt: "MqttConfig | None" = None
    control_socket: str | None = None
    # Liveness timeouts must exceed the baked REPORT_INTERVAL (300s): an idle-but-
    # alive sensor reports every 300s, so shorter timeouts declare the link dead
    # between reports and flap HA unavailable. These clear 2x the interval
    # (tolerating one missed report). The watchdog's short-0x42-storm trigger
    # (watchdog_short_challenge_k) still catches a genuinely stuck link fast,
    # independent of this time threshold.
    link_lost_timeout: float = 660.0
    watchdog_timeout: float = 900.0
    watchdog_short_challenge_k: int = 3

    @classmethod
    def load(cls, path: str) -> "RuntimeConfig":
        with open(path) as f:
            doc = yaml.safe_load(f) or {}

        gw_mac = bytes.fromhex(doc["gw_mac"])
        if len(gw_mac) != 6:
            raise ValueError(f"gw_mac must be 6 bytes, got {len(gw_mac)}")

        pk = doc.get("pairing_key")
        pairing_key = bytes.fromhex(pk) if pk else DEFAULT_PAIRING_KEY

        raw_adopt = doc.get("adopt", [])
        if isinstance(raw_adopt, str) and raw_adopt.lower() == "all":
            adopt: object = ADOPT_ALL
        else:
            adopt = {bytes.fromhex(m) for m in raw_adopt}

        log = doc.get("log") or {}

        # Operator control socket: on by default (key absent -> standard path);
        # `control_socket: null` disables it.
        from .control import DEFAULT_SOCKET_PATH
        control_socket = doc.get("control_socket", DEFAULT_SOCKET_PATH)

        mqtt_doc = doc.get("mqtt")
        mqtt = None
        if mqtt_doc is not None:
            if "host" not in mqtt_doc:
                raise ValueError("mqtt block requires 'host'")
            mqtt = MqttConfig(
                host=mqtt_doc["host"],
                port=int(mqtt_doc.get("port", 1883)),
                username=mqtt_doc.get("username"),
                password=mqtt_doc.get("password"),
                base_topic=mqtt_doc.get("base_topic", "superlink"),
                discovery_prefix=mqtt_doc.get("discovery_prefix", "homeassistant"),
                tls=bool(mqtt_doc.get("tls", False)),
            )

        return cls(
            gw_mac=gw_mac,
            pairing_key=pairing_key,
            store_path=doc.get("store_path", "superlink_devices.json"),
            adopt=adopt,
            downlink_delay_us=int(doc.get("downlink_delay_us", 1_000_000)),
            burst_spacing_us=int(doc.get("burst_spacing_us", 500_000)),
            invert_iq=bool(doc.get("invert_iq", False)),
            log_level=log.get("level", "INFO"),
            csv_path=log.get("csv"),
            mqtt=mqtt,
            control_socket=control_socket,
            link_lost_timeout=float(doc.get("link_lost_timeout", 60.0)),
            watchdog_timeout=float(doc.get("watchdog_timeout", 150.0)),
            watchdog_short_challenge_k=int(
                doc.get("watchdog_short_challenge_k", 3)),
        )

    def is_allowed(self, mac: bytes) -> bool:
        return self.adopt is ADOPT_ALL or mac in self.adopt
