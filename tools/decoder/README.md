# SuperLink Packet Decoder

Placeholder for the SuperLink protocol decoder/dissector.

## Planned Components

- **Frame parser** — Decode raw bytes from LoRa demodulator into structured frames
- **Wireshark dissector** — Lua plugin for analyzing captures in Wireshark
- **CLI decoder** — Standalone tool to decode hex-encoded frames from stdin

## Frame Structure (Hypothesized)

Based on typical proprietary LoRa protocols and Ubiquiti patterns:

```
+----------+--------+------+-------+---------+---------+-----+
| Preamble | SyncWd | Len  | Type  | SrcAddr | DstAddr | ... |
| (LoRa)   | (LoRa) | 1-2B | 1B    | 2-6B    | 2-6B    |     |
+----------+--------+------+-------+---------+---------+-----+
    ... | Seq# | Payload (encrypted?) | MIC/CRC |
        | 2-4B | variable             | 2-4B    |
        +------+----------------------+---------+
```

This is speculative — actual structure TBD from captures.
