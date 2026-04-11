"""Tests for SX1302 HAL constants and configuration."""
from superlink.hal import DL_FREQ_HZ, BEACON_FREQ_HZ, UL_TO_DL_FREQ


def test_dl_channel_count():
    """Must have 8 DL channels."""
    assert len(DL_FREQ_HZ) == 8


def test_dl_frequencies():
    """DL frequencies must match protocol spec."""
    expected = [
        920_400_000, 921_000_000, 921_600_000, 922_200_000,
        922_800_000, 923_400_000, 924_000_000, 924_600_000,
    ]
    assert DL_FREQ_HZ == expected


def test_beacon_frequency():
    assert BEACON_FREQ_HZ == 927_600_000


def test_ul_to_dl_mapping():
    """UL channel index 0-7 maps to paired DL frequency."""
    assert UL_TO_DL_FREQ[0] == 920_400_000  # CH1 → CH9
    assert UL_TO_DL_FREQ[7] == 924_600_000  # CH8 → CH16
    assert len(UL_TO_DL_FREQ) == 8
