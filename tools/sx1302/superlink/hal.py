"""
ctypes wrapper for the Semtech SX1302 HAL (libloragw).

Configures the concentrator for SuperLink's US channel plan:
  - 8 UL channels: 915.6-917.0 MHz, 125 kHz BW, SF5
  - Private LoRa sync word (0x1424)
  - SX1250 radios, SPI interface
"""

import ctypes
import ctypes.util
import os
import subprocess
from dataclasses import dataclass

# --- Constants from loragw_hal.h ---

LGW_RF_CHAIN_NB = 2
LGW_IF_CHAIN_NB = 10
LGW_MULTI_NB = 8

# com_type enum
LGW_COM_SPI = 0
LGW_COM_USB = 1

# radio_type enum
LGW_RADIO_TYPE_NONE = 0
LGW_RADIO_TYPE_SX1250 = 5

# modulation
MOD_LORA = 0x10

# bandwidth
BW_125KHZ = 0x04
BW_500KHZ = 0x06

# datarate (SF)
DR_LORA_SF5 = 5

# coderate
CR_LORA_4_5 = 0x01

# CRC status
STAT_CRC_OK = 0x10
STAT_CRC_BAD = 0x11
STAT_NO_CRC = 0x01

# --- SuperLink channel plan ---

RADIO_A_FREQ_HZ = 916_000_000  # radio 0
RADIO_B_FREQ_HZ = 917_000_000  # radio 1

# IF channel assignments for mode 0 (from test_loragw_hal_rx.c)
# radio 1: ch0=-400k, ch1=-200k, ch2=0
# radio 0: ch3=-400k, ch4=-200k, ch5=0, ch6=+200k, ch7=+400k
CHANNEL_IF_HZ = [-400_000, -200_000, 0, -400_000, -200_000, 0, 200_000, 400_000]
CHANNEL_RFCHAIN = [1, 1, 1, 0, 0, 0, 0, 0]

# Resulting UL frequencies (for display)
UL_FREQ_HZ = [
    RADIO_B_FREQ_HZ + CHANNEL_IF_HZ[0],  # 916.6 MHz - ch0
    RADIO_B_FREQ_HZ + CHANNEL_IF_HZ[1],  # 916.8 MHz - ch1
    RADIO_B_FREQ_HZ + CHANNEL_IF_HZ[2],  # 917.0 MHz - ch2
    RADIO_A_FREQ_HZ + CHANNEL_IF_HZ[3],  # 915.6 MHz - ch3
    RADIO_A_FREQ_HZ + CHANNEL_IF_HZ[4],  # 915.8 MHz - ch4
    RADIO_A_FREQ_HZ + CHANNEL_IF_HZ[5],  # 916.0 MHz - ch5
    RADIO_A_FREQ_HZ + CHANNEL_IF_HZ[6],  # 916.2 MHz - ch6
    RADIO_A_FREQ_HZ + CHANNEL_IF_HZ[7],  # 916.4 MHz - ch7
]

# Map IF chain index to SuperLink UL channel number (1-8)
IF_TO_UL_CH = {
    3: 1,  # 915.6 MHz
    4: 2,  # 915.8 MHz
    5: 3,  # 916.0 MHz
    6: 4,  # 916.2 MHz
    7: 5,  # 916.4 MHz
    0: 6,  # 916.6 MHz
    1: 7,  # 916.8 MHz
    2: 8,  # 917.0 MHz
}

# --- Downlink channel plan (500 kHz, SF5) ---

DL_FREQ_HZ = [
    920_400_000,  # CH9  (paired with UL CH1)
    921_000_000,  # CH10 (paired with UL CH2)
    921_600_000,  # CH11 (paired with UL CH3)
    922_200_000,  # CH12 (paired with UL CH4)
    922_800_000,  # CH13 (paired with UL CH5)
    923_400_000,  # CH14 (paired with UL CH6)
    924_000_000,  # CH15 (paired with UL CH7)
    924_600_000,  # CH16 (paired with UL CH8)
]

BEACON_FREQ_HZ = 927_600_000  # CH17

# UL channel index (0-7) → paired DL frequency
UL_TO_DL_FREQ = {i: DL_FREQ_HZ[i] for i in range(8)}

SPI_PATH = b"/dev/spidev0.0"
HAL_LIB_PATH = os.path.expanduser("~/sx1302_hal/libloragw/libloragw.so")
RESET_SCRIPT = os.path.expanduser("~/sx1302_hal/tools/reset_lgw.sh")

# --- C struct definitions ---

class lgw_conf_board_s(ctypes.Structure):
    _fields_ = [
        ("lorawan_public", ctypes.c_bool),
        ("clksrc", ctypes.c_uint8),
        ("full_duplex", ctypes.c_bool),
        ("com_type", ctypes.c_int),
        ("com_path", ctypes.c_char * 64),
    ]

class lgw_rssi_tcomp_s(ctypes.Structure):
    _fields_ = [
        ("coeff_a", ctypes.c_float),
        ("coeff_b", ctypes.c_float),
        ("coeff_c", ctypes.c_float),
        ("coeff_d", ctypes.c_float),
        ("coeff_e", ctypes.c_float),
    ]

class lgw_conf_rxrf_s(ctypes.Structure):
    _fields_ = [
        ("enable", ctypes.c_bool),
        ("freq_hz", ctypes.c_uint32),
        ("rssi_offset", ctypes.c_float),
        ("rssi_tcomp", lgw_rssi_tcomp_s),
        ("type", ctypes.c_int),
        ("tx_enable", ctypes.c_bool),
        ("single_input_mode", ctypes.c_bool),
    ]

class lgw_conf_rxif_s(ctypes.Structure):
    _fields_ = [
        ("enable", ctypes.c_bool),
        ("rf_chain", ctypes.c_uint8),
        ("freq_hz", ctypes.c_int32),
        ("bandwidth", ctypes.c_uint8),
        ("datarate", ctypes.c_uint32),
        ("sync_word_size", ctypes.c_uint8),
        ("sync_word", ctypes.c_uint64),
        ("implicit_hdr", ctypes.c_bool),
        ("implicit_payload_length", ctypes.c_uint8),
        ("implicit_crc_en", ctypes.c_bool),
        ("implicit_coderate", ctypes.c_uint8),
    ]

class lgw_conf_demod_s(ctypes.Structure):
    _fields_ = [
        ("multisf_datarate", ctypes.c_uint8),
    ]

class lgw_pkt_rx_s(ctypes.Structure):
    _fields_ = [
        ("freq_hz", ctypes.c_uint32),
        ("freq_offset", ctypes.c_int32),
        ("if_chain", ctypes.c_uint8),
        ("status", ctypes.c_uint8),
        ("count_us", ctypes.c_uint32),
        ("rf_chain", ctypes.c_uint8),
        ("modem_id", ctypes.c_uint8),
        ("modulation", ctypes.c_uint8),
        ("bandwidth", ctypes.c_uint8),
        ("datarate", ctypes.c_uint32),
        ("coderate", ctypes.c_uint8),
        ("rssic", ctypes.c_float),
        ("rssis", ctypes.c_float),
        ("snr", ctypes.c_float),
        ("snr_min", ctypes.c_float),
        ("snr_max", ctypes.c_float),
        ("crc", ctypes.c_uint16),
        ("size", ctypes.c_uint16),
        ("payload", ctypes.c_uint8 * 256),
        ("ftime_received", ctypes.c_bool),
        ("ftime", ctypes.c_uint32),
    ]

# TX mode enum
TX_IMMEDIATE = 0
TX_TIMESTAMPED = 1
TX_ON_GPS = 2


class lgw_pkt_tx_s(ctypes.Structure):
    """TX packet structure. Field order matches loragw_hal.h."""
    _fields_ = [
        ("freq_hz", ctypes.c_uint32),
        ("tx_mode", ctypes.c_uint8),
        ("count_us", ctypes.c_uint32),
        ("rf_chain", ctypes.c_uint8),
        ("rf_power", ctypes.c_int8),
        ("modulation", ctypes.c_uint8),
        ("bandwidth", ctypes.c_uint8),
        ("datarate", ctypes.c_uint32),
        ("coderate", ctypes.c_uint8),
        ("invert_pol", ctypes.c_bool),
        ("f_dev", ctypes.c_uint8),
        ("preamble", ctypes.c_uint16),
        ("no_crc", ctypes.c_bool),
        ("no_header", ctypes.c_bool),
        ("size", ctypes.c_uint16),
        ("payload", ctypes.c_uint8 * 256),
    ]


# --- Python dataclass for clean interface ---

@dataclass
class RxPacket:
    """A received SuperLink packet."""
    freq_hz: int
    if_chain: int
    ul_channel: int  # 1-8
    rssi: float
    snr: float
    crc_ok: bool
    payload: bytes
    timestamp_us: int
    datarate: int
    bandwidth: int
    coderate: int

class SX1302:
    """SX1302 concentrator interface for SuperLink sniffing."""

    MAX_RX_PKT = 16

    def __init__(self, lib_path: str = HAL_LIB_PATH, spi_path: bytes = SPI_PATH):
        self._lib = ctypes.CDLL(lib_path)
        self._spi_path = spi_path
        self._started = False
        self._setup_prototypes()

    def _setup_prototypes(self):
        """Set C function signatures."""
        self._lib.lgw_board_setconf.argtypes = [ctypes.POINTER(lgw_conf_board_s)]
        self._lib.lgw_board_setconf.restype = ctypes.c_int

        self._lib.lgw_rxrf_setconf.argtypes = [ctypes.c_uint8, ctypes.POINTER(lgw_conf_rxrf_s)]
        self._lib.lgw_rxrf_setconf.restype = ctypes.c_int

        self._lib.lgw_rxif_setconf.argtypes = [ctypes.c_uint8, ctypes.POINTER(lgw_conf_rxif_s)]
        self._lib.lgw_rxif_setconf.restype = ctypes.c_int

        self._lib.lgw_demod_setconf.argtypes = [ctypes.POINTER(lgw_conf_demod_s)]
        self._lib.lgw_demod_setconf.restype = ctypes.c_int

        self._lib.lgw_start.argtypes = []
        self._lib.lgw_start.restype = ctypes.c_int

        self._lib.lgw_stop.argtypes = []
        self._lib.lgw_stop.restype = ctypes.c_int

        self._lib.lgw_receive.argtypes = [ctypes.c_uint8, ctypes.POINTER(lgw_pkt_rx_s)]
        self._lib.lgw_receive.restype = ctypes.c_int

        self._lib.lgw_get_instcnt.argtypes = [ctypes.POINTER(ctypes.c_uint32)]
        self._lib.lgw_get_instcnt.restype = ctypes.c_int

        self._lib.lgw_version_info.argtypes = []
        self._lib.lgw_version_info.restype = ctypes.c_char_p

        self._lib.lgw_send.argtypes = [ctypes.POINTER(lgw_pkt_tx_s)]
        self._lib.lgw_send.restype = ctypes.c_int

    def _configure(self):
        """Apply SuperLink channel configuration."""
        # Board config
        board = lgw_conf_board_s()
        board.lorawan_public = False
        board.clksrc = 0
        board.full_duplex = False
        board.com_type = LGW_COM_SPI
        board.com_path = self._spi_path
        rc = self._lib.lgw_board_setconf(ctypes.byref(board))
        if rc != 0:
            raise RuntimeError("lgw_board_setconf failed")

        # Radio 0 (916.0 MHz)
        rf0 = lgw_conf_rxrf_s()
        rf0.enable = True
        rf0.freq_hz = RADIO_A_FREQ_HZ
        rf0.rssi_offset = -215.4
        rf0.type = LGW_RADIO_TYPE_SX1250
        rf0.tx_enable = True
        rf0.single_input_mode = False
        rc = self._lib.lgw_rxrf_setconf(0, ctypes.byref(rf0))
        if rc != 0:
            raise RuntimeError("lgw_rxrf_setconf(0) failed")

        # Radio 1 (917.0 MHz)
        rf1 = lgw_conf_rxrf_s()
        rf1.enable = True
        rf1.freq_hz = RADIO_B_FREQ_HZ
        rf1.rssi_offset = -215.4
        rf1.type = LGW_RADIO_TYPE_SX1250
        rf1.tx_enable = False
        rf1.single_input_mode = False
        rc = self._lib.lgw_rxrf_setconf(1, ctypes.byref(rf1))
        if rc != 0:
            raise RuntimeError("lgw_rxrf_setconf(1) failed")

        # 8 IF channels (multi-SF)
        for i in range(LGW_MULTI_NB):
            ifconf = lgw_conf_rxif_s()
            ifconf.enable = True
            ifconf.rf_chain = CHANNEL_RFCHAIN[i]
            ifconf.freq_hz = CHANNEL_IF_HZ[i]
            rc = self._lib.lgw_rxif_setconf(i, ctypes.byref(ifconf))
            if rc != 0:
                raise RuntimeError(f"lgw_rxif_setconf({i}) failed")

        # Demod config: SF5 only (bit 0 = SF5 in the bitmask: SF12..SF5)
        demod = lgw_conf_demod_s()
        demod.multisf_datarate = 0x01
        rc = self._lib.lgw_demod_setconf(ctypes.byref(demod))
        if rc != 0:
            raise RuntimeError("lgw_demod_setconf failed")

    def version(self) -> str:
        return self._lib.lgw_version_info().decode()

    def start(self):
        """Reset the concentrator and start receiving."""
        subprocess.run([RESET_SCRIPT, "start"], check=True)
        self._configure()
        rc = self._lib.lgw_start()
        if rc != 0:
            raise RuntimeError("lgw_start failed")
        self._started = True

    def stop(self):
        """Stop the concentrator."""
        if self._started:
            self._lib.lgw_stop()
            subprocess.run([RESET_SCRIPT, "stop"], check=False)
            self._started = False

    def receive(self) -> list[RxPacket]:
        """Non-blocking fetch of received packets."""
        pkt_buf = (lgw_pkt_rx_s * self.MAX_RX_PKT)()
        nb = self._lib.lgw_receive(self.MAX_RX_PKT, pkt_buf)
        if nb < 0:
            raise RuntimeError("lgw_receive failed")

        packets = []
        for i in range(nb):
            p = pkt_buf[i]
            packets.append(RxPacket(
                freq_hz=p.freq_hz,
                if_chain=p.if_chain,
                ul_channel=IF_TO_UL_CH.get(p.if_chain, 0),
                rssi=p.rssic,
                snr=p.snr,
                crc_ok=(p.status == STAT_CRC_OK),
                payload=bytes(p.payload[:p.size]),
                timestamp_us=p.count_us,
                datarate=p.datarate,
                bandwidth=p.bandwidth,
                coderate=p.coderate,
            ))
        return packets

    def send(self, freq_hz: int, payload: bytes,
             rf_power: int = 10, bandwidth: int = BW_500KHZ) -> None:
        """Transmit a frame.

        Args:
            freq_hz: TX frequency in Hz.
            payload: Frame bytes to transmit.
            rf_power: TX power in dBm (default 10).
            bandwidth: LoRa bandwidth (BW_500KHZ for DL, BW_125KHZ for UL).
        """
        pkt = lgw_pkt_tx_s()
        pkt.freq_hz = freq_hz
        pkt.tx_mode = TX_IMMEDIATE
        pkt.rf_chain = 0
        pkt.rf_power = rf_power
        pkt.modulation = MOD_LORA
        pkt.bandwidth = bandwidth
        pkt.datarate = DR_LORA_SF5
        pkt.coderate = CR_LORA_4_5
        pkt.invert_pol = False
        pkt.preamble = 12
        pkt.no_crc = False
        pkt.no_header = False
        pkt.size = len(payload)
        ctypes.memmove(pkt.payload, payload, len(payload))

        rc = self._lib.lgw_send(ctypes.byref(pkt))
        if rc != 0:
            raise RuntimeError(f"lgw_send failed (rc={rc})")

    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *args):
        self.stop()
