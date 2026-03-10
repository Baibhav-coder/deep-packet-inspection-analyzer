from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional
from datetime import datetime


class AppType(Enum):
    UNKNOWN = 0
    HTTP = 1
    HTTPS = 2
    DNS = 3
    TLS = 4
    QUIC = 5
    GOOGLE = 6
    FACEBOOK = 7
    YOUTUBE = 8
    TWITTER = 9
    INSTAGRAM = 10
    NETFLIX = 11
    AMAZON = 12
    MICROSOFT = 13
    APPLE = 14
    WHATSAPP = 15
    TELEGRAM = 16
    TIKTOK = 17
    SPOTIFY = 18
    ZOOM = 19
    DISCORD = 20
    GITHUB = 21
    CLOUDFLARE = 22


class ConnectionState(Enum):
    NEW = "NEW"
    ESTABLISHED = "ESTABLISHED"
    CLASSIFIED = "CLASSIFIED"
    BLOCKED = "BLOCKED"
    CLOSED = "CLOSED"


class PacketAction(Enum):
    FORWARD = "FORWARD"
    DROP = "DROP"
    INSPECT = "INSPECT"
    LOG_ONLY = "LOG_ONLY"


@dataclass(frozen=True)
class FiveTuple:
    src_ip: int
    dst_ip: int
    src_port: int
    dst_port: int
    protocol: int  # TCP=6, UDP=17

    def reverse(self) -> "FiveTuple":
        return FiveTuple(
            src_ip=self.dst_ip,
            dst_ip=self.src_ip,
            src_port=self.dst_port,
            dst_port=self.src_port,
            protocol=self.protocol,
        )

    @staticmethod
    def _format_ip(ip: int) -> str:
        return ".".join(
            [
                str((ip >> 0) & 0xFF),
                str((ip >> 8) & 0xFF),
                str((ip >> 16) & 0xFF),
                str((ip >> 24) & 0xFF),
            ]
        )

    def __str__(self) -> str:
        proto = "TCP" if self.protocol == 6 else "UDP" if self.protocol == 17 else "?"
        return (
            f"{self._format_ip(self.src_ip)}:{self.src_port} -> "
            f"{self._format_ip(self.dst_ip)}:{self.dst_port} ({proto})"
        )


@dataclass
class Connection:
    tuple: FiveTuple
    state: ConnectionState = ConnectionState.NEW
    app_type: AppType = AppType.UNKNOWN
    sni: str = ""

    packets_in: int = 0
    packets_out: int = 0
    bytes_in: int = 0
    bytes_out: int = 0

    first_seen: datetime = field(default_factory=datetime.now)
    last_seen: datetime = field(default_factory=datetime.now)

    action: PacketAction = PacketAction.FORWARD

    syn_seen: bool = False
    syn_ack_seen: bool = False
    fin_seen: bool = False


@dataclass
class PacketJob:
    packet_id: int
    tuple: FiveTuple
    data: bytes

    eth_offset: int = 0
    ip_offset: int = 0
    transport_offset: int = 0
    payload_offset: int = 0
    payload_length: int = 0
    tcp_flags: int = 0
    payload_data: Optional[bytes] = None

    ts_sec: int = 0
    ts_usec: int = 0


@dataclass
class DPIStats:
    total_packets: int = 0
    total_bytes: int = 0
    forwarded_packets: int = 0
    dropped_packets: int = 0
    tcp_packets: int = 0
    udp_packets: int = 0
    other_packets: int = 0
    active_connections: int = 0


def app_type_to_string(app_type: AppType) -> str:
    mapping = {
        AppType.UNKNOWN: "Unknown",
        AppType.HTTP: "HTTP",
        AppType.HTTPS: "HTTPS",
        AppType.DNS: "DNS",
        AppType.TLS: "TLS",
        AppType.QUIC: "QUIC",
        AppType.GOOGLE: "Google",
        AppType.FACEBOOK: "Facebook",
        AppType.YOUTUBE: "YouTube",
        AppType.TWITTER: "Twitter/X",
        AppType.INSTAGRAM: "Instagram",
        AppType.NETFLIX: "Netflix",
        AppType.AMAZON: "Amazon",
        AppType.MICROSOFT: "Microsoft",
        AppType.APPLE: "Apple",
        AppType.WHATSAPP: "WhatsApp",
        AppType.TELEGRAM: "Telegram",
        AppType.TIKTOK: "TikTok",
        AppType.SPOTIFY: "Spotify",
        AppType.ZOOM: "Zoom",
        AppType.DISCORD: "Discord",
        AppType.GITHUB: "GitHub",
        AppType.CLOUDFLARE: "Cloudflare",
    }
    return mapping.get(app_type, "Unknown")


def sni_to_app_type(sni: str) -> AppType:
    if not sni:
        return AppType.UNKNOWN

    lower_sni = sni.lower()

    if (
        "google" in lower_sni
        or "gstatic" in lower_sni
        or "googleapis" in lower_sni
        or "ggpht" in lower_sni
        or "gvt1" in lower_sni
    ):
        return AppType.GOOGLE

    if (
        "youtube" in lower_sni
        or "ytimg" in lower_sni
        or "youtu.be" in lower_sni
        or "yt3.ggpht" in lower_sni
    ):
        return AppType.YOUTUBE

    if (
        "facebook" in lower_sni
        or "fbcdn" in lower_sni
        or "fb.com" in lower_sni
        or "fbsbx" in lower_sni
        or "meta.com" in lower_sni
    ):
        return AppType.FACEBOOK

    if "instagram" in lower_sni or "cdninstagram" in lower_sni:
        return AppType.INSTAGRAM

    if "whatsapp" in lower_sni or "wa.me" in lower_sni:
        return AppType.WHATSAPP

    if (
        "twitter" in lower_sni
        or "twimg" in lower_sni
        or "x.com" in lower_sni
        or "t.co" in lower_sni
    ):
        return AppType.TWITTER

    if (
        "netflix" in lower_sni
        or "nflxvideo" in lower_sni
        or "nflximg" in lower_sni
    ):
        return AppType.NETFLIX

    if (
        "amazon" in lower_sni
        or "amazonaws" in lower_sni
        or "cloudfront" in lower_sni
        or "aws" in lower_sni
    ):
        return AppType.AMAZON

    if (
        "microsoft" in lower_sni
        or "msn.com" in lower_sni
        or "office" in lower_sni
        or "azure" in lower_sni
        or "live.com" in lower_sni
        or "outlook" in lower_sni
        or "bing" in lower_sni
    ):
        return AppType.MICROSOFT

    if (
        "apple" in lower_sni
        or "icloud" in lower_sni
        or "mzstatic" in lower_sni
        or "itunes" in lower_sni
    ):
        return AppType.APPLE

    if "telegram" in lower_sni or "t.me" in lower_sni:
        return AppType.TELEGRAM

    if (
        "tiktok" in lower_sni
        or "tiktokcdn" in lower_sni
        or "musical.ly" in lower_sni
        or "bytedance" in lower_sni
    ):
        return AppType.TIKTOK

    if "spotify" in lower_sni or "scdn.co" in lower_sni:
        return AppType.SPOTIFY

    if "zoom" in lower_sni:
        return AppType.ZOOM

    if "discord" in lower_sni or "discordapp" in lower_sni:
        return AppType.DISCORD

    if "github" in lower_sni or "githubusercontent" in lower_sni:
        return AppType.GITHUB

    if "cloudflare" in lower_sni or "cf-" in lower_sni:
        return AppType.CLOUDFLARE

    return AppType.HTTPS