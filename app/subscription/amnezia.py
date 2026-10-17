from typing import Any

from app.models.amnezia import AmneziaProperties, validate_cps_packet
from app.utils.logger import get_logger

logger = get_logger("amnezia-subscription")

AMNEZIA_PACKET_FIELDS = ("i1", "i2", "i3", "i4", "i5")
AMNEZIA_CONF_KEYS = {
    "jc": "Jc",
    "jmin": "Jmin",
    "jmax": "Jmax",
    "s1": "S1",
    "s2": "S2",
    "s3": "S3",
    "s4": "S4",
    "h1": "H1",
    "h2": "H2",
    "h3": "H3",
    "h4": "H4",
    "i1": "I1",
    "i2": "I2",
    "i3": "I3",
    "i4": "I4",
    "i5": "I5",
    "header_protection_key": "HeaderProtectionKey",
    "content_padding_addition": "ContentPaddingAddition",
    "rekey_after_time": "RekeyAfterTime",
    "rekey_timeout": "RekeyTimeout",
    "reject_after_time": "RejectAfterTime",
    "keepalive_timeout": "KeepaliveTimeout",
    "max_handshake_attempts": "MaxHandshakeAttempts",
    "random_trailers": "RandomTrailers",
    "disable_cookies": "DisableCookies",
}


def finalmask_cps_packets(finalmask: dict[str, Any] | None) -> list[str]:
    if not finalmask:
        return []
    for layer in finalmask.get("tcp") or []:
        logger.warning("finalmask tcp layer %r has no AmneziaWG equivalent and is skipped", layer.get("type"))
    packets: list[str] = []
    for layer in finalmask.get("udp") or []:
        if layer.get("type") != "noise":
            logger.warning("finalmask udp layer %r has no AmneziaWG equivalent and is skipped", layer.get("type"))
            continue
        for item in (layer.get("settings") or {}).get("noise") or []:
            if item.get("type") != "exp":
                logger.warning(
                    "finalmask noise item type %r has no AmneziaWG equivalent and is skipped", item.get("type")
                )
                continue
            try:
                packets.append(validate_cps_packet(str(item.get("packet") or "")))
            except ValueError as error:
                logger.warning("finalmask exp packet has no AmneziaWG equivalent and is skipped: %s", error)
    return packets


def resolve_amnezia_settings(
    amnezia: AmneziaProperties | None, finalmask: dict[str, Any] | None
) -> dict[str, int | str]:
    """Из finalmask создаются только I1–I5; S/H/HeaderProtectionKey/RandomTrailers задаются явно у хоста, иначе Xray WireGuard inbound ломается."""
    settings: dict[str, int | str] = amnezia.model_dump(exclude_none=True) if amnezia else {}
    free_slots = [field for field in AMNEZIA_PACKET_FIELDS if field not in settings]
    packets = finalmask_cps_packets(finalmask)
    if len(packets) > len(free_slots):
        logger.warning(
            "AmneziaWG accepts at most %d CPS packets, %d finalmask packets are dropped",
            len(free_slots),
            len(packets) - len(free_slots),
        )
    for slot, packet in zip(free_slots, packets):
        settings[slot] = packet
    return settings
