from PasarGuardNodeBridge import create_proxy, create_user
from PasarGuardNodeBridge.common.service_pb2 import User, Wireguard


def create_user_for_node(
    email: str,
    user_settings: dict,
    inbounds: list[str] | None = None,
) -> User:
    wg = user_settings.get("wireguard") or {}
    vmess = user_settings.get("vmess", {})
    vless = user_settings.get("vless", {})
    if vless.get("flow") == "xtls-rprx-vision-udp443":
        vless = {**vless, "flow": "xtls-rprx-vision"}
    trojan = user_settings.get("trojan", {})
    ss = user_settings.get("shadowsocks", {})
    hysteria = user_settings.get("hysteria", {})

    proxy = create_proxy(
        vmess_id=vmess.get("id"),
        vless_id=vless.get("id"),
        vless_flow=vless.get("flow"),
        trojan_password=trojan.get("password"),
        shadowsocks_password=ss.get("password"),
        shadowsocks_method=ss.get("method"),
        hysteria_auth=hysteria.get("auth"),
    )

    if wg.get("public_key"):
        proxy.wireguard.CopyFrom(
            Wireguard(
                public_key=wg["public_key"],
                peer_ips=list(wg.get("peer_ips") or []),
                pre_shared_key=wg.get("pre_shared_key") or "",
            )
        )

    return create_user(email, proxy, inbounds or [])
