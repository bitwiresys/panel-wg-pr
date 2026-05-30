"""WireGuard node serialization (runtime sync path, no debounced reconnect)."""

from app.node.bridge_proto import create_user_for_node


def test_create_user_for_node_includes_wireguard_psk():
    user = create_user_for_node(
        "1.alice",
        {
            "wireguard": {
                "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "peer_ips": ["10.0.0.2/32"],
                "pre_shared_key": "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
            }
        },
        inbounds=["wg-in"],
    )
    assert user.proxies.wireguard.public_key.startswith("AAAA")
    assert user.proxies.wireguard.pre_shared_key.startswith("BBBB")
    assert list(user.proxies.wireguard.peer_ips) == ["10.0.0.2/32"]
    assert user.inbounds == ["wg-in"]
