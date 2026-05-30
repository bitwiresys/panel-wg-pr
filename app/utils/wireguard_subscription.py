"""Defaults for WireGuard client subscription (.conf) AllowedIPs.

Full-tunnel 0.0.0.0/0 + ::/0 breaks many clients:
- wireguard-windows kill-switch when /0 is present (see netquirk.md)
- xray gVisor WG inbound drops client IPv6 when ::/0 is used
Split IPv4 default routes cover the same destinations without /0 semantics.
"""

DEFAULT_CLIENT_ALLOWED_IPS: list[str] = ["0.0.0.0/1", "128.0.0.0/1"]

# Legacy panel default; kept for explicit opt-in / tests only.
LEGACY_FULL_TUNNEL_ALLOWED_IPS: list[str] = ["0.0.0.0/0", "::/0"]

DEFAULT_CLIENT_MTU = 1280
DEFAULT_CLIENT_KEEPALIVE = 25
