from types import SimpleNamespace

import pytest

from app.db.models import HostPlatform, UserStatus
from app.subscription.config_cache import make_sub_config_key
from app.subscription.share import filter_hosts
from app.utils.platform import detect_host_platform


@pytest.mark.parametrize(
    ("device_os", "expected"),
    [
        (None, HostPlatform.unknown),
        ("", HostPlatform.unknown),
        ("Plan9", HostPlatform.unknown),
        ("Windows 11", HostPlatform.windows),
        ("macOS 15", HostPlatform.macos),
        ("Linux x86_64", HostPlatform.linux),
        ("Android 14", HostPlatform.android),
        ("Android TV 13", HostPlatform.androidtv),
        ("iOS 18", HostPlatform.ios),
        ("tvOS 18", HostPlatform.appletv),
    ],
)
def test_detect_host_platform_buckets(device_os: str | None, expected: HostPlatform) -> None:
    assert detect_host_platform(device_os) is expected


async def test_filter_hosts_respects_device_os_restrictions() -> None:
    unrestricted = SimpleNamespace(status=None, device_os=None)
    windows_only = SimpleNamespace(status=None, device_os=[HostPlatform.windows])
    ios_only = SimpleNamespace(status=None, device_os=[HostPlatform.ios])
    hosts = [unrestricted, windows_only, ios_only]

    assert await filter_hosts(hosts, UserStatus.active, HostPlatform.windows) == [unrestricted, windows_only]
    assert await filter_hosts(hosts, UserStatus.active, HostPlatform.unknown) == [unrestricted]
    assert await filter_hosts(hosts, UserStatus.active, None) == hosts


def test_sub_config_key_differs_by_platform() -> None:
    user = SimpleNamespace(id=1, expire=None, status=UserStatus.active, inbounds=(), proxy_settings=None)

    windows_key = make_sub_config_key(user, "links", False, False, HostPlatform.windows)
    ios_key = make_sub_config_key(user, "links", False, False, HostPlatform.ios)

    assert windows_key != ios_key
