from app.db.models import HostPlatform


def detect_host_platform(device_os: str | None) -> HostPlatform:
    """Map a client-supplied X-Device-OS header to a HostPlatform bucket.

    Client-supplied and trivially spoofable: used only to pick which hosts a
    subscription shows, never for access control.
    """
    if not device_os:
        return HostPlatform.unknown

    value = device_os.strip().lower()
    if not value:
        return HostPlatform.unknown

    # TV variants first: "android tv" contains "android", "apple tv"/"tvos" overlap with ios.
    if "androidtv" in value or "android tv" in value:
        return HostPlatform.androidtv
    if "appletv" in value or "apple tv" in value or "tvos" in value:
        return HostPlatform.appletv

    if "android" in value:
        return HostPlatform.android
    if "ios" in value or "iphone" in value or "ipad" in value:
        return HostPlatform.ios
    if "windows" in value or "win32" in value or "win64" in value:
        return HostPlatform.windows
    if "macos" in value or "mac os" in value or "os x" in value or "osx" in value:
        return HostPlatform.macos
    if "linux" in value:
        return HostPlatform.linux

    return HostPlatform.unknown
