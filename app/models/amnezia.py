import base64
import re
from typing import Any, Self

from pydantic import BaseModel, Field, field_validator, model_validator

UINT16_MAX = 65535
UINT32_MAX = 4294967295
CPS_TAG_PATTERN = re.compile(r"<([^<>]*)>")
CPS_TAG_NAMES = frozenset({"b", "r", "rd", "rc", "t"})
CPS_HEX_BYTES_PATTERN = re.compile(r"0x[0-9a-fA-F]+")
DIGITS_PATTERN = re.compile(r"[0-9]+")
TOGGLE_VALUES = frozenset({"on", "off"})
HEADER_PROTECTION_KEY_BYTES = 32
HEADER_PROTECTION_MIN_PADDING = 12


def _parse_bounded_int(value: Any, maximum: int) -> int:
    if isinstance(value, int) and not isinstance(value, bool):
        number = value
    elif isinstance(value, str) and DIGITS_PATTERN.fullmatch(value.strip()):
        number = int(value.strip())
    else:
        raise ValueError("value must be a non-negative integer")
    if not 0 <= number <= maximum:
        raise ValueError(f"value must be between 0 and {maximum}")
    return number


def parse_uint_range(value: Any, maximum: int) -> int | str:
    if isinstance(value, str) and value.strip().lower() == "(off)":
        return "(off)"
    if isinstance(value, str) and "-" in value:
        low_text, _, high_text = value.partition("-")
        low = _parse_bounded_int(low_text.strip(), maximum)
        high = _parse_bounded_int(high_text.strip(), maximum)
        if low > high:
            raise ValueError("range lower bound cannot exceed upper bound")
        return f"{low}-{high}"
    return _parse_bounded_int(value, maximum)


def parse_header_range(value: str) -> str:
    low_text, separator, high_text = value.strip().partition("-")
    low = _parse_bounded_int(low_text.strip(), UINT32_MAX)
    if not separator:
        return str(low)
    high = _parse_bounded_int(high_text.strip(), UINT32_MAX)
    if low > high:
        raise ValueError("header range lower bound cannot exceed upper bound")
    return f"{low}-{high}"


def _validate_cps_tag(tag: str) -> None:
    parts = tag.split()
    if not parts or parts[0] not in CPS_TAG_NAMES:
        raise ValueError(f"unsupported CPS tag <{tag}>")
    name, args = parts[0], parts[1:]
    if name == "t":
        if args:
            raise ValueError("<t> takes no arguments")
    elif name == "b":
        if len(args) != 1 or not CPS_HEX_BYTES_PATTERN.fullmatch(args[0]):
            raise ValueError("<b> needs 0x followed by hex digits")
        if len(args[0]) % 2:
            raise ValueError(f"<b 0x…> hex must have even length, got {len(args[0]) - 2} digits")
    elif len(args) != 1 or not DIGITS_PATTERN.fullmatch(args[0]) or int(args[0]) < 1:
        raise ValueError(f"<{name}> needs a positive size")


def validate_cps_packet(value: str) -> str:
    text = value.strip()
    if CPS_TAG_PATTERN.sub("", text).strip():
        raise ValueError("CPS packet may contain only <tag> sequences")
    tags = CPS_TAG_PATTERN.findall(text)
    if not tags:
        raise ValueError("CPS packet needs at least one tag")
    for tag in tags:
        _validate_cps_tag(tag)
    return text


def _blank_to_none(value: Any) -> Any:
    if value is None or (isinstance(value, str) and not value.strip()):
        return None
    return value


class AmneziaProperties(BaseModel):
    jc: int | None = Field(default=None)
    jmin: int | None = Field(default=None)
    jmax: int | None = Field(default=None)
    s1: int | None = Field(default=None)
    s2: int | None = Field(default=None)
    s3: int | None = Field(default=None)
    s4: int | None = Field(default=None)
    h1: str | None = Field(default=None)
    h2: str | None = Field(default=None)
    h3: str | None = Field(default=None)
    h4: str | None = Field(default=None)
    i1: str | None = Field(default=None)
    i2: str | None = Field(default=None)
    i3: str | None = Field(default=None)
    i4: str | None = Field(default=None)
    i5: str | None = Field(default=None)
    header_protection_key: str | None = Field(default=None)
    content_padding_addition: int | str | None = Field(default=None)
    rekey_after_time: int | str | None = Field(default=None)
    rekey_timeout: int | str | None = Field(default=None)
    reject_after_time: int | str | None = Field(default=None)
    keepalive_timeout: int | str | None = Field(default=None)
    max_handshake_attempts: int | str | None = Field(default=None)
    random_trailers: str | None = Field(default=None)
    disable_cookies: str | None = Field(default=None)

    @field_validator("jc", "jmin", "jmax", "s1", "s2", "s3", "s4", mode="before")
    @classmethod
    def validate_uint16(cls, value: Any) -> int | None:
        value = _blank_to_none(value)
        return None if value is None else _parse_bounded_int(value, UINT16_MAX)

    @field_validator("h1", "h2", "h3", "h4", mode="before")
    @classmethod
    def validate_header(cls, value: Any) -> str | None:
        value = _blank_to_none(value)
        if value is None:
            return None
        return parse_header_range(str(value))

    @field_validator("i1", "i2", "i3", "i4", "i5", mode="before")
    @classmethod
    def validate_packet(cls, value: Any) -> str | None:
        value = _blank_to_none(value)
        if value is None:
            return None
        return validate_cps_packet(str(value))

    @field_validator("header_protection_key", mode="before")
    @classmethod
    def validate_key_format(cls, value: Any) -> str | None:
        value = _blank_to_none(value)
        if value is None:
            return None
        text = str(value).strip()
        try:
            decoded = base64.b64decode(text, validate=True)
        except ValueError as error:
            raise ValueError("header_protection_key must be base64") from error
        if len(decoded) != HEADER_PROTECTION_KEY_BYTES:
            raise ValueError("header_protection_key must decode to exactly 32 bytes")
        return text

    @field_validator(
        "content_padding_addition",
        "rekey_after_time",
        "rekey_timeout",
        "reject_after_time",
        "keepalive_timeout",
        "max_handshake_attempts",
        mode="before",
    )
    @classmethod
    def validate_timing_range(cls, value: Any) -> int | str | None:
        value = _blank_to_none(value)
        return None if value is None else parse_uint_range(value, UINT16_MAX)

    @field_validator("random_trailers", "disable_cookies", mode="before")
    @classmethod
    def validate_toggle(cls, value: Any) -> str | None:
        value = _blank_to_none(value)
        if value is None:
            return None
        text = str(value).strip().lower()
        if text not in TOGGLE_VALUES:
            raise ValueError("value must be 'on' or 'off'")
        return text

    @model_validator(mode="after")
    def validate_consistency(self) -> Self:
        if self.jmin is not None and self.jmax is not None and self.jmin > self.jmax:
            raise ValueError("jmin cannot exceed jmax")
        if self.header_protection_key is not None:
            for field_name in ("s1", "s2", "s3", "s4"):
                value = getattr(self, field_name)
                if value is None or value < HEADER_PROTECTION_MIN_PADDING:
                    raise ValueError(
                        f"{field_name} must be at least {HEADER_PROTECTION_MIN_PADDING} "
                        "when header_protection_key is configured"
                    )
        return self
