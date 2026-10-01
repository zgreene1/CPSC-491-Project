"""Validation helpers for vulnerability scan targets."""

from dataclasses import dataclass
from typing import Optional
import ipaddress
import re


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    target_type: Optional[str] = None
    normalized_target: Optional[str] = None
    error: Optional[str] = None


_HOST_LABEL = re.compile(
    r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


def _valid_hostname(hostname: str) -> bool:
    """Return True if the hostname follows basic DNS hostname rules."""

    if len(hostname) > 253:
        return False

    hostname = hostname.rstrip(".")

    if not hostname:
        return False

    labels = hostname.split(".")

    return all(_HOST_LABEL.fullmatch(label) for label in labels)


def validate_target(target: str) -> ValidationResult:
    """Validate an IPv4 address or hostname before a scan begins."""

    if target is None or not target.strip():
        return ValidationResult(
            valid=False,
            error="Target cannot be empty.",
        )

    target = target.strip()

    # Check whether the target is a valid IPv4 address.
    try:
        address = ipaddress.IPv4Address(target)

        return ValidationResult(
            valid=True,
            target_type="ipv4",
            normalized_target=str(address),
        )

    except ipaddress.AddressValueError:
        pass

    # Numeric dotted input that failed IPv4 validation should not
    # accidentally be accepted as a hostname.
    if re.fullmatch(r"[0-9.]+", target):
        return ValidationResult(
            valid=False,
            error="Invalid IPv4 address.",
        )

    # Check whether the target is a valid hostname.
    if _valid_hostname(target):
        return ValidationResult(
            valid=True,
            target_type="hostname",
            normalized_target=target.rstrip(".").lower(),
        )

    return ValidationResult(
        valid=False,
        error="Invalid or unsupported hostname.",
    )