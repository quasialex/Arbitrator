"""Conservative global asset address-space classification.
Assessment internal/external perspective is independent of asset exposure.
"""
from __future__ import annotations
import ipaddress

PRIVATE = [ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")]

def classify_asset(identifier: str, _unused=None) -> tuple[str,str]:
    try: address = ipaddress.ip_address(identifier.strip())
    except ValueError:
        return "Review required", "Hostname alone does not demonstrate network exposure; analyst review required"
    if any(address in net for net in PRIVATE):
        return "Internal", "Private address space; not evidence of network reachability"
    if address.is_global:
        return "External", "Globally scoped address; internet reachability has not been verified"
    return "Review required", "Special-use, loopback or documentation address; analyst review required"


def address_fields_from_source(identifier: str) -> tuple[str | None, str | None]:
    """Preserve IP and hostname as separate evidence; never perform DNS lookups.

    A source that supplies only an IP has *not* established an FQDN, and vice versa.
    Neither field is an asset's permanent organizational inventory identifier.
    """
    value = identifier.strip().rstrip(".").lower()
    try:
        return None, str(ipaddress.ip_address(value))
    except ValueError:
        # URLs are already normalized to their hostname by the import adapter.
        return (value if "." in value else None), None


def service_code_from_identifier(identifier: str) -> None:
    """Deprecated guessing heuristic: DNS first label is not a service code.

    Service codes must come from an explicitly supplied value or a configured,
    reviewed naming policy. Returning None prevents false classification.
    """
    return None
