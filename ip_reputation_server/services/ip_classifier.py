import ipaddress


def classify_ip(ip_string: str):
    """
    Classify an IPv4 or IPv6 address before external
    reputation providers are queried.

    This prevents MedShield from incorrectly treating
    private, loopback, multicast, or other special-purpose
    addresses as Internet threat-intelligence targets.
    """

    try:
        ip = ipaddress.ip_address(
            ip_string.strip()
        )

    except ValueError:
        raise ValueError(
            "Invalid IPv4 or IPv6 address"
        )


    # -----------------------------------------------------
    # Determine IP category
    # -----------------------------------------------------

    if ip.is_loopback:

        category = "loopback"

        reason = (
            "Loopback address. External reputation "
            "intelligence is not applicable."
        )


    elif ip.is_link_local:

        category = "link_local"

        reason = (
            "Link-local address. External reputation "
            "intelligence is not applicable."
        )


    elif ip.is_private:

        category = "private"

        reason = (
            "Private/internal address. Internet reputation "
            "providers should not be treated as authoritative "
            "for this address."
        )


    elif ip.is_multicast:

        category = "multicast"

        reason = (
            "Multicast address. External reputation "
            "lookup is not applicable."
        )


    elif ip.is_unspecified:

        category = "unspecified"

        reason = (
            "Unspecified address. Reputation lookup "
            "is not applicable."
        )


    elif ip.is_reserved:

        category = "reserved"

        reason = (
            "Reserved address. External reputation lookup "
            "is normally not applicable."
        )


    elif ip.is_global:

        category = "public"

        reason = (
            "Public globally routable address eligible "
            "for external reputation enrichment."
        )


    else:

        category = "special"

        reason = (
            "Special-purpose IP address requiring "
            "contextual interpretation."
        )


    # -----------------------------------------------------
    # Decide whether Internet threat intelligence applies
    # -----------------------------------------------------

    external_reputation_applicable = bool(
        ip.is_global
        and not ip.is_multicast
        and not ip.is_unspecified
        and not ip.is_loopback
        and not ip.is_link_local
    )


    # -----------------------------------------------------
    # Return structured classification
    # -----------------------------------------------------

    return {

        "ip": str(ip),

        "version": ip.version,

        "category": category,

        "is_global": ip.is_global,

        "is_private": ip.is_private,

        "is_loopback": ip.is_loopback,

        "is_link_local": ip.is_link_local,

        "is_multicast": ip.is_multicast,

        "is_reserved": ip.is_reserved,

        "is_unspecified": ip.is_unspecified,

        "external_reputation_applicable":
            external_reputation_applicable,

        "reason": reason
    }
