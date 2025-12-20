"""Format string constants for Oboron. 

All constants follow the pattern:  {SCHEME}_{ENCODING}
- Schemes: ZDC, UPC, ADGS, APGS, ADSV, APSV, OB70, OB71, OB00 (legacy)
- Encodings: C32 (Base32Crockford), B32 (Base32Rfc), B64 (Base64), HEX

Example:
    >>> from oboron import formats
    >>> from oboron import Ob
    >>> 
    >>> ob = Ob(formats.ADSV_B64, key)
    >>> ot = ob.enc("secret")
"""

# zdc - AES-CBC (deterministic, insecure - obfuscation only)
ZDC_C32: str = "zdc:c32"
ZDC_B32: str = "zdc:b32"
ZDC_B64: str = "zdc:b64"
ZDC_HEX: str = "zdc:hex"

# upc - AES-CBC (probabilistic, secure but not authenticated)
UPC_C32: str = "upc:c32"
UPC_B32: str = "upc:b32"
UPC_B64: str = "upc:b64"
UPC_HEX: str = "upc:hex"

# adgs - AES-GCM-SIV (deterministic, secure and authenticated)
ADGS_C32: str = "adgs:c32"
ADGS_B32: str = "adgs:b32"
ADGS_B64: str = "adgs:b64"
ADGS_HEX: str = "adgs:hex"

# apgs - AES-GCM-SIV (probabilistic, secure and authenticated)
APGS_C32: str = "apgs:c32"
APGS_B32: str = "apgs:b32"
APGS_B64: str = "apgs:b64"
APGS_HEX: str = "apgs:hex"

# adsv - AES-SIV (deterministic, secure and authenticated, nonce-misuse resistant)
ADSV_C32: str = "adsv:c32"
ADSV_B32: str = "adsv:b32"
ADSV_B64: str = "adsv:b64"
ADSV_HEX: str = "adsv:hex"

# apsv - AES-SIV (probabilistic, secure and authenticated)
APSV_C32: str = "apsv:c32"
APSV_B32: str = "apsv:b32"
APSV_B64: str = "apsv:b64"
APSV_HEX: str = "apsv:hex"

# Testing schemes (no encryption)
OB70_C32: str = "ob70:c32"
OB70_B32: str = "ob70:b32"
OB70_B64: str = "ob70:b64"
OB70_HEX: str = "ob70:hex"

OB71_C32: str = "ob71:c32"
OB71_B32: str = "ob71:b32"
OB71_B64: str = "ob71:b64"
OB71_HEX: str = "ob71:hex"

# Legacy (ob00 - deprecated, use zdc instead)
OB00_C32: str = "ob00:c32"
OB00_B32: str = "ob00:b32"
OB00_B64: str = "ob00:b64"
OB00_HEX: str = "ob00:hex"

__all__ = [
    # zdc
    "ZDC_C32", "ZDC_B32", "ZDC_B64", "ZDC_HEX",
    # upc
    "UPC_C32", "UPC_B32", "UPC_B64", "UPC_HEX",
    # adgs
    "ADGS_C32", "ADGS_B32", "ADGS_B64", "ADGS_HEX",
    # apgs
    "APGS_C32", "APGS_B32", "APGS_B64", "APGS_HEX",
    # adsv
    "ADSV_C32", "ADSV_B32", "ADSV_B64", "ADSV_HEX",
    # apsv
    "APSV_C32", "APSV_B32", "APSV_B64", "APSV_HEX",
    # Testing
    "OB70_C32", "OB70_B32", "OB70_B64", "OB70_HEX",
    "OB71_C32", "OB71_B32", "OB71_B64", "OB71_HEX",
    # Legacy
    "OB00_C32", "OB00_B32", "OB00_B64", "OB00_HEX",
]
