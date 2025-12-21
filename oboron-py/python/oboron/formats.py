"""Format string constants for Oboron. 

All constants follow the pattern:  {SCHEME}_{ENCODING}
- Schemes: ZDC, UPC, ADGS, APGS, ADSV, APSV, MOCK1, MOCK2, LEGACY (legacy)
- Encodings: C32 (Crockford base32), B32 (RFC 4648 base32), B64 (RFC 4648 base64url), HEX

Example:
    >>> from oboron import formats
    >>> from oboron import Ob
    >>> 
    >>> ob = Ob(formats.ADSV_B64, key)
    >>> ot = ob.enc("secret")
"""

# zdc - AES-CBC (deterministic, insecure - obfuscation only)
ZDC_C32: str = "zdc.c32"
ZDC_B32: str = "zdc.b32"
ZDC_B64: str = "zdc.b64"
ZDC_HEX: str = "zdc.hex"

# upc - AES-CBC (probabilistic, secure but not authenticated)
UPC_C32: str = "upc.c32"
UPC_B32: str = "upc.b32"
UPC_B64: str = "upc.b64"
UPC_HEX: str = "upc.hex"

# adgs - AES-GCM-SIV (deterministic, secure and authenticated)
ADGS_C32: str = "adgs.c32"
ADGS_B32: str = "adgs.b32"
ADGS_B64: str = "adgs.b64"
ADGS_HEX: str = "adgs.hex"

# apgs - AES-GCM-SIV (probabilistic, secure and authenticated)
APGS_C32: str = "apgs.c32"
APGS_B32: str = "apgs.b32"
APGS_B64: str = "apgs.b64"
APGS_HEX: str = "apgs.hex"

# adsv - AES-SIV (deterministic, secure and authenticated, nonce-misuse resistant)
ADSV_C32: str = "adsv.c32"
ADSV_B32: str = "adsv.b32"
ADSV_B64: str = "adsv.b64"
ADSV_HEX: str = "adsv.hex"

# apsv - AES-SIV (probabilistic, secure and authenticated)
APSV_C32: str = "apsv.c32"
APSV_B32: str = "apsv.b32"
APSV_B64: str = "apsv.b64"
APSV_HEX: str = "apsv.hex"

# Testing schemes (no encryption)
MOCK1_C32: str = "mock1.c32"
MOCK1_B32: str = "mock1.b32"
MOCK1_B64: str = "mock1.b64"
MOCK1_HEX: str = "mock1.hex"

MOCK2_C32: str = "mock2.c32"
MOCK2_B32: str = "mock2.b32"
MOCK2_B64: str = "mock2.b64"
MOCK2_HEX: str = "mock2.hex"

# Legacy (legacy - deprecated, use zdc instead)
LEGACY_C32: str = "legacy.c32"
LEGACY_B32: str = "legacy.b32"
LEGACY_B64: str = "legacy.b64"
LEGACY_HEX: str = "legacy.hex"

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
    "MOCK1_C32", "MOCK1_B32", "MOCK1_B64", "MOCK1_HEX",
    "MOCK2_C32", "MOCK2_B32", "MOCK2_B64", "MOCK2_HEX",
    # Legacy
    "LEGACY_C32", "LEGACY_B32", "LEGACY_B64", "LEGACY_HEX",
]
