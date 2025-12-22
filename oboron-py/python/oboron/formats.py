"""Format string constants for Oboron. 

All constants follow the pattern:  {SCHEME}_{ENCODING}
- Schemes: ADGS, ADSV, APGS, APSV, UPC, ZFBCX, LEGACY, MOCK1, MOCK2
- Encodings:
  - B32 (RFC 4648 base32),
  - B64 (RFC 4648 base64url),
  - C32 (Crockford base32),
  - HEX (hexadecimal)

Example:
    >>> from oboron import formats
    >>> from oboron import Ob
    >>> 
    >>> ob = Ob(formats.ADSV_B64, key)
    >>> ot = ob.enc("secret")
"""

# adgs - deterministic AES-GCM-SIV (secure and authenticated)
ADGS_B32: str = "adgs.b32"
ADGS_B64: str = "adgs.b64"
ADGS_C32: str = "adgs.c32"
ADGS_HEX: str = "adgs.hex"

# adsv - deterministic AES-SIV (secure and authenticated, nonce-misuse resistant)
ADSV_B32: str = "adsv.b32"
ADSV_B64: str = "adsv.b64"
ADSV_C32: str = "adsv.c32"
ADSV_HEX: str = "adsv.hex"

# apgs - probabilistic AES-GCM-SIV (secure and authenticated)
APGS_B32: str = "apgs.b32"
APGS_B64: str = "apgs.b64"
APGS_C32: str = "apgs.c32"
APGS_HEX: str = "apgs.hex"

# apsv - probabilistic AES-SIV (secure and authenticated)
APSV_B32: str = "apsv.b32"
APSV_B64: str = "apsv.b64"
APSV_C32: str = "apsv.c32"
APSV_HEX: str = "apsv.hex"

# upc - probabilistic AES-CBC (secure but not authenticated)
UPC_B32: str = "upc.b32"
UPC_B64: str = "upc.b64"
UPC_C32: str = "upc.c32"
UPC_HEX: str = "upc.hex"

# zfbcx - deterministic AES-CBC (insecure - obfuscation only)
ZFBCX_B32: str = "zfbcx.b32"
ZFBCX_B64: str = "zfbcx.b64"
ZFBCX_C32: str = "zfbcx.c32"
ZFBCX_HEX: str = "zfbcx.hex"

# Testing schemes (no encryption)
MOCK1_B32: str = "mock1.b32"
MOCK1_B64: str = "mock1.b64"
MOCK1_C32: str = "mock1.c32"
MOCK1_HEX: str = "mock1.hex"

MOCK2_B32: str = "mock2.b32"
MOCK2_B64: str = "mock2.b64"
MOCK2_C32: str = "mock2.c32"
MOCK2_HEX: str = "mock2.hex"

# Legacy (legacy - insecure - obfuscation only; backwards compatibility only - use zfbcx instead)
LEGACY_B32: str = "legacy.b32"
LEGACY_B64: str = "legacy.b64"
LEGACY_C32: str = "legacy.c32"
LEGACY_HEX: str = "legacy.hex"

__all__ = [
    # adgs
    "ADGS_B32", "ADGS_B64", "ADGS_C32", "ADGS_HEX",
    # adsv
    "ADSV_B32", "ADSV_B64", "ADSV_C32", "ADSV_HEX",
    # apgs
    "APGS_B32", "APGS_B64", "APGS_C32", "APGS_HEX",
    # apsv
    "APSV_B32", "APSV_B64", "APSV_C32", "APSV_HEX",
    # zfbcx
    "ZFBCX_B32", "ZFBCX_B64", "ZFBCX_C32", "ZFBCX_HEX",
    # upc
    "UPC_B32", "UPC_B64", "UPC_C32", "UPC_HEX",
    # Legacy
    "LEGACY_B32", "LEGACY_B64", "LEGACY_C32", "LEGACY_HEX",
    # Testing
    "MOCK1_B32", "MOCK1_B64", "MOCK1_C32", "MOCK1_HEX",
    "MOCK2_B32", "MOCK2_B64", "MOCK2_C32", "MOCK2_HEX",
]
