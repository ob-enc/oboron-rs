"""Format string constants for Oboron. 

All constants follow the pattern:  {SCHEME}_{ENCODING}
- Schemes: OB01, OB21P, OB31, OB31P, OB32, OB32P, OB70, OB71, OB00 (legacy)
- Encodings: C32 (Base32Crockford), B32 (Base32Rfc), B64 (Base64), HEX

Example:
    >>> from oboron import formats
    >>> from oboron import Ob
    >>> 
    >>> ob = Ob(formats.OB32_B64, key)
    >>> ot = ob.enc("secret")
"""

# ob01 - AES-CBC (deterministic, insecure - obfuscation only)
OB01_C32: str = "ob01:c32"
OB01_B32: str = "ob01:b32"
OB01_B64: str = "ob01:b64"
OB01_HEX: str = "ob01:hex"

# ob21p - AES-CBC (probabilistic, secure but not authenticated)
OB21P_C32: str = "ob21p:c32"
OB21P_B32: str = "ob21p:b32"
OB21P_B64: str = "ob21p:b64"
OB21P_HEX: str = "ob21p:hex"

# ob31 - AES-GCM-SIV (deterministic, secure and authenticated)
OB31_C32: str = "ob31:c32"
OB31_B32: str = "ob31:b32"
OB31_B64: str = "ob31:b64"
OB31_HEX: str = "ob31:hex"

# ob31p - AES-GCM-SIV (probabilistic, secure and authenticated)
OB31P_C32: str = "ob31p:c32"
OB31P_B32: str = "ob31p:b32"
OB31P_B64: str = "ob31p:b64"
OB31P_HEX: str = "ob31p:hex"

# ob32 - AES-SIV (deterministic, secure and authenticated, nonce-misuse resistant)
OB32_C32: str = "ob32:c32"
OB32_B32: str = "ob32:b32"
OB32_B64: str = "ob32:b64"
OB32_HEX: str = "ob32:hex"

# ob32p - AES-SIV (probabilistic, secure and authenticated)
OB32P_C32: str = "ob32p:c32"
OB32P_B32: str = "ob32p:b32"
OB32P_B64: str = "ob32p:b64"
OB32P_HEX: str = "ob32p:hex"

# Testing schemes (no encryption)
OB70_C32: str = "ob70:c32"
OB70_B32: str = "ob70:b32"
OB70_B64: str = "ob70:b64"
OB70_HEX: str = "ob70:hex"

OB71_C32: str = "ob71:c32"
OB71_B32: str = "ob71:b32"
OB71_B64: str = "ob71:b64"
OB71_HEX: str = "ob71:hex"

# Legacy (ob00 - deprecated, use ob01 instead)
OB00_C32: str = "ob00:c32"
OB00_B32: str = "ob00:b32"
OB00_B64: str = "ob00:b64"
OB00_HEX: str = "ob00:hex"

__all__ = [
    # ob01
    "OB01_C32", "OB01_B32", "OB01_B64", "OB01_HEX",
    # ob21p
    "OB21P_C32", "OB21P_B32", "OB21P_B64", "OB21P_HEX",
    # ob31
    "OB31_C32", "OB31_B32", "OB31_B64", "OB31_HEX",
    # ob31p
    "OB31P_C32", "OB31P_B32", "OB31P_B64", "OB31P_HEX",
    # ob32
    "OB32_C32", "OB32_B32", "OB32_B64", "OB32_HEX",
    # ob32p
    "OB32P_C32", "OB32P_B32", "OB32P_B64", "OB32P_HEX",
    # Testing
    "OB70_C32", "OB70_B32", "OB70_B64", "OB70_HEX",
    "OB71_C32", "OB71_B32", "OB71_B64", "OB71_HEX",
    # Legacy
    "OB00_C32", "OB00_B32", "OB00_B64", "OB00_HEX",
]
