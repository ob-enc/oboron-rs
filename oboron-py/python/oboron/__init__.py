"""
Oboron - General purpose symmetric encryption+encoding library

Docs: https://www.oboron.org/

This module provides a Pythonic wrapper around the Rust oboron extension,
adding proper inheritance and type checking support.
"""

from abc import ABC, abstractmethod
from . import _oboron

__version__ = (_oboron.__version__
               if hasattr(_oboron, '__version__') else "1.0.0")


class OboronBase(ABC):
    """
    Abstract base class for all Oboron cipher implementations.

    All cipher classes (AdsvB32, ZdcB64, etc.) are registered as virtual
    subclasses, enabling isinstance() and issubclass() checks.

    Example:
        >>> cipher = AdsvC32(hex_key=key)
        >>> isinstance(cipher, OboronBase)
        True

        >>> def process_cipher(cipher: OboronBase) -> str:
        ...     return cipher.enc("hello")
    """

    @abstractmethod
    def enc(self, plaintext: str) -> str:
        """Encrypt and encode plaintext to obtext."""
        ...

    @abstractmethod
    def dec(self, obtext: str, strict: bool = False) -> str:
        """Decode and decrypt obtext to plaintext."""
        ...

    @property
    @abstractmethod
    def scheme(self) -> str:
        """Get the scheme identifier (e.g., 'AdsvC32')."""
        ...

    @property
    @abstractmethod
    def encoding(self) -> str:
        """Get the encoding format (e.g., 'Base32Crockford')."""
        ...

    @property
    @abstractmethod
    def key(self) -> str:
        """Get the encryption key as a hex string."""
        ...

    @property
    @abstractmethod
    def key_bytes(self) -> bytes:
        """Get the encryption key as raw bytes."""
        ...


# ============================================================================
# Register all Rust classes as virtual subclasses
# ============================================================================

# Ob00 variants (LEGACY)
OboronBase.register(_oboron.Ob00Base32Crockford)
OboronBase.register(_oboron.Ob00Base32Rfc)
OboronBase.register(_oboron.Ob00Base64)
OboronBase.register(_oboron.Ob00Hex)

# Zdc variants
OboronBase.register(_oboron.ZdcC32)
OboronBase.register(_oboron.ZdcB32)
OboronBase.register(_oboron.ZdcB64)
OboronBase.register(_oboron.ZdcHex)

# Upc variants
OboronBase.register(_oboron.UpcC32)
OboronBase.register(_oboron.UpcB32)
OboronBase.register(_oboron.UpcB64)
OboronBase.register(_oboron.UpcHex)

# Adgs variants
OboronBase.register(_oboron.AdgsC32)
OboronBase.register(_oboron.AdgsB32)
OboronBase.register(_oboron.AdgsB64)
OboronBase.register(_oboron.AdgsHex)

# Apgs variants
OboronBase.register(_oboron.ApgsC32)
OboronBase.register(_oboron.ApgsB32)
OboronBase.register(_oboron.ApgsB64)
OboronBase.register(_oboron.ApgsHex)

# Adsv variants
OboronBase.register(_oboron.AdsvC32)
OboronBase.register(_oboron.AdsvB32)
OboronBase.register(_oboron.AdsvB64)
OboronBase.register(_oboron.AdsvHex)

# Apsv variants
OboronBase.register(_oboron.ApsvC32)
OboronBase.register(_oboron.ApsvB32)
OboronBase.register(_oboron.ApsvB64)
OboronBase.register(_oboron.ApsvHex)

# Ob71 variants (testing)
OboronBase.register(_oboron.Ob71Base32Crockford)
OboronBase.register(_oboron.Ob71Base32Rfc)
OboronBase.register(_oboron.Ob71Base64)
OboronBase.register(_oboron.Ob71Hex)

# Tdi variants (testing)
OboronBase.register(_oboron.TdiC32)
OboronBase.register(_oboron.TdiB32)
OboronBase.register(_oboron.TdiB64)
OboronBase.register(_oboron.TdiHex)

# Flexible interface
OboronBase.register(_oboron.Ob)

# ============================================================================
# Re-export all classes and functions
# ============================================================================

# Main flexible interface
Ob = _oboron.Ob

# Ob00 variants (LEGACY)
Ob00Base32Crockford = _oboron.Ob00Base32Crockford
Ob00Base32Rfc = _oboron.Ob00Base32Rfc
Ob00Base64 = _oboron.Ob00Base64
Ob00Hex = _oboron.Ob00Hex

# Zdc variants
ZdcC32 = _oboron.ZdcC32
ZdcB32 = _oboron.ZdcB32
ZdcB64 = _oboron.ZdcB64
ZdcHex = _oboron.ZdcHex

# Upc variants
UpcC32 = _oboron.UpcC32
UpcB32 = _oboron.UpcB32
UpcB64 = _oboron.UpcB64
UpcHex = _oboron.UpcHex

# Adgs variants
AdgsC32 = _oboron.AdgsC32
AdgsB32 = _oboron.AdgsB32
AdgsB64 = _oboron.AdgsB64
AdgsHex = _oboron.AdgsHex

# Apgs variants
ApgsC32 = _oboron.ApgsC32
ApgsB32 = _oboron.ApgsB32
ApgsB64 = _oboron.ApgsB64
ApgsHex = _oboron.ApgsHex

# Adsv variants
AdsvC32 = _oboron.AdsvC32
AdsvB32 = _oboron.AdsvB32
AdsvB64 = _oboron.AdsvB64
AdsvHex = _oboron.AdsvHex

# Apsv variants
ApsvC32 = _oboron.ApsvC32
ApsvB32 = _oboron.ApsvB32
ApsvB64 = _oboron.ApsvB64
ApsvHex = _oboron.ApsvHex

# Tdi variants (testing)
TdiC32 = _oboron.TdiC32
TdiB32 = _oboron.TdiB32
TdiB64 = _oboron.TdiB64
TdiHex = _oboron.TdiHex

# Ob71 variants (testing)
Ob71Base32Crockford = _oboron.Ob71Base32Crockford
Ob71Base32Rfc = _oboron.Ob71Base32Rfc
Ob71Base64 = _oboron.Ob71Base64
Ob71Hex = _oboron.Ob71Hex

# Utility functions
generate_key = _oboron.generate_key
generate_key_bytes = _oboron.generate_key_bytes

# Convenience functions
enc = _oboron.enc
dec = _oboron.dec
autodec = _oboron.autodec
enc_keyless = _oboron.enc_keyless
dec_keyless = _oboron.dec_keyless
autodec_keyless = _oboron.autodec_keyless

# ============================================================================
# __all__ export
# ============================================================================

__all__ = [
    # Base classes
    'OboronBase',

    # Main interfaces
    'Ob',

    # Ob00 (LEGACY)
    'Ob00',
    'Ob00Base32Crockford',
    'Ob00Base32Rfc',
    'Ob00Base64',
    'Ob00Hex',

    # Zdc
    'ZdcC32',
    'ZdcB32',
    'ZdcB64',
    'ZdcHex',

    # Upc
    'UpcC32',
    'UpcB32',
    'UpcB64',
    'UpcHex',

    # Adgs
    'AdgsC32',
    'AdgsB32',
    'AdgsB64',
    'AdgsHex',

    # Apgs
    'ApgsC32',
    'ApgsB32',
    'ApgsB64',
    'ApgsHex',

    # Adsv
    'AdsvC32',
    'AdsvB32',
    'AdsvB64',
    'AdsvHex',

    # Apsv
    'ApsvC32',
    'ApsvB32',
    'ApsvB64',
    'ApsvHex',

    # Tdi (testing)
    'TdiC32',
    'TdiB32',
    'TdiB64',
    'TdiHex',

    # Ob71 (testing)
    'Ob71Base32Crockford',
    'Ob71Base32Rfc',
    'Ob71Base64',
    'Ob71Hex',

    # Format constants module
    'formats',

    # Utility functions
    'generate_key',
    'generate_key_bytes',

    # Convenience functions
    'enc',
    'dec',
    'autodec',
    'enc_keyless',
    'dec_keyless',
    'autodec_keyless',
]
