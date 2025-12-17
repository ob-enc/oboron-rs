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

    All cipher classes (Ob32, Ob01, etc.) are registered as virtual
    subclasses, enabling isinstance() and issubclass() checks.

    Example:
        >>> cipher = Ob32(hex_key=key)
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
        """Get the scheme identifier (e.g., 'Ob32')."""
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
OboronBase.register(_oboron.Ob00)
OboronBase.register(_oboron.Ob00Base32Crockford)
OboronBase.register(_oboron.Ob00Base32Rfc)
OboronBase.register(_oboron.Ob00Base64)
OboronBase.register(_oboron.Ob00Hex)

# Ob01 variants
OboronBase.register(_oboron.Ob01)
OboronBase.register(_oboron.Ob01Base32Crockford)
OboronBase.register(_oboron.Ob01Base32Rfc)
OboronBase.register(_oboron.Ob01Base64)
OboronBase.register(_oboron.Ob01Hex)

# Ob21p variants
OboronBase.register(_oboron.Ob21p)
OboronBase.register(_oboron.Ob21pBase32Crockford)
OboronBase.register(_oboron.Ob21pBase32Rfc)
OboronBase.register(_oboron.Ob21pBase64)
OboronBase.register(_oboron.Ob21pHex)

# Ob31 variants
OboronBase.register(_oboron.Ob31)
OboronBase.register(_oboron.Ob31Base32Crockford)
OboronBase.register(_oboron.Ob31Base32Rfc)
OboronBase.register(_oboron.Ob31Base64)
OboronBase.register(_oboron.Ob31Hex)

# Ob31p variants
OboronBase.register(_oboron.Ob31p)
OboronBase.register(_oboron.Ob31pBase32Crockford)
OboronBase.register(_oboron.Ob31pBase32Rfc)
OboronBase.register(_oboron.Ob31pBase64)
OboronBase.register(_oboron.Ob31pHex)

# Ob32 variants
OboronBase.register(_oboron.Ob32)
OboronBase.register(_oboron.Ob32Base32Crockford)
OboronBase.register(_oboron.Ob32Base32Rfc)
OboronBase.register(_oboron.Ob32Base64)
OboronBase.register(_oboron.Ob32Hex)

# Ob32p variants
OboronBase.register(_oboron.Ob32p)
OboronBase.register(_oboron.Ob32pBase32Crockford)
OboronBase.register(_oboron.Ob32pBase32Rfc)
OboronBase.register(_oboron.Ob32pBase64)
OboronBase.register(_oboron.Ob32pHex)

# Ob71 variants (testing)
OboronBase.register(_oboron.Ob71)
OboronBase.register(_oboron.Ob71Base32Crockford)
OboronBase.register(_oboron.Ob71Base32Rfc)
OboronBase.register(_oboron.Ob71Base64)
OboronBase.register(_oboron.Ob71Hex)

# Ob70 variants (testing)
OboronBase.register(_oboron.Ob70)
OboronBase.register(_oboron.Ob70Base32Crockford)
OboronBase.register(_oboron.Ob70Base32Rfc)
OboronBase.register(_oboron.Ob70Base64)
OboronBase.register(_oboron.Ob70Hex)

# Flexible interfaces
OboronBase.register(_oboron.Ob)
OboronBase.register(_oboron.ObMulti)

# ============================================================================
# Re-export all classes and functions
# ============================================================================

# Main flexible interface
Ob = _oboron.Ob
ObMulti = _oboron.ObMulti

# Ob00 variants (LEGACY)
Ob00 = _oboron.Ob00
Ob00Base32Crockford = _oboron.Ob00Base32Crockford
Ob00Base32Rfc = _oboron.Ob00Base32Rfc
Ob00Base64 = _oboron.Ob00Base64
Ob00Hex = _oboron.Ob00Hex

# Ob01 variants
Ob01 = _oboron.Ob01
Ob01Base32Crockford = _oboron.Ob01Base32Crockford
Ob01Base32Rfc = _oboron.Ob01Base32Rfc
Ob01Base64 = _oboron.Ob01Base64
Ob01Hex = _oboron.Ob01Hex

# Ob21p variants
Ob21p = _oboron.Ob21p
Ob21pBase32Crockford = _oboron.Ob21pBase32Crockford
Ob21pBase32Rfc = _oboron.Ob21pBase32Rfc
Ob21pBase64 = _oboron.Ob21pBase64
Ob21pHex = _oboron.Ob21pHex

# Ob31 variants
Ob31 = _oboron.Ob31
Ob31Base32Crockford = _oboron.Ob31Base32Crockford
Ob31Base32Rfc = _oboron.Ob31Base32Rfc
Ob31Base64 = _oboron.Ob31Base64
Ob31Hex = _oboron.Ob31Hex

# Ob31p variants
Ob31p = _oboron.Ob31p
Ob31pBase32Crockford = _oboron.Ob31pBase32Crockford
Ob31pBase32Rfc = _oboron.Ob31pBase32Rfc
Ob31pBase64 = _oboron.Ob31pBase64
Ob31pHex = _oboron.Ob31pHex

# Ob32 variants
Ob32 = _oboron.Ob32
Ob32Base32Crockford = _oboron.Ob32Base32Crockford
Ob32Base32Rfc = _oboron.Ob32Base32Rfc
Ob32Base64 = _oboron.Ob32Base64
Ob32Hex = _oboron.Ob32Hex

# Ob32p variants
Ob32p = _oboron.Ob32p
Ob32pBase32Crockford = _oboron.Ob32pBase32Crockford
Ob32pBase32Rfc = _oboron.Ob32pBase32Rfc
Ob32pBase64 = _oboron.Ob32pBase64
Ob32pHex = _oboron.Ob32pHex

# Ob70 variants (testing)
Ob70 = _oboron.Ob70
Ob70Base32Crockford = _oboron.Ob70Base32Crockford
Ob70Base32Rfc = _oboron.Ob70Base32Rfc
Ob70Base64 = _oboron.Ob70Base64
Ob70Hex = _oboron.Ob70Hex

# Ob71 variants (testing)
Ob71 = _oboron.Ob71
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
    'ObMulti',

    # Ob00 (LEGACY)
    'Ob00',
    'Ob00Base32Crockford',
    'Ob00Base32Rfc',
    'Ob00Base64',
    'Ob00Hex',

    # Ob01
    'Ob01',
    'Ob01Base32Crockford',
    'Ob01Base32Rfc',
    'Ob01Base64',
    'Ob01Hex',

    # Ob21p
    'Ob21p',
    'Ob21pBase32Crockford',
    'Ob21pBase32Rfc',
    'Ob21pBase64',
    'Ob21pHex',

    # Ob31
    'Ob31',
    'Ob31Base32Crockford',
    'Ob31Base32Rfc',
    'Ob31Base64',
    'Ob31Hex',

    # Ob31p
    'Ob31p',
    'Ob31pBase32Crockford',
    'Ob31pBase32Rfc',
    'Ob31pBase64',
    'Ob31pHex',

    # Ob32
    'Ob32',
    'Ob32Base32Crockford',
    'Ob32Base32Rfc',
    'Ob32Base64',
    'Ob32Hex',

    # Ob32p
    'Ob32p',
    'Ob32pBase32Crockford',
    'Ob32pBase32Rfc',
    'Ob32pBase64',
    'Ob32pHex',

    # Ob70 (testing)
    'Ob70',
    'Ob70Base32Crockford',
    'Ob70Base32Rfc',
    'Ob70Base64',
    'Ob70Hex',

    # Ob71 (testing)
    'Ob71',
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
