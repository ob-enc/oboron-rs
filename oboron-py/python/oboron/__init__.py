"""
Oboron - General purpose symmetric encryption+encoding library

Docs: https://www.oboron.org/

This module provides a Pythonic wrapper around the Rust oboron extension,
adding proper inheritance and type checking support.
"""

from abc import ABC, abstractmethod
from . import _oboron
from . import formats  # Add this import

__version__ = (_oboron.__version__
               if hasattr(_oboron, '__version__') else "1.0.0")


class OboronBase(ABC):
    """
    Abstract base class for all Oboron cipher implementations.

    All cipher classes (AasvB32, ZrbcxB64, etc.) are registered as virtual
    subclasses, enabling isinstance() and issubclass() checks.

    Example:
        >>> cipher = AasvC32(key=key)
        >>> isinstance(cipher, OboronBase)
        True

        >>> def process_cipher(cipher:  OboronBase) -> str:
        ...     return cipher. enc("hello")
    """

    @abstractmethod
    def enc(self, plaintext: str) -> str:
        """Encrypt and encode plaintext to obtext."""
        ...

    @abstractmethod
    def dec(self, obtext: str) -> str:
        """Decode and decrypt obtext to plaintext."""
        ...

    @property
    @abstractmethod
    def format(self) -> str:
        """Get the format identifier (e.g., 'aasv.b64')."""
        ...

    @property
    @abstractmethod
    def scheme(self) -> str:
        """Get the scheme identifier (e.g., 'aasv')."""
        ...

    @property
    @abstractmethod
    def encoding(self) -> str:
        """Get the encoding format (e.g., 'c32')."""
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

# Aags variants
OboronBase.register(_oboron.AagsC32)
OboronBase.register(_oboron.AagsB32)
OboronBase.register(_oboron.AagsB64)
OboronBase.register(_oboron.AagsHex)

# Aasv variants
OboronBase.register(_oboron.AasvC32)
OboronBase.register(_oboron.AasvB32)
OboronBase.register(_oboron.AasvB64)
OboronBase.register(_oboron.AasvHex)

# Apgs variants
OboronBase.register(_oboron.ApgsC32)
OboronBase.register(_oboron.ApgsB32)
OboronBase.register(_oboron.ApgsB64)
OboronBase.register(_oboron.ApgsHex)

# Apsv variants
OboronBase.register(_oboron.ApsvC32)
OboronBase.register(_oboron.ApsvB32)
OboronBase.register(_oboron.ApsvB64)
OboronBase.register(_oboron.ApsvHex)

# Upbc variants
OboronBase.register(_oboron.UpbcC32)
OboronBase.register(_oboron.UpbcB32)
OboronBase.register(_oboron.UpbcB64)
OboronBase.register(_oboron.UpbcHex)

# Zrbcx variants
OboronBase.register(_oboron.ZrbcxC32)
OboronBase.register(_oboron.ZrbcxB32)
OboronBase.register(_oboron.ZrbcxB64)
OboronBase.register(_oboron.ZrbcxHex)

# Legacy variants
OboronBase.register(_oboron.LegacyC32)
OboronBase.register(_oboron.LegacyB32)
OboronBase.register(_oboron.LegacyB64)
OboronBase.register(_oboron.LegacyHex)

# Mock1 variants (testing)
OboronBase.register(_oboron.Mock1C32)
OboronBase.register(_oboron.Mock1B32)
OboronBase.register(_oboron.Mock1B64)
OboronBase.register(_oboron.Mock1Hex)

# Mock2 variants (testing)
OboronBase.register(_oboron.Mock2C32)
OboronBase.register(_oboron.Mock2B32)
OboronBase.register(_oboron.Mock2B64)
OboronBase.register(_oboron.Mock2Hex)

# Flexible interfaces
OboronBase.register(_oboron.Ob)
OboronBase.register(_oboron.Omnib)

# ============================================================================
# Re-export all classes and functions
# ============================================================================

# Main flexible interfaces
Ob = _oboron.Ob
Omnib = _oboron.Omnib

# Aags variants
AagsC32 = _oboron.AagsC32
AagsB32 = _oboron.AagsB32
AagsB64 = _oboron.AagsB64
AagsHex = _oboron.AagsHex

# Aasv variants
AasvC32 = _oboron.AasvC32
AasvB32 = _oboron.AasvB32
AasvB64 = _oboron.AasvB64
AasvHex = _oboron.AasvHex

# Apgs variants
ApgsC32 = _oboron.ApgsC32
ApgsB32 = _oboron.ApgsB32
ApgsB64 = _oboron.ApgsB64
ApgsHex = _oboron.ApgsHex

# Apsv variants
ApsvC32 = _oboron.ApsvC32
ApsvB32 = _oboron.ApsvB32
ApsvB64 = _oboron.ApsvB64
ApsvHex = _oboron.ApsvHex

# Upbc variants
UpbcC32 = _oboron.UpbcC32
UpbcB32 = _oboron.UpbcB32
UpbcB64 = _oboron.UpbcB64
UpbcHex = _oboron.UpbcHex

# Zrbcx variants
ZrbcxC32 = _oboron.ZrbcxC32
ZrbcxB32 = _oboron.ZrbcxB32
ZrbcxB64 = _oboron.ZrbcxB64
ZrbcxHex = _oboron.ZrbcxHex

# Legacy variants (LEGACY)
LegacyC32 = _oboron.LegacyC32
LegacyB32 = _oboron.LegacyB32
LegacyB64 = _oboron.LegacyB64
LegacyHex = _oboron.LegacyHex

# Mock1 variants (testing)
Mock1C32 = _oboron.Mock1C32
Mock1B32 = _oboron.Mock1B32
Mock1B64 = _oboron.Mock1B64
Mock1Hex = _oboron.Mock1Hex

# Mock2 variants (testing)
Mock2C32 = _oboron.Mock2C32
Mock2B32 = _oboron.Mock2B32
Mock2B64 = _oboron.Mock2B64
Mock2Hex = _oboron.Mock2Hex

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
    'Omnib',

    # Aags
    'AagsC32',
    'AagsB32',
    'AagsB64',
    'AagsHex',

    # Aasv
    'AasvC32',
    'AasvB32',
    'AasvB64',
    'AasvHex',

    # Apgs
    'ApgsC32',
    'ApgsB32',
    'ApgsB64',
    'ApgsHex',

    # Apsv
    'ApsvC32',
    'ApsvB32',
    'ApsvB64',
    'ApsvHex',

    # Upbc
    'UpbcC32',
    'UpbcB32',
    'UpbcB64',
    'UpbcHex',

    # Zrbcx
    'ZrbcxC32',
    'ZrbcxB32',
    'ZrbcxB64',
    'ZrbcxHex',

    # Legacy
    'LegacyC32',
    'LegacyB32',
    'LegacyB64',
    'LegacyHex',

    # Mock1 (testing)
    'Mock1C32',
    'Mock1B32',
    'Mock1B64',
    'Mock1Hex',

    # Mock2 (testing)
    'Mock2C32',
    'Mock2B32',
    'Mock2B64',
    'Mock2Hex',

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
