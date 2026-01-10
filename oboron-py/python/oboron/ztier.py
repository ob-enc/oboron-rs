from abc import ABC, abstractmethod
from . import _oboron


class ZtierBase(ABC):
    """
    Abstract base class for all Ztier codec implementations.

    All cipher classes (AasvB32, AasvC32, etc.) are registered as virtual
    subclasses, enabling isinstance() and issubclass() checks.

    Example:
        >>> cipher = AasvC32(key=key)
        >>> isinstance(cipher, OboronBase)
        True

        >>> def process_cipher(cipher:  OboronBase) -> str:
        ...     return cipher.enc("hello")
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
    def secret(self) -> str:
        """Get the encryption secret as a base64 string."""
        ...

    @property
    @abstractmethod
    def secret_hex(self) -> str:
        """Get the encryption secret as a hex string."""
        ...

    @property
    @abstractmethod
    def secret_bytes(self) -> bytes:
        """Get the encryption secret as raw bytes."""
        ...


# ============================================================================
# Register all Rust classes as virtual subclasses
# ============================================================================

# Zrbcx variants
ZtierBase.register(_oboron.ZrbcxC32)
ZtierBase.register(_oboron.ZrbcxB32)
ZtierBase.register(_oboron.ZrbcxB64)
ZtierBase.register(_oboron.ZrbcxHex)

# Legacy variants
ZtierBase.register(_oboron.LegacyC32)
ZtierBase.register(_oboron.LegacyB32)
ZtierBase.register(_oboron.LegacyB64)
ZtierBase.register(_oboron.LegacyHex)

# Zmock1 variants
ZtierBase.register(_oboron.Zmock1C32)
ZtierBase.register(_oboron.Zmock1B32)
ZtierBase.register(_oboron.Zmock1B64)
ZtierBase.register(_oboron.Zmock1Hex)

# Flexible interface
ZtierBase.register(_oboron.Obz)


# ============================================================================
# Re-export all classes and functions
# ============================================================================

# Z-tier interfaces
Obz = _oboron.Obz
Omnibz = _oboron.Omnibz

# Zrbcx variants
ZrbcxC32 = _oboron.ZrbcxC32
ZrbcxB32 = _oboron.ZrbcxB32
ZrbcxB64 = _oboron.ZrbcxB64
ZrbcxHex = _oboron.ZrbcxHex

# Legacy variants
LegacyC32 = _oboron.LegacyC32
LegacyB32 = _oboron.LegacyB32
LegacyB64 = _oboron.LegacyB64
LegacyHex = _oboron.LegacyHex

# Zmock1 (testing)
Zmock1C32 = _oboron.Zmock1C32
Zmock1B32 = _oboron.Zmock1B32
Zmock1B64 = _oboron.Zmock1B64
Zmock1Hex = _oboron.Zmock1Hex

# Utility functions
generate_secret = _oboron.generate_secret
generate_secret_hex = _oboron.generate_secret_hex
generate_secret_bytes = _oboron.generate_secret_bytes

__all__ = [
    # Z-tier interfaces
    'Obz',
    'Omnibz',

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

    # Zmock1
    'Zmock1C32',
    'Zmock1B32',
    'Zmock1B64',
    'Zmock1Hex',

    # Utility functions
    'generate_secret',
    'generate_secret_hex',
    'generate_secret_bytes',
]
