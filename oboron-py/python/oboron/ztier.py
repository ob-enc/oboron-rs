from . import _oboron

# Z-tier interfaces
Obz = _oboron.Obz
Omniz = _oboron.Omniz

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

__all__ = [
    # Z-tier interfaces
    'Obz',
    'Omniz',

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
]
