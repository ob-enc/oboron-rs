"""Test that inheritance works correctly."""

import oboron


def test_isinstance_checks():
    """Test that isinstance works with OboronBase."""
    key = oboron.generate_key()

    # Test specific cipher classes
    aasv = oboron.AasvC32(key=key)
    assert isinstance(aasv, oboron.OboronBase)

    zrbcx = oboron.ZrbcxB64(key=key)
    assert isinstance(zrbcx, oboron.OboronBase)

    # Test flexible interfaces
    ob = oboron.Ob("aasv.b64", key=key)
    assert isinstance(ob, oboron.OboronBase)

    omnib = oboron.Omnib(key=key)
    assert isinstance(omnib, oboron. OboronBase)

    print("✓ All isinstance checks passed!")


def test_polymorphic_function():
    """Test that we can write generic functions over OboronBase."""
    def encrypt_with_cipher(cipher: oboron.OboronBase, data: str) -> str:
        """Generic function that works with any Oboron cipher."""
        return cipher.enc(data)

    key = oboron.generate_key()
    plaintext = "Hello, World!"

    # Test with different cipher types
    aasv = oboron.AasvC32(key=key)
    zrbcx = oboron.ZrbcxC32(key=key)

    ot1 = encrypt_with_cipher(aasv, plaintext)
    ot2 = encrypt_with_cipher(zrbcx, plaintext)

    assert aasv.dec(ot1) == plaintext
    assert zrbcx.dec(ot2) == plaintext

    print("✓ Polymorphic function test passed!")


def test_omnib_operations():
    """Test Omnib multi-format operations."""
    key = oboron.generate_key()
    omnib = oboron.Omnib(key=key)

    # Encode with different formats
    ot_aasv = omnib.enc("test", "aasv. b64")
    ot_apgs = omnib.enc("test", "apgs.b64")

    # Decode with autodec
    assert omnib.autodec(ot_aasv) == "test"
    assert omnib.autodec(ot_apgs) == "test"

    print("✓ Omnib test passed!")


if __name__ == "__main__":
    test_isinstance_checks()
    test_polymorphic_function()
    test_omnib_operations()
    print("\n✅ All tests passed!")
