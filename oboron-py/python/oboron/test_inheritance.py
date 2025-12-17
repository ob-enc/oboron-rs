"""Test that inheritance works correctly."""

import oboron

def test_isinstance_checks():
    """Test that isinstance works with OboronBase."""
    key = oboron.generate_key()
    
    # Test specific cipher classes
    ob32 = oboron.Ob32(key=key)
    assert isinstance(ob32, oboron.OboronBase)
    
    ob01 = oboron.Ob01Base64(key=key)
    assert isinstance(ob01, oboron.OboronBase)
    
    # Test flexible interfaces
    ob = oboron.Ob("ob32:b64", key=key)
    assert isinstance(ob, oboron.OboronBase)
    
    ob_multi = oboron.ObMulti(key=key)
    assert isinstance(ob_multi, oboron.OboronBase)
    
    print("✓ All isinstance checks passed!")


def test_protocol_checks():
    """Test that Protocol duck typing works."""
    key = oboron.generate_key()
    
    ob32 = oboron.Ob32(key=key)
    assert isinstance(ob32, oboron. OboronBase)
    
    print("✓ Protocol checks passed!")


def test_polymorphic_function():
    """Test that we can write generic functions over OboronBase."""
    def encrypt_with_cipher(cipher:  oboron.OboronBase, data: str) -> str:
        """Generic function that works with any Oboron cipher."""
        return cipher.enc(data)
    
    key = oboron.generate_key()
    plaintext = "Hello, World!"
    
    # Test with different cipher types
    ob32 = oboron.Ob32(key=key)
    ob01 = oboron.Ob01(key=key)
    
    enc1 = encrypt_with_cipher(ob32, plaintext)
    enc2 = encrypt_with_cipher(ob01, plaintext)
    
    assert ob32.dec(enc1) == plaintext
    assert ob01.dec(enc2) == plaintext
    
    print("✓ Polymorphic function test passed!")


if __name__ == "__main__": 
    test_isinstance_checks()
    test_protocol_checks()
    test_polymorphic_function()
    print("\n✅ All tests passed!")
