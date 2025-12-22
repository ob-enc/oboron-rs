"""Test that inheritance works correctly."""

import oboron

def test_isinstance_checks():
    """Test that isinstance works with OboronBase."""
    key = oboron.generate_key()
    
    # Test specific cipher classes
    adsv = oboron.AdsvC32(key=key)
    assert isinstance(adsv, oboron.OboronBase)
    
    zfbcx = oboron.ZfbcxB64(key=key)
    assert isinstance(zfbcx, oboron.OboronBase)
    
    # Test flexible interfaces
    ob = oboron.Ob("adsv.b64", key=key)
    assert isinstance(ob, oboron.OboronBase)
    
    ob_multi = oboron.ObMulti(key=key)
    assert isinstance(ob_multi, oboron.OboronBase)
    
    print("✓ All isinstance checks passed!")


def test_protocol_checks():
    """Test that Protocol duck typing works."""
    key = oboron.generate_key()
    
    adsv = oboron.AdsvC32(key=key)
    assert isinstance(adsv, oboron. OboronBase)
    
    print("✓ Protocol checks passed!")


def test_polymorphic_function():
    """Test that we can write generic functions over OboronBase."""
    def encrypt_with_cipher(cipher:  oboron.OboronBase, data: str) -> str:
        """Generic function that works with any Oboron cipher."""
        return cipher.enc(data)
    
    key = oboron.generate_key()
    plaintext = "Hello, World!"
    
    # Test with different cipher types
    adsv = oboron.AdsvC32(key=key)
    zfbcx = oboron.ZfbcxC32(key=key)
    
    ot1 = encrypt_with_cipher(adsv, plaintext)
    ot2 = encrypt_with_cipher(zfbcx, plaintext)
    
    assert adsv.dec(ot1) == plaintext
    assert zfbcx.dec(ot2) == plaintext
    
    print("✓ Polymorphic function test passed!")


if __name__ == "__main__": 
    test_isinstance_checks()
    test_protocol_checks()
    test_polymorphic_function()
    print("\n✅ All tests passed!")
