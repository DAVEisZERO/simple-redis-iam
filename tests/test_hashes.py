import hashlib
from pwdlib import PasswordHash
import pytest



def test_md5_hash():
    """
    Test the MD5 hashing function.

    This test computes the MD5 hash of the string "213456789" 
    and asserts that the computed hash matches the expected value.
    """
    print(hashlib.md5("213456789".encode()).hexdigest())
    assert "0b2b732d6c5848ec7784c57c2e3acba3" == hashlib.md5("213456789".encode()).hexdigest()

def test_argon2_hash():
    """
    Test the Argon2 password hashing function.

    This test hashes the password "123456789" using the Argon2 
    algorithm and verifies that the hash can be used to validate 
    the original password.
    """
    password_hash = PasswordHash.recommended()
    new_hash = password_hash.hash("123456789")
    print(new_hash)
    print(new_hash.split('$')[-1])

    assert password_hash.verify("123456789", new_hash)
