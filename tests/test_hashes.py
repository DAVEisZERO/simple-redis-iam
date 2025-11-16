import hashlib
from pwdlib import PasswordHash
import pytest


def test_md5_hash():
    print(hashlib.md5("213456789".encode()).hexdigest())
    assert "0b2b732d6c5848ec7784c57c2e3acba3" == hashlib.md5("213456789".encode()).hexdigest()

def test_argon2_hash():
    password_hash = PasswordHash.recommended()
    new_hash = password_hash.hash("123456789")
    print(new_hash)
    print(new_hash.split('$')[-1])

    assert password_hash.verify("123456789", new_hash)
