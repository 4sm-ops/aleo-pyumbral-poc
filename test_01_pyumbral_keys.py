import os
import string
from tkinter.filedialog import test

import hashlib

import pytest

from umbral.keys import PublicKey, SecretKey, SecretKeyFactory


def test_gen_key():
    sk = SecretKey.random()
    assert type(sk) == SecretKey

    print(sk.serialized_size())
    print(sk.to_secret_bytes())

    pk = sk.public_key()
    assert type(pk) == PublicKey

    print(sk.public_key())

    pk2 = sk.public_key()
    assert pk == pk2


def restore_keys_from_aleo():

    
    m = hashlib.sha256()
    m.update(b"APrivateKey1zkpJfEMPSA6PTq3phcPcNCKapDr9kKFsNoD5kyf8gfGBLSj")
    print(m.digest())
    print(m.digest_size)

    sk = SecretKey.from_bytes(m.digest())
    pk_from_sk = sk.public_key()

    print(sk.serialized_size())
    print(sk.to_secret_bytes())
    
    assert type(sk) == SecretKey

    assert type(pk_from_sk) == PublicKey

#test_gen_key()

restore_keys_from_aleo()