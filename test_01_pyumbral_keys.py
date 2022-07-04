import os
import string
from tkinter.filedialog import test

import hashlib

import random

import pytest

from umbral import PublicKey, SecretKey, Signer, encrypt, decrypt_original, generate_kfrags, reencrypt, CapsuleFrag, decrypt_reencrypted

# Aleo Private Key -> Umbral SecretKey PoC function

def restore_keys_from_aleo():
    
    # Calculate sha256 hash from sample Aleo Private Key
    # snarkos experimental new_account
    aleo_private_key_hash = hashlib.sha256()
    aleo_private_key_hash.update(b"APrivateKey1zkpJfEMPSA6PTq3phcPcNCKapDr9kKFsNoD5kyf8gfGBLSj")

    print(aleo_private_key_hash.digest())
    print(aleo_private_key_hash.digest_size)

    # We use .from_bytes function to read new SecretKey from sha256() output
    # .from_bytes function expects 32 bytes
    # that's why we cannot use Aleo Private Key itself (which is 59 bytes long)

    sk = SecretKey.from_bytes(aleo_private_key_hash.digest())

    print(sk.to_secret_bytes())
    print(sk.serialized_size())
    
    # Generating public key from SecretKey
    pk_from_sk = sk.public_key()

    # Validation of data types
    
    assert type(sk) == SecretKey
    assert type(pk_from_sk) == PublicKey

    return sk

# Umbral encryption / decryption test

def encrypt_decrypt(alice_secret_key):

    alices_secret_key = alice_secret_key
    alices_public_key = alices_secret_key.public_key()

    alices_signing_key = alice_secret_key
    alices_verifying_key = alices_signing_key.public_key()
    alices_signer = Signer(alices_signing_key)

    # Encrypt with a public key
    # Now let’s encrypt data with Alice’s public key. Invocation of umbral.encrypt() returns both a capsule and a ciphertext. Note that anyone with Alice’s public key can perform this operation.

    print("Decrypted with Alice key:")
    plaintext = b'Aleo Private Key usage PoC. Plaintext'
    capsule, ciphertext = encrypt(alices_public_key, plaintext)

    # Decrypt with a private key
    # Since data was encrypted with Alice’s public key, Alice can open the capsule and decrypt the ciphertext with her private key.

    cleartext = decrypt_original(alices_secret_key, capsule, ciphertext)
    print(cleartext)

    # Threshold Re-Encryption
    # Bob Exists

    bobs_secret_key = SecretKey.random() # but can be Aleo Private key as well
    bobs_public_key = bobs_secret_key.public_key()

    # Alice grants access to Bob by generating kfrags
    # When Alice wants to grant Bob access to view her encrypted data, 
    # she creates re-encryption key fragments, or “kfrags”, which are next sent to N proxies or Ursulas.

    kfrags = generate_kfrags(delegating_sk=alices_secret_key,
                            receiving_pk=bobs_public_key,
                            signer=alices_signer,
                            threshold=10,
                            shares=20)

    # Bob receives a capsule
    # Next, let’s generate a key pair for Bob, and pretend to send him the capsule 
    # through a side channel like S3, IPFS, Google Cloud, Sneakernet, etc.

    bobs_capsule = capsule

    # Bob fails to open the capsule
    # If Bob attempts to open a capsule that was not encrypted for his public key, 
    # or re-encrypted for him by Ursula, he will not be able to open it.

    # This will fail!!!
    # fail = decrypt_original(delegating_sk=bobs_secret_key, capsule=capsule, ciphertext=ciphertext)

    # Ursulas perform re-encryption
    # Bob asks several Ursulas to re-encrypt the capsule so he can open it. 
    # Each Ursula performs re-encryption on the capsule using the kfrag provided by Alice, obtaining this way a “capsule fragment”, or cfrag. 

    # All kfrags from above
    # M - Threshold
    kfrags = random.sample(kfrags, 10)      

    cfrags = list()                 # Bob's cfrag collection
    for kfrag in kfrags:
        cfrag = reencrypt(capsule=bobs_capsule, kfrag=kfrag)
        cfrags.append(cfrag)        # Bob collects a cfrag

    # Decryption
    # Bob checks the capsule fragments
    # If Bob received the capsule fragments in serialized form, he can verify that 
    # they are valid and really originate from Alice, using Alice’s public keys.

    suspicious_cfrags = [CapsuleFrag.from_bytes(bytes(cfrag)) for cfrag in cfrags]
    cfrags = [cfrag.verify(capsule, verifying_pk=alices_verifying_key,
                       delegating_pk=alices_public_key,
                           receiving_pk=bobs_public_key,
                           )
              for cfrag in suspicious_cfrags]
    
    # Bob opens the capsule

    # Finally, Bob decrypts the re-encrypted ciphertext using his key.

    decrypted_cleartext = decrypt_reencrypted(receiving_sk=bobs_secret_key,
                                    delegating_pk=alices_public_key,
                                    capsule=capsule,
                                    verified_cfrags=cfrags,
                                    ciphertext=ciphertext)

    # Verify decryption result

    print("Bob decrypted text:")
    print(decrypted_cleartext)
    

# test function to generate SecretKey and PublicKey using random() function

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



#test_gen_key()
secret_key = restore_keys_from_aleo()

encrypt_decrypt(secret_key)