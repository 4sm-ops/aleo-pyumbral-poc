# PoC Overview

We checked Aleo and Umbral documentation and we would like to test 2 scenarios:

1. Umbral SecretKey from byte_read of Aleo Private Key SHA256 hash 32 bytes long

![Aleo Umbral Approach #1](https://raw.githubusercontent.com/4sm-ops/aleo-pyumbral-poc/master/assets/aleo-umbral-approach_1.png)

2. Both Aleo and Umbral Private/Secret Keys can be generated from single 32 bytes seed

![Aleo Umbral Approach #2](https://raw.githubusercontent.com/4sm-ops/aleo-pyumbral-poc/master/assets/aleo-umbral-approach_2.png)

# Umbral SecretKey from byte_read of Aleo Private Key

PoC code: https://github.com/4sm-ops/aleo-pyumbral-poc/blob/master/test_01_pyumbral_keys.py

## Generate new Aleo Private Key

```
# snarkos experimental new_account | grep Private
```

## Calculate sha256 hash

Calculate sha256 hash from sample Aleo Private Key

```
aleo_private_key_hash = hashlib.sha256()
aleo_private_key_hash.update(b"APrivateKey1zkpJfEMPSA6PTq3phcPcNCKapDr9kKFsNoD5kyf8gfGBLSj")

print(aleo_private_key_hash.digest())
print(aleo_private_key_hash.digest_size)
```

## Read SecretKey from sha256() output

We use .from_bytes function to read new SecretKey from sha256() output
.from_bytes function expects 32 bytes that's why we cannot use Aleo Private Key itself (which is 59 bytes long)

```
sk = SecretKey.from_bytes(aleo_private_key_hash.digest())

print(sk.to_secret_bytes())
print(sk.serialized_size())
```

## Generating of PublicKey from SecretKey

```
pk_from_sk = sk.public_key()
```

## Validation of data types

```
assert type(sk) == SecretKey
assert type(pk_from_sk) == PublicKey
```

## Validate encryption / decryption of sample data

```
secret_key = restore_keys_from_aleo()

encrypt_decrypt(secret_key)
```

```
Decrypted with Alice key:
b'Aleo Private Key usage PoC. Plaintext'
Bob decrypted text:
b'Aleo Private Key usage PoC. Plaintext'
```
