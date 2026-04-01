<p align="center">
  🔐 A simple cryptography package based on Monocypher library.<br>
  Supporting E2EE Streams &bullet; Password Hashing/Validation Argon2id&bullet;<br>
  Key Derivation/Exchange &bullet; Seal/Unseal<br>
  👑 Written in Nim language | Powered by 🔐 Monocypher
</p>

<p align="center">
  <code>nimble install e2ee</code>
</p>

<p align="center">
  <a href="https://openpeeps.github.io/e2ee/">API reference</a><br>
  <img src="https://github.com/openpeeps/e2ee/workflows/test/badge.svg" alt="Github Actions">  <img src="https://github.com/openpeeps/e2ee/workflows/docs/badge.svg" alt="Github Actions">
</p>

## 😍 Key Features
- Powered by the Monocypher library
- 🔐 End-to-End Encryption (E2EE) for secure communication
- Key Derivation and Exchange for secure key management
- Seal and Unseal functions for data protection
- Password Hashing and Validation using Argon2id
- Hash functions including BLAKE2b for data integrity and authentication
- Low-level and high-level cryptographic operations for flexibility

## Examples

## Password generation, hashing and verification
Generate a random password using a master password and a salt:
```nim
import e2ee/password
let salt = generateSalt().toHex()
let pwd = generatePassword("masterpassword", salt, length = 16)
echo "Generated password: ", pwd
```

Use the Argon2id algorithm to hash passwords and verify them securely:
```nim
import e2ee/password

let hashedPwd = hashPassword("securepassword123")
assert verifyPassword("securepassword123", hashedPwd) == true
```

## AEAD encryption and decryption
Use AEAD for sealing and unsealing messages with a shared secret derived from passwords. This example demonstrates how two parties can independently derive the same shared secret from their passwords and use it for secure communication:
```nim
import e2ee/aead

let alicePwd = "alice-super-secret-passphrase"
let bobPwd   = "bob-different-secret-passphrase"
let aliceSalt = generateSalt()
let bobSalt   = generateSalt()

# independent long-term identities
let (aliceSK, alicePK) = keyPairFromPassword(alicePwd, aliceSalt)
let (bobSK, bobPK) = keyPairFromPassword(bobPwd, bobSalt)

# should be different identities
assert aliceSK != bobSK
assert alicePK != bobPK

# ECDH agreement should still match
let aliceShared = aliceSK.sharedSecret(bobPK)
let bobShared = bobSK.sharedSecret(alicePK)
assert aliceShared == bobShared

# use shared secret as symmetric key
let msg = "Hi Bob, this is Alice."
let sealed = aead.seal(msg, aliceShared)
let opened = aead.unseal(sealed, bobShared)
assert opened == msg
```

### AEAD streaming encryption and decryption
For encrypting large data streams, you can use the streaming API, here
is an example of how to encrypt and decrypt a message in chunks:
```nim
import e2ee/aead
let key = randomBytes[32]()
let nonce = randomBytes[24]()

# Split a message into chunks
let message = "Hello, this is a test of AEAD streaming!"
let chunk1 = message.toOpenArrayByte(0, 15).toSeq()
let chunk2 = message.toOpenArrayByte(16, message.high).toSeq()

# Encrypt chunks
var stream = aeadStreamInitX(key, nonce)
let (cipher1, mac1) = aeadStreamWrite(stream, chunk1)
let (cipher2, mac2) = aeadStreamWrite(stream, chunk2)

assert cipher1.len == chunk1.len
assert cipher2.len == chunk2.len

assert mac1.len == 16
assert mac2.len == 16

# Decrypt chunks
var decStream = aeadStreamInitX(key, nonce)
let plain1 = aeadStreamRead(decStream, cipher1, mac1)
let plain2 = aeadStreamRead(decStream, cipher2, mac2)

assert plain1 == chunk1
assert plain2 == chunk2

# Combine and print
let decrypted = cast[string](plain1 & plain2)
assert decrypted == message
```

### ChaCha sealing and opening
Simple sealing and opening of messages using ChaCha20:
```nim
let salt = generateSalt()
let password = "password123"
let msg = "This is a secret message."

let sealed = chacha.sealWithPassword(msg, password, salt)
let opened = chacha.unsealWithPassword(sealed, password, salt)

assert opened == msg
```

### BLAKE2b hashing
Compute a BLAKE2b hash of a message. For more examples and test vectors, see the [test suite](https://github.com/openpeeps/e2ee/blob/main/tests/test1.nim):
```nim
import e2ee/blake2b
let msg = "Hello, world!"
echo "BLAKE2b digest: ", blakeHex(msg)
```


Check the tests for more runnable examples of the high-level API, including keyed hashing, incremental hashing, and password hashing 👉 [tests/*.nim](https://github.com/openpeeps/e2ee/blob/main/tests/test1.nim)

### ❤ Contributions & Support
- 🐛 Found a bug? [Create a new Issue](https://github.com/openpeeps/e2ee/issues)
- 👋 Wanna help? [Fork it!](https://github.com/openpeeps/e2ee/fork)
- 😎 [Get €20 in cloud credits from Hetzner](https://hetzner.cloud/?ref=Hm0mYGM9NxZ4)

### 🎩 License
MIT license. [Made by Humans from OpenPeeps](https://github.com/openpeeps).<br>
Copyright OpenPeeps & Contributors &mdash; All rights reserved.
