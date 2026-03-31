<p align="center">
  🔐 A simple cryptography package based on Monocypher library.<br>
  Supporting E2EE, Hashing, Key Derivation/Exchange, Seal/Unseal<br>
  👑 Written in Nim language
</p>

<p align="center">
  <code>nimble install e2ee</code>
</p>

<p align="center">
  <a href="https://github.com/">API reference</a><br>
  <img src="https://github.com/openpeeps/pistachio/workflows/test/badge.svg" alt="Github Actions">  <img src="https://github.com/openpeeps/pistachio/workflows/docs/badge.svg" alt="Github Actions">
</p>

## 😍 Key Features
- Powered by the Monocypher library
- 🔐 End-to-End Encryption (E2EE) for secure communication
- Key Derivation and Exchange for secure key management
- Seal and Unseal functions for data protection
- Low-level and high-level cryptographic operations for flexibility

## Examples

Password hashing and verification using Argon2id:
```nim
import e2ee/password

let hashedPwd = hashPassword("securepassword123")
assert verifyPassword("securepassword123", hashedPwd) == true
```

## AEAD encryption and decryption:
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

_todo more examples/tests_

### ❤ Contributions & Support
- 🐛 Found a bug? [Create a new Issue](https://github.com/openpeeps/e2ee/issues)
- 👋 Wanna help? [Fork it!](https://github.com/openpeeps/e2ee/fork)
- 😎 [Get €20 in cloud credits from Hetzner](https://hetzner.cloud/?ref=Hm0mYGM9NxZ4)

### 🎩 License
MIT license. [Made by Humans from OpenPeeps](https://github.com/openpeeps).<br>
Copyright OpenPeeps & Contributors &mdash; All rights reserved.
