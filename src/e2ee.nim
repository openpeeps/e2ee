# A super simple crypography module for end-to-end encryption (E2EE),
# hashing, key derivation, and key exchange using the Monocypher library.
#
# (c) 2025 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/e2ee

## This is a simple wrapper around the Monocypher library to provide both
## low-level access to the cryptographic primitives and a higher-level API for
## common use cases like password hashing, authenticated encryption, and key exchange.
##
## The high-level API is designed to be easy to use for typical E2EE applications,
## while the low-level API expose a C-like interface for those who need more control.
## 
## The library includes:
## - Password hashing and verification using Argon2id
## - Key derivation from passwords
## - AEAD encryption and decryption using crypto_aead_lock/unlock
## - XChaCha20 stream cipher encryption and decryption
## - Sealing and unsealing messages with random nonces
## - Challenge-response MACs for mutual authentication

import std/[sequtils, strutils]

import ./e2ee/private/[monocypher, utils]
import ./e2ee/[password, aead, chacha]

export password, aead, chacha
export monocypher, utils

# when isMainModule:
#   block ee2eExample:
#     echo " --- E2EE key exchange example"
#     let pwd = "correct horse battery staple"
#     let salt = generateSalt()

#     # Derive keypairs from password+salt
#     let (aliceSK, alicePK) = keyPairFromPassword(pwd, salt)
#     let (bobSK, bobPK) = keyPairFromPassword(pwd, salt)

#     # Derive shared secret (both sides should match)
#     let aliceShared = aliceSK.sharedSecret(bobPK)
#     let bobShared = bobSK.sharedSecret(alicePK)

#     echo "Shared secret matches: ", (aliceShared == bobShared)

#     # High-level sealing/unsealing
#     let message = "Hello from Alice via seal/unseal API"
#     let sealed = aead.seal(message, aliceShared)

#     echo "Sealed cipher length: ", sealed.cipherText.len
#     let opened = aead.unseal(sealed, bobShared)

#     echo "Opened message: ", opened

#   block e2eeStreamExample:
#     echo " --- AEAD streaming example"
#     let key = randomBytes[32]()
#     let nonce = randomBytes[24]()

#     # Split a message into chunks
#     let message = "Hello, this is a test of AEAD streaming!"
#     let chunk1 = message.toOpenArrayByte(0, 15).toSeq()
#     let chunk2 = message.toOpenArrayByte(16, message.high).toSeq()

#     # Encrypt chunks
#     var stream = aeadStreamInitX(key, nonce)
#     let (cipher1, mac1) = aeadStreamWrite(stream, chunk1)
#     let (cipher2, mac2) = aeadStreamWrite(stream, chunk2)

#     # Decrypt chunks
#     var decStream = aeadStreamInitX(key, nonce)
#     let plain1 = aeadStreamRead(decStream, cipher1, mac1)
#     let plain2 = aeadStreamRead(decStream, cipher2, mac2)

#     # Combine and print
#     let decrypted = cast[string](plain1 & plain2)
#     echo "Original:  ", message
#     echo "Decrypted: ", decrypted

#   block chachaExample:
#     echo " --- XChaCha20 example"
#     let salt = generateSalt()
#     let msg = chacha.sealWithPassword("Secret", "password123", salt)
#     let opened = chacha.unsealWithPassword(msg, "password123", salt)
#     echo opened # "Secret"