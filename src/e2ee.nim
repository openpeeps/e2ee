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

when defined(linux):
  {.passC: "-I/usr/local/include".}
  {.passL: "-L/usr/local/lib -lmonocypher".}
else:
  {.passC: "-I/usr/local/include".}
  {.passL: "-L/usr/local/lib -lmonocypher".}

import std/[sequtils, strutils]

import ./e2ee/private/[monocypher, utils]
import ./e2ee/[password, aead, chacha, blake2b, signs]

export password, aead, chacha, blake2b, signs
export monocypher, utils

when isMainModule:
  let seedA: Seed32 = [
    1'u8, 2, 3, 4, 5, 6, 7, 8,
    9, 10, 11, 12, 13, 14, 15, 16,
    17, 18, 19, 20, 21, 22, 23, 24,
    25, 26, 27, 28, 29, 30, 31, 32
  ]

  let seedB: Seed32 = [
    32'u8, 31, 30, 29, 28, 27, 26, 25,
    24, 23, 22, 21, 20, 19, 18, 17,
    16, 15, 14, 13, 12, 11, 10, 9,
    8, 7, 6, 5, 4, 3, 2, 1
  ]
  let kp1 = generateSigningKeyPair(seedA)
  let kp2 = generateSigningKeyPair(seedA)