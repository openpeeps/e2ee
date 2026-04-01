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
import ./e2ee/[password, aead, chacha, blake2b, signs]

export password, aead, chacha, blake2b, signs
export monocypher, utils
