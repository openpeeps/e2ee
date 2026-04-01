# A super simple crypography module for end-to-end encryption (E2EE),
# hashing, key derivation, and key exchange using the Monocypher library.
#
# (c) 2025 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/e2ee

import ./private/[monocypher, utils]

## This module implements Ed25519 signatures for signing and verifying messages. It provides
## high-level nim style APIs for generating signing key pairs, signing messages
## and verifying signatures.

type
  Seed32* = array[32, uint8]
  PublicKey* = array[32, uint8]
  SecretKey* = array[64, uint8]
  Signature* = array[64, uint8]

  SigningKeyPair* = object
    publicKey*: PublicKey
      ## The public key is 32 bytes, derived from the secret key.
      ## It can be shared publicly and is used for verifying signatures
    secretKey*: SecretKey
      ## The secret key is actually 64 bytes, consisting of the 32-byte
      ## seed followed by the 32-byte public key

proc generateSigningKeyPair*(seed: Seed32): SigningKeyPair =
  ## Deterministic keypair from a 32-byte seed.
  crypto_eddsa_key_pair(result.secretKey, result.publicKey, seed)

proc generateSigningKeyPair*(): SigningKeyPair =
  ## Random keypair generated from a random 32-byte seed
  let seed = randomBytes[32]()
  result = generateSigningKeyPair(seed)

proc sign*(secretKey: SecretKey, message: openArray[uint8]): Signature =
  ## Create detached EdDSA signature.
  let msgPtr =
    if message.len == 0: nil
    else: cast[ptr uint8](unsafeAddr message[0])
  crypto_eddsa_sign(result, secretKey, msgPtr, csize_t(message.len))

proc sign*(secretKey: SecretKey, message: string): Signature =
  let msgPtr =
    if message.len == 0: nil
    else: cast[ptr uint8](unsafeAddr message[0])
  crypto_eddsa_sign(result, secretKey, msgPtr, csize_t(message.len))

proc verify*(publicKey: PublicKey, message: openArray[uint8], signature: Signature): bool =
  ## Verify detached EdDSA signature
  let msgPtr =
    if message.len == 0: nil
    else: cast[ptr uint8](unsafeAddr message[0])
  result = crypto_eddsa_check(signature, publicKey, msgPtr, csize_t(message.len)) == 0

proc verify*(publicKey: PublicKey, message: string, signature: Signature): bool =
  ## Verify detached EdDSA signature
  let msgPtr =
    if message.len == 0: nil
    else: cast[ptr uint8](unsafeAddr message[0])
  result = crypto_eddsa_check(signature, publicKey, msgPtr, csize_t(message.len)) == 0

# Convenience functions for hex encoding/decoding of keys and signatures
proc publicKeyToHex*(k: PublicKey): string = k.toHex()
proc secretKeyToHex*(k: SecretKey): string = k.toHex()
proc signatureToHex*(s: Signature): string = s.toHex()

proc publicKeyFromHex*(s: string): PublicKey =
  ## Convert a hex string back to a PublicKey. The hex string must
  ## be 64 characters (32 bytes).
  if s.len != 64:
    raise newException(ValueError, "Public key must be 64 hex chars")
  result = fromHex[32, uint8](s)

proc secretKeyFromHex*(s: string): SecretKey =
  ## Convert a hex string back to a SecretKey. The hex string must
  if s.len != 128:
    raise newException(ValueError, "Secret key must be 128 hex chars")
  result = fromHex[64, uint8](s)

proc signatureFromHex*(s: string): Signature =
  ## Convert a hex string back to a Signature. The hex string must
  ## be 128 characters (64 bytes)
  if s.len != 128:
    raise newException(ValueError, "Signature must be 128 hex chars")
  result = fromHex[64, uint8](s)