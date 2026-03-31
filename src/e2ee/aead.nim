# A super simple crypography module for end-to-end encryption (E2EE),
# hashing, key derivation, and key exchange using the Monocypher library.
#
# (c) 2025 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/e2ee

## This module provides a simple interface for encrypting and decrypting
## messages using a shared secret key derived from a password or generated
## through X25519 key exchange. It also includes functions for sealing and
## unsealing messages, as well as computing and verifying challenge-response
## MACs for mutual authentication

import ./private/[monocypher, utils]
import ./password

type
  SealedMessage* = object
    nonce*: Nonce24
    mac*: Mac16
    cipherText*: seq[uint8]

proc encrypt*(text: string, key: array[32, uint8],
          nonce: array[24, uint8]): (seq[uint8], RandomBytes) =
  ## Encrypts the given plainText using the provided key and nonce.
  ## Returns a tuple of (cipherText, mac).
  ## 
  ## This is using the crypto_aead_lock that encrypts and authenticates a plaintext.
  ## It can be decrypted using decrypt which uses crypto_aead_unlock. The MAC
  ## is generated as part of the encryption process and is required for decryption
  let plainBytes = cast[seq[uint8]](text)
  var cipherText = newSeq[uint8](plainBytes.len)
  var mac: RandomBytes
  crypto_aead_lock(
    cipherText[0].addr,  # cipher_text
    mac,                 # mac[16]
    key,                 # key[32]
    nonce,               # nonce[24]
    nil, 0,              # ad, ad_size (no additional data)
    plainBytes[0].addr, csize_t(plainBytes.len)  # plain_text, text_size
  )
  return (cipherText, mac)

proc encrypt*(text: string, key: string, nonce: string): (seq[uint8], RandomBytes) =
  ## Encrypts the given plainText using the provided key and nonce as hex strings.
  ## Returns a tuple of (cipherText, mac).
  ## 
  ## This is using the crypto_aead_lock that encrypts and authenticates a plaintext.
  ## It can be decrypted using decrypt which uses crypto_aead_unlock. The MAC
  ## is generated as part of the encryption process and is required for decryption
  let keyBytes = cast[seq[uint8]](key)
  let nonceBytes = cast[seq[uint8]](nonce)
  if keyBytes.len != 32:
    raise newException(ValueError, "Key must be 32 bytes (64 hex characters)")
  if nonceBytes.len != 24:
    raise newException(ValueError, "Nonce must be 24 bytes (48 hex characters)")
  return encrypt(text, cast[array[32, uint8]](keyBytes), cast[array[24, uint8]](nonceBytes))

proc decrypt*(cipherText: seq[uint8], mac: RandomBytes,
                key: array[32, uint8], nonce: array[24, uint8]): string =
  ## Decrypts the given cipherText using the provided key and nonce.
  ## Returns the decrypted plainText as a string.
  ## 
  ## This uses crypto_aead_unlock to decrypt and verify the MAC. If decryption fails
  ## or if the MAC verification fails, it raises an exception
  var plainBytes = newSeq[uint8](cipherText.len)
  let result = crypto_aead_unlock(
    plainBytes[0].addr,   # plain_text
    mac,                  # mac[16]
    key,                  # key[32]
    nonce,                # nonce[24]
    nil, 0,              # ad, ad_size
    cipherText[0].addr, csize_t(cipherText.len)  # cipher_text, text_size
  )
  if result != 0:
    raise newException(ValueError, "Decryption failed or MAC verification failed")
  return cast[string](plainBytes)

#
# High-level APIs for sealing and unsealing messages
# including key pair generation, shared secret computation, and challenge-response MACs
#
proc x25519KeyPair*(secret: Key32): (Key32, Key32) =
  ## Generate X25519 key pair from secret. Returns (secret, publicKey)
  var publicKey: Key32
  crypto_x25519_public_key(publicKey, secret)
  (secret, publicKey)

proc sharedSecret*(mySecret: Key32, theirPublic: Key32): Key32 =
  ## Compute the shared secret using X25519. Returns the shared secret
  var secret: Key32
  crypto_x25519(secret, mySecret, theirPublic)
  secret

proc keyPairFromPassword*(password: string, salt: RandomBytes): (Key32, Key32) =
  ## Derive a key pair from a password and salt. Returns (secret, publicKey)
  let secret = deriveKeyFromPassword(password, salt)
  x25519KeyPair(secret)

proc seal*(plainText: string, key: Key32): SealedMessage =
  ## Encrypts the plainText using the provided key and a random nonce
  let nonce = randomBytes[24]()
  let (cipherText, mac) = encrypt(plainText, key, nonce)
  SealedMessage(nonce: nonce, mac: mac, cipherText: cipherText)

proc unseal*(msg: SealedMessage, key: Key32): string =
  ## Decrypts the sealed message using the provided key. Returns the decrypted plainText
  decrypt(msg.cipherText, msg.mac, key, msg.nonce)

proc computeChallengeMac*(secret: Key32, challenge: Mac16): Mac16 =
  ## Compute a MAC for the given challenge using the shared secret. Returns the MAC
  var mac: Mac16
  crypto_blake2b_keyed(mac[0].addr, 16, secret[0].addr, 32, challenge[0].addr, 16)
  mac

proc verifyChallengeMac*(secret: Key32, challenge: Mac16, received: Mac16): bool =
  ## Verify the received MAC against the expected MAC computed from the
  ## secret and challenge. Returns true if valid, false otherwise
  let expected = computeChallengeMac(secret, challenge)
  crypto_verify16(expected[0].addr, received[0].unsafeAddr) == 0

type
  AeadStreamMode* = enum
    ## The mode of AEAD streaming to use. Each mode corresponds to a
    ## different nonce size and initialization function
    aeadX, aeadDjb, aeadIetf

  AeadStream* = object
    ## The AeadStream type represents an AEAD streaming encryption context for
    ctx: crypto_aead_ctx
    mode: AeadStreamMode
      # The mode determines which AEAD algorithm and
      # nonce size to use for encryption and decryption.

proc aeadStreamInit*(mode: AeadStreamMode, key: Key32, nonce: openArray[uint8]): AeadStream =
  ## Initializes an AEAD streaming context for the given mode and nonce.
  var ctx: crypto_aead_ctx
  case mode
  of aeadX:
    doAssert nonce.len == 24
    crypto_aead_init_x(addr ctx, key, cast[array[24, uint8]](nonce))
  of aeadDjb:
    doAssert nonce.len == 8
    crypto_aead_init_djb(addr ctx, key, cast[array[8, uint8]](nonce))
  of aeadIetf:
    doAssert nonce.len == 12
    crypto_aead_init_ietf(addr ctx, key, cast[array[12, uint8]](nonce))
  result = AeadStream(ctx: ctx, mode: mode)

proc aeadStreamWrite*(stream: var AeadStream, plainText: openArray[uint8],
    ad: openArray[uint8] = []): (seq[uint8], Mac16) =
  ## Encrypts a chunk of plaintext with optional associated data
  var cipherText = newSeq[uint8](plainText.len)
  var mac: Mac16
  crypto_aead_write(
    addr stream.ctx,
    cipherText[0].addr,
    mac,
    if ad.len > 0: ad[0].unsafeAddr else: nil,
    csize_t(ad.len),
    plainText[0].unsafeAddr,
    csize_t(plainText.len)
  )
  (cipherText, mac)

proc aeadStreamRead*(stream: var AeadStream, cipherText: openArray[uint8],
        mac: Mac16, ad: openArray[uint8] = []): seq[uint8] =
  ## Decrypts a chunk of ciphertext with optional associated data
  var plainText = newSeq[uint8](cipherText.len)
  let res = crypto_aead_read(
    addr stream.ctx,
    plainText[0].addr,
    mac,
    if ad.len > 0: ad[0].unsafeAddr else: nil,
    csize_t(ad.len),
    cipherText[0].unsafeAddr,
    csize_t(cipherText.len)
  )
  if res != 0:
    raise newException(ValueError, "AEAD stream decryption failed or MAC verification failed")
  plainText

proc aeadStreamInitX*(key: Key32, nonce: array[24, uint8]): AeadStream =
  var ctx: crypto_aead_ctx
  crypto_aead_init_x(addr ctx, key, nonce)
  AeadStream(ctx: ctx, mode: aeadX)

proc aeadStreamInitDjb*(key: Key32, nonce: array[8, uint8]): AeadStream =
  var ctx: crypto_aead_ctx
  crypto_aead_init_djb(addr ctx, key, nonce)
  AeadStream(ctx: ctx, mode: aeadDjb)

proc aeadStreamInitIetf*(key: Key32, nonce: array[12, uint8]): AeadStream =
  var ctx: crypto_aead_ctx
  crypto_aead_init_ietf(addr ctx, key, nonce)
  AeadStream(ctx: ctx, mode: aeadIetf)