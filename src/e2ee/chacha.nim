# A super simple crypography module for end-to-end encryption (E2EE),
# hashing, key derivation, and key exchange using the Monocypher library.
#
# (c) 2025 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/e2ee

## This module provides a simple interface for encrypting and decrypting
## messages using XChaCha20 stream cipher. It includes functions for encrypting
## and decrypting messages with a given key and nonce, as well as a high-level
## sealing and opening API that generates a random nonce for each message.

import ./private/[monocypher, utils]
import ./password

type
  ChachaMessage* = object
    ## The ChachaMessage type represents an encrypted message using XChaCha20.
    nonce*: Nonce24
      ## A random nonce used for encryption. Must be unique
      ## for each message encrypted with the same key.
    cipherText*: seq[uint8]
      ## The encrypted message as a sequence of bytes.

proc encrypt*(plainText: string, key: Key32, nonce: Nonce24): seq[uint8] =
  ## Encrypts the plainText using XChaCha20 with the given key and nonce.
  let plainBytes = cast[seq[uint8]](plainText)
  var cipherText = newSeq[uint8](plainBytes.len)
  if plainBytes.len == 0:
    return cipherText # empty string case
  discard crypto_chacha20_x(
    cipherText[0].addr,
    plainBytes[0].addr,
    csize_t(plainBytes.len),
    key,
    nonce,
    0'u64
  )
  cipherText

proc decrypt*(cipherText: seq[uint8], key: Key32, nonce: Nonce24): string =
  ## Decrypts the cipherText using XChaCha20 with the given key and nonce.
  var plainBytes = newSeq[uint8](cipherText.len)
  if cipherText.len == 0:
    return # empty string
  discard crypto_chacha20_x(
    plainBytes[0].addr,
    cipherText[0].addr,
    csize_t(cipherText.len),
    key,
    nonce,
    0'u64
  )
  cast[string](plainBytes)

proc seal*(plainText: string, key: Key32): ChachaMessage =
  ## Encrypts the plainText with a random nonce, returns ChachaMessage.
  let nonce = randomBytes[24]()
  let cipherText = encrypt(plainText, key, nonce)
  ChachaMessage(nonce: nonce, cipherText: cipherText)

proc sealWithPassword*(plainText, password: string, salt: RandomBytes): ChachaMessage =
  ## Encrypts plainText using a key derived from password+salt, with a random nonce.
  let key = deriveKeyFromPassword(password, salt)
  seal(plainText, key)

proc unseal*(msg: ChachaMessage, key: Key32): string =
  ## Decrypts the ChachaMessage using the provided key.
  decrypt(msg.cipherText, key, msg.nonce)

proc unsealWithPassword*(msg: ChachaMessage, password: string, salt: RandomBytes): string =
  ## Decrypts the ChachaMessage using a key derived from password+salt.
  let key = deriveKeyFromPassword(password, salt)
  unseal(msg, key)
