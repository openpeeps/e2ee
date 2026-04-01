# A super simple crypography module for end-to-end encryption (E2EE),
# hashing, key derivation, and key exchange using the Monocypher library.
#
# (c) 2025 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/e2ee

import std/strutils

import ./private/[monocypher, utils]
import ./password

## This module implements a high-level API for the BLAKE2b hash funcionality provided by th
## Monocypher library. It includes functions for computing BLAKE2b hashes, keyed hashes (MACs),
## and incremental hashing with a stateful Blake2b object.
## 
## The API is designed to be easy to use while still providing access to the full functionality
## of the underlying library. It also includes utility functions for converting digests to hex
## strings and verifying digests in constant time

const
  Blake2bMinDigestSize* = 1
  Blake2bMaxDigestSize* = 64
  Blake2bDefaultDigestSize* = 32
  Blake2bMaxKeySize* = 64

type
  Blake2b* = object
    ## The Blake2b type represents the state of an incremental BLAKE2b hash computation. It
    ## allows you to update the hash with chunks of data and then finish to get the final digest.
    ctx: crypto_blake2b_ctx
    hashSize: int
    finalized: bool

proc ensureHashSize(hashSize: int) {.inline.} =
  if hashSize < Blake2bMinDigestSize or hashSize > Blake2bMaxDigestSize:
    raise newException(ValueError, "BLAKE2b hash size must be in 1..64 bytes")

proc ensureKeySize(keySize: int) {.inline.} =
  if keySize < 1 or keySize > Blake2bMaxKeySize:
    raise newException(ValueError, "BLAKE2b key size must be in 1..64 bytes")

proc toPtr(data: openArray[byte]): ptr uint8 {.inline.} =
  if data.len == 0: nil
  else: cast[ptr uint8](unsafeAddr data[0])

proc strPtr(s: string): ptr uint8 {.inline.} =
  if s.len == 0: nil
  else: cast[ptr uint8](unsafeAddr s[0])

proc toHexDigest*(digest: openArray[byte]): string =
  ## Convert a binary digest to a hex string. Each byte is represented by two hex characters.
  result = newStringOfCap(digest.len * 2)
  for b in digest:
    result.add strutils.toHex(b, 2)

proc blake*(message: openArray[byte], hashSize: int = Blake2bDefaultDigestSize): seq[byte] =
  ## Compute the BLAKE2b hash of the message. The hash size must be between 1 and 64 bytes,
  ## default is 32 bytes (256 bits).
  ensureHashSize(hashSize)
  result = newSeq[byte](hashSize)
  crypto_blake2b(
    cast[ptr uint8](addr result[0]),
    csize_t(hashSize),
    toPtr(message),
    csize_t(message.len)
  )

proc blake*(message: string, hashSize: int = Blake2bDefaultDigestSize): seq[byte] =
  ## Compute the BLAKE2b hash of the message. The hash size must be between 1 and 64 bytes,
  ## default is 32 bytes (256 bits).
  ensureHashSize(hashSize)
  result = newSeq[byte](hashSize)
  crypto_blake2b(
    cast[ptr uint8](addr result[0]),
    csize_t(hashSize),
    strPtr(message),
    csize_t(message.len)
  )

proc blakeHex*(message: openArray[byte], hashSize: int = Blake2bDefaultDigestSize): string =
  ## Compute the BLAKE2b hash of the message and return it as a hex string. The hash
  ## size must be between 1 and 64 bytes, default is 32 bytes (256 bits).
  toHexDigest(blake(message, hashSize))

proc blakeHex*(message: string, hashSize: int = Blake2bDefaultDigestSize): string =
  ## Compute the BLAKE2b hash of the message and return it as a hex string. The
  ## hash size must be between 1 and 64 bytes, default is 32 bytes (256 bits).
  toHexDigest(blake(message, hashSize))

proc blakeKeyed*(message: openArray[byte], key: openArray[byte],
    hashSize: int = Blake2bDefaultDigestSize): seq[byte] =
  ## Compute a keyed BLAKE2b hash. The key is used to create a
  ## MAC (message authentication code) instead of a general-purpose hash.
  ensureHashSize(hashSize)
  ensureKeySize(key.len)
  result = newSeq[byte](hashSize)
  crypto_blake2b_keyed(
    cast[ptr uint8](addr result[0]),
    csize_t(hashSize),
    toPtr(key),
    csize_t(key.len),
    toPtr(message),
    csize_t(message.len)
  )

proc blakeKeyed*(message, key: string, hashSize: int = Blake2bDefaultDigestSize): seq[byte] =
  ## Compute a keyed BLAKE2b hash. The key is used to create a MAC (message authentication code) instead of a general-purpose hash.
  ensureHashSize(hashSize)
  ensureKeySize(key.len)
  result = newSeq[byte](hashSize)
  crypto_blake2b_keyed(
    cast[ptr uint8](addr result[0]),
    csize_t(hashSize),
    strPtr(key),
    csize_t(key.len),
    strPtr(message),
    csize_t(message.len)
  )

proc blakeKeyedHex*(message: openArray[byte], key: openArray[byte], hashSize: int = Blake2bDefaultDigestSize): string =
  ## Compute a keyed BLAKE2b hash and return it as a hex string. The key is
  ## used to create a MAC (message authentication code).
  toHexDigest(blakeKeyed(message, key, hashSize))

proc blakeKeyedHex*(message, key: string, hashSize: int = Blake2bDefaultDigestSize): string =
  ## Compute a keyed BLAKE2b hash and return it as a hex string. The key is
  ## used to create a MAC (message authentication code).
  toHexDigest(blakeKeyed(message, key, hashSize))

proc initBlake2b*(hashSize: int = Blake2bDefaultDigestSize): Blake2b =
  ## Initialize a Blake2b state with the given hash size. The hash size
  ## must be between 1 and 64 bytes.
  ensureHashSize(hashSize)
  result.hashSize = hashSize
  result.finalized = false
  crypto_blake2b_init(addr result.ctx, csize_t(hashSize))

proc initBlake2bKeyed*(key: openArray[byte], hashSize: int = Blake2bDefaultDigestSize): Blake2b =
  ## Initialize a keyed Blake2b state with the given key and hash size. The
  ## key must be 1..64 bytes.
  ensureHashSize(hashSize)
  ensureKeySize(key.len)
  result.hashSize = hashSize
  result.finalized = false
  crypto_blake2b_keyed_init(addr result.ctx, csize_t(hashSize), toPtr(key), csize_t(key.len))

proc initBlake2bKeyed*(key: string, hashSize: int = Blake2bDefaultDigestSize): Blake2b =
  ## Initialize a keyed Blake2b state with the given key and hash size.
  ## The key is used to create a MAC (message authentication code) instead
  ## of a general-purpose hash.
  ensureHashSize(hashSize)
  ensureKeySize(key.len)
  result.hashSize = hashSize
  result.finalized = false
  crypto_blake2b_keyed_init(addr result.ctx, csize_t(hashSize), strPtr(key), csize_t(key.len))

proc update*(state: var Blake2b, chunk: openArray[byte]) =
  ## Update the Blake2b state with a chunk of data. Can be called multiple times before finishing.
  if state.finalized:
    raise newException(ValueError, "Blake2b context already finalized")
  crypto_blake2b_update(addr state.ctx, toPtr(chunk), csize_t(chunk.len))

proc update*(state: var Blake2b, chunk: string) =
  ## Update the Blake2b state with a chunk of data. Can be called
  ## multiple times before finishing.
  if state.finalized:
    raise newException(ValueError, "Blake2b context already finalized")
  crypto_blake2b_update(addr state.ctx, strPtr(chunk), csize_t(chunk.len))

proc finish*(state: var Blake2b): seq[byte] =
  ## Finish the Blake2b hash and return the digest. The state is finalized after this call.
  if state.finalized:
    raise newException(ValueError, "Blake2b context already finalized")
  result = newSeq[byte](state.hashSize)
  crypto_blake2b_final(addr state.ctx, cast[ptr uint8](addr result[0]))
  state.finalized = true

proc finishHex*(state: var Blake2b): string =
  ## Finish the Blake2b hash and return the digest as a hex string.
  ## The state is finalized after this call.
  toHexDigest(finish(state))

proc verifyDigest*(a, b: openArray[byte]): bool =
  ## Constant-time comparison of two digests. Returns true if they are equal.
  if a.len != b.len: return false
  var diff: uint8 = 0
  for i in 0 ..< a.len:
    diff = diff or (a[i] xor b[i])
  result = diff == 0

proc verifyDigest*(a, b: string): bool =
  ## Constant-time comparison of two digests. Returns true if they are equal.
  if a.len != b.len: return false
  var diff: uint8 = 0
  for i in 0 ..< a.len:
    diff = diff or (uint8(a[i]) xor uint8(b[i]))
  result = diff == 0