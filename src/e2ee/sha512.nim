# A super simple crypography module for end-to-end encryption (E2EE),
# hashing, key derivation, and key exchange using the Monocypher library.
#
# (c) 2025 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/e2ee
import ./private/[monocypher, utils]

## This module implements a high-level API for SHA-512 hashing,
## HMAC, and HKDF key derivation using the underlying Monocypher library
## 
## The API includes both one-shot functions for hashing and HMAC, as well as
## streaming interfaces that allow you to update the hash or HMAC state with
## multiple chunks of data before finalizing the result.
## 
## The HKDF functions allow you to derive keys of arbitrary length from a given input key material (IKM) and salt, using the
## HKDF construction with SHA-512 as the underlying hash function. The API is designed to be easy to use while still providing
## the flexibility needed for various cryptographic applications.
## 
## For lower-level access to the Monocypher functions, see the
## `monocypher` module, and for general utilities, see the
## `utils` module.

const
  Sha512DigestSize* = 64
  Sha512BlockSize* = 128

type
  Sha512Digest* = array[Sha512DigestSize, uint8]
  Sha512Hmac* = array[Sha512DigestSize, uint8]
  Sha512Prk* = array[Sha512DigestSize, uint8]

  Sha512State* = object
    ## The SHA-512 state
    ctx: crypto_sha512_ctx
    finalized: bool

  Sha512HmacState* = object
    ## The HMAC state for SHA-512
    ctx: crypto_sha512_hmac_ctx
    finalized: bool

#
# SHA-512 (one-shot)
#
proc sha512*(message: openArray[byte]): Sha512Digest =
  ## Compute the SHA-512 hash of the given message and return it as a digest
  crypto_sha512(
    result[0].addr,
    toPtr(message),
    csize_t(message.len)
  )

proc sha512*(message: string): Sha512Digest =
  ## Compute the SHA-512 hash of the given message and return it as a digest
  crypto_sha512(
    result[0].addr,
    strPtr(message),
    csize_t(message.len)
  )

proc sha512Hex*(message: openArray[byte]): string =
  ## Compute the SHA-512 hash of the given message and return it as a hex string
  sha512(message).toHex()

proc sha512Hex*(message: string): string =
  ## Compute the SHA-512 hash of the given message and return it as a hex string
  sha512(message).toHex()

#
# SHA-512 (streaming)
#
proc initSha512*(): Sha512State =
  ## Initialize a new SHA-512 state. After initialization,
  ## the state is ready to accept message updates
  crypto_sha512_init(result.ctx.addr)
  result.finalized = false

proc update*(state: var Sha512State, message: openArray[byte]) =
  ## Update the SHA-512 state with a new message chunk. If the state has
  ## already been finalized, an exception is raised
  if state.finalized:
    raise newException(ValueError, "SHA-512 state already finalized")
  crypto_sha512_update(state.ctx.addr, toPtr(message), csize_t(message.len))

proc update*(state: var Sha512State, message: string) =
  ## Update the SHA-512 state with a new message chunk. If the state has
  ## already been finalized, an exception is raised
  if state.finalized:
    raise newException(ValueError, "SHA-512 state already finalized")
  crypto_sha512_update(state.ctx.addr, strPtr(message), csize_t(message.len))

proc finish*(state: var Sha512State): Sha512Digest =
  ## Finalize the SHA-512 computation and return the resulting digest. Once called,
  ## the state is marked as finalized and cannot be used for further updates
  if state.finalized:
    raise newException(ValueError, "SHA-512 state already finalized")
  crypto_sha512_final(state.ctx.addr, result[0].addr)
  state.finalized = true

proc finishHex*(state: var Sha512State): string =
  finish(state).toHex()

#
# HMAC-SHA512 (one-shot)
#

proc sha512Hmac*(key, message: openArray[byte]): Sha512Hmac =
  ## Compute the HMAC-SHA512 of the given message using the provided key.
  ## The key can be of any length; if it is longer than the block size (128 bytes), it will be hashed first.
  crypto_sha512_hmac(
    result[0].addr,
    toPtr(key),
    csize_t(key.len),
    toPtr(message),
    csize_t(message.len)
  )

proc sha512Hmac*(key, message: string): Sha512Hmac =
  ## Compute the HMAC-SHA512 of the given message using the provided key.
  ## The key can be of any length; if it is longer than the block size (128 bytes), it will be hashed first.
  crypto_sha512_hmac(
    result[0].addr,
    strPtr(key),
    csize_t(key.len),
    strPtr(message),
    csize_t(message.len)
  )

proc sha512HmacHex*(key, message: openArray[byte]): string =
  ## Compute the HMAC-SHA512 of the given message using the provided key,
  ## and return the result as a hexadecimal string.
  sha512Hmac(key, message).toHex()

proc sha512HmacHex*(key, message: string): string =
  ## Compute the HMAC-SHA512 of the given message using the provided key,
  ## and return the result as a hexadecimal string.
  sha512Hmac(key, message).toHex()

#
# HMAC-SHA512 (streaming)
#
proc initSha512Hmac*(key: openArray[byte]): Sha512HmacState =
  ## Initialize a new HMAC-SHA512 state with the given key.
  crypto_sha512_hmac_init(result.ctx.addr, toPtr(key), csize_t(key.len))
  result.finalized = false

proc initSha512Hmac*(key: string): Sha512HmacState =
  ## Initialize a new HMAC-SHA512 state with the given key. The key can be
  ## of any length; if it is longer than the block size (128 bytes), it will be
  ## hashed first. After initialization, the state is ready to accept message updates.
  crypto_sha512_hmac_init(result.ctx.addr, strPtr(key), csize_t(key.len))
  result.finalized = false

proc update*(state: var Sha512HmacState, message: openArray[byte]) =
  ## Update the HMAC state with a new message chunk. If the state
  ## has already been finalized, an exception is raised.
  if state.finalized:
    raise newException(ValueError, "HMAC-SHA512 state already finalized")
  crypto_sha512_hmac_update(state.ctx.addr, toPtr(message), csize_t(message.len))

proc update*(state: var Sha512HmacState, message: string) =
  ## Update the HMAC state with a new message chunk. If the state has
  ## already been finalized, an exception is raised.
  if state.finalized:
    raise newException(ValueError, "HMAC-SHA512 state already finalized")
  crypto_sha512_hmac_update(state.ctx.addr, strPtr(message), csize_t(message.len))

proc finish*(state: var Sha512HmacState): Sha512Hmac =
  ## Finalize the HMAC computation and return the resulting HMAC value. After calling this procedure,
  ## the state is marked as finalized and cannot be updated further. If the state is already finalized,
  ## an exception is raised.
  if state.finalized:
    raise newException(ValueError, "HMAC-SHA512 state already finalized")
  crypto_sha512_hmac_final(state.ctx.addr, result[0].addr)
  state.finalized = true

proc finishHex*(state: var Sha512HmacState): string =
  ## Finalize the HMAC computation and return the resulting HMAC value as a
  ## hexadecimal string. After calling this procedure, the state is marked as finalized
  ## and cannot be updated further
  finish(state).toHex()

#
# HKDF-SHA512
#
proc hkdfSha512*(ikm, salt, info: openArray[byte], okmLen: Natural): seq[uint8] =
  result = newSeq[uint8](okmLen)
  crypto_sha512_hkdf(
    seqPtr(result), csize_t(okmLen),
    toPtr(ikm), csize_t(ikm.len),
    toPtr(salt), csize_t(salt.len),
    toPtr(info), csize_t(info.len)
  )

proc hkdfSha512*(ikm, salt, info: string, okmLen: Natural): seq[uint8] =
  result = newSeq[uint8](okmLen)
  crypto_sha512_hkdf(
    seqPtr(result), csize_t(okmLen),
    strPtr(ikm), csize_t(ikm.len),
    strPtr(salt), csize_t(salt.len),
    strPtr(info), csize_t(info.len)
  )

proc hkdfExpandSha512*(prk, info: openArray[byte], okmLen: Natural): seq[uint8] =
  ## Expand a pseudorandom key (PRK) using HKDF with SHA-512. Returns an output key (OKM) of length okmLen.
  result = newSeq[uint8](okmLen)
  crypto_sha512_hkdf_expand(
    seqPtr(result), csize_t(okmLen),
    toPtr(prk), csize_t(prk.len),
    toPtr(info), csize_t(info.len)
  )

proc hkdfExpandSha512*(prk, info: string, okmLen: Natural): seq[uint8] =
  ## Expand a pseudorandom key (PRK) using HKDF with SHA-512
  result = newSeq[uint8](okmLen)
  crypto_sha512_hkdf_expand(
    seqPtr(result), csize_t(okmLen),
    strPtr(prk), csize_t(prk.len),
    strPtr(info), csize_t(info.len)
  )

proc hkdfSha512*[N: static[int]](ikm, salt, info: openArray[byte]): array[N, uint8] =
  ## Derive a fixed-size output key (OKM) of N bytes using HKDF with SHA-512
  crypto_sha512_hkdf(
    result[0].addr, csize_t(N),
    toPtr(ikm), csize_t(ikm.len),
    toPtr(salt), csize_t(salt.len),
    toPtr(info), csize_t(info.len)
  )

proc hkdfExpandSha512*[N: static[int]](prk, info: openArray[byte]): array[N, uint8] =
  ## Expand a pseudorandom key (PRK) using HKDF with SHA-512
  crypto_sha512_hkdf_expand(
    result[0].addr, csize_t(N),
    toPtr(prk), csize_t(prk.len),
    toPtr(info), csize_t(info.len)
  )
