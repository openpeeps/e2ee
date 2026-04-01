# A super simple crypography module for end-to-end encryption (E2EE),
# hashing, key derivation, and key exchange using the Monocypher library.
#
# (c) 2025 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/e2ee

import std/[strutils, times, random]
import ./private/[utils, monocypher]

randomize(234)

const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
const charsetLen = charset.len

proc generatePassword*(master: string, salt: string, length: int): string =
  var hash: array[64, uint8]
  let input = master & salt & $(now().toTime.toUnix)
  crypto_blake2b(cast[ptr uint8](addr(hash)), csize_t(hash.len), cast[ptr uint8](cstring(input)), csize_t(input.len))
  result = ""
  for i in 0..<length:
    let idx = hash[i mod hash.len] mod charsetLen
    result.add charset[idx]

const
  HashLen = 32
  SaltLen = 16

when defined(e2eeFastTests):
  const
    Argon2Blocks = 32'u32   # fast test mode
    Argon2Passes = 1'u32
else:
  const
    Argon2Blocks = 1024'u32 # production defaults
    Argon2Passes = 3'u32

proc argon2Config(): crypto_argon2_config {.inline.} =
  result.algorithm = CRYPTO_ARGON2_ID
  result.nb_blocks = Argon2Blocks
  result.nb_passes = Argon2Passes
  result.nb_lanes = 1

proc hashPassword*(password: string): string =
  ## Hash a password for storage using Argon2id.
  ## Returns a hex string of the form "hex(salt):hex(hash)"
  let salt = generateSalt(SaltLen)
  var hash: array[HashLen, uint8]
  var workArea: array[Argon2Blocks.int * 1024, uint8]
  let config = argon2Config()
  var inputs: crypto_argon2_inputs
  inputs.pass = cast[ptr uint8](password.cstring)
  inputs.salt = cast[ptr uint8](unsafeAddr salt[0])
  inputs.pass_size = uint32(password.len)
  inputs.salt_size = uint32(salt.len)
  crypto_argon2(
    cast[ptr uint8](addr hash),
    HashLen.uint32,
    addr workArea,
    config,
    inputs,
    crypto_argon2_no_extras
  )
  result = salt.toHex() & ":" & hash.toHex()

proc verifyPassword*(password, stored: string): bool =
  ## Verify a password against a stored hash. The stored hash should be in
  ## the format "hex(salt):hex(hash)"
  let parts = stored.split(":")
  if parts.len != 2 or parts[0].len != SaltLen*2 or parts[1].len != HashLen*2:
    return false
  let salt = fromHex[SaltLen, uint8](parts[0])
  let expected = fromHex[HashLen, uint8](parts[1])
  var hash: array[HashLen, uint8]
  var workArea: array[Argon2Blocks.int * 1024, uint8]
  let config = argon2Config()
  var inputs: crypto_argon2_inputs
  inputs.pass = cast[ptr uint8](password.cstring)
  inputs.salt = cast[ptr uint8](unsafeAddr salt[0])
  inputs.pass_size = uint32(password.len)
  inputs.salt_size = uint32(salt.len)
  crypto_argon2(
    cast[ptr uint8](addr hash),
    HashLen.uint32,
    addr workArea,
    config,
    inputs,
    crypto_argon2_no_extras
  )
  result = hash == expected

proc deriveKeyFromPassword*(password: string, salt: RandomBytes): Key32 =
  ## Derive a 32-byte key from a password and salt using Argon2id
  var hash: Key32
  var workArea = alloc(32 * 1024) # Argon2 work area, size depends on config
  let config = crypto_argon2_config(
    algorithm: CRYPTO_ARGON2_ID,
    nb_blocks: 32,
    nb_passes: 3,
    nb_lanes: 1
  )
  let inputs = crypto_argon2_inputs(
    pass: cast[ptr uint8](password[0].unsafeAddr),
    salt: salt[0].unsafeAddr,
    pass_size: uint32(password.len),
    salt_size: uint32(salt.len)
  )
  crypto_argon2(hash[0].addr, 32, workArea, config, inputs, crypto_argon2_no_extras)
  dealloc(workArea)
  return hash
