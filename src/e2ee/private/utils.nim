# A super simple crypography module for end-to-end encryption (E2EE),
# hashing, key derivation, and key exchange using the Monocypher library.
#
# (c) 2025 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/e2ee

import std/[strutils, sysrand]
import ./monocypher

## This module provides utility functions. It includes functions for converting between byte arrays
## and hex strings, generating random bytes, and creating salts for password hashing. These
## utilities are used by the higher-level APIs in the other modules to simplify common tasks and
## ensure consistent handling of data formats across the library.

type
  RandomBytes* = array[16, uint8]
  Key32* = array[32, uint8]
  Nonce24* = array[24, uint8]
  Mac16* = RandomBytes

proc toHex*[T](v: T): string =
  ## Convert any value to a hex string representation of its bytes.
  var p = cast[ByteAddress](v.unsafeAddr)
  let e = p + v.sizeof
  result = ""
  while p < e:
    result.add(toHex(cast[ptr uint8](p)[]))
    p.inc

proc fromHex*[N: static int, T](s: string): array[N, T] =
  ## Convert a hex string back to an array of bytes of type T.
  if s.len != N * 2:
    # Each byte is represented by 2 hex characters, so the string
    # length must be exactly N*2
    raise newException(ValueError, "invalid hex length")
  for i in 0..<N:
    let a = i * 2
    let b = a + 1
    result[i] = T(parseHexInt(s[a..b]))

proc toPtr*(data: openArray[byte]): ptr uint8 {.inline.} =
  if data.len == 0: nil
  else: cast[ptr uint8](unsafeAddr data[0])

proc strPtr*(s: string): ptr uint8 {.inline.} =
  if s.len == 0: nil
  else: cast[ptr uint8](unsafeAddr s[0])

proc randomBytes*[N: static int]: array[N, uint8] =
  ## Generate N random bytes using urandom. Returns an array of uint8.
  let bytes = urandom(N)
  if bytes.len != N:
    raise newException(ValueError, "Could not read enough bytes from urandom")
  for i in 0..<N:
    result[i] = uint8(bytes[i])

proc generateSalt*(len: static int = 16): RandomBytes =
  ## Generate a random salt of the given length (default 16 bytes).
  randomBytes[len]()