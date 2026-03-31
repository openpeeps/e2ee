# A super simple crypography module for end-to-end encryption (E2EE),
# hashing, key derivation, and key exchange using the Monocypher library.
#
# (c) 2025 George Lemon | MIT License
#          Made by Humans from OpenPeeps
#          https://github.com/openpeeps/e2ee

import std/[strutils, sysrand]
import ./monocypher

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
  for i in 0..<N:
    result[i] = T(parseHexInt(s.substr(i*2, 2)))

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