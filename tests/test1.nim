import unittest, sequtils, strutils

import ../src/e2ee

suite "basics":
  test "generate salts":
    let salt1 = generateSalt()
    let salt2 = generateSalt()
    assert salt1.len == 16
    assert salt2.len == 16
    assert salt1 != salt2

  test "generate password with master pwd and salt":
    let salt = generateSalt().toHex()
    let pwd = generatePassword("masterpassword", salt, length = 16)
    assert pwd.len == 16
    # same master password and salt should give same result
    let pwd2 = generatePassword("masterpassword", salt, length = 16)
    assert pwd == pwd2
    # different salt should give different result
    let salt2 = generateSalt().toHex()
    let pwd3 = generatePassword("masterpassword", salt2, length = 16)
    assert pwd != pwd3

  test "key pair from password":
    let password = "my-secure-password"
    let salt = generateSalt()
    let (secret, public) = keyPairFromPassword(password, salt)
    assert secret.len == 32
    assert public.len == 32

    # same password and salt should give same key pair
    let (secret2, public2) = keyPairFromPassword(password, salt)
    assert secret == secret2
    assert public == public2

  test "generate password with master password and salt":
    let password1 = generatePassword("master-password", "salt1", 16)
    let password2 = generatePassword("master-password", "salt2", 16)
    assert password1.len == 16
    assert password2.len == 16
    assert password1 != password2

  test "password hashing and verification argon2id":
    let password = generatePassword("my-password", "my-salt", 16)
    let hashpwd = hashPassword(password)
    assert verifyPassword(password, hashpwd)
    assert not verifyPassword("wrong-password", hashpwd)
    assert not verifyPassword(password, "invalid-format")

suite "aead tests":
  test "key exchange and AEAD seal/unseal":
    let alicePwd = "alice-super-secret-passphrase"
    let bobPwd   = "bob-different-secret-passphrase"
    let aliceSalt = generateSalt()
    let bobSalt   = generateSalt()

    # independent long-term identities
    let (aliceSK, alicePK) = keyPairFromPassword(alicePwd, aliceSalt)
    let (bobSK, bobPK) = keyPairFromPassword(bobPwd, bobSalt)

    # should be different identities
    assert aliceSK != bobSK
    assert alicePK != bobPK

    # ECDH agreement should still match
    let aliceShared = aliceSK.sharedSecret(bobPK)
    let bobShared = bobSK.sharedSecret(alicePK)
    assert aliceShared == bobShared

    # use shared secret as symmetric key
    let msg = "Hi Bob, this is Alice."
    let sealed = aead.seal(msg, aliceShared)
    let opened = aead.unseal(sealed, bobShared)
    assert opened == msg

  test "AEAD streaming":
    let key = randomBytes[32]()
    let nonce = randomBytes[24]()

    # Split a message into chunks
    let message = "Hello, this is a test of AEAD streaming!"
    let chunk1 = message.toOpenArrayByte(0, 15).toSeq()
    let chunk2 = message.toOpenArrayByte(16, message.high).toSeq()

    # Encrypt chunks
    var stream = aeadStreamInitX(key, nonce)
    let (cipher1, mac1) = aeadStreamWrite(stream, chunk1)
    let (cipher2, mac2) = aeadStreamWrite(stream, chunk2)

    assert cipher1.len == chunk1.len
    assert cipher2.len == chunk2.len

    assert mac1.len == 16
    assert mac2.len == 16

    # Decrypt chunks
    var decStream = aeadStreamInitX(key, nonce)
    let plain1 = aeadStreamRead(decStream, cipher1, mac1)
    let plain2 = aeadStreamRead(decStream, cipher2, mac2)

    assert plain1 == chunk1
    assert plain2 == chunk2

    # Combine and print
    let decrypted = cast[string](plain1 & plain2)
    assert decrypted == message

suite "chacha tests":
  test "XChaCha20 seal/unseal with password":
    let salt = generateSalt()
    let password = "password123"
    let msg = "This is a secret message."

    let sealed = chacha.sealWithPassword(msg, password, salt)
    let opened = chacha.unsealWithPassword(sealed, password, salt)

    assert opened == msg

proc asBytes(s: string): seq[byte] =
  result = newSeq[byte](s.len)
  for i, c in s:
    result[i] = byte(c)

suite "blake2b tests":
  test "known vectors (unkeyed)":
    check blakeHex("", 64).toLowerAscii ==
      "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    check blakeHex("abc", 64).toLowerAscii ==
      "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"

  test "string and byte input produce same digest":
    let msg = "hello blake2b"
    check blake(msg, 32) == blake(asBytes(msg), 32)
    check blakeHex(msg, 32) == blakeHex(asBytes(msg), 32)

  test "digest size controls output length":
    check blake("x", 1).len == 1
    check blake("x", 32).len == 32
    check blake("x", 64).len == 64
    check blakeHex("x", 1).len == 2
    check blakeHex("x", 32).len == 64
    check blakeHex("x", 64).len == 128

  test "keyed hash basics":
    let msg = "authenticated message"
    let keyA = "super-secret-key"
    let keyB = "different-secret-key"

    let macA1 = blakeKeyed(msg, keyA, 32)
    let macA2 = blakeKeyed(msg, keyA, 32)
    let macB = blakeKeyed(msg, keyB, 32)

    check macA1 == macA2
    check macA1 != macB
    check blakeKeyed(msg, keyA, 32) == blakeKeyed(asBytes(msg), asBytes(keyA), 32)

  test "incremental equals one-shot":
    let msg = "The quick brown fox jumps over the lazy dog"
    let expected = blake(msg, 64)

    var st = initBlake2b(64)
    st.update("The quick brown ")
    st.update("fox jumps over ")
    st.update("the lazy dog")
    let got = st.finish()

    check got == expected

  test "incremental keyed equals one-shot keyed":
    let msg = "chunked mac input"
    let key = "my-key-material"
    let expected = blakeKeyed(msg, key, 32)

    var st = initBlake2bKeyed(key, 32)
    st.update("chunked ")
    st.update("mac ")
    st.update("input")
    let got = st.finish()

    check got == expected

  test "verifyDigest works":
    let a = blake("same", 32)
    let b = blake("same", 32)
    let c = blake("different", 32)

    check verifyDigest(a, b)
    check not verifyDigest(a, c)

    let ha = blakeHex("same", 32)
    let hb = blakeHex("same", 32)
    let hc = blakeHex("different", 32)

    check verifyDigest(ha, hb)
    check not verifyDigest(ha, hc)

  test "invalid params and finalized-state checks":
    expect(ValueError):
      discard blake("x", 0)
    expect(ValueError):
      discard blake("x", 65)
    expect(ValueError):
      discard initBlake2b(0)
    expect(ValueError):
      discard initBlake2b(65)

    expect(ValueError):
      discard blakeKeyed("x", "", 32) # empty key not allowed
    expect(ValueError):
      discard initBlake2bKeyed("", 32)

    var st = initBlake2b(32)
    st.update("abc")
    discard st.finish()

    expect(ValueError):
      discard st.finish()
    expect(ValueError):
      st.update("more")


suite "signs (Ed25519)":
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

  test "generate deterministic keypair from seed":
    let kp1 = generateSigningKeyPair(seedA)
    let kp2 = generateSigningKeyPair(seedA)

    check kp1.publicKey == kp2.publicKey
    check kp1.secretKey == kp2.secretKey
    check kp1.publicKey.len == 32
    check kp1.secretKey.len == 64

  test "different seeds produce different keypairs":
    let a = generateSigningKeyPair(seedA)
    let b = generateSigningKeyPair(seedB)

    check a.publicKey != b.publicKey
    check a.secretKey != b.secretKey

  test "sign and verify string":
    let kp = generateSigningKeyPair(seedA)
    let msg = "hello signed world"
    let sig = sign(kp.secretKey, msg)

    check sig.len == 64
    check verify(kp.publicKey, msg, sig)

  test "sign and verify bytes":
    let kp = generateSigningKeyPair(seedA)
    let msg = asBytes("bytes payload")
    let sig = sign(kp.secretKey, msg)

    check verify(kp.publicKey, msg, sig)

  test "verification fails for modified message":
    let kp = generateSigningKeyPair(seedA)
    let sig = sign(kp.secretKey, "original message")

    check not verify(kp.publicKey, "tampered message", sig)

  test "verification fails with wrong public key":
    let alice = generateSigningKeyPair(seedA)
    let bob = generateSigningKeyPair(seedB)
    let msg = "message from alice"
    let sig = sign(alice.secretKey, msg)

    check not verify(bob.publicKey, msg, sig)

  test "verification fails for modified signature":
    let kp = generateSigningKeyPair(seedA)
    let msg = "integrity check"
    var sig = sign(kp.secretKey, msg)

    sig[0] = sig[0] xor 0x01'u8
    check not verify(kp.publicKey, msg, sig)

  test "empty message can be signed and verified":
    let kp = generateSigningKeyPair(seedA)
    let sig = sign(kp.secretKey, "")

    check verify(kp.publicKey, "", sig)

  test "hex roundtrip for public/secret/signature":
    let kp = generateSigningKeyPair(seedA)
    let msg = "roundtrip"
    let sig = sign(kp.secretKey, msg)

    let pkHex = publicKeyToHex(kp.publicKey)
    let skHex = secretKeyToHex(kp.secretKey)
    let sigHex = signatureToHex(sig)

    check publicKeyFromHex(pkHex) == kp.publicKey
    check secretKeyFromHex(skHex) == kp.secretKey
    check signatureFromHex(sigHex) == sig
    check verify(publicKeyFromHex(pkHex), msg, signatureFromHex(sigHex))

  test "hex decode rejects invalid lengths":
    expect(ValueError):
      discard publicKeyFromHex("aa")
    expect(ValueError):
      discard secretKeyFromHex("aa")
    expect(ValueError):
      discard signatureFromHex("aa")

suite "sha512 tests":
  test "known vectors (SHA-512)":
    check sha512Hex("").toLowerAscii ==
      "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce" &
      "47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"

    check sha512Hex("abc").toLowerAscii ==
      "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a" &
      "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"

  test "string and byte input produce same SHA-512 digest":
    let msg = "hello sha512"
    check sha512(msg) == sha512(asBytes(msg))
    check sha512Hex(msg) == sha512Hex(asBytes(msg))

  test "streaming SHA-512 equals one-shot":
    let msg = "The quick brown fox jumps over the lazy dog"
    let expected = sha512(msg)

    var st = initSha512()
    st.update("The quick brown ")
    st.update("fox jumps over ")
    st.update("the lazy dog")
    let got = st.finish()

    check got == expected

  test "SHA-512 finalized-state checks":
    var st = initSha512()
    st.update("abc")
    discard st.finish()

    expect(ValueError):
      discard st.finish()
    expect(ValueError):
      st.update("more")

  test "known vector (HMAC-SHA512)":
    let key = "key"
    let msg = "The quick brown fox jumps over the lazy dog"
    check sha512HmacHex(key, msg).toLowerAscii ==
      "b42af09057bac1e2d41708e48a902e09b5ff7f12ab428a4fe86653c73dd248fb" &
      "82f948a549f7b791a5b41915ee4d1ec3935357e4e2317250d0372afa2ebeeb3a"

  test "string and byte input produce same HMAC":
    let key = "super-secret"
    let msg = "payload"
    check sha512Hmac(key, msg) == sha512Hmac(asBytes(key), asBytes(msg))
    check sha512HmacHex(key, msg) == sha512HmacHex(asBytes(key), asBytes(msg))

  test "streaming HMAC equals one-shot":
    let key = "my-hmac-key"
    let expected = sha512Hmac(key, "chunked message input")

    var st = initSha512Hmac(key)
    st.update("chunked ")
    st.update("message ")
    st.update("input")
    let got = st.finish()

    check got == expected

  test "HMAC finalized-state checks":
    var st = initSha512Hmac("k")
    st.update("abc")
    discard st.finish()

    expect(ValueError):
      discard st.finish()
    expect(ValueError):
      st.update("more")

  test "HKDF length and determinism":
    let okm1 = hkdfSha512("ikm", "salt", "info", 48)
    let okm2 = hkdfSha512("ikm", "salt", "info", 48)
    let okm3 = hkdfSha512("ikm", "saltX", "info", 48)

    check okm1.len == 48
    check okm1 == okm2
    check okm1 != okm3

  test "HKDF fixed-size overload matches dynamic overload":
    let dyn = hkdfSha512("ikm", "salt", "info", 32)
    let fixed = hkdfSha512[32](asBytes("ikm"), asBytes("salt"), asBytes("info"))

    check dyn == @fixed

  test "HKDF-Expand fixed-size overload matches dynamic overload":
    let prk = sha512Hmac("salt", "ikm")
    let dyn = hkdfExpandSha512(@prk, asBytes("ctx"), 32)
    let fixed = hkdfExpandSha512[32](@prk, asBytes("ctx"))

    check dyn == @fixed
