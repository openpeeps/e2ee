import unittest, sequtils, strutils

import ../src/e2ee

suite "basics":
  test "generate salts":
    let salt1 = generateSalt()
    let salt2 = generateSalt()
    assert salt1.len == 16
    assert salt2.len == 16
    assert salt1 != salt2

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