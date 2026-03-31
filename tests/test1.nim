import unittest, sequtils

import ../src/e2ee

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