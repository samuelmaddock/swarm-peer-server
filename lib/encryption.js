// Code copied from sodium-encryption as to remove dependency on
// older sodium-native module.

/**
The MIT License (MIT)

Copyright (c) 2016 Mathias Buus

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

var sodium = require('libsodium-wrappers')

exports.key = function () {
  return randomBytes(sodium.crypto_secretbox_KEYBYTES)
}

exports.nonce = function () {
  return randomBytes(sodium.crypto_secretbox_NONCEBYTES)
}

exports.encrypt = function (msg, nonce, key) {
  var cipher = Buffer.alloc(msg.length + sodium.crypto_secretbox_MACBYTES)
  sodium.crypto_secretbox_easy(cipher, msg, nonce, key)
  return cipher
}

exports.decrypt = function (cipher, nonce, key) {
  if (cipher.length < sodium.crypto_secretbox_MACBYTES) return null
  var msg = Buffer.alloc(cipher.length - sodium.crypto_secretbox_MACBYTES)
  if (!sodium.crypto_secretbox_open_easy(msg, cipher, nonce, key)) return null
  return msg
}

exports.scalarMultiplication = function (secretKey, otherPublicKey) {
  var sharedSecret = Buffer.alloc(sodium.crypto_scalarmult_BYTES)
  sodium.crypto_scalarmult(sharedSecret, secretKey, otherPublicKey)
  return sharedSecret
}

exports.scalarMultiplicationKeyPair = function (secretKey) {
  if (!secretKey) secretKey = randomBytes(sodium.crypto_scalarmult_SCALARBYTES)
  var publicKey = Buffer.alloc(sodium.crypto_scalarmult_BYTES)
  sodium.crypto_scalarmult_base(publicKey, secretKey)
  return {
    secretKey: secretKey,
    publicKey: publicKey
  }
}

function randomBytes (n) {
  var buf = Buffer.alloc(n)
  sodium.randombytes_buf(buf)
  return buf
}
