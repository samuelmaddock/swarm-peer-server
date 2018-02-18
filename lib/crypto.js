const sodium = require('sodium-native')

function pub2auth(publicKey) {
  const publicAuthKey = new Buffer(sodium.crypto_box_PUBLICKEYBYTES)
  sodium.crypto_sign_ed25519_pk_to_curve25519(publicAuthKey, publicKey)
  return publicAuthKey
}

function secret2auth(secretKey) {
  const secretAuthKey = new Buffer(sodium.crypto_box_SECRETKEYBYTES)
  sodium.crypto_sign_ed25519_sk_to_curve25519(secretAuthKey, secretKey)
  return secretAuthKey
}

function seal(msg, publicKey) {
  var cipher = new Buffer(msg.length + sodium.crypto_box_SEALBYTES)
  sodium.crypto_box_seal(cipher, msg, publicKey)
  return cipher
}

function unseal(cipher, publicKey, secretKey) {
  if (cipher.length < sodium.crypto_box_SEALBYTES) return null
  var msg = new Buffer(cipher.length - sodium.crypto_box_SEALBYTES)
  if (!sodium.crypto_box_seal_open(msg, cipher, publicKey, secretKey)) return null
  return msg
}

module.exports = { pub2auth, secret2auth, seal, unseal }