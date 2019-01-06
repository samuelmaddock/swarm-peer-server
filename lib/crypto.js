const sodium = require('libsodium-wrappers')

function pub2auth(publicKey) {
  const publicAuthKey = sodium.crypto_sign_ed25519_pk_to_curve25519(publicKey)
  return publicAuthKey
}

function secret2auth(secretKey) {
  const secretAuthKey = sodium.crypto_sign_ed25519_sk_to_curve25519(secretKey)
  return secretAuthKey
}

function seal(msg, publicKey) {
  const cipher = sodium.crypto_box_seal(msg, publicKey)
  return cipher
}

function unseal(cipher, publicKey, secretKey) {
  if (cipher.length < sodium.crypto_box_SEALBYTES) return null
  let msg
  try {
    msg = sodium.crypto_box_seal_open(cipher, publicKey, secretKey)
  } catch (e) {
    return null
  }
  return msg
}

module.exports = { pub2auth, secret2auth, seal, unseal }