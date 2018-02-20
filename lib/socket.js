const EventEmitter = require('events').EventEmitter
const sodium = require('sodium-native')
const enc = require('sodium-encryption')
const lpstream = require('length-prefixed-stream')
const debug = require('debug')('swarm-peer-server:socket')

const crypto = require('./crypto')

const SUCCESS = new Buffer('chat-auth-success')
const AUTH_TIMEOUT = 5000

// FIX: for https://github.com/nodejs/node/pull/14330
const Decoder = lpstream.decode
Decoder.prototype._destroy = function () {
  this._destroyed = true
}
Decoder.prototype._transform = function (data, enc, cb) {
  var offset = 0
  while (!this._destroyed && offset < data.length) {
    if (this._missing && this._missing > 1000000) {
      // HACK: some bug causes this, idk what
      break
      cb()
    } else if (this._missing) {
      offset = this._parseMessage(data, offset)
    } else {
      offset = this._parseLength(data, offset)
    }
  }
  cb()
}

/** Pack curve25519 public key and optionally ed25519 public key. */
function packPublicKeys(publicKey, ed25519PublicKey, ed25519SecretKey) {
  const sign = !!ed25519PublicKey
  const signBytes = sign ? sodium.crypto_sign_PUBLICKEYBYTES : 0
  const bytes = 1 + sodium.crypto_box_PUBLICKEYBYTES + signBytes

  const keysBuf = new Buffer(bytes)
  keysBuf.writeUInt8(sign ? 1 : 0)
  publicKey.copy(keysBuf, 1)

  if (!sign) {
    return keysBuf
  }

  ed25519PublicKey.copy(keysBuf, 1 + sodium.crypto_box_PUBLICKEYBYTES)

  let signature = new Buffer(sodium.crypto_sign_BYTES)
  sodium.crypto_sign_detached(signature, keysBuf, ed25519SecretKey)

  const buf = new Buffer(keysBuf.length + sodium.crypto_sign_BYTES)
  keysBuf.copy(buf)
  signature.copy(buf, keysBuf.length)
  return buf
}

/** Unpack curve25519 public key and optionally ed25519 public key. */
function unpackPublicKeys(data) {
  const signed = !!data.readUInt8()
  const publicKey = data.slice(1, 1 + sodium.crypto_box_PUBLICKEYBYTES)

  if (!signed) {
    return { publicKey }
  }

  const message = data.slice(0, data.length - sodium.crypto_sign_BYTES)
  const signature = data.slice(data.length - sodium.crypto_sign_BYTES, data.length)
  const ed25519PublicKey = message.slice(1 + sodium.crypto_box_PUBLICKEYBYTES, 1 + sodium.crypto_box_PUBLICKEYBYTES + sodium.crypto_sign_PUBLICKEYBYTES)
  const valid = sodium.crypto_sign_verify_detached(signature, message, ed25519PublicKey)

  if (valid) {
    return { publicKey, ed25519PublicKey }
  }
}

/**
 * Socket wrapper to use encrypted keypair communication
 */
class EncryptedSocket extends EventEmitter {
  constructor(socket, publicKey, secretKey, ed25519PublicKey, ed25519SecretKey) {
    super()

    this.socket = socket
    this.publicKey = publicKey
    this.secretKey = secretKey

    // Optionally include ed25519 keypair to transmit public key
    // TODO: is it possible to convert curve25519 to ed25519 with libsodium?
    this.ed25519PublicKey = ed25519PublicKey
    this.ed25519SecretKey = ed25519SecretKey

    this._error = this._error.bind(this)
    this._onReceive = this._onReceive.bind(this)
    this._authTimeout = this._authTimeout.bind(this)

    this.socket.once('close', this.destroy.bind(this))
  }

  /**
   * Connect to peer
   * @param {*} hostKey If present, authenticate with the host
   * @param {*} initiator Whether this connection is initiating
   */
  connect(hostKey) {
    if (hostKey) {
      this._authHost(hostKey)
    } else {
      this._authPeer()
    }

    this._authTimeoutId = setTimeout(this._authTimeout, AUTH_TIMEOUT)
  }

  _authTimeout() {
    this._authTimeoutId = null
    this._error(`Auth timed out`)
  }

  _setupSocket() {
    this._encode = lpstream.encode()
    this._decode = lpstream.decode()

    this._decode.on('data', this._onReceive)
    this._decode.once('error', this._error)

    this._encode.pipe(this.socket)
    this.socket.pipe(this._decode)
  }

  _setupEncryptionKey(peerKey, ed25519PeerKey) {
    if (!this.sharedKey) {
      this.peerKey = peerKey
      this.ed25519PeerKey = ed25519PeerKey
      this.sharedKey = enc.scalarMultiplication(this.secretKey, this.peerKey)
      this._setupSocket()
    }
  }

  /** Auth connection to host */
  _authHost(hostKey) {
    const self = this

    /** 1. Send auth request with encrypted identity */
    function sendAuthRequest() {
      const keysBuf = packPublicKeys(self.publicKey, self.ed25519PublicKey, self.ed25519SecretKey)
      const box = crypto.seal(keysBuf, self.peerKey)

      // Send without shared key encryption until peer can derive it
      self.socket.write(box)

      self.once('data', receiveChallenge)
    }

    /** 2. Receive challenge to decrypt, send back decrypted */
    function receiveChallenge(challenge) {
      self.write(challenge)
      self.once('data', receiveAuthSuccess)
    }

    /** 3. Receive auth success */
    function receiveAuthSuccess(data) {
      if (data.equals(SUCCESS)) {
        self._onAuthed()
      }
    }

    this._setupEncryptionKey(hostKey)
    sendAuthRequest()
  }

  /** Auth connection to peer */
  _authPeer(socket, publicKey, secretKey) {
    const self = this

    let challenge

    /** 1. Learn peer identity */
    function receiveAuthRequest(data) {
      const buf = Buffer.from(data)
      const keysBuf = crypto.unseal(buf, self.publicKey, self.secretKey)

      if (!keysBuf) {
        self._error('Failed to unseal peer box')
        return
      }

      const keys = unpackPublicKeys(keysBuf)

      if (!keysBuf) {
        self._error('Failed to unpack keys')
        return
      }

      const peerPublicKey = keys.publicKey
      const peerEd25519PublicKey = keys.ed25519PublicKey

      if (self.publicKey.equals(peerPublicKey)) {
        // debug('Auth request key is the same as the host')
        // return
      }

      self._setupEncryptionKey(peerPublicKey, peerEd25519PublicKey)
      sendChallenge()
    }

    /** 2. Respond with challenge to decrypt */
    function sendChallenge() {
      challenge = enc.nonce()
      self.write(challenge)
      self.once('data', receiveChallengeVerification)
    }

    /** 3. Verify decrypted challenge */
    function receiveChallengeVerification(decryptedChallenge) {
      if (challenge.equals(decryptedChallenge)) {
        self.write(SUCCESS)
        self._onAuthed()
      } else {
        self._error('Failed to authenticate peer')
      }
    }

    this.socket.once('data', receiveAuthRequest)
  }

  _onAuthed() {
    if (this._authTimeoutId) {
      clearTimeout(this._authTimeoutId)
      this._authTimeoutId = null
    }

    this.emit('connection')
  }

  write(data) {
    if (!this.socket) {
      return
    }

    if (!this.sharedKey) {
      this._error(`EncryptedSocket failed to write. Missing 'sharedKey'`)
      return
    }

    const nonce = enc.nonce()
    const box = enc.encrypt(data, nonce, this.sharedKey)

    const msg = new Buffer(nonce.length + box.length)
    nonce.copy(msg)
    box.copy(msg, nonce.length)

    this._encode.write(msg)
    debug(`Write ${msg.length} to ${this.peerKey.toString('hex')}`)
  }

  _onReceive(data) {
    if (!this.socket) {
      // Received chunk after socket destroyed
      return
    }

    if (!this.sharedKey) {
      this._error(`EncryptedSocket failed to receive. Missing 'sharedKey'`)
      return
    }

    debug(`Received ${data.length} from ${this.peerKey.toString('hex')}`)

    const nonce = data.slice(0, sodium.crypto_box_NONCEBYTES)
    const box = data.slice(sodium.crypto_box_NONCEBYTES, data.length)

    const msg = enc.decrypt(box, nonce, this.sharedKey)

    if (!msg) {
      this._error('EncryptedSocket failed to decrypt received data.')
      return
    }

    this.emit('data', msg)
  }

  destroy() {
    if (this._authTimeoutId) {
      clearTimeout(this._authTimeoutId)
      this._authTimeoutId = null
    }
    if (this.socket) {
      this.socket.removeAllListeners()
      this.socket.destroy()
      this.socket = null
    }
    if (this._decode) {
      this._encode.destroy()
      this._decode.destroy()
      this._decode = null
    }
    this.emit('close')
  }

  _error(err) {
    debug(`[EncryptedSocket]`, err)
    this.emit('error', err)
    this.destroy()
  }
}

module.exports = EncryptedSocket