const EventEmitter = require('events').EventEmitter
const sodium = require('libsodium-wrappers')
const lpstream = require('length-prefixed-stream')
const debug = require('debug')('swarm-peer-server:socket')

const enc = require('./encryption')
const crypto = require('./crypto')

const SUCCESS = Buffer.from('chat-auth-success')
const AUTH_TIMEOUT = 5000

// FIX: for https://github.com/nodejs/node/pull/14330
const Decoder = lpstream.decode
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


/**
 * Socket wrapper to use encrypted keypair communication
 */
class EncryptedSocket extends EventEmitter {
  constructor(socket, publicKey, secretKey) {
    super()

    this.socket = socket
    this.publicKey = publicKey
    this.secretKey = secretKey

    this._error = this._error.bind(this)
    this._onReceive = this._onReceive.bind(this)
    this._authTimeout = this._authTimeout.bind(this)
    this.destroy = this.destroy.bind(this)

    this.socket.once('close', this.destroy)
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

  _setupEncryptionKey(peerKey) {
    if (!this.sharedKey) {
      this.peerKey = peerKey
      this.sharedKey = enc.scalarMultiplication(this.secretKey, this.peerKey)
      this._setupSocket()
    }
  }

  /** Auth connection to host */
  _authHost(hostKey) {
    const self = this

    /** 1. Send auth request with encrypted identity */
    function sendAuthRequest() {
      const box = crypto.seal(self.publicKey, self.peerKey)

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
      const peerPublicKey = crypto.unseal(buf, self.publicKey, self.secretKey)

      if (!peerPublicKey) {
        self._error('Failed to unseal peer box')
        return
      }

      if (self.publicKey.equals(peerPublicKey)) {
        // debug('Auth request key is the same as the host')
        // return
      }

      self._setupEncryptionKey(peerPublicKey)
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

    const msg = Buffer.alloc(nonce.length + box.length)
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

  destroy(destroySocket = true) {
    if (this._authTimeoutId) {
      clearTimeout(this._authTimeoutId)
      this._authTimeoutId = null
    }
    if (this._decode) {
      if (this.socket) {
        this.socket.unpipe(this._decode)
      }
      this._decode.unpipe()
      this._decode.destroy()
      this._decode = null
      this._encode.unpipe()
      this._encode.destroy()
      this._encode = null
    }
    if (this.socket) {
      this.socket.removeListener('close', this.destroy)
      if (destroySocket) {
        this.socket.destroy()
      }
      this.socket = null
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