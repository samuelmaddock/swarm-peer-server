const sodium = require('sodium-native')
const discoverySwarm = require('discovery-swarm')
const debug = require('debug')('swarm-peer-server')

const EncryptedSocket = require('./lib/socket')
const crypto = require('./lib/crypto')

const NETWORK_TIMEOUT = 15000
const DISCOVERY_HASH = new Buffer('swarmserver')

// +1 from Dat protocol default to reduce conflict
const DEFAULT_PORT = 3283

function getDiscoveryKey(tree) {
  var digest = new Buffer(32)
  sodium.crypto_generichash(digest, DISCOVERY_HASH, tree)
  return digest
}

function createSwarm(opts) {
  const swarm = discoverySwarm(opts)
  swarm.on('error', () => swarm.listen(0))
  swarm.listen(opts.port || DEFAULT_PORT)
  swarm.join(opts.name, { announce: true })
  return swarm
}

async function authConnection(socket, opts) {
  return new Promise((resolve, reject) => {
    const esocket = new EncryptedSocket(socket, opts.publicKey, opts.secretKey)

    esocket.once('connection', () => resolve(esocket))
    esocket.once('error', () => {})
    esocket.once('close', reject)

    // TODO: timeout
    esocket.connect(opts.hostPublicKey)
  })
}

function listen(opts, connectionHandler) {
  let publicKey = opts.publicKey
  let secretKey = opts.secretKey

  if (opts.convert) {
    publicKey = crypto.pub2auth(publicKey)
    secretKey = crypto.secret2auth(secretKey)
  }

  const discoveryKey = getDiscoveryKey(publicKey)
  const swarmOpts = Object.assign({}, opts, { name: discoveryKey })
  const swarm = createSwarm(swarmOpts)
  debug(`Listen ${publicKey.toString('hex')}`)

  // Wait for connections to perform auth handshake with
  swarm.on('connection', async (socket, info) => {
    const address = socket.address().address
    debug(`Local swarm connection ${address}`)

    let esocket
    try {
      debug(`Attempting to auth...`)
      esocket = await authConnection(socket, {
        publicKey: publicKey,
        secretKey: secretKey
      })
    } catch (e) {
      debug('Failed to auth peer\n', e)
      return
    }

    debug(`Authed with peer: ${address}`)
    connectionHandler(esocket, esocket.peerKey, info)
  })

  return swarm
}

function connect(opts) {
  return new Promise((resolve, reject) => {
    let timeoutId, timeout, connected

    let publicKey = opts.publicKey
    let secretKey = opts.secretKey
    let hostPublicKey = opts.hostPublicKey

    if (opts.convert) {
      publicKey = crypto.pub2auth(publicKey)
      secretKey = crypto.secret2auth(secretKey)
      hostPublicKey = crypto.pub2auth(hostPublicKey)
    }

    const discoveryKey = getDiscoveryKey(hostPublicKey)
    const swarmOpts = Object.assign({}, opts, { name: discoveryKey })
    const swarm = createSwarm(swarmOpts)

    debug(`Connecting to remote swarm ${hostPublicKey.toString('hex')}`)

    let queue = []
    let connecting = false

    const cleanup = () => {
      if (timeoutId) {
        clearTimeout(timeoutId)
        timeoutId = null
      }

      queue.forEach(conn => conn.socket.destroy())
      queue = []

      swarm.removeListener('connection', onConnection)

      if (!connected) {
        swarm.close()
      }
    }

    async function attemptConnect() {
      connecting = true

      let conn
      while (!connected && !timeout && (conn = queue.shift())) {
        const { socket, info } = conn
        let esocket
        try {
          debug(`Attempting to auth ${hostPublicKey.toString('hex')}...`)
          esocket = await authConnection(socket, {
            publicKey: publicKey,
            secretKey: secretKey,
            hostPublicKey
          })
        } catch (e) {
          debug('Failed to auth peer\n', e)
          continue
        }

        const address = socket.address().address
        debug(`Authed with host: ${address}`)

        if (!timeout && !connected) {
          // close swarm when we're done with the socket
          esocket.once('close', () => {
            swarm.close()
            // TODO: unannounce to DHT
            // https://github.com/webtorrent/bittorrent-dht/pull/184
          })

          connected = true
          cleanup()
          resolve({ socket: esocket, info: info })
        } else {
          esocket.destroy()
        }
      }

      connecting = false
    }

    // Wait for connections and attempt to auth with host
    const onConnection = (socket, info) => {
      const address = socket.address().address
      debug(`Remote swarm connection ${address}`)

      queue.push({ socket, info })

      if (!connecting) {
        attemptConnect()
      }
    }
    swarm.on('connection', onConnection)

    timeoutId = setTimeout(() => {
      cleanup()
      timeout = true
      reject('Timeout connecting to swarm')
    }, opts.timeout || NETWORK_TIMEOUT)
  })
}

module.exports = {
  listen,
  connect
}
