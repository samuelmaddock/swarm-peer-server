/**
 * Echo client/server example.
 * 
 * Usage:
 * # MUST generate keypair first
 * node examples/echo.js gen-keypair
 * 
 * # Create listen server which echos any messages received
 * node examples/echo.js listen
 * 
 * # Connect to server, send message, receive message, then disconnects
 * node examples/echo.js connect deadbeafdeadbeafdeadbeafdeadbeaf
 * 
 * # Show debug output
 * DEBUG=swarm-server node examples/echo.js listen
 */

const fs = require('fs')
const path = require('path')
const yargs = require('yargs')
const sodium = require('sodium-native')
const swarmDefaults = require('dat-swarm-defaults')

const swarm = require('../index.js')

const KEY_FILENAME = 'key'

/** Generate authenticated encryption keypair. */
function generateKeyPair(seed) {
  let publicKey = new Buffer(sodium.crypto_box_PUBLICKEYBYTES)
  let secretKey = new Buffer(sodium.crypto_box_SECRETKEYBYTES)

  if (seed) sodium.crypto_box_seed_keypair(publicKey, secretKey, seed)
  else sodium.crypto_box_keypair(publicKey, secretKey)

  return {
    publicKey: publicKey,
    secretKey: secretKey
  }
}

function writeKeyPair(keypair, dirpath = __dirname) {
  const filepath = path.join(dirpath, KEY_FILENAME)
  fs.writeFileSync(`${filepath}.pub`, keypair.publicKey)
  fs.writeFileSync(filepath, keypair.secretKey)
  console.log(`Created keypair under ${filepath}.pub`)
}

function readKeyPair(dirpath = __dirname) {
  const filepath = path.join(dirpath, KEY_FILENAME)
  return {
    publicKey: fs.readFileSync(`${filepath}.pub`),
    secretKey: fs.readFileSync(filepath)
  }
}

// prettier-ignore
yargs
  .demand(1)
  .command(
    'gen-keypair [path] [seed]',
    'Generate encryption keypair to use for swarm.',
    {},
    opts => {
      const keypair = generateKeyPair(opts.seed)
      writeKeyPair(keypair, opts.path)
    }
  )
  .command(
    'listen',
    'Create swarm server listening at the public key hash.',
    {},
    opts => {
      const keypair = readKeyPair()

      const swarmOpts = Object.assign({}, swarmDefaults({ hash: false }), keypair)
      swarm.listen(swarmOpts, (socket, peerKey, info) => {
        console.log('Got connection')

        // Echo server
        socket.on('data', data => {
          const address = socket.socket.address().address
          console.log(`recv[${address}]: ${data}`)
          socket.write(data)
        })
      })
    }
  )
  .command(
    'connect <desthash>',
    'Connect to swarm server at the given hash.',
    {},
    opts => {
      const keypair = readKeyPair()
      const hostPublicKey = Buffer.from(opts.desthash, 'hex')

      const swarmOpts = Object.assign({}, swarmDefaults({ hash: false }), keypair, {
        hostPublicKey: hostPublicKey
      })

      swarm.connect(swarmOpts)
        .then(conn => {
          console.log('Connected to swarm')
          const { socket, info } = conn
          const msg = new Buffer('Hello world')
          console.log(`send: ${msg}`)
          socket.write(msg)
          socket.once('data', data => {
            console.log(`recv: ${data}`)
            socket.destroy()
          })
          socket.on('error', err => {
            console.error('Socket error', err)
          })
          socket.once('close', () => {
            console.log('Swarm connection closed')
          })
        })
        .catch(err => {
          console.error('Swarm connect error', err)
        })
    }
  )
  .help()
  .strict().argv
