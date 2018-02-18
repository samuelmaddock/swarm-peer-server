const fs = require('fs')
const path = require('path')
const yargs = require('yargs')
const sodium = require('sodium-native')

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

function writeKeyPair(dirpath = __dirname) {
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
      writeKeyPair(opts.path)
    }
  )
  .command(
    'listen',
    'Create swarm server listening at the public key hash.',
    {},
    opts => {
      const keypair = readKeyPair()

      swarm.listen(keypair, socket => {
        console.log('Got connection')
      })
    }
  )
  .command(
    'connect <desthash>',
    'Connect to swarm server at the given hash.',
    {},
    opts => {
      const keypair = readKeyPair()

      const swarmOpts = Object.assign({}, keypair, {
        hostPublicKey: Buffer.from(opts.desthash)
      })

      swarm.connect(swarmOpts)
        .then(socket => {
          console.log('Connected to swarm')
        })
        .catch(err => {
          console.error('Swarm connect error', err)
        })
    }
  )
  .help()
  .strict().argv
