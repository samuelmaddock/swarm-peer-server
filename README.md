# swarm-peer-server

A network swarm for creating secure P2P connections over Bittorrent DHT, DNS, and mDNS.

Uses [discovery-swarm](https://github.com/mafintosh/discovery-swarm) to find and connect peers. Connections use asymmetric encryption and [Elliptic-curve Diffie-Hellman](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) to establish a secure communication channel. Clients must know the public key of a peer ahead of time to initiate the connection.

Depends on native modules [libsodium](https://libsodium.org) (via [sodium-native](https://github.com/sodium-friends/sodium-native)) and [libutp](https://github.com/bittorrent/libutp) (via [utp-native](https://github.com/mafintosh/utp-native)).

```bash
npm install swarm-peer-server
```

## Usage

### Server
```js
var swarm = require('swarm-peer-server')

swarm.listen({
  publicKey: Buffer.from('...'),
  secretKey: Buffer.from('...')
}, (socket, peerKey, info) => {
  console.log('New authenticated connection')
  socket.once('data', data => {
    console.log('Received:', data.toString())
    socket.destroy()
  })
})
```

### Client
```js
var swarm = require('swarm-peer-server')

var { socket } = await swarm.connect({
  publicKey: Buffer.from('...'),
  secretKey: Buffer.from('...'),
  hostPublicKey: Buffer.from('...')
})

console.log('Established connection')
const data = Buffer.from('hello world')
socket.write(data)
```

### Examples

```bash
examples/echo.js # CLI echo server
```

## API

#### `var sw = swarm.listen(opts)`

Create a new swarm server. Options include:

```js
{
  publicKey: crypto.randomBytes(32), // server public key
  secretKey: crypto.randomBytes(64), // server secret key
  convert: false, // convert signatures to authentication encryption [1]
}
```
[1] https://download.libsodium.org/doc/advanced/ed25519-curve25519.html

For full list of options take a look at [discovery-swarm](https://github.com/mafintosh/discovery-swarm/blob/master/README.md#var-sw--swarmopts) or the [TypeScript definitions](index.d.ts).

#### `swarm.connect(opts, (socket, peerKey, info) => {})`

Create a new swarm server. Options include:

```js
{
  hostPublicKey: crypto.randomBytes(32), // host/server public key
  publicKey: crypto.randomBytes(32), // client public key
  secretKey: crypto.randomBytes(64), // client secret key
  convert: false, // convert signatures to authentication encryption
}
```

## License

MIT