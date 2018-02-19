import { EventEmitter } from 'events'

declare namespace SwarmServer {
  export interface EncryptedSocket extends EventEmitter {
    write(data: Buffer): void
    on(eventName: 'data', callback: (data: Buffer) => void): this
    destroy(): void
  }

  type DiscoverySwarm = any
  type Key = Buffer

  export interface SwarmListenOptions {
    publicKey: Key
    secretKey: Key

    /** Whether the keypair needs to be converted from a signature key to an encryption key. */
    convert?: boolean
  }

  export interface SwarmConnectOptions {
    publicKey: Key
    secretKey: Key
    hostPublicKey: Key

    /** Whether the keypair needs to be converted from a signature key to an encryption key. */
    convert?: boolean
  }

  export function listen(
    opts: SwarmListenOptions,
    handler: (socket: EncryptedSocket, peerKey: Key) => void
  ): DiscoverySwarm

  export function connect(opts: SwarmConnectOptions): Promise<EncryptedSocket>
}

export = SwarmServer
