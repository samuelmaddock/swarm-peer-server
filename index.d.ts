export interface EncryptedSocket {
  write(data: Buffer): void;
  on(eventName: "data", callback: (data: Buffer) => void): void;
}

type DiscoverySwarm = any;
type Key = Buffer;

export interface SwarmListenOptions {
  publicKey: Key;
  secretKey: Key;

  /** Whether the keypair needs to be converted from a signature key to an encryption key. */
  convert?: boolean;
}

export interface SwarmConnectOptions {
  publicKey: Key;
  secretKey: Key;
  hostPublicKey: Key;

  /** Whether the keypair needs to be converted from a signature key to an encryption key. */
  convert?: boolean;
}

interface Swarm {
  listen(
    opts: SwarmListenOptions,
    handler: (socket: EncryptedSocket) => void
  ): DiscoverySwarm;
  connect(opts: SwarmConnectOptions): Promise<EncryptedSocket>;
}

export default Swarm;
