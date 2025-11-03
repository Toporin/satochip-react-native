import { ec as EC } from 'elliptic';
import { console_log } from './logging';

export class ECPubkey {
  private key: any;
  private ec: EC;

  constructor(pubkeyBytes: Buffer) {
    this.ec = new EC('secp256k1');
    this.key = this.ec.keyFromPublic(pubkeyBytes);
  }

  getPublicKeyBytes(compressed = true): Buffer {
    return Buffer.from(this.key.getPublic().encode('array', compressed));
  }

  static fromSigString(sigString: Buffer, recid: number, hash: Buffer): ECPubkey {
    console_log(`In parser ECPubkey fromSigString`);
    const ec = new EC('secp256k1');
    const r = sigString.slice(0, 32);
    const s = sigString.slice(32, 64);

    const signature = { r: r.toString('hex'), s: s.toString('hex') };
    console_log(`In parser ECPubkey fromSigString signature: ${signature}`);
    const recoveredPubkey = ec.recoverPubKey(
      hash.toString('hex'),
      signature,
      recid
    );

    return new ECPubkey(Buffer.from(recoveredPubkey.encode('array', false)));
  }

  equals(other: ECPubkey): boolean {
    return this.getPublicKeyBytes().equals(other.getPublicKeyBytes());
  }
}

export class ECPrivkey {
  private key: any;

  constructor(privkeyBytes: Buffer) {
    const ec = new EC('secp256k1');
    this.key = ec.keyFromPrivate(privkeyBytes);
  }

  getPublicKey(): ECPubkey {
    return new ECPubkey(Buffer.from(this.key.getPublic().encode('array', false)));
  }
}

export class InvalidECPointException extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'InvalidECPointException';
  }
}