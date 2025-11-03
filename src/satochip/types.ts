import { ECPubkey } from './utils/ECKey';

export interface APDUCommand {
  cla: number;
  ins: number;
  p1: number;
  p2: number;
  data?: Buffer;
  le?: number;
}

// export interface APDUResponse {
//   data: Buffer;
//   sw1: number;
//   sw2: number;
//   statusWord: number;
// }

export class APDUResponse {
  data: Buffer;
  sw1: number;
  sw2: number;
  statusWord: number;

  constructor(data: Buffer, sw1: number, sw2: number, statusWord: number) {
    this.data = data;
    this.sw1 = sw1;
    this.sw2 = sw2;
    this.statusWord = statusWord;
  }

  toString(): string {
    return `APDUResponse { data: ${this.data.toString('hex')}, sw1: 0x${this.sw1.toString(16)}, sw2: 0x${this.sw2.toString(16)}, statusWord: 0x${this.statusWord.toString(16)} }`;
  }
}

// Secure channel related types
export interface SecureChannelData {
  iv: Buffer;
  ciphertext: Buffer;
  mac: Buffer;
}

export interface SecureChannelInitResponse {
  cardPublicKey: ECPubkey;
  authentikeyCandidates: ECPubkey[];
}

export interface SatochipStatus {
  protocol_version: number;
  applet_version: number;
  pin0_tries: number;
  puk0_tries: number;
  pin1_tries: number;
  puk1_tries: number;
  needs_2fa: boolean;
  is_seeded: boolean;
  setup_done: boolean;
  needs_secure_channel: boolean;
  nfc_policy: number;
  schnorr_policy: number;
  nostr_policy: number;
  liquid_policy: number;
  musig2_policy: number;
}

export enum Feature {
  SCHNORR = 0x00,
  NOSTR = 0x01,
  LIQUID = 0x02,
  MUSIG2 = 0x03,
}

export enum Policy {
  ENABLED = 0x00,
  DISABLED = 0x01,
  BLOCKED = 0x02,
}

export enum NFCPolicy {
  ENABLED = 0x00,
  DISABLED = 0x01,
  BLOCKED = 0x02,
}

// BIP32 related types for Phase 2
export interface BIP32Path {
  path: number[];
  pathString: string;
}

export interface ExtendedKey {
  pubkey: Buffer;
  chaincode: Buffer;
}