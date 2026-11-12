import { CardVersion } from '../core/status';
import { KeyslotState } from './constants';

/** GET_STATUS (0x3C) response for a Satodime. */
export interface SatodimeCardStatus {
  version: CardVersion;
  /** true when the card has an owner (setup done). */
  setupDone: boolean;
  needsSecureChannel: boolean;
}

/** GET_SATODIME_STATUS (0x50) response. */
export interface SatodimeStatus {
  /** Current unlock counter (4 bytes). */
  unlockCounter: Buffer;
  nbKeyslots: number;
  keyslotStates: KeyslotState[];
  /** Protocol >= 0.2: the unlock secret is a fixed CVC engraved on the card. */
  fixedUnlockSecret?: boolean;
  /** Protocol >= 0.2: card used as Certificate of Authenticity. */
  isCoA?: boolean;
}

/** GET_SATODIME_KEYSLOT_STATUS (0x51) response. */
export interface KeyslotStatus {
  state: KeyslotState;
  keyType: number;
  asset: number;
  /** Raw SLIP-44 value (uint32 big-endian), including the mainnet bit. */
  slip44: number;
  /** Satodime convention: the most significant bit is CLEARED for testnets. */
  isTestnet: boolean;
  /** [tag/RFU(1) | size(1) | value(32)] */
  contract: Buffer;
  /** [tag/RFU(1) | size(1) | value(32)] */
  tokenId: Buffer;
  /** [RFU(1) | size(1) | value(64)] */
  data: Buffer;
}

/** GET_SATODIME_PUBKEY (0x55) / SEAL (0x57) response. */
export interface SatodimePubkeyResponse {
  /** 65-byte uncompressed public key (0x04 | X | Y). */
  pubkey: Buffer;
  /** Bytes signed by the authentikey. */
  signedData: Buffer;
  /** DER signature by the authentikey. */
  signature: Buffer;
}

/** GET_SATODIME_PRIVKEY (0x56) / UNSEAL (0x58) response. */
export interface SatodimePrivkey {
  privkey: Buffer;
  userEntropy: Buffer;
  authentikeyCoordx: Buffer;
  cardEntropy: Buffer;
  signedData: Buffer;
  signature: Buffer;
}

/** SETUP (0x2A) response: ownership data, to be stored securely. */
export interface SatodimeOwnership {
  unlockCounter: Buffer;
  unlockSecret: Buffer;
}

/** Metadata written by SET_SATODIME_KEYSLOT_STATUS with P2=0x00. */
export interface KeyslotMetadata {
  asset: number;
  slip44: number;
  /** 34 bytes [tag|size|value(32)]; defaults to [0x00, 0x20, 0...] */
  contract?: Buffer;
  /** 34 bytes [tag|size|value(32)]; defaults to [0x00, 0x20, 0...] */
  tokenId?: Buffer;
}
