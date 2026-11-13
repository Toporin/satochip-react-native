/**
 * Satodime applet constants.
 * Source of truth: Satodime-Applet (branch support-dynamic-ndef), Satodime.java.
 */
export const SATODIME_CLA = 0xB0;
/** "SatoDime" (selected by prefix; the installed instance AID is 5361746f44696d6500). */
export const SATODIME_AID = Buffer.from('5361746f44696d65', 'hex');

export const INS_SETUP = 0x2A;
export const INS_GET_STATUS = 0x3C;
export const INS_GET_SATODIME_STATUS = 0x50;
export const INS_GET_SATODIME_KEYSLOT_STATUS = 0x51;
export const INS_SET_SATODIME_KEYSLOT_STATUS = 0x52;
// 0x53 INS_GET_SATODIME_UNLOCK_CODE is deprecated in the applet
export const INS_CHECK_SATODIME_UNLOCK_CODE = 0x54; // protocol >= 0.2
export const INS_GET_SATODIME_PUBKEY = 0x55;
export const INS_GET_SATODIME_PRIVKEY = 0x56;
export const INS_SEAL_SATODIME_KEY = 0x57;
export const INS_UNSEAL_SATODIME_KEY = 0x58;
export const INS_RESET_SATODIME_KEY = 0x59;
export const INS_INITIATE_SATODIME_TRANSFER = 0x5A;
export const INS_SIGN_SATODIME_TRANSACTION_HASH = 0x5B; // protocol >= 0.2

export const SIZE_UNLOCK_COUNTER = 4;
export const SIZE_UNLOCK_SECRET = 20;
export const SIZE_UNLOCK_CODE = 20;
export const SIZE_ENTROPY = 32;
export const SIZE_SLIP44 = 4;
export const SIZE_CONTRACT = 34;
export const SIZE_TOKENID = 34;
export const SIZE_DATA = 66;
export const SIZE_KEYSLOT_STATUS = 3 + SIZE_SLIP44 + SIZE_CONTRACT + SIZE_TOKENID + SIZE_DATA; // 141
export const MAX_NUM_KEYSLOTS = 16; // P1 bound checked by the applet

/** Hash signing (0x5B) and unlock-code check (0x54) need protocol version >= 0.2. */
export const MIN_PROTOCOL_VERSION_HASH_SIGNING = 0x0002;

export enum KeyslotState {
  UNINITIALIZED = 0,
  SEALED = 1,
  UNSEALED = 2,
}

/** Asset codes stored in a key slot (key_asset). */
export const SATODIME_ASSET = {
  UNDEFINED: 0x00,
  COIN: 0x01,
  TOKEN: 0x10,
  ERC20: 0x11,
  BEP20: 0x12,
  NFT: 0x40,
  ERC721: 0x41,
  BEP721: 0x42,
  OTHER: 0xff,
} as const;

/** Satodime-specific status words. */
export const SW_INCORRECT_UNLOCK_COUNTER = 0x9C50;
export const SW_INCORRECT_UNLOCK_CODE = 0x9C51;
export const SW_INCORRECT_KEYSLOT_STATE = 0x9C52;
export const SW_INCORRECT_PROTOCOL_MEDIA = 0x9C53;
export const SW_UNKNOWN_PROTOCOL_MEDIA = 0x9C54;
