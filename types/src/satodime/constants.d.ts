/**
 * Satodime applet constants.
 * Source of truth: Satodime-Applet (branch support-dynamic-ndef), Satodime.java.
 */
export declare const SATODIME_CLA = 176;
/** "SatoDime" (selected by prefix; the installed instance AID is 5361746f44696d6500). */
export declare const SATODIME_AID: Buffer;
export declare const INS_SETUP = 42;
export declare const INS_GET_STATUS = 60;
export declare const INS_GET_SATODIME_STATUS = 80;
export declare const INS_GET_SATODIME_KEYSLOT_STATUS = 81;
export declare const INS_SET_SATODIME_KEYSLOT_STATUS = 82;
export declare const INS_CHECK_SATODIME_UNLOCK_CODE = 84;
export declare const INS_GET_SATODIME_PUBKEY = 85;
export declare const INS_GET_SATODIME_PRIVKEY = 86;
export declare const INS_SEAL_SATODIME_KEY = 87;
export declare const INS_UNSEAL_SATODIME_KEY = 88;
export declare const INS_RESET_SATODIME_KEY = 89;
export declare const INS_INITIATE_SATODIME_TRANSFER = 90;
export declare const INS_SIGN_SATODIME_TRANSACTION_HASH = 91;
export declare const SIZE_UNLOCK_COUNTER = 4;
export declare const SIZE_UNLOCK_SECRET = 20;
export declare const SIZE_UNLOCK_CODE = 20;
export declare const SIZE_ENTROPY = 32;
export declare const SIZE_SLIP44 = 4;
export declare const SIZE_CONTRACT = 34;
export declare const SIZE_TOKENID = 34;
export declare const SIZE_DATA = 66;
export declare const SIZE_KEYSLOT_STATUS: number;
export declare const MAX_NUM_KEYSLOTS = 16;
/** Hash signing (0x5B) and unlock-code check (0x54) need protocol version >= 0.2. */
export declare const MIN_PROTOCOL_VERSION_HASH_SIGNING = 2;
export declare enum KeyslotState {
    UNINITIALIZED = 0,
    SEALED = 1,
    UNSEALED = 2
}
/** Asset codes stored in a key slot (key_asset). */
export declare const SATODIME_ASSET: {
    readonly UNDEFINED: 0;
    readonly COIN: 1;
    readonly TOKEN: 16;
    readonly ERC20: 17;
    readonly BEP20: 18;
    readonly NFT: 64;
    readonly ERC721: 65;
    readonly BEP721: 66;
    readonly OTHER: 255;
};
/** Satodime-specific status words. */
export declare const SW_INCORRECT_UNLOCK_COUNTER = 40016;
export declare const SW_INCORRECT_UNLOCK_CODE = 40017;
export declare const SW_INCORRECT_KEYSLOT_STATE = 40018;
export declare const SW_INCORRECT_PROTOCOL_MEDIA = 40019;
export declare const SW_UNKNOWN_PROTOCOL_MEDIA = 40020;
