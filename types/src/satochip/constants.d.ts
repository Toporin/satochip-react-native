export declare const SATOCHIP_CLA = 176;
export declare const SATOCHIP_AID: Buffer;
export declare const INS_SELECT = 164;
export declare const INS_GET_STATUS = 60;
export declare const INS_SETUP = 42;
export declare const INS_VERIFY_PIN = 66;
export declare const INS_CHANGE_PIN = 68;
export declare const INS_UNBLOCK_PIN = 70;
export declare const INS_CREATE_PIN = 64;
export declare const INS_LIST_PINS = 72;
export declare const INS_LOGOUT_ALL = 96;
export declare const INS_CARD_LABEL = 61;
export declare const INS_SET_NFC_POLICY = 62;
export declare const INS_SET_FEATURE_POLICY = 58;
export declare const INS_RESET_TO_FACTORY = 255;
export declare const INS_GET_PUBLIC_FROM_PRIVATE = 53;
export declare const INS_BIP32_IMPORT_SEED = 108;
export declare const INS_BIP32_RESET_SEED = 119;
export declare const INS_BIP32_GET_AUTHENTIKEY = 115;
export declare const INS_BIP32_GET_EXTENDED_KEY = 109;
export declare const INS_EXPORT_AUTHENTIKEY = 173;
export declare const INS_SIGN_MESSAGE = 110;
export declare const INS_SIGN_TRANSACTION_HASH = 122;
export declare const INS_SIGN_SCHNORR_HASH = 123;
export declare const INS_TAPROOT_TWEAK_PRIVKEY = 124;
export declare const INS_PARSE_TRANSACTION = 113;
export declare const INS_SIGN_TRANSACTION = 111;
export declare const INS_INIT_SECURE_CHANNEL = 129;
export declare const INS_PROCESS_SECURE_CHANNEL = 130;
export declare const INS_EXPORT_PKI_CERTIFICATE = 147;
export declare const INS_CHALLENGE_RESPONSE_PKI = 154;
export declare const INS_EXPORT_PKI_PUBKEY = 152;
export declare const SW_OK = 36864;
export declare const SW_WRONG_LENGTH = 26368;
export declare const SW_SECURITY_NOT_SATISFIED = 27010;
export declare const SW_CONDITIONS_NOT_SATISFIED = 27013;
export declare const SW_FILE_NOT_FOUND = 27266;
export declare const SW_INS_NOT_SUPPORTED = 27904;
export declare const SW_NO_MEMORY_LEFT = 39937;
export declare const SW_AUTH_FAILED = 39938;
export declare const SW_OPERATION_NOT_ALLOWED = 39939;
export declare const SW_SETUP_NOT_DONE = 39940;
export declare const SW_UNSUPPORTED_FEATURE = 39941;
export declare const SW_UNAUTHORIZED = 39942;
export declare const SW_SETUP_ALREADY_DONE = 39943;
export declare const SW_INCORRECT_ALG = 39945;
export declare const SW_SIGNATURE_INVALID = 39947;
export declare const SW_IDENTITY_BLOCKED = 39948;
export declare const SW_INVALID_PARAMETER = 39951;
export declare const SW_INCORRECT_P1 = 39952;
export declare const SW_INCORRECT_P2 = 39953;
export declare const SW_INCORRECT_INITIALIZATION = 39955;
export declare const SW_BIP32_UNINITIALIZED_SEED = 39956;
export declare const SW_INCORRECT_TXHASH = 39957;
export declare const SW_BIP32_INITIALIZED_SEED = 39959;
export declare const SW_2FA_INITIALIZED_KEY = 39960;
export declare const SW_2FA_UNINITIALIZED_KEY = 39961;
export declare const SW_PIN_FAILED_BASE = 25536;
export declare const OP_INIT = 1;
export declare const OP_PROCESS = 2;
export declare const OP_FINALIZE = 3;
export declare const MAX_PIN_LENGTH = 32;
export declare const MIN_PIN_LENGTH = 4;
export declare const MAX_SEED_LENGTH = 64;
export declare const MIN_SEED_LENGTH = 16;
export declare const MAX_BIP32_PATH_DEPTH = 10;
export declare const MAX_NUM_KEYS = 16;
export declare const DEFAULT_PIN_BYTES: Buffer;
/**
 * Supported xpub types for different address formats
 */
export declare const SUPPORTED_XTYPES: readonly ["standard", "p2wpkh-p2sh", "p2wpkh", "p2wsh-p2sh", "p2wsh"];
export type XType = typeof SUPPORTED_XTYPES[number];
/**
 * XPUB header bytes for mainnet (in hex)
 */
export declare const XPUB_HEADERS_MAINNET: Record<XType, string>;
/**
 * XPUB header bytes for testnet (in hex)
 */
export declare const XPUB_HEADERS_TESTNET: Record<XType, string>;
