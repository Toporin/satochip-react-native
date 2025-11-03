// Satochip APDU Class byte
export const SATOCHIP_CLA = 0xB0;

// Satochip applet AID
export const SATOCHIP_AID = Buffer.from('5361746f43686970', 'hex'); // "SatoChip" in ASCII

// Instruction codes for Satochip commands
export const INS_SELECT = 0xA4;
export const INS_GET_STATUS = 0x3C;
export const INS_SETUP = 0x2A;
export const INS_VERIFY_PIN = 0x42;
export const INS_CHANGE_PIN = 0x44;
export const INS_UNBLOCK_PIN = 0x46;
export const INS_CREATE_PIN = 0x40;
export const INS_LIST_PINS = 0x48;
export const INS_LOGOUT_ALL = 0x60;
export const INS_CARD_LABEL = 0x3D;
export const INS_SET_NFC_POLICY = 0x3E;
export const INS_SET_FEATURE_POLICY = 0x3A;
export const INS_RESET_TO_FACTORY = 0xFF;

// key slot commands
export const INS_GET_PUBLIC_FROM_PRIVATE = 0x35;

// BIP32 commands
export const INS_BIP32_IMPORT_SEED = 0x6C;
export const INS_BIP32_RESET_SEED = 0x77;
export const INS_BIP32_GET_AUTHENTIKEY = 0x73;
export const INS_BIP32_GET_EXTENDED_KEY = 0x6D;

export const INS_EXPORT_AUTHENTIKEY = 0xAD;

// Signing commands
export const INS_SIGN_MESSAGE = 0x6E;
export const INS_SIGN_TRANSACTION_HASH = 0x7A;
export const INS_PARSE_TRANSACTION = 0x71;
export const INS_SIGN_TRANSACTION = 0x6F;

// Secure channel commands
export const INS_INIT_SECURE_CHANNEL = 0x81;
export const INS_PROCESS_SECURE_CHANNEL = 0x82;

// PKI commands
export const INS_EXPORT_PKI_CERTIFICATE = 0x93;
export const INS_CHALLENGE_RESPONSE_PKI = 0x9A;
export const INS_EXPORT_PKI_PUBKEY = 0x98;

// Success status word
export const SW_OK = 0x9000;

// Common error status words
export const SW_WRONG_LENGTH = 0x6700;
export const SW_SECURITY_NOT_SATISFIED = 0x6982;
export const SW_CONDITIONS_NOT_SATISFIED = 0x6985;
export const SW_FILE_NOT_FOUND = 0x6A82;
export const SW_INS_NOT_SUPPORTED = 0x6D00;

// Satochip specific error codes
export const SW_NO_MEMORY_LEFT = 0x9C01;
export const SW_AUTH_FAILED = 0x9C02;
export const SW_OPERATION_NOT_ALLOWED = 0x9C03;
export const SW_SETUP_NOT_DONE = 0x9C04;
export const SW_UNSUPPORTED_FEATURE = 0x9C05;
export const SW_UNAUTHORIZED = 0x9C06;
export const SW_SETUP_ALREADY_DONE = 0x9C07;
export const SW_INCORRECT_ALG = 0x9C09;
export const SW_SIGNATURE_INVALID = 0x9C0B;
export const SW_IDENTITY_BLOCKED = 0x9C0C;
export const SW_INVALID_PARAMETER = 0x9C0F;
export const SW_INCORRECT_P1 = 0x9C10;
export const SW_INCORRECT_P2 = 0x9C11;
export const SW_INCORRECT_INITIALIZATION = 0x9C13;
export const SW_BIP32_UNINITIALIZED_SEED = 0x9C14;
export const SW_INCORRECT_TXHASH = 0x9C15;
export const SW_BIP32_INITIALIZED_SEED = 0x9C17;
export const SW_2FA_INITIALIZED_KEY = 0x9C18;
export const SW_2FA_UNINITIALIZED_KEY = 0x9C19;

// PIN failure codes (0x63C0-0x63CF)
export const SW_PIN_FAILED_BASE = 0x63C0;

// Operation modes for multi-step commands
export const OP_INIT = 0x01;
export const OP_PROCESS = 0x02;
export const OP_FINALIZE = 0x03;

// Maximum lengths
export const MAX_PIN_LENGTH = 32;
export const MIN_PIN_LENGTH = 4;
export const MAX_SEED_LENGTH = 64;
export const MIN_SEED_LENGTH = 16;
export const MAX_BIP32_PATH_DEPTH = 10;
export const MAX_NUM_KEYS = 16; // Max number of keys handled by Satochip

// Default PIN
export const DEFAULT_PIN_BYTES : Buffer = Buffer.from('4D7573636C653030', 'hex'); //[0x4D, 0x75, 0x73, 0x63, 0x6C, 0x65, 0x30, 0x30];


/**
 * Supported xpub types for different address formats
 */
export const SUPPORTED_XTYPES = [
  'standard',
  'p2wpkh-p2sh',
  'p2wpkh',
  'p2wsh-p2sh',
  'p2wsh',
] as const;

export type XType = typeof SUPPORTED_XTYPES[number];

/**
 * XPUB header bytes for mainnet (in hex)
 */
export const XPUB_HEADERS_MAINNET: Record<XType, string> = {
  'standard': '0488b21e',      // xpub
  'p2wpkh-p2sh': '049d7cb2',   // ypub
  'p2wpkh': '04b24746',        // zpub
  'p2wsh-p2sh': '0295b43f',    // Ypub
  'p2wsh': '02aa7ed3',         // Zpub
};

/**
 * XPUB header bytes for testnet (in hex)
 */
export const XPUB_HEADERS_TESTNET: Record<XType, string> = {
  'standard': '043587cf',      // tpub
  'p2wpkh-p2sh': '044a5262',   // upub
  'p2wpkh': '045f1cf6',        // vpub
  'p2wsh-p2sh': '024289ef',    // Upub
  'p2wsh': '02575483',         // Vpub
};

