import { ResponseChecker } from '../errors';
import { APDUResponse, SecureChannelData, SecureChannelInitResponse } from '../../satochip/types';
/** CLA used by every applet of the Satochip family. */
export declare const CARD_CLA = 176;
export declare const INS_INIT_SECURE_CHANNEL = 129;
export declare const INS_PROCESS_SECURE_CHANNEL = 130;
/**
 * Initialize the secure channel with the card (INS 0x81, sent in plain).
 * @param clientPublicKey - Client's ECDH public key (65 bytes uncompressed)
 */
export declare function initSecureChannel(clientPublicKey: Buffer, check: ResponseChecker): Promise<SecureChannelInitResponse>;
/**
 * Send an encrypted payload with INS 0x82.
 * Returns the raw (still encrypted) response; the status word is NOT checked,
 * so that the caller can map it with its own card-specific error table.
 */
export declare function processSecureChannel(encryptedData: SecureChannelData): Promise<APDUResponse>;
