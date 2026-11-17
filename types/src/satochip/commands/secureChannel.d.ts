import { APDUResponse, SecureChannelData, SecureChannelInitResponse } from '../types';
/**
 * Initialize secure channel with the card
 * @param clientPublicKey - Client's ECDH public key (65 bytes uncompressed)
 * @returns Card's public key and challenge
 */
export declare function initSecureChannel(clientPublicKey: Buffer): Promise<SecureChannelInitResponse>;
/**
 * Process encrypted secure channel command
 * @param encryptedData - Encrypted APDU data
 * @returns Raw encrypted response (status word checked with the Satochip mapping)
 */
export declare function processSecureChannel(encryptedData: SecureChannelData): Promise<APDUResponse>;
/**
 * Helper function to determine if a command requires secure channel encryption
 * Based on the Satochip protocol specification
 */
export declare function requiresSecureChannel(ins: number): boolean;
