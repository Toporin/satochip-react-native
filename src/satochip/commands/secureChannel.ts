import { checkResponse } from '../errors';
import { APDUResponse, SecureChannelData, SecureChannelInitResponse } from '../types';
import {
  initSecureChannel as coreInitSecureChannel,
  processSecureChannel as coreProcessSecureChannel,
} from '../../core/commands/secureChannel';

/**
 * Initialize secure channel with the card
 * @param clientPublicKey - Client's ECDH public key (65 bytes uncompressed)
 * @returns Card's public key and challenge
 */
export async function initSecureChannel(clientPublicKey: Buffer): Promise<SecureChannelInitResponse> {
  return coreInitSecureChannel(clientPublicKey, checkResponse);
}

/**
 * Process encrypted secure channel command
 * @param encryptedData - Encrypted APDU data
 * @returns Raw encrypted response (status word checked with the Satochip mapping)
 */
export async function processSecureChannel(encryptedData: SecureChannelData): Promise<APDUResponse> {
  const response = await coreProcessSecureChannel(encryptedData);
  checkResponse(response.sw1, response.sw2);
  return response;
}

/**
 * Helper function to determine if a command requires secure channel encryption
 * Based on the Satochip protocol specification
 */
export function requiresSecureChannel(ins: number): boolean {
  const secureChannelCommands = [
    // BIP32 commands that need encryption
    0x6C, // INS_BIP32_IMPORT_SEED
    0x77, // INS_BIP32_RESET_SEED
    0x73, // INS_BIP32_GET_AUTHENTIKEY
    0x6D, // INS_BIP32_GET_EXTENDED_KEY
    
    // Signing commands that need encryption
    0x6E, // INS_SIGN_MESSAGE
    0x7A, // INS_SIGN_TRANSACTION_HASH
    0x71, // INS_PARSE_TRANSACTION
    0x6F, // INS_SIGN_TRANSACTION
    
    // Sensitive configuration commands
    0x3A, // INS_SET_FEATURE_POLICY (some cases)
    0xFF, // INS_RESET_TO_FACTORY
  ];
  
  return secureChannelCommands.includes(ins);
}