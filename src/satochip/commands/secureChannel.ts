import { sendAPDU } from '../apduSecure';
import { INS_INIT_SECURE_CHANNEL, INS_PROCESS_SECURE_CHANNEL, SATOCHIP_CLA } from '../constants';
import { APDUCommand, APDUResponse, SecureChannelData, SecureChannelInitResponse } from '../types';
import { CardDataParser } from '../parser';

/**
 * Initialize secure channel with the card
 * @param clientPublicKey - Client's ECDH public key (65 bytes uncompressed)
 * @returns Card's public key and challenge
 */
export async function initSecureChannel(clientPublicKey: Buffer): Promise<SecureChannelInitResponse> {
  // console_log(`In commands/SecureChannel initSecureChannel clientPublicKey: ${clientPublicKey.toString('hex')}`);
  const command: APDUCommand = {
    cla: SATOCHIP_CLA,
    ins: INS_INIT_SECURE_CHANNEL,
    p1: 0x00,
    p2: 0x00,
    data: clientPublicKey,
    le: 0x00, // Expect response
  };

  const response = await sendAPDU(command);
  return CardDataParser.parseInitiateSecureChannel(response.data);
}

/**
 * Process encrypted secure channel command
 * @param encryptedData - Encrypted APDU data
 * @returns Decrypted response data
 */
export async function processSecureChannel(encryptedData: SecureChannelData): Promise<APDUResponse> {
  // console_log(`In commands/secureChannel processSecureChannel encryptedData: ${encryptedData}`);

  // Build the secure channel data: iv(16) + length(2) + ciphertext + mac(20)
  const lengthBytes = Buffer.alloc(2);
  lengthBytes.writeUInt16BE(encryptedData.ciphertext.length, 0);

  // length mac
  const lengthMacBytes = Buffer.alloc(2);
  lengthMacBytes.writeUInt16BE(encryptedData.mac.length, 0);

  const secureChannelPayload = Buffer.concat([
    encryptedData.iv,
    lengthBytes,
    encryptedData.ciphertext,
    lengthMacBytes,
    encryptedData.mac
  ]);
  // console_log(`In commands/secureChannel processSecureChannel secureChannelPayload: ${secureChannelPayload.toString('hex')}`);

  const command: APDUCommand = {
    cla: SATOCHIP_CLA,
    ins: INS_PROCESS_SECURE_CHANNEL,
    p1: 0x00,
    p2: 0x00,
    data: secureChannelPayload,
    le: 0x00, // Expect response
  };
  
  const response = await sendAPDU(command);
  // console_log(`In commands/secureChannel processSecureChannel response data: ${response.data.toString('hex')}`);
  // console_log(`In commands/secureChannel processSecureChannel response statusWord: 0x${response.statusWord.toString(16)}`);
  
  return response; // Return raw encrypted response for decryption by SecureChannel class
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