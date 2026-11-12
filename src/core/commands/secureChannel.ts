import { transmitAPDU } from '../apdu';
import { ResponseChecker } from '../errors';
import { APDUCommand, APDUResponse, SecureChannelData, SecureChannelInitResponse } from '../../satochip/types';
import { CardDataParser } from '../../satochip/parser';

/** CLA used by every applet of the Satochip family. */
export const CARD_CLA = 0xB0;
export const INS_INIT_SECURE_CHANNEL = 0x81;
export const INS_PROCESS_SECURE_CHANNEL = 0x82;

/**
 * Initialize the secure channel with the card (INS 0x81, sent in plain).
 * @param clientPublicKey - Client's ECDH public key (65 bytes uncompressed)
 */
export async function initSecureChannel(
  clientPublicKey: Buffer,
  check: ResponseChecker,
): Promise<SecureChannelInitResponse> {
  const command: APDUCommand = {
    cla: CARD_CLA,
    ins: INS_INIT_SECURE_CHANNEL,
    p1: 0x00,
    p2: 0x00,
    data: clientPublicKey,
    le: 0x00,
  };
  const response = await transmitAPDU(command);
  check(response.sw1, response.sw2);
  return CardDataParser.parseInitiateSecureChannel(response.data);
}

/**
 * Send an encrypted payload with INS 0x82.
 * Returns the raw (still encrypted) response; the status word is NOT checked,
 * so that the caller can map it with its own card-specific error table.
 */
export async function processSecureChannel(encryptedData: SecureChannelData): Promise<APDUResponse> {
  const lengthBytes = Buffer.alloc(2);
  lengthBytes.writeUInt16BE(encryptedData.ciphertext.length, 0);
  const lengthMacBytes = Buffer.alloc(2);
  lengthMacBytes.writeUInt16BE(encryptedData.mac.length, 0);

  const secureChannelPayload = Buffer.concat([
    encryptedData.iv,
    lengthBytes,
    encryptedData.ciphertext,
    lengthMacBytes,
    encryptedData.mac,
  ]);

  const command: APDUCommand = {
    cla: CARD_CLA,
    ins: INS_PROCESS_SECURE_CHANNEL,
    p1: 0x00,
    p2: 0x00,
    data: secureChannelPayload,
    le: 0x00,
  };
  return transmitAPDU(command);
}
