import NfcManager from 'react-native-nfc-manager';
import { APDUCommand, APDUResponse } from './types';
import { checkResponse } from './errors';
import { SecureChannel } from './SecureChannel';
import { requiresSecureChannel } from './commands/secureChannel';
import { processSecureChannel } from './commands/secureChannel';
import { console_log } from './utils/logging';

export function buildAPDU(command: APDUCommand): number[] {
  const apdu = [command.cla, command.ins, command.p1, command.p2];
  
  if (command.data && command.data.length > 0) {
    apdu.push(command.data.length);
    apdu.push(...Array.from(command.data));
  }
  
  if (command.le !== undefined) {
    apdu.push(command.le);
  }
  
  return apdu;
}

export function parseAPDUResponse(responseBytes: number[]): APDUResponse {
  if (responseBytes.length < 2) {
    throw new Error('Invalid APDU response: too short');
  }
  
  const sw1 = responseBytes[responseBytes.length - 2];
  const sw2 = responseBytes[responseBytes.length - 1];
  const data = Buffer.from(responseBytes.slice(0, responseBytes.length - 2));
  const statusWord = (sw1 << 8) | sw2;
  
  return { data, sw1, sw2, statusWord };
}

export async function sendAPDU(command: APDUCommand, check = true): Promise<APDUResponse> {
  const apduBytes = buildAPDU(command);
  const responseBytes = await NfcManager.isoDepHandler.transceive(apduBytes);
  const response = parseAPDUResponse(responseBytes);

  if (check){
    // Check for errors and throw if needed
    checkResponse(response.sw1, response.sw2);
  }

  return response;
}

/**
 * Enhanced APDU sender that can handle secure channel encryption automatically
 * This is the main function that should be used for secure commands
 */
export async function sendSecureAPDU(
  command: APDUCommand, 
  secureChannel: SecureChannel | null = null,
): Promise<APDUResponse> {
  // console_log(`In apduSecure sendSecureAPDU command: ${command}`);

  if (requiresSecureChannel(command.ins)){
    if (!secureChannel) {
      throw new Error(`Command 0x${command.ins.toString(16)} requires secure channel but none provided`);
    }
  } else {
    if (!secureChannel) {
      // Send as regular APDU
      return sendAPDU(command);
    }
  }

  // establish secure channel if needed
  if ( !secureChannel.isEstablished()) {
    await secureChannel.establishSecureChannel();
  }

  // Build the original APDU bytes for encryption
  const originalAPDU = buildAPDU(command);
  const apduData = Buffer.from(originalAPDU);
  
  // Encrypt the APDU using secure channel
  const encryptedData = secureChannel.encryptSecureChannel(apduData);
  // console_log(`In apduSecure sendSecureAPDU encryptedData: ${encryptedData}`);

  // Send via secure channel process command
  const encryptedResponse = await processSecureChannel(encryptedData);
  // console_log(`In apduSecure sendSecureAPDU encryptedResponse APDU: ${encryptedResponse}`);

  // Check for errors and throw if needed
  checkResponse(encryptedResponse.sw1, encryptedResponse.sw2);

  // Decrypt the response
  const data = Buffer.from(encryptedResponse.data);
  if (data.length == 0){
    return encryptedResponse;
  } else if (data.length < 18) { // 16 + 2
    throw new Error('Invalid encrypted response format');
  }

  const responseIV = data.slice(0, 16);
  const responseLength = data.readUInt16BE(16);
  const responseCiphertext = data.slice(18, 18 + responseLength);
  // console_log(`In apduSecure sendSecureAPDU responseIV: ${responseIV.toString('hex')}`);
  // console_log(`In apduSecure sendSecureAPDU responseLength: ${responseLength}`);
  // console_log(`In apduSecure sendSecureAPDU responseCiphertext: ${responseCiphertext.toString('hex')}`);

  // Decrypt the response data
  const decryptedResponse = secureChannel.decryptSecureChannel(responseIV, responseCiphertext);
  // console_log(`In apduSecure sendSecureAPDU decryptedResponse: ${decryptedResponse.toString('hex')}`);

  const response = new APDUResponse(decryptedResponse, encryptedResponse.sw1, encryptedResponse.sw2, encryptedResponse.statusWord);

  return response;
}
