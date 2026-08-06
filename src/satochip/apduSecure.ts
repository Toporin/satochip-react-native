import { APDUCommand, APDUResponse } from './types';
import { checkResponse } from './errors';
import { SecureChannel } from './SecureChannel';
import { requiresSecureChannel } from './commands/secureChannel';
import { processSecureChannel } from './commands/secureChannel';
import { buildAPDU, sendAPDU } from './apdu';

export { buildAPDU, parseAPDUResponse, sendAPDU } from './apdu';

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
