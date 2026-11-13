/**
 * Satochip APDU helpers. The transport and secure-channel wrapping are
 * card-agnostic (src/core/apdu.ts); this module keeps the historical Satochip
 * API and error mapping (SatochipCardError).
 */
import { APDUCommand, APDUResponse } from './types';
import { checkResponse } from './errors';
import { SecureChannel } from '../core/SecureChannel';
import { requiresSecureChannel } from './commands/secureChannel';
import { buildAPDU, parseAPDUResponse, transmitAPDU, sendEncryptedAPDU } from '../core/apdu';

export { buildAPDU, parseAPDUResponse };

export async function sendAPDU(command: APDUCommand, check = true): Promise<APDUResponse> {
  const response = await transmitAPDU(command);
  if (check) {
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
  if (requiresSecureChannel(command.ins)) {
    if (!secureChannel) {
      throw new Error(`Command 0x${command.ins.toString(16)} requires secure channel but none provided`);
    }
  } else if (!secureChannel) {
    // Send as regular APDU
    return sendAPDU(command);
  }
  return sendEncryptedAPDU(command, secureChannel, checkResponse);
}
