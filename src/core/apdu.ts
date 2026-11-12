/**
 * Card-agnostic APDU transport and secure-channel wrapping.
 *
 * Status-word checking is injected (ResponseChecker) so that each card type
 * maps its own error codes.
 */
import NfcManager from 'react-native-nfc-manager';
import { APDUCommand, APDUResponse } from '../satochip/types';
import { ResponseChecker } from './errors';
import type { SecureChannel } from './SecureChannel';
import { processSecureChannel } from './commands/secureChannel';

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

  return new APDUResponse(data, sw1, sw2, statusWord);
}

/** Send a plain APDU and return the raw response (status word not checked). */
export async function transmitAPDU(command: APDUCommand): Promise<APDUResponse> {
  const apduBytes = buildAPDU(command);
  const responseBytes = await NfcManager.isoDepHandler.transceive(apduBytes);
  return parseAPDUResponse(responseBytes);
}

/** Send a plain APDU and check its status word with `check`. */
export async function sendPlainAPDU(
  command: APDUCommand,
  check: ResponseChecker,
): Promise<APDUResponse> {
  const response = await transmitAPDU(command);
  check(response.sw1, response.sw2);
  return response;
}

/**
 * Send an APDU wrapped in the secure channel (establishing it if needed),
 * check the status word with `check` and return the decrypted response.
 */
export async function sendEncryptedAPDU(
  command: APDUCommand,
  secureChannel: SecureChannel,
  check: ResponseChecker,
): Promise<APDUResponse> {
  if (!secureChannel.isEstablished()) {
    await secureChannel.establishSecureChannel();
  }

  const apduData = Buffer.from(buildAPDU(command));
  const encryptedData = secureChannel.encryptSecureChannel(apduData);
  const encryptedResponse = await processSecureChannel(encryptedData);

  check(encryptedResponse.sw1, encryptedResponse.sw2);

  const data = Buffer.from(encryptedResponse.data);
  if (data.length == 0) {
    return encryptedResponse;
  } else if (data.length < 18) { // 16 + 2
    throw new Error('Invalid encrypted response format');
  }

  const responseIV = data.slice(0, 16);
  const responseLength = data.readUInt16BE(16);
  const responseCiphertext = data.slice(18, 18 + responseLength);
  const decryptedResponse = secureChannel.decryptSecureChannel(responseIV, responseCiphertext);

  return new APDUResponse(
    decryptedResponse,
    encryptedResponse.sw1,
    encryptedResponse.sw2,
    encryptedResponse.statusWord,
  );
}
