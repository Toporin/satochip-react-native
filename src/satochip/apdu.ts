import NfcManager from 'react-native-nfc-manager';

import { checkResponse } from './errors';
import { APDUCommand, APDUResponse } from './types';

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

export async function sendAPDU(
  command: APDUCommand,
  check = true,
): Promise<APDUResponse> {
  const apduBytes = buildAPDU(command);
  const responseBytes = await NfcManager.isoDepHandler.transceive(apduBytes);
  const response = parseAPDUResponse(responseBytes);

  if (check) {
    checkResponse(response.sw1, response.sw2);
  }

  return response;
}
