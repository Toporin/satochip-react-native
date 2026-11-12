import { CardError, SW_OK } from '../core/errors';
import { mapErrorCode } from '../satochip/errors';
import {
  SW_INCORRECT_KEYSLOT_STATE,
  SW_INCORRECT_PROTOCOL_MEDIA,
  SW_INCORRECT_UNLOCK_CODE,
  SW_INCORRECT_UNLOCK_COUNTER,
  SW_UNKNOWN_PROTOCOL_MEDIA,
} from './constants';

export class SatodimeCardError extends CardError {
  constructor(statusWord: number, code: string, message: string) {
    super(statusWord, code, message);
    this.name = 'SatodimeCardError';
  }
}

/** Satodime-specific status words, plus shared ones with a Satodime meaning. */
const SATODIME_SW: Readonly<Record<number, [string, string]>> = {
  [SW_INCORRECT_UNLOCK_COUNTER]: ['SW_INCORRECT_UNLOCK_COUNTER', 'Incorrect unlock counter'],
  [SW_INCORRECT_UNLOCK_CODE]: ['SW_INCORRECT_UNLOCK_CODE', 'Incorrect unlock code: this device is not the owner of the card'],
  [SW_INCORRECT_KEYSLOT_STATE]: ['SW_INCORRECT_KEYSLOT_STATE', 'Operation not allowed in the current vault state'],
  [SW_INCORRECT_PROTOCOL_MEDIA]: ['SW_INCORRECT_PROTOCOL_MEDIA', 'Incorrect protocol media'],
  [SW_UNKNOWN_PROTOCOL_MEDIA]: ['SW_UNKNOWN_PROTOCOL_MEDIA', 'Unknown protocol media'],
  0x9C04: ['SW_SETUP_NOT_DONE', 'The card has no owner (setup not done)'],
  0x9C07: ['SW_SETUP_ALREADY_DONE', 'The card already has an owner (setup already done)'],
  0x9C10: ['SW_INCORRECT_P1', 'Incorrect vault index'],
  0x6A82: ['SW_FILE_NOT_FOUND', 'Satodime applet not found'],
};

export function mapSatodimeErrorCode(sw1: number, sw2: number): SatodimeCardError {
  const statusWord = (sw1 << 8) | sw2;
  const known = SATODIME_SW[statusWord];
  if (known) {
    return new SatodimeCardError(statusWord, known[0], known[1]);
  }
  // fall back to the codes shared with Satochip
  const shared = mapErrorCode(sw1, sw2);
  return new SatodimeCardError(statusWord, shared.code, shared.message);
}

export function checkSatodimeResponse(sw1: number, sw2: number): void {
  if (((sw1 << 8) | sw2) !== SW_OK) {
    throw mapSatodimeErrorCode(sw1, sw2);
  }
}
