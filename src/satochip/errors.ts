import {
  SW_OK,
  SW_WRONG_LENGTH,
  SW_SECURITY_NOT_SATISFIED,
  SW_CONDITIONS_NOT_SATISFIED,
  SW_FILE_NOT_FOUND,
  SW_INS_NOT_SUPPORTED,
  SW_NO_MEMORY_LEFT,
  SW_AUTH_FAILED,
  SW_OPERATION_NOT_ALLOWED,
  SW_SETUP_NOT_DONE,
  SW_UNSUPPORTED_FEATURE,
  SW_UNAUTHORIZED,
  SW_SETUP_ALREADY_DONE,
  SW_INCORRECT_ALG,
  SW_SIGNATURE_INVALID,
  SW_IDENTITY_BLOCKED,
  SW_INVALID_PARAMETER,
  SW_INCORRECT_P1,
  SW_INCORRECT_P2,
  SW_INCORRECT_INITIALIZATION,
  SW_BIP32_UNINITIALIZED_SEED,
  SW_INCORRECT_TXHASH,
  SW_BIP32_INITIALIZED_SEED,
  SW_2FA_INITIALIZED_KEY,
  SW_2FA_UNINITIALIZED_KEY,
  SW_PIN_FAILED_BASE,
} from './constants';
import { APDUResponse } from './types';

export class SatochipError extends Error {
  constructor(
    message: string,
  ) {
    super(message);
    this.name = 'SatochipErrorNew';
  }
}

export class SatochipCardError extends Error {
  constructor(
    public statusWord: number,
    public code: string,
    message: string,
    public remainingAttempts?: number
  ) {
    super(message);
    this.name = 'SatochipError';
  }
}

export function mapErrorCode(sw1: number, sw2: number): SatochipCardError {
  const statusWord = (sw1 << 8) | sw2;
  
  // Handle PIN failure codes specially
  if ((statusWord & 0xFFF0) === SW_PIN_FAILED_BASE) {
    const remainingAttempts = statusWord & 0x0F;
    return new SatochipCardError(
      statusWord,
      'SW_PIN_FAILED',
      `Wrong PIN. ${remainingAttempts} attempts remaining.`,
      remainingAttempts
    );
  }
  
  switch (statusWord) {
    case SW_OK:
      throw new Error('Should not map success status to error');
      
    case SW_WRONG_LENGTH:
      return new SatochipCardError(statusWord, 'SW_WRONG_LENGTH', 'Wrong length in Lc or Le');
      
    case SW_SECURITY_NOT_SATISFIED:
      return new SatochipCardError(statusWord, 'SW_SECURITY_NOT_SATISFIED', 'Security condition not satisfied');
      
    case SW_CONDITIONS_NOT_SATISFIED:
      return new SatochipCardError(statusWord, 'SW_CONDITIONS_NOT_SATISFIED', 'Conditions of use not satisfied');
      
    case SW_FILE_NOT_FOUND:
      return new SatochipCardError(statusWord, 'SW_FILE_NOT_FOUND', 'File/application not found');
      
    case SW_INS_NOT_SUPPORTED:
      return new SatochipCardError(statusWord, 'SW_INS_NOT_SUPPORTED', 'Instruction not supported');
      
    case SW_NO_MEMORY_LEFT:
      return new SatochipCardError(statusWord, 'SW_NO_MEMORY_LEFT', 'Insufficient memory');
      
    case SW_AUTH_FAILED:
      return new SatochipCardError(statusWord, 'SW_AUTH_FAILED', 'Authentication failed');
      
    case SW_OPERATION_NOT_ALLOWED:
      return new SatochipCardError(statusWord, 'SW_OPERATION_NOT_ALLOWED', 'Operation not allowed');
      
    case SW_SETUP_NOT_DONE:
      return new SatochipCardError(statusWord, 'SW_SETUP_NOT_DONE', 'Card setup required');
      
    case SW_UNSUPPORTED_FEATURE:
      return new SatochipCardError(statusWord, 'SW_UNSUPPORTED_FEATURE', 'Feature not supported');
      
    case SW_UNAUTHORIZED:
      return new SatochipCardError(statusWord, 'SW_UNAUTHORIZED', 'PIN verification required');
      
    case SW_SETUP_ALREADY_DONE:
      return new SatochipCardError(statusWord, 'SW_SETUP_ALREADY_DONE', 'Card already set up');
      
    case SW_INCORRECT_ALG:
      return new SatochipCardError(statusWord, 'SW_INCORRECT_ALG', 'Wrong algorithm specified');
      
    case SW_SIGNATURE_INVALID:
      return new SatochipCardError(statusWord, 'SW_SIGNATURE_INVALID', 'Invalid signature');
      
    case SW_IDENTITY_BLOCKED:
      return new SatochipCardError(statusWord, 'SW_IDENTITY_BLOCKED', 'PIN/PUK blocked after max attempts');
      
    case SW_INVALID_PARAMETER:
      return new SatochipCardError(statusWord, 'SW_INVALID_PARAMETER', 'Invalid parameter');
      
    case SW_INCORRECT_P1:
      return new SatochipCardError(statusWord, 'SW_INCORRECT_P1', 'Invalid P1 parameter');
      
    case SW_INCORRECT_P2:
      return new SatochipCardError(statusWord, 'SW_INCORRECT_P2', 'Invalid P2 parameter');
      
    case SW_INCORRECT_INITIALIZATION:
      return new SatochipCardError(statusWord, 'SW_INCORRECT_INITIALIZATION', 'Wrong initialization');
      
    case SW_BIP32_UNINITIALIZED_SEED:
      return new SatochipCardError(statusWord, 'SW_BIP32_UNINITIALIZED_SEED', 'BIP32 seed not initialized');
      
    case SW_INCORRECT_TXHASH:
      return new SatochipCardError(statusWord, 'SW_INCORRECT_TXHASH', 'Wrong transaction hash');
      
    case SW_BIP32_INITIALIZED_SEED:
      return new SatochipCardError(statusWord, 'SW_BIP32_INITIALIZED_SEED', 'BIP32 seed already exists');
      
    case SW_2FA_INITIALIZED_KEY:
      return new SatochipCardError(statusWord, 'SW_2FA_INITIALIZED_KEY', '2FA already set up');
      
    case SW_2FA_UNINITIALIZED_KEY:
      return new SatochipCardError(statusWord, 'SW_2FA_UNINITIALIZED_KEY', '2FA not initialized');
      
    default:
      return new SatochipCardError(
        statusWord,
        'SW_UNKNOWN',
        `Unknown status word: 0x${statusWord.toString(16).toUpperCase()}`
      );
  }
}


export function checkResponseApdu(rapdu: APDUResponse): void {
  const statusWord = (rapdu.sw1 << 8) | rapdu.sw2;
  if (statusWord !== SW_OK) {
    throw mapErrorCode(rapdu.sw1, rapdu.sw2);
  }
}

export function checkResponse(sw1: number, sw2: number): void {
  const statusWord = (sw1 << 8) | sw2;
  if (statusWord !== SW_OK) {
    throw mapErrorCode(sw1, sw2);
  }
}