import { APDUResponse } from './types';
import { CardError } from '../core/errors';
export declare class SatochipError extends Error {
    constructor(message: string);
}
export declare class SatochipCardError extends CardError {
    constructor(statusWord: number, code: string, message: string, remainingAttempts?: number);
}
export declare function mapErrorCode(sw1: number, sw2: number): SatochipCardError;
export declare function checkResponseApdu(rapdu: APDUResponse): void;
export declare function checkResponse(sw1: number, sw2: number): void;
