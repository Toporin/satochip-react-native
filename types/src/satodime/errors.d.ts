import { CardError } from '../core/errors';
export declare class SatodimeCardError extends CardError {
    constructor(statusWord: number, code: string, message: string);
}
export declare function mapSatodimeErrorCode(sw1: number, sw2: number): SatodimeCardError;
export declare function checkSatodimeResponse(sw1: number, sw2: number): void;
