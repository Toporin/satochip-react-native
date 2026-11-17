/**
 * Error types shared by every card applet of the Satochip family
 * (Satochip, Satodime, Seedkeeper, Satocash...).
 */
/** Error raised when a card returns a status word other than 0x9000. */
export declare class CardError extends Error {
    statusWord: number;
    code: string;
    remainingAttempts?: number;
    constructor(statusWord: number, code: string, message: string, remainingAttempts?: number);
}
/** Checks a status word and throws a card-specific error if it is not 0x9000. */
export type ResponseChecker = (sw1: number, sw2: number) => void;
export declare const SW_OK = 36864;
