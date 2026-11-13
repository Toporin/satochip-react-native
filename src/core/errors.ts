/**
 * Error types shared by every card applet of the Satochip family
 * (Satochip, Satodime, Seedkeeper, Satocash...).
 */

/** Error raised when a card returns a status word other than 0x9000. */
export class CardError extends Error {
  constructor(
    public statusWord: number,
    public code: string,
    message: string,
    public remainingAttempts?: number
  ) {
    super(message);
    this.name = 'CardError';
  }
}

/** Checks a status word and throws a card-specific error if it is not 0x9000. */
export type ResponseChecker = (sw1: number, sw2: number) => void;

export const SW_OK = 0x9000;
