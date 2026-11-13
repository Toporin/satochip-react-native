/**
 * Satochip secure channel: the card-agnostic implementation lives in
 * src/core/SecureChannel.ts. This subclass keeps the historical Satochip
 * behaviour (SatochipCardError mapping) and import path.
 */
import { SecureChannel as CoreSecureChannel, UninitializedSecureChannelError } from '../core/SecureChannel';
import { checkResponse, SatochipCardError } from './errors';

export { UninitializedSecureChannelError };

export class SecureChannel extends CoreSecureChannel {
  constructor() {
    super({
      check: checkResponse,
      makeInitError: (cause: Error) =>
        new SatochipCardError(
          0x9C13,
          'SW_INCORRECT_INITIALIZATION',
          `Failed to establish secure channel: ${cause.message}`
        ),
    });
  }
}
