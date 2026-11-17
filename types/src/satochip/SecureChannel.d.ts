/**
 * Satochip secure channel: the card-agnostic implementation lives in
 * src/core/SecureChannel.ts. This subclass keeps the historical Satochip
 * behaviour (SatochipCardError mapping) and import path.
 */
import { SecureChannel as CoreSecureChannel, UninitializedSecureChannelError } from '../core/SecureChannel';
export { UninitializedSecureChannelError };
export declare class SecureChannel extends CoreSecureChannel {
    constructor();
}
