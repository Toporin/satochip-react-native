import { APDUCommand, APDUResponse } from '../satochip/types';
import { ECPubkey } from '../satochip/utils/ECKey';
import { CertificateValidationResult, DeviceType } from '../satochip/utils/certificateValidator';
import { ResponseChecker } from './errors';
import { SecureChannel } from './SecureChannel';
import { ChallengeResponseResult } from './commands/common';
export declare abstract class BaseCard {
    /** Applet identifier used for ISO SELECT. */
    protected abstract readonly aid: Buffer;
    /** Device type used to pick the PKI sub-CA during authenticity checks. */
    abstract readonly deviceType: DeviceType;
    /** If true, selectApplet() throws when the applet is not found on the card. */
    protected readonly strictSelect: boolean;
    protected secureChannel: SecureChannel;
    protected readonly check: ResponseChecker;
    protected constructor(secureChannel: SecureChannel, check: ResponseChecker);
    startNfcSession(): Promise<void>;
    endNfcSession(): Promise<void>;
    nfcWrapper<T>(callback: () => Promise<T>): Promise<T>;
    protected handleError(error: unknown): never;
    /** Clear values cached for the currently selected card. Called on every SELECT. */
    protected clearCache(): void;
    selectApplet(): Promise<void>;
    /** Send a plain APDU, mapping errors with this card's table. */
    protected sendPlain(command: APDUCommand): Promise<APDUResponse>;
    /** Send an APDU through the secure channel, mapping errors with this card's table. */
    protected sendSecure: (command: APDUCommand) => Promise<APDUResponse>;
    /** Card authentikey (card identity key). */
    getAuthentikey(): Promise<ECPubkey>;
    getLabel(): Promise<string>;
    setLabel(label: string): Promise<void>;
    exportPersoCertificate(): Promise<string>;
    cardChallengeResponsePki(): Promise<ChallengeResponseResult>;
    verifyCertificateChain(): Promise<CertificateValidationResult>;
}
