import { ResponseChecker } from './errors';
import { ECPubkey } from '../satochip/utils/ECKey';
export interface SecureChannelOptions {
    /** Status-word checker used for INIT_SECURE_CHANNEL (card-specific error mapping). */
    check?: ResponseChecker;
    /** Builds the error thrown when the secure channel cannot be established. */
    makeInitError?: (cause: Error) => Error;
}
export declare class UninitializedSecureChannelError extends Error {
    constructor(message: string);
}
export declare class SecureChannel {
    private initializedSecureChannel;
    private scPubkey;
    private scPeerPubkey;
    private scIVcounter;
    private sharedKey;
    private derivedKey;
    private macKey;
    private ec;
    private keyPair;
    private authentikeyCandidates;
    private readonly check;
    private readonly makeInitError;
    constructor(options?: SecureChannelOptions);
    getPublicKey(): Buffer;
    isEstablished(): boolean;
    reset(): void;
    checkAuthentikeyCandidates(keys: ECPubkey[]): void;
    /**
     * Establish secure channel with the card
     * This should be called before any operations that require encryption
     */
    establishSecureChannel(): Promise<void>;
    initiateSecureChannel(peerPubkeyBytes: Buffer): void;
    encryptSecureChannel(dataBytes: Buffer): {
        iv: Buffer;
        ciphertext: Buffer;
        mac: Buffer;
    };
    decryptSecureChannel(iv: Buffer, ciphertext: Buffer): Buffer;
}
