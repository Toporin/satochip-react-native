/**
 * Satodime card ("bearer" card with up to 3 key slots / vaults).
 *
 * - No PIN. State-changing commands, and hash signing from protocol 0.2, need
 *   an unlock code derived from the owner's unlock secret (see unlock.ts).
 * - Every command except GET_STATUS is sent through the secure channel.
 * - The unlock secret is only kept in memory (setUnlockSecret); persisting it
 *   securely is the caller's responsibility.
 */
import { BaseCard } from '../core/BaseCard';
import { KeyslotState } from './constants';
import { KeyslotMetadata, KeyslotStatus, SatodimeCardStatus, SatodimeOwnership, SatodimePrivkey, SatodimeStatus } from './types';
export declare class SatodimeCard extends BaseCard {
    protected readonly aid: Buffer;
    readonly deviceType: "Satodime";
    protected readonly strictSelect = true;
    private cardStatus;
    private authentikeyBytes;
    private unlockSecret;
    constructor();
    protected clearCache(): void;
    /** GET_STATUS (0x3C): versions and ownership (setupDone). */
    getStatus(): Promise<SatodimeCardStatus>;
    /**
     * True if the card supports on-card hash signing (0x5B) and unlock-code
     * checking (0x54): protocol version >= 0.2 ("v0.2-0.1" = protocol 0.2, applet 0.1).
     */
    supportsHashSigning(status?: SatodimeCardStatus | null): boolean;
    /** GET_SATODIME_STATUS (0x50). */
    getSatodimeStatus(): Promise<SatodimeStatus>;
    /** GET_SATODIME_KEYSLOT_STATUS (0x51). */
    getKeyslotStatus(slot: number): Promise<KeyslotStatus>;
    /** Card authentikey as a 65-byte uncompressed public key (cached per SELECT). */
    getAuthentikeyBytes(): Promise<Buffer>;
    /**
     * GET_SATODIME_PUBKEY (0x55): 65-byte uncompressed public key of a sealed or
     * unsealed vault. The authentikey signature over the key is verified.
     */
    getPubkey(slot: number): Promise<Buffer>;
    /** Set (or clear) the unlock secret used for commands requiring an unlock code. */
    setUnlockSecret(secret: Buffer | null): void;
    hasUnlockSecret(): boolean;
    /**
     * SETUP (0x2A): take ownership of a card without owner (setupDone=false).
     * Returns the ownership data, which must be stored securely by the caller,
     * and keeps the secret in memory for this card instance.
     */
    claimOwnership(): Promise<SatodimeOwnership>;
    /**
     * Send a command carrying an unlock code. The unlock counter is read from
     * the card first (0x50), so a stale local counter can never desynchronize.
     */
    private sendUnlocked;
    private requireProtocol02;
    /**
     * CHECK_SATODIME_UNLOCK_CODE (0x54, protocol >= 0.2): true if the current
     * unlock secret is the owner's. Increments the card counter on success.
     */
    checkUnlockCode(): Promise<boolean>;
    /** INITIATE_SATODIME_TRANSFER (0x5A): release ownership. */
    transferOwnership(): Promise<void>;
    /**
     * SIGN_SATODIME_TRANSACTION_HASH (0x5B, protocol >= 0.2): sign a 32-byte hash
     * with an UNSEALED vault. Needs the unlock secret. Returns the DER signature
     * as produced by the card (s is NOT normalized; no recovery id).
     */
    signTransactionHash(slot: number, hash: Buffer): Promise<Buffer>;
    /** SEAL (0x57): uninitialized -> sealed. Returns the new vault public key. */
    seal(slot: number, entropy: Buffer): Promise<Buffer>;
    /** UNSEAL (0x58): sealed -> unsealed. Returns the private key. */
    unseal(slot: number): Promise<SatodimePrivkey>;
    /** GET_SATODIME_PRIVKEY (0x56): private key of an unsealed vault. */
    getPrivkey(slot: number): Promise<SatodimePrivkey>;
    /** RESET (0x59): unsealed -> uninitialized (the key is erased). */
    reset(slot: number): Promise<void>;
    /** SET_SATODIME_KEYSLOT_STATUS (0x52, P2=0): asset, SLIP-44, contract, token id. */
    setKeyslotMetadata(slot: number, meta: KeyslotMetadata): Promise<void>;
    /** SET_SATODIME_KEYSLOT_STATUS (0x52, P2=1): 66-byte free data. */
    setKeyslotData(slot: number, data: Buffer): Promise<void>;
    /** Convenience: states of all vaults. */
    getKeyslotStates(): Promise<KeyslotState[]>;
}
