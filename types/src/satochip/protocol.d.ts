import { BaseCard } from '../core/BaseCard';
import { SatochipStatus, ExtendedKey } from './types';
import { XType } from './constants';
import { FactoryResetResult } from '../core/commands/common';
import { ECPubkey } from './utils/ECKey';
export declare class SatochipCard extends BaseCard {
    protected readonly aid: Buffer;
    readonly deviceType: "Satochip";
    private pinVerified;
    private status;
    private lastBip32Path;
    private masterXfp;
    constructor();
    private resetPinState;
    /** Cached values are cleared on every applet SELECT. */
    protected clearCache(): void;
    getStatus(): Promise<SatochipStatus>;
    getCachedStatus(): Promise<SatochipStatus>;
    setup(pin: string, max_try?: number): Promise<void>;
    /**
     * Advance the factory-reset sequence by one card presentation.
     * The applet requires several separate presentations (remove the card in
     * between) and no other command may be sent to the card meanwhile.
     * WARNING: once complete, all keys and settings are permanently erased.
     */
    factoryReset(): Promise<FactoryResetResult>;
    verifyPIN(pinNumber: number, pin: string): Promise<void>;
    changePIN(pinNumber: number, oldPin: string, newPin: string): Promise<void>;
    unblockPIN(pinNumber: number, puk: string): Promise<void>;
    logoutAll(): Promise<void>;
    isPINVerified(pinNumber: number): boolean;
    private ensurePINVerified;
    withPINVerification<T>(operation: () => Promise<T>, pinNumber?: number): Promise<T>;
    getCardInfo(): Promise<{
        appletVersion: string;
        protocolVersion: string;
        setupDone: boolean;
        isSeeded: boolean;
        needs2FA: boolean;
        pinStates: {
            pin0Tries: number;
            pin1Tries: number;
        };
    }>;
    getPubkeyFromKeyslot(keynbr: number): Promise<ECPubkey>;
    /**
     * Import BIP32 seed from entropy (one-time setup)
     * Automatically establishes secure channel if needed
     */
    importSeed(seed: Buffer, options?: number): Promise<void>;
    /**
     * Factory reset: permanently delete all seeds and keys
     * WARNING: This operation cannot be undone!
     */
    resetSeed(pin: string): Promise<void>;
    /**
     * Get extended public key for a BIP32 derivation path
     * @param pathString - BIP32 path like "m/44'/0'/0'"
     */
    getExtendedKey(pathString: string): Promise<ExtendedKey>;
    getXpub(pathString: string, xtype?: XType, isMainnet?: boolean): Promise<string>;
    getMasterXfp(): Promise<string>;
    /**
     * Sign a message hash with a static or BIP32 derived key
     * @param keynbr - keyslot number (0..MAX_NUM_KEYS-1), or 0xFF for the BIP32 key
     *   at the path of the last getExtendedKey() call (master key by default)
     * @param msgHash - 32-byte hash to sign
     * @param hmac - optional 20-byte hmac (when 2FA is enabled, experimental)
     * @returns 65-byte compact signature (header byte + r + s)
     */
    signMessage(keynbr: number, msgHash: Buffer, hmac?: Buffer): Promise<Buffer>;
    /**
     * Sign a transaction hash with a BIP32 derived key
     * @param keynumber
     * @param txHash - 32-byte transaction hash
     * @param hmac - optional 20-byte hmac (when 2FA is enabled, experimental)
     */
    signTransactionHash(keynumber: number, txHash: Buffer, hmac?: Buffer): Promise<Buffer>;
    /**
     * Prepare a key for BIP340 Schnorr signing by applying the Taproot tweak.
     * Must be called before signSchnorrHash() for the same key.
     * @param keynbr - The key to use (0xFF for the last derived BIP32 key)
     * @param tweak - optional 32-byte tweak (BIP341 script tree hash); none by default
     * @param bypass - if true, skip the tweak (e.g. Nostr, which signs with the untweaked key)
     */
    taprootTweakPrivkey(keynbr: number, tweak?: Buffer | null, bypass?: boolean): Promise<Buffer>;
    /**
     * Sign a 32-byte hash with BIP340 Schnorr (call taprootTweakPrivkey() first).
     * @param keynbr - The key to use (0xFF for the last derived BIP32 key)
     * @param hash - 32-byte hash to sign
     * @param hmac - optional 20-byte hmac (when 2FA is enabled, experimental)
     * @returns 64-byte Schnorr signature
     */
    signSchnorrHash(keynbr: number, hash: Buffer, hmac?: Buffer): Promise<Buffer>;
    /**
     * Check if card has been seeded
     */
    isSeeded(): Promise<boolean>;
    /**
     * Get comprehensive card capabilities and state
     */
    getCapabilities(): Promise<{
        appletVersion: number;
        protocolVersion: number;
        isSetup: boolean;
        isSeeded: boolean;
        needsSecureChannel: boolean;
        needs2FA: boolean;
        pin0Tries: number;
        pin1Tries: number;
        nfcPolicy: number;
        schnorrPolicy: number;
        nostrPolicy: number;
        liquidPolicy: number;
        musig2Policy: number;
        secureChannelActive: boolean;
        pin0Verified: boolean;
        pin1Verified: boolean;
    }>;
}
