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
import { SecureChannel } from '../core/SecureChannel';
import { APDUCommand, APDUResponse } from '../satochip/types';
import {
  KeyslotState,
  MIN_PROTOCOL_VERSION_HASH_SIGNING,
  SATODIME_AID,
  SW_INCORRECT_UNLOCK_CODE,
  SW_INCORRECT_UNLOCK_COUNTER,
} from './constants';
import * as codec from './codec';
import { SatodimeCardError, checkSatodimeResponse } from './errors';
import {
  KeyslotMetadata,
  KeyslotStatus,
  SatodimeCardStatus,
  SatodimeOwnership,
  SatodimePrivkey,
  SatodimeStatus,
} from './types';
import { normalizeUnlockSecret } from './unlock';

export class SatodimeCard extends BaseCard {
  protected readonly aid = SATODIME_AID;
  readonly deviceType = 'Satodime' as const;
  protected readonly strictSelect = true;

  private cardStatus: SatodimeCardStatus | null = null;
  private authentikeyBytes: Buffer | null = null;
  private unlockSecret: Buffer | null = null;

  constructor() {
    super(
      new SecureChannel({
        check: checkSatodimeResponse,
        makeInitError: (cause: Error) =>
          new SatodimeCardError(0x9C13, 'SW_INCORRECT_INITIALIZATION', `Failed to establish secure channel: ${cause.message}`),
      }),
      checkSatodimeResponse,
    );
  }

  protected clearCache(): void {
    this.cardStatus = null;
    this.authentikeyBytes = null;
  }

  // ========================================
  // Status & version
  // ========================================

  /** GET_STATUS (0x3C): versions and ownership (setupDone). */
  async getStatus(): Promise<SatodimeCardStatus> {
    const rapdu = await this.sendPlain(codec.encodeGetStatus());
    this.cardStatus = codec.decodeCardStatus(rapdu.data);
    return this.cardStatus;
  }

  /**
   * True if the card supports on-card hash signing (0x5B) and unlock-code
   * checking (0x54): protocol version >= 0.2 ("v0.2-0.1" = protocol 0.2, applet 0.1).
   */
  supportsHashSigning(status: SatodimeCardStatus | null = this.cardStatus): boolean {
    if (!status) {
      throw new Error('Card status unknown: call getStatus() first');
    }
    return status.version.protocolVersion >= MIN_PROTOCOL_VERSION_HASH_SIGNING;
  }

  /** GET_SATODIME_STATUS (0x50). */
  async getSatodimeStatus(): Promise<SatodimeStatus> {
    const rapdu = await this.sendSecure(codec.encodeGetSatodimeStatus());
    return codec.decodeSatodimeStatus(rapdu.data);
  }

  /** GET_SATODIME_KEYSLOT_STATUS (0x51). */
  async getKeyslotStatus(slot: number): Promise<KeyslotStatus> {
    const rapdu = await this.sendSecure(codec.encodeGetKeyslotStatus(slot));
    return codec.decodeKeyslotStatus(rapdu.data);
  }

  /** Card authentikey as a 65-byte uncompressed public key (cached per SELECT). */
  async getAuthentikeyBytes(): Promise<Buffer> {
    if (!this.authentikeyBytes) {
      const authentikey = await this.getAuthentikey();
      this.authentikeyBytes = authentikey.getPublicKeyBytes(false);
    }
    return this.authentikeyBytes;
  }

  /**
   * GET_SATODIME_PUBKEY (0x55): 65-byte uncompressed public key of a sealed or
   * unsealed vault. The authentikey signature over the key is verified.
   */
  async getPubkey(slot: number): Promise<Buffer> {
    const rapdu = await this.sendSecure(codec.encodeGetPubkey(slot));
    const resp = codec.decodePubkeyResponse(rapdu.data);
    const authentikey = await this.getAuthentikeyBytes();
    if (!codec.verifyAuthentikeySignature(resp.signedData, resp.signature, authentikey)) {
      throw new Error(`Vault ${slot}: public key signature by the card authentikey is invalid`);
    }
    return resp.pubkey;
  }

  // ========================================
  // Ownership
  // ========================================

  /** Set (or clear) the unlock secret used for commands requiring an unlock code. */
  setUnlockSecret(secret: Buffer | null): void {
    this.unlockSecret = secret ? normalizeUnlockSecret(secret) : null;
  }

  hasUnlockSecret(): boolean {
    return this.unlockSecret !== null;
  }

  /**
   * SETUP (0x2A): take ownership of a card without owner (setupDone=false).
   * Returns the ownership data, which must be stored securely by the caller,
   * and keeps the secret in memory for this card instance.
   */
  async claimOwnership(): Promise<SatodimeOwnership> {
    const rapdu = await this.sendSecure(codec.encodeSetup());
    const ownership = codec.decodeSetupResponse(rapdu.data);
    this.unlockSecret = ownership.unlockSecret;
    this.cardStatus = null;
    return ownership;
  }

  /**
   * Send a command carrying an unlock code. The unlock counter is read from
   * the card first (0x50), so a stale local counter can never desynchronize.
   */
  private async sendUnlocked(build: (counter: Buffer, secret: Buffer) => APDUCommand): Promise<APDUResponse> {
    if (!this.unlockSecret) {
      throw new SatodimeCardError(SW_INCORRECT_UNLOCK_CODE, 'SW_UNLOCK_SECRET_MISSING', 'Unlock secret required for this operation');
    }
    const status = await this.getSatodimeStatus();
    return this.sendSecure(build(status.unlockCounter, this.unlockSecret));
  }

  private async requireProtocol02(feature: string): Promise<void> {
    const status = this.cardStatus ?? (await this.getStatus());
    if (!this.supportsHashSigning(status)) {
      throw new SatodimeCardError(0x9C05, 'SW_UNSUPPORTED_FEATURE', `${feature} requires Satodime protocol v0.2 or later`);
    }
  }

  /**
   * CHECK_SATODIME_UNLOCK_CODE (0x54, protocol >= 0.2): true if the current
   * unlock secret is the owner's. Increments the card counter on success.
   */
  async checkUnlockCode(): Promise<boolean> {
    await this.requireProtocol02('Unlock code check');
    try {
      await this.sendUnlocked((counter, secret) => codec.encodeCheckUnlockCode(counter, secret));
      return true;
    } catch (error) {
      if (
        error instanceof SatodimeCardError &&
        (error.statusWord === SW_INCORRECT_UNLOCK_CODE || error.statusWord === SW_INCORRECT_UNLOCK_COUNTER)
      ) {
        return false;
      }
      throw error;
    }
  }

  /** INITIATE_SATODIME_TRANSFER (0x5A): release ownership. */
  async transferOwnership(): Promise<void> {
    await this.sendUnlocked((counter, secret) => codec.encodeTransfer(counter, secret));
    this.unlockSecret = null;
    this.cardStatus = null;
  }

  // ========================================
  // Signing
  // ========================================

  /**
   * SIGN_SATODIME_TRANSACTION_HASH (0x5B, protocol >= 0.2): sign a 32-byte hash
   * with an UNSEALED vault. Needs the unlock secret. Returns the DER signature
   * as produced by the card (s is NOT normalized; no recovery id).
   */
  async signTransactionHash(slot: number, hash: Buffer): Promise<Buffer> {
    await this.requireProtocol02('Hash signing');
    const rapdu = await this.sendUnlocked((counter, secret) =>
      codec.encodeSignTransactionHash(slot, hash, counter, secret));
    return rapdu.data;
  }

  // ========================================
  // Vault life cycle (state-changing, need the unlock secret)
  // ========================================

  /** SEAL (0x57): uninitialized -> sealed. Returns the new vault public key. */
  async seal(slot: number, entropy: Buffer): Promise<Buffer> {
    const rapdu = await this.sendUnlocked((counter, secret) => codec.encodeSeal(slot, counter, secret, entropy));
    const resp = codec.decodePubkeyResponse(rapdu.data);
    const authentikey = await this.getAuthentikeyBytes();
    if (!codec.verifyAuthentikeySignature(resp.signedData, resp.signature, authentikey)) {
      throw new Error(`Vault ${slot}: public key signature by the card authentikey is invalid`);
    }
    return resp.pubkey;
  }

  /** UNSEAL (0x58): sealed -> unsealed. Returns the private key. */
  async unseal(slot: number): Promise<SatodimePrivkey> {
    const rapdu = await this.sendUnlocked((counter, secret) => codec.encodeUnseal(slot, counter, secret));
    return codec.decodePrivkeyResponse(rapdu.data);
  }

  /** GET_SATODIME_PRIVKEY (0x56): private key of an unsealed vault. */
  async getPrivkey(slot: number): Promise<SatodimePrivkey> {
    const rapdu = await this.sendUnlocked((counter, secret) => codec.encodeGetPrivkey(slot, counter, secret));
    return codec.decodePrivkeyResponse(rapdu.data);
  }

  /** RESET (0x59): unsealed -> uninitialized (the key is erased). */
  async reset(slot: number): Promise<void> {
    await this.sendUnlocked((counter, secret) => codec.encodeReset(slot, counter, secret));
  }

  /** SET_SATODIME_KEYSLOT_STATUS (0x52, P2=0): asset, SLIP-44, contract, token id. */
  async setKeyslotMetadata(slot: number, meta: KeyslotMetadata): Promise<void> {
    await this.sendUnlocked((counter, secret) => codec.encodeSetKeyslotMetadata(slot, counter, secret, meta));
  }

  /** SET_SATODIME_KEYSLOT_STATUS (0x52, P2=1): 66-byte free data. */
  async setKeyslotData(slot: number, data: Buffer): Promise<void> {
    await this.sendUnlocked((counter, secret) => codec.encodeSetKeyslotData(slot, counter, secret, data));
  }

  /** Convenience: states of all vaults. */
  async getKeyslotStates(): Promise<KeyslotState[]> {
    return (await this.getSatodimeStatus()).keyslotStates;
  }
}
