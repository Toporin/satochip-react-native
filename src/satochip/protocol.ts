import { Platform } from 'react-native';
import { 
  startConnection, 
  closeConnection, 
  isNfcSupported 
} from '../nfc';

import { SatochipStatus, ExtendedKey } from './types';
import { SatochipCardError, SatochipError } from './errors';
import { SecureChannel } from './SecureChannel';

// Import command functions
import {
  selectApplet,
  getStatus,
  setup, getAuthentikey, cardGetLabel, cardSetLabel
} from './commands/cardManagement';
import { 
  verifyPIN, 
  changePIN, 
  unblockPIN,
  logoutAll 
} from './commands/pinManagement';
import {
  importSeed,
  resetSeed,
  getExtendedKey, cardBip32GetXpub, cardBip32GetMasterXFP
} from './commands/bip32';
import {
  signTransactionHash,
} from './commands/signature'
import {
  getPubkeyFromKeyslot,
} from './commands/keyslot'
import {
  ChallengeResponseResult, exportPersoCertificate, cardChallengeResponsePki,
} from './commands/authenticity';

import { MAX_NUM_KEYS, XType } from './constants';

import { ECPubkey } from './utils/ECKey';
import { CardDataParser } from './parser';
import { CertificateValidationResult, CertificateValidator } from './utils/certificateValidator';
import { console_log } from './utils/logging';

export class SatochipCard {
  private pinVerified: Map<number, boolean> = new Map();
  private status: SatochipStatus | null = null;
  private secureChannel: SecureChannel = new SecureChannel();
  private lastBip32Path = 'm/';

  constructor() {
    this.pinVerified.set(0, false);
    this.pinVerified.set(1, false);
  }

  // NFC session management
  async startNfcSession(): Promise<void> {
    try {
      await startConnection();
      await this.selectApplet();
    } catch (error) {
      // Handle Android-specific error for already active session
      if (
        error.toString() === 'Error: You can only issue one request at a time'
      ) {
        return;
      } else {
        throw error;
      }
    }
  }

  async endNfcSession(): Promise<void> {
    await closeConnection();
  }

  // NFC wrapper for operations
  async nfcWrapper<T>(callback: () => Promise<T>): Promise<T> {
    const supported = await isNfcSupported();

    if (!supported) {
      throw new Error("Sorry, this device doesn't support NFC");
    }

    return Platform.select({
      android: async () => {
        try {
          await this.startNfcSession();
          const result = await callback();
          return result;
        } catch (error) {
          this.handleError(error);
        }
      },
      ios: async () => {
        try {
          await startConnection();
          await this.selectApplet();
          const result = await callback();
          return result;
        } catch (error) {
          this.handleError(error);
        }
      },
    })();
  }

  private handleError(error: any): never {
    if (error.toString() === 'Error: Initialisation failed') {
      throw new Error('Please hold the card more stably or longer');
    }
    throw error;
  }

  // ========================================
  // Core card management operations
  // ========================================


  async selectApplet(): Promise<void> {

    const rapdu = await selectApplet();
    if (rapdu.statusWord === 0x9000){
      console_log('cardManagement selectApplet applet selected!');
      this.secureChannel.reset()
    }
  }

  async getStatus(): Promise<SatochipStatus> {
    this.status = await getStatus();
    return this.status;
  }

  /**
   * Get the card master public key (authentikey)
   */
  async getAuthentikey(): Promise<ECPubkey> {
    console_log(`In protocol getAuthentikey`);
    return await getAuthentikey(this.secureChannel); // todo: return buffer instead of ECPubkey?
  }

  async getCachedStatus(): Promise<SatochipStatus> {
    if (this.status==null){
      this.status = await getStatus();
    }
    return this.status;
  }

  async setup(pin: string, max_try= 5): Promise<void> {
    await setup(this.secureChannel, pin, max_try);
    // Clear cached status after setup
    this.status = null;
  }

  async getLabel(): Promise<string> {
    const label = await cardGetLabel(this.secureChannel);
    return label;
  }

  async setLabel(label: string): Promise<void> {
    await cardSetLabel(this.secureChannel, label);
  }


  // ========================================
  // PIN management operations
  // ========================================

  async verifyPIN(pinNumber: number, pin: string): Promise<void> {
    try {
      await verifyPIN(this.secureChannel, pinNumber, pin);
      this.pinVerified.set(pinNumber, true);
    } catch (error) {
      this.pinVerified.set(pinNumber, false);
      throw error;
    }
  }

  async changePIN(
    pinNumber: number,
    oldPin: string,
    newPin: string
  ): Promise<void> {
    console_log(`In protocol changePIN ${oldPin} to ${newPin}`);
    await changePIN(this.secureChannel, pinNumber, oldPin, newPin);
  }

  async unblockPIN(pinNumber: number, puk: string): Promise<void> {
    await unblockPIN(this.secureChannel, pinNumber, puk);
    this.pinVerified.set(pinNumber, false); // PIN is reset, needs new verification
  }

  async logoutAll(): Promise<void> {
    await logoutAll(this.secureChannel);
    // Clear all PIN verification states
    this.pinVerified.clear();
    this.pinVerified.set(0, false);
    this.pinVerified.set(1, false);
  }

  // Helper methods
  isPINVerified(pinNumber: number): boolean {
    return this.pinVerified.get(pinNumber) || false;
  }

  // Utility method to ensure PIN is verified TODO refactor
  private ensurePINVerified(pinNumber = 0): void {
    if (!this.isPINVerified(pinNumber)) {
      throw new SatochipCardError(
        0x9C06,
        'SW_UNAUTHORIZED',
        `PIN ${pinNumber} verification required`
      );
    }
  }

  // High-level operations that require PIN verification
  async withPINVerification<T>(
    operation: () => Promise<T>,
    pinNumber = 0
  ): Promise<T> {
    this.ensurePINVerified(pinNumber);
    return await operation();
  }

  // Get card information summary
  async getCardInfo(): Promise<{
    appletVersion: string;
    protocolVersion: string;
    setupDone: boolean;
    isSeeded: boolean;
    needs2FA: boolean;
    pinStates: { pin0Tries: number; pin1Tries: number };
  }> {
    const status = await this.getStatus();
    
    return {
      appletVersion: `${(status.applet_version >> 8) & 0xFF}.${status.applet_version & 0xFF}`,
      protocolVersion: `${(status.protocol_version >> 8) & 0xFF}.${status.protocol_version & 0xFF}`,
      setupDone: status.setup_done,
      isSeeded: status.is_seeded,
      needs2FA: status.needs_2fa,
      pinStates: {
        pin0Tries: status.pin0_tries,
        pin1Tries: status.pin1_tries,
      },
    };
  }

  // ========================================
  // Keyslot Management
  // ========================================


  async getPubkeyFromKeyslot(
    keynbr: number,
  ): Promise<ECPubkey>{
    console_log(`In protocol getPubkeyFromKeyslot`);
    const pubkey = await getPubkeyFromKeyslot(this.secureChannel, keynbr);
    return pubkey;
  }


  // ========================================
  // BIP32 Seed and Key Management
  // ========================================

  /**
   * Import BIP32 seed from entropy (one-time setup)
   * Automatically establishes secure channel if needed
   */
  async importSeed(seed: Buffer, options = 0x00): Promise<void> {
    console_log(`In protocol importSeed`);

    await importSeed(this.secureChannel, seed, options);

    // Clear cached status as seeding state changed
    this.status = null;
  }

  /**
   * Factory reset: permanently delete all seeds and keys
   * WARNING: This operation cannot be undone!
   */
  async resetSeed(pin: string): Promise<void> {
    console_log(`In protocol resetSeed`);
    const pinBytes = Buffer.from(pin, 'utf8')
    const hmacBytes = null; // todo
    await resetSeed(this.secureChannel, pinBytes, hmacBytes);
    
    // Clear all cached state
    this.status = null;
  }

  /**
   * Get extended public key for a BIP32 derivation path
   * @param pathString - BIP32 path like "m/44'/0'/0'"
   */
  async getExtendedKey(pathString: string): Promise<ExtendedKey>  {
    console_log(`In protocol getExtendedKey pathString: ${pathString}`);
    this.lastBip32Path = pathString
    return await getExtendedKey(this.secureChannel, pathString);
  }

  async getXpub(pathString: string, xtype: XType='standard', isMainnet=true ): Promise<string>  {
    console_log(`In protocol getXpub pathString: ${pathString}`);
    return await cardBip32GetXpub(this.secureChannel, pathString, xtype, isMainnet);
  }

  async getMasterXfp(): Promise<string>  {
    console_log(`In protocol getMasterXfp`);
    return await cardBip32GetMasterXFP(this.secureChannel);
  }

  // ========================================
  // Signatures
  // ========================================

  /**
   * Sign a message hash with a static or BIP32 derived key
   * @param keynbr
   * @param msgHash - 32-byte hash to sign
   * @param hmac - optional 20-byte hmac (when 2FA is enabled, experimental)
   */
  async signMessage(keynbr: number, msgHash: Buffer, hmac: Buffer = Buffer.alloc(0)): Promise<Buffer> {
    const derSig =  await signTransactionHash(this.secureChannel, keynbr, msgHash, hmac);

    // recover pubkey (needed to compute compact signature)
    let pubkey: ECPubkey;
    if (keynbr==0xff){
      // get extended key
      const pubkey = await this.getExtendedKey(this.lastBip32Path);
    } else if (keynbr>=0 && keynbr<=MAX_NUM_KEYS){
      // get pubkey from keyslot
      const pubkey = await this.getPubkeyFromKeyslot(keynbr);
    } else {
      throw new SatochipError(`Wrong key number: ${keynbr}`)
    }

    // convert to compact sig
    const compactSig= CardDataParser.parseMessageSignature(derSig, msgHash, pubkey);
    return compactSig;
  }

  /**
   * Sign a transaction hash with a BIP32 derived key
   * @param keynumber
   * @param txHash - 32-byte transaction hash
   * @param hmac - optional 20-byte hmac (when 2FA is enabled, experimental)
   */
  async signTransactionHash(keynumber: number, txHash: Buffer, hmac: Buffer = Buffer.alloc(0)): Promise<Buffer> {
    console_log(`In protocol signTransactionHash keynumber: ${keynumber} - txHash: ${txHash.toString('hex')}`);
    return await signTransactionHash(this.secureChannel, keynumber, txHash, hmac);
  }

  // ========================================
  // PKI Methods
  // ========================================

  async exportPersoCertificate(): Promise<string> {
    console_log(`In protocol ExportPersoCertificate`);
    return await exportPersoCertificate(this.secureChannel);
  }

  async cardChallengeResponsePki(): Promise<ChallengeResponseResult> {
    console_log(`In protocol cardChallengeResponsePki`);
    const authentikey = await this.getAuthentikey();
    const res = await cardChallengeResponsePki(this.secureChannel, authentikey.getPublicKeyBytes(false));
    console_log(`In protocol cardChallengeResponsePki res: ${res}`);
    console_log(JSON.stringify(res, null, 2));

    return res;
  }

  async verifyCertificateChain(): Promise<CertificateValidationResult> {
    console_log(`In protocol verifyCertificateChain`);

    const devicePem = await this.exportPersoCertificate();
    console_log(`In protocol verifyCertificateChain devicePem: ${devicePem}`);

    const validator = new CertificateValidator();
    const res = await validator.validateCertificateChain(devicePem, 'Satochip')

    console_log(`In protocol verifyCertificateChain res: ${res}`);
    console_log(JSON.stringify(res, null, 2));

    return res;
  }


  // ========================================
  // Utility Methods
  // ========================================

  /**
   * Check if card has been seeded
   */
  async isSeeded(): Promise<boolean> {
    const status = await this.getStatus();
    return status.is_seeded;
  }

  /**
   * Get comprehensive card capabilities and state
   */
  async getCapabilities() {
    const status = await this.getStatus();
    
    return {
      // Basic info
      appletVersion: status.applet_version,
      protocolVersion: status.protocol_version,
      
      // Setup state
      isSetup: status.setup_done,
      isSeeded: status.is_seeded,
      needsSecureChannel: status.needs_secure_channel,
      needs2FA: status.needs_2fa,
      
      // PIN state
      pin0Tries: status.pin0_tries,
      pin1Tries: status.pin1_tries,
      
      // Feature policies
      nfcPolicy: status.nfc_policy,
      schnorrPolicy: status.schnorr_policy,
      nostrPolicy: status.nostr_policy,
      liquidPolicy: status.liquid_policy,
      musig2Policy: status.musig2_policy,
      
      // Session state
      secureChannelActive: this.secureChannel.isEstablished(),
      pin0Verified: this.isPINVerified(0),
      pin1Verified: this.isPINVerified(1)
    };
  }
}