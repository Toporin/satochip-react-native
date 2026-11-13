/**
 * Base class for every applet of the Satochip family (Satochip, Satodime,
 * and later Seedkeeper, Satocash).
 *
 * It owns the NFC session handling, the applet SELECT, the secure channel and
 * the commands that every applet implements identically: authentikey, card
 * label and PKI authenticity checks. Card-specific classes add their own
 * commands, status parsing and status-word mapping.
 */
import { Platform } from 'react-native';
import { startConnection, closeConnection, isNfcSupported } from '../nfc';
import { APDUCommand, APDUResponse } from '../satochip/types';
import { ECPubkey } from '../satochip/utils/ECKey';
import { CertificateValidationResult, CertificateValidator, DeviceType } from '../satochip/utils/certificateValidator';
import { console_log } from '../satochip/utils/logging';
import { sendEncryptedAPDU, sendPlainAPDU } from './apdu';
import { CardError, ResponseChecker, SW_OK } from './errors';
import { SecureChannel } from './SecureChannel';
import {
  ChallengeResponseResult,
  cardChallengeResponsePki,
  exportPersoCertificate,
  getAuthentikey,
  getLabel,
  selectAid,
  setLabel,
} from './commands/common';

export abstract class BaseCard {
  /** Applet identifier used for ISO SELECT. */
  protected abstract readonly aid: Buffer;
  /** Device type used to pick the PKI sub-CA during authenticity checks. */
  abstract readonly deviceType: DeviceType;
  /** If true, selectApplet() throws when the applet is not found on the card. */
  protected readonly strictSelect: boolean = false;

  protected secureChannel: SecureChannel;
  protected readonly check: ResponseChecker;

  protected constructor(secureChannel: SecureChannel, check: ResponseChecker) {
    this.secureChannel = secureChannel;
    this.check = check;
  }

  // ========================================
  // NFC session management
  // ========================================

  async startNfcSession(): Promise<void> {
    try {
      await startConnection();
      await this.selectApplet();
    } catch (error) {
      // Handle Android-specific error for already active session
      if (String(error) === 'Error: You can only issue one request at a time') {
        return;
      }
      throw error;
    }
  }

  async endNfcSession(): Promise<void> {
    await closeConnection();
  }

  async nfcWrapper<T>(callback: () => Promise<T>): Promise<T> {
    const supported = await isNfcSupported();
    if (!supported) {
      throw new Error("Sorry, this device doesn't support NFC");
    }

    const run = Platform.select<() => Promise<T>>({
      android: async () => {
        try {
          await this.startNfcSession();
          return await callback();
        } catch (error) {
          this.handleError(error);
        }
      },
      ios: async () => {
        try {
          await startConnection();
          await this.selectApplet();
          return await callback();
        } catch (error) {
          this.handleError(error);
        }
      },
    });
    if (!run) {
      throw new Error('NFC is not supported on this platform');
    }
    return run();
  }

  protected handleError(error: unknown): never {
    if (String(error) === 'Error: Initialisation failed') {
      throw new Error('Please hold the card more stably or longer');
    }
    throw error;
  }

  // ========================================
  // Applet selection & transport
  // ========================================

  /** Clear values cached for the currently selected card. Called on every SELECT. */
  protected clearCache(): void {
    // overridden by subclasses
  }

  async selectApplet(): Promise<void> {
    this.clearCache();
    const rapdu = await selectAid(this.aid);
    if (rapdu.statusWord === SW_OK) {
      console_log(`${this.deviceType} applet selected`);
      this.secureChannel.reset();
    } else if (this.strictSelect) {
      throw new CardError(
        rapdu.statusWord,
        'SW_APPLET_NOT_FOUND',
        `This is not a ${this.deviceType} card (select failed: 0x${rapdu.statusWord.toString(16).toUpperCase()})`
      );
    }
  }

  /** Send a plain APDU, mapping errors with this card's table. */
  protected sendPlain(command: APDUCommand): Promise<APDUResponse> {
    return sendPlainAPDU(command, this.check);
  }

  /** Send an APDU through the secure channel, mapping errors with this card's table. */
  protected sendSecure = (command: APDUCommand): Promise<APDUResponse> =>
    sendEncryptedAPDU(command, this.secureChannel, this.check);

  // ========================================
  // Commands common to every applet
  // ========================================

  /** Card authentikey (card identity key). */
  async getAuthentikey(): Promise<ECPubkey> {
    return getAuthentikey(this.sendSecure, this.secureChannel);
  }

  async getLabel(): Promise<string> {
    return getLabel(this.sendSecure);
  }

  async setLabel(label: string): Promise<void> {
    await setLabel(this.sendSecure, label);
  }

  async exportPersoCertificate(): Promise<string> {
    return exportPersoCertificate(this.sendSecure);
  }

  async cardChallengeResponsePki(): Promise<ChallengeResponseResult> {
    const authentikey = await this.getAuthentikey();
    return cardChallengeResponsePki(this.sendSecure, authentikey.getPublicKeyBytes(false));
  }

  async verifyCertificateChain(): Promise<CertificateValidationResult> {
    const devicePem = await this.exportPersoCertificate();
    const validator = new CertificateValidator();
    return validator.validateCertificateChain(devicePem, this.deviceType);
  }
}
