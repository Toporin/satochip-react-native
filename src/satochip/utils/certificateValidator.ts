/**
 * Certificate Validator for Satochip PKI
 *
 * This module validates the certificate chain from the root CA to the device certificate.
 * It requires certificate files to be bundled with the application.
 *
 * NOTE: For React Native, certificate validation typically requires:
 * 1. Bundling certificate files as assets
 * 2. Using a library like 'node-forge' or '@peculiar/x509' for validation
 * 3. Platform-specific certificate stores
 *
 * This implementation provides the structure and logic.
 * You'll need to integrate with your build system for certificate loading.
 */

// import * as crypto from 'crypto';
import { X509Certificate, X509ChainBuilder } from '@peculiar/x509';
import { Crypto } from '@peculiar/webcrypto';
import { CERTIFICATES } from './certs';
import { console_log } from './logging';

export type DeviceType = 'SeedKeeper' | 'Satochip' | 'Satodime';

export interface CertificateValidationResult {
  isValid: boolean;
  devicePubkey: Buffer;
  txtCa: string;
  txtSubca: string;
  txtDevice: string;
  txtError: string;
}

export interface ParsedCertificate {
  isExpired: boolean;
  issuer: string; //{ [key: string]: string };
  subject: string; //{ [key: string]: string };
  publicKey: Buffer;
  notBefore: Date;
  notAfter: Date;
}

const crypto = new Crypto();

/**
 * Certificate Validator Class
 *
 * Validates the certificate chain for Satochip devices.
 * Supports production and test CA certificates.
 */
export class CertificateValidator {

  /**
   * Validate certificate chain with fallback to test CA
   *
   * @param devicePem - Device certificate in PEM format
   * @param deviceType - Type of device (SeedKeeper, Satochip, Satodime)
   * @returns Validation result
   */
  async validateCertificateChain(
    devicePem: string,
    deviceType: DeviceType
  ): Promise<CertificateValidationResult> {
    console_log('In validateCertificateChain');

    const USE_TEST_CA = false;

    // Try production certificates first
    const result = await this._validateChain(devicePem, deviceType, false);

    if (result.isValid) {
      return result;
    } else if (USE_TEST_CA) {
      // Try with test CA
      console.warn('Certificate chain NOT VALID for production PKI');

      const testResult = await this._validateChain(devicePem, deviceType, true);

      if (testResult.isValid) {
        // Mark as test CA (not for production)
        testResult.isValid = false;
        testResult.txtError = 'WARNING: Chain certificate validated with TEST CA! NOT FOR PRODUCTION!';
        return testResult;
      } else {
        // Return original production error
        return result;
      }
    }

    return result;
  }

  /**
   * Internal method to validate certificate chain
   *
   * @param devicePem - Device certificate in PEM format
   * @param deviceType - Type of device
   * @param useTest - Whether to use test certificates
   * @returns Validation result
   */
  private async _validateChain(
    devicePem: string,
    deviceType: DeviceType,
    useTest = false
  ): Promise<CertificateValidationResult> {
    console_log(`In _validateChain, useTest: ${useTest}`);

    let txtCa = '';
    let txtSubca = '';
    let txtDevice = '';
    let txtError = '';
    let devicePubkey = Buffer.alloc(65);

    // Determine certificate file paths based on device type
    const certPrefix = useTest ? 'test-' : '';
    let subcaFilename: string;

    switch (deviceType) {
      case 'SeedKeeper':
        subcaFilename = `${certPrefix}subca-seedkeeper.cert`;
        break;
      case 'Satochip':
        subcaFilename = `${certPrefix}subca-satochip.cert`;
        break;
      case 'Satodime':
        subcaFilename = `${certPrefix}subca-satodime.cert`;
        break;
      default:
        txtError = `Unknown card_type: ${deviceType}`;
        return { isValid: false, devicePubkey, txtCa, txtSubca, txtDevice, txtError };
    }

    const caFilename = useTest ? 'test-ca.cert' : 'ca.cert';

    try {
      // Load certificates
      const caPem = this.loadCertificate(caFilename);
      const subcaPem = this.loadCertificate(subcaFilename);

      // Parse certificates
      const parsedCa = this.parseCertificate(caPem);
      const parsedSubca = this.parseCertificate(subcaPem);
      const parsedDevice = this.parseCertificate(devicePem);

      txtCa = this.certificateToText(parsedCa);
      txtSubca = this.certificateToText(parsedSubca);
      txtDevice = this.certificateToText(parsedDevice);

      // Extract public key from device certificate
      devicePubkey = parsedDevice.publicKey;

      // validate certificate chain
      const isValid = await this.validateChain(caPem, subcaPem, devicePem);
      if (!isValid) {
        txtError = 'Device certificate validation failed';
        return { isValid: false, devicePubkey, txtCa, txtSubca, txtDevice, txtError };
      }

      // Check expiration
      if (parsedDevice.isExpired) {
        txtError = 'Device certificate has expired';
        return { isValid: false, devicePubkey, txtCa, txtSubca, txtDevice, txtError };
      }

      console_log('Certificate chain validation successful');
      return { isValid: true, devicePubkey, txtCa, txtSubca, txtDevice, txtError };

    } catch (error: any) {
      txtError = `Exception during certificate validation: ${error.message || error}`;
      console.error(txtError);
      return { isValid: false, devicePubkey, txtCa, txtSubca, txtDevice, txtError };
    }
  }

  /**
   * Load certificate from file or asset
   *
   * @param filename - Certificate filename
   * @returns Certificate in PEM format
   */
  private loadCertificate(filename: string): string {
    const cert = CERTIFICATES[filename];
    if (!cert) {
      throw new Error(`Certificate ${filename} not found`);
    }
    return cert;
  }

  private async validateChain(caPem, subcaPem, devicePem) {
    console_log(`In validateChain`);
    const ca = new X509Certificate(caPem);
    const subca = new X509Certificate(subcaPem);
    const device = new X509Certificate(devicePem);

    const chain = new X509ChainBuilder({
      certificates: [ca, subca, device]
      //certificates: [ca, device, subca] // debug: WRONG order!
    });

    const items = await chain.build(device, crypto);
    console_log(`In validateChain items: ${items}`);
    console_log(`In validateChain items.length: ${items.length}`);
    console_log(JSON.stringify(items, null, 2));

    return items.length > 0;
  }

  /**
   * Parse PEM certificate
   *
   * @param certPem - Certificate in PEM format
   * @returns Parsed certificate
   */
  private parseCertificate(certPem: string): ParsedCertificate {

    const cert = new X509Certificate(certPem);
    return {
      isExpired: new Date() > new Date(cert.notAfter),
      issuer: cert.issuer,
      subject: cert.subject,
      publicKey: Buffer.from(cert.publicKey.rawData),
      notBefore: new Date(cert.notBefore),
      notAfter: new Date(cert.notAfter),
    };

  }

  /**
   * Convert parsed certificate to text representation
   *
   * @param cert - Parsed certificate
   * @returns Human-readable certificate info
   */
  private certificateToText(cert: ParsedCertificate): string {
    return JSON.stringify({
      subject: cert.subject,
      issuer: cert.issuer,
      notBefore: cert.notBefore,
      notAfter: cert.notAfter,
      isExpired: cert.isExpired,
    }, null, 2);
  }

}