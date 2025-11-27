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

import { CERTIFICATES } from './certs';
import { console_log } from './logging';

// Basic certificate check
import { fromBER, Integer, Sequence, BitString } from 'asn1js';
import * as elliptic from 'elliptic';
import * as crypto from 'crypto';

export type DeviceType = 'SeedKeeper' | 'Satochip' | 'Satodime';

export interface CertificateValidationResult {
  isValid: boolean;
  devicePubkey: Buffer;
  txtCa: string;
  txtSubca: string;
  txtDevice: string;
  txtError: string;
}

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
    console_log('certificateValidator validateCertificateChain');

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
    console_log(`certificateValidator _validateChain, useTest: ${useTest}`);

    // todo: parse certificates to human readable form...
    const txtCa = '';
    const txtSubca = '';
    const txtDevice = '';
    let txtError = '';
    const devicePubkey = Buffer.alloc(65);

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
    console_log(`certificateValidator _validateChain caFilename: ${caFilename}`);

    try {
      // Load certificates
      const caPem = this.loadCertificate(caFilename);
      const subcaPem = this.loadCertificate(subcaFilename);
      console_log(`certificateValidator _validateChain after PEM certificate loading`);

      // Basic check: we check that the device signature is valid for the subca pubkey
      // We implicitly suppose that the (hardcoded) subca is valid and signed by the root CA.
      const authResult = await this.verifyCertificateChain(devicePem, subcaPem);
      //console_log(`_validateChain authResult: ${authResult}`);
      console_log(JSON.stringify(authResult, null, 2));
      console_log(`certificateValidator _validateChain isValid: ${authResult.isValid}`);
      console_log(`certificateValidator _validateChain caPublicKey: ${authResult.caPublicKey.toString('hex')}`);
      console_log(`certificateValidator _validateChain devicePublicKey: ${authResult.devicePublicKey.toString('hex')}`);
      if (!authResult.isValid){
        txtError = "Failed to validate device certificate";
      }

      // DEBUG only: checking the device cert vs the root CA should always fail!
      // console_log(`certificateValidator _validateChain DEBUG - USING WRONG CERTIFICATE!`);
      // const authResultWrong = await this.verifyCertificateChain(devicePem, caPem);
      // console_log(`certificateValidator _validateChain authResultWrong: ${authResultWrong}`);
      // console_log(JSON.stringify(authResultWrong, null, 2));
      // console_log(`certificateValidator _validateChain isValid: ${authResultWrong.isValid}`);
      // console_log(`certificateValidator _validateChain caPublicKey: ${authResultWrong.caPublicKey.toString('hex')}`);
      // console_log(`certificateValidator _validateChain devicePublicKey: ${authResultWrong.devicePublicKey.toString('hex')}`);

      return { isValid: authResult.isValid, devicePubkey:authResult.devicePublicKey, txtCa: caPem, txtSubca: subcaPem, txtDevice: devicePem, txtError };
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

  private pemToDer(pem: string) {
    console_log(`pemToDer START`);

    // Remove PEM headers and newlines
    const base64 = pem
      .replace(/-----BEGIN [A-Z0-9\s]+-----/g, '')
      .replace(/-----END [A-Z0-9\s]+-----/g, '')
      .replace(/\s+/g, '');
    console_log(`pemToDer base64: ${base64}`);

    const derBytes = Buffer.from(base64, 'base64');
    console_log(`pemToDer derBytes: ${derBytes.toString('hex')}`);
    return derBytes;
  }

  // Helper to safely get sequence values
  private getSequenceValues(sequence) {
    if (!(sequence instanceof Sequence)) {
      throw new Error('Expected a Sequence');
    }

    // Check if valueBlock has the value property
    if (!sequence.valueBlock || !('value' in sequence.valueBlock)) {
      throw new Error('Invalid Sequence structure - no value array found');
    }

    return sequence.valueBlock.value;
  }

  // Parse the certificate and extract TBS and signature
  private async parseCertificate(pemCertificate: string) {
    console_log(`certificateValidator parseCertificate start`);
    try {
      // Convert PEM to DER
      const derBuffer = this.pemToDer(pemCertificate);

      // Parse ASN.1 structure
      const asn1 = fromBER(derBuffer.buffer);
      if (asn1.offset === -1) {
        throw new Error('Error parsing certificate ASN.1');
      }

      // The certificate is a SEQUENCE with 3 elements:
      // - TBSCertificate (SEQUENCE)
      // - SignatureAlgorithm (SEQUENCE)
      // - SignatureValue (BIT STRING)
      const certificate = asn1.result;

      if (!(certificate instanceof Sequence) || certificate.valueBlock.value.length !== 3) {
        throw new Error('Invalid certificate structure');
      }

      // Safely get the certificate components
      const certValues = this.getSequenceValues(certificate);
      if (certValues.length !== 3) {
        throw new Error(`Invalid certificate structure - expected 3 elements, got ${certValues.length}`);
      }

      // Extract the three main components
      const tbsCertificate = certValues[0];
      const signatureAlgorithm = certValues[1];
      const signatureValue = certValues[2];

      // Get TBS bytes (To Be Signed)
      // Re-encode TBS to get exact DER bytes (most reliable method)
      const tbsDer = tbsCertificate.toBER(false);
      const tbsBuffer = Buffer.from(tbsDer);
      console_log(`certificateValidator parseCertificate tbsBuffer: ${tbsBuffer.toString('hex')}`);

      // Hash the TBS certificate (usually SHA-256 for modern certificates)
      const tbsHash = crypto.createHash('sha256').update(tbsBuffer).digest();
      console_log(`certificateValidator parseCertificate tbsHash: ${tbsHash.toString('hex')}`);

      // Extract signature bytes
      let signatureBuffer;
      if (signatureValue instanceof BitString) {
        const sigView = new Uint8Array(signatureValue.valueBlock.valueHex);
        signatureBuffer = Buffer.from(sigView);
      } else {
        throw new Error('Invalid signature format');
      }
      console_log(`certificateValidator parseCertificate signatureBuffer: ${signatureBuffer.toString('hex')}`);

      // For secp256k1 with ECDSA, signature is typically in DER format (r,s values)
      const signature = this.parseECDSASignature(signatureBuffer);

      return {
        tbsCertificate: tbsBuffer,
        tbsHash: tbsHash,
        signature: signature,
        signatureBuffer: signatureBuffer,
        signatureAlgorithm: signatureAlgorithm
      };
    } catch (error) {
      console.error('certificateValidator parseCertificate error parsing certificate:', error);
      throw error;
    }
  }

  // Parse ECDSA signature from DER format
  private parseECDSASignature(signatureBuffer) {
    try {
      console_log(`certificateValidator parseECDSASignature start`);
      const asn1 = fromBER(signatureBuffer.buffer);
      if (asn1.offset === -1) {
        throw new Error('Error parsing signature ASN.1');
      }

      const sequence = asn1.result;
      if (!(sequence instanceof Sequence) || sequence.valueBlock.value.length !== 2) {
        throw new Error('Invalid ECDSA signature structure');
      }

      const sigValues = this.getSequenceValues(sequence);
      if (sigValues.length !== 2) {
        throw new Error('Invalid ECDSA signature structure - expected 2 components');
      }

      const r = sigValues[0];
      const s = sigValues[1];

      if (!(r instanceof Integer) || !(s instanceof Integer)) {
        throw new Error('Invalid ECDSA signature components');
      }

      return {
        r: Buffer.from(r.valueBlock.valueHex),
        s: Buffer.from(s.valueBlock.valueHex)
      };
    } catch (error) {
      console.error('Error parsing ECDSA signature:', error);
      throw error;
    }
  }

// Extract public key from root CA certificate
  private async extractPublicKeyFromCA(pemCACertificate: string) {
    console_log(`certificateValidator extractPublicKeyFromCA start`);
    try {
      // Convert PEM to DER
      const derBuffer = this.pemToDer(pemCACertificate);

      // Parse ASN.1 structure
      const asn1 = fromBER(derBuffer.buffer);
      if (asn1.offset === -1) {
        throw new Error('Error parsing CA certificate ASN.1');
      }

      const certificate = asn1.result;
      const certValues = this.getSequenceValues(certificate);
      if (certValues.length < 1) {
        throw new Error('Invalid CA certificate structure');
      }

      const tbsCertificate = certValues[0];

      // Navigate to SubjectPublicKeyInfo
      const tbsValues = this.getSequenceValues(tbsCertificate);

      // Find SubjectPublicKeyInfo (usually at index 6, but may vary)
      let subjectPublicKeyInfo = null;
      for (let i = 5; i < tbsValues.length; i++) {
        const element = tbsValues[i];
        if (element instanceof Sequence) {
          try {
            const elementValues = this.getSequenceValues(element);
            if (elementValues.length === 2) {
              const firstElement = elementValues[0];
              const secondElement = elementValues[1];
              if (firstElement instanceof Sequence && secondElement instanceof BitString) {
                subjectPublicKeyInfo = element;
                break;
              }
            }
          } catch {
            // Not the right structure, continue searching
            continue;
          }
        }
      }

      if (!subjectPublicKeyInfo) {
        throw new Error('Could not find SubjectPublicKeyInfo');
      }

      // Extract the public key bytes
      const publicKeyBitString = subjectPublicKeyInfo.valueBlock.value[1];
      const publicKeyBytes = Buffer.from(new Uint8Array(publicKeyBitString.valueBlock.valueHex));
      console_log(`certificateValidator parseCertificate publicKeyBytes: ${publicKeyBytes.toString('hex')}`);

      // For secp256k1, the public key is typically 65 bytes (uncompressed) or 33 bytes (compressed)
      return publicKeyBytes;
    } catch (error) {
      console.error('Error extracting public key:', error);
      throw error;
    }
  }

  // Verify the signature using elliptic library for secp256k1
  private async verifySignature(tbsHash, signature, publicKey) {
    try {
      // For secp256k1 ECDSA verification, we need the elliptic library
      const ec = new elliptic.ec('secp256k1');

      // Import the public key
      const key = ec.keyFromPublic(publicKey);

      // Verify the signature
      const isValid = key.verify(tbsHash, {
        r: signature.r,
        s: signature.s
      });

      return isValid;
    } catch (error) {
      console.error('Error verifying signature:', error);
      throw error;
    }
  }

// Complete verification function
  private async verifyCertificateChain(certificatePem, rootCAPem) {
    try {
      console_log('certificateValidator verifyCertificateChain');
      const certData = await this.parseCertificate(certificatePem);

      console_log('certificateValidator verifyCertificateChain TBS Hash:', certData.tbsHash.toString('hex'));
      console_log('certificateValidator verifyCertificateChain Signature R:', certData.signature.r.toString('hex'));
      console_log('certificateValidator verifyCertificateChain Signature S:', certData.signature.s.toString('hex'));

      const devicePublicKey = await this.extractPublicKeyFromCA(certificatePem);
      console_log('certificateValidator verifyCertificateChain Device Pubkey:', devicePublicKey.toString('hex'));

      const caPublicKey = await this.extractPublicKeyFromCA(rootCAPem);
      console_log('certificateValidator verifyCertificateChain CA Pubkey:', caPublicKey.toString('hex'));

      const isValid = await this.verifySignature(
        certData.tbsHash,
        certData.signature,
        caPublicKey
      );
      console_log('certificateValidator verifyCertificateChain Signature verification result:', isValid);

      return {
        isValid,
        tbsHash: certData.tbsHash,
        signature: certData.signature,
        caPublicKey,
        devicePublicKey
      };
    } catch (error) {
      console.error('certificateValidator verifyCertificateChain Certificate verification failed:', error);
      throw error;
    }
  }

}