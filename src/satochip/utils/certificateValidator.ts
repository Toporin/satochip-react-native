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

// obsolete, should not be used
// import { Certificate, CertificateChainValidationEngine } from 'pkijs';
// import { fromBER } from 'asn1js';  // For parsing DER
// import webcrypto from "react-native-quick-crypto"; // Polyfill full WebCrypto API
// globalThis.crypto = webcrypto;  // Make it available globally for pkijs

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

// export interface ParsedCertificate {
//   isExpired: boolean;
//   issuer: string; //{ [key: string]: string };
//   subject: string; //{ [key: string]: string };
//   publicKey: Buffer;
//   notBefore: Date;
//   notAfter: Date;
// }

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
   * Internal method to validate certificate chain
   *
   * @param devicePem - Device certificate in PEM format
   * @param deviceType - Type of device
   * @param useTest - Whether to use test certificates
   * @returns Validation result
   */
  // private async _validateChainOld(
  //   devicePem: string,
  //   deviceType: DeviceType,
  //   useTest = false
  // ): Promise<CertificateValidationResult> {
  //   console_log(`certificateValidator _validateChain, useTest: ${useTest}`);
  //
  //   let txtCa = '';
  //   let txtSubca = '';
  //   let txtDevice = '';
  //   let txtError = '';
  //   let devicePubkey = Buffer.alloc(65);
  //
  //   // Determine certificate file paths based on device type
  //   const certPrefix = useTest ? 'test-' : '';
  //   let subcaFilename: string;
  //
  //   switch (deviceType) {
  //     case 'SeedKeeper':
  //       subcaFilename = `${certPrefix}subca-seedkeeper.cert`;
  //       break;
  //     case 'Satochip':
  //       subcaFilename = `${certPrefix}subca-satochip.cert`;
  //       break;
  //     case 'Satodime':
  //       subcaFilename = `${certPrefix}subca-satodime.cert`;
  //       break;
  //     default:
  //       txtError = `Unknown card_type: ${deviceType}`;
  //       return { isValid: false, devicePubkey, txtCa, txtSubca, txtDevice, txtError };
  //   }
  //
  //   const caFilename = useTest ? 'test-ca.cert' : 'ca.cert';
  //
  //   try {
  //     // Load certificates
  //     const caPem = this.loadCertificate(caFilename);
  //     const subcaPem = this.loadCertificate(subcaFilename);
  //
  //     // Parse certificates
  //     const parsedCa = this.parseCertificate(caPem);
  //     const parsedSubca = this.parseCertificate(subcaPem);
  //     const parsedDevice = this.parseCertificate(devicePem);
  //
  //     txtCa = this.certificateToText(parsedCa);
  //     txtSubca = this.certificateToText(parsedSubca);
  //     txtDevice = this.certificateToText(parsedDevice);
  //
  //     // Extract public key from device certificate
  //     devicePubkey = parsedDevice.publicKey;
  //
  //     // validate certificate chain
  //     const isValid = await this.validateChain(caPem, subcaPem, devicePem);
  //     if (!isValid) {
  //       txtError = 'Device certificate validation failed';
  //       return { isValid: false, devicePubkey, txtCa, txtSubca, txtDevice, txtError };
  //     }
  //
  //     // Check expiration
  //     if (parsedDevice.isExpired) {
  //       txtError = 'Device certificate has expired';
  //       return { isValid: false, devicePubkey, txtCa, txtSubca, txtDevice, txtError };
  //     }
  //
  //     console_log('Certificate chain validation successful');
  //     return { isValid: true, devicePubkey, txtCa, txtSubca, txtDevice, txtError };
  //
  //   } catch (error: any) {
  //     txtError = `Exception during certificate validation: ${error.message || error}`;
  //     console.error(txtError);
  //     return { isValid: false, devicePubkey, txtCa, txtSubca, txtDevice, txtError };
  //   }
  // }

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

  // private async validateChain(caPem, subcaPem, devicePem) {
  //   console_log(`In validateChain`);
  //   const ca = new X509Certificate(caPem);
  //   const subca = new X509Certificate(subcaPem);
  //   const device = new X509Certificate(devicePem);
  //
  //   const chain = new X509ChainBuilder({
  //     certificates: [ca, subca, device]
  //     //certificates: [ca, device, subca] // debug: WRONG order!
  //   });
  //
  //   const items = await chain.build(device, crypto);
  //   console_log(`In validateChain items: ${items}`);
  //   console_log(`In validateChain items.length: ${items.length}`);
  //   console_log(JSON.stringify(items, null, 2));
  //
  //   return items.length > 0;
  // }

  /**
   * Parse PEM certificate
   *
   * @param certPem - Certificate in PEM format
   * @returns Parsed certificate
   */
  // private parseCertificate(certPem: string): ParsedCertificate {
  //
  //   const cert = new X509Certificate(certPem);
  //   return {
  //     isExpired: new Date() > new Date(cert.notAfter),
  //     issuer: cert.issuer,
  //     subject: cert.subject,
  //     publicKey: Buffer.from(cert.publicKey.rawData),
  //     notBefore: new Date(cert.notBefore),
  //     notAfter: new Date(cert.notAfter),
  //   };
  //
  // }

  /**
   * Convert parsed certificate to text representation
   *
   * @param cert - Parsed certificate
   * @returns Human-readable certificate info
   */
  // private certificateToText(cert: ParsedCertificate): string {
  //   return JSON.stringify({
  //     subject: cert.subject,
  //     issuer: cert.issuer,
  //     notBefore: cert.notBefore,
  //     notAfter: cert.notAfter,
  //     isExpired: cert.isExpired,
  //   }, null, 2);
  // }

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

  // // Helper function to convert PEM to DER
  // function pemToDer(pem) {
  //   const base64 = pem
  //     .replace(/-----BEGIN CERTIFICATE-----/g, '')
  //     .replace(/-----END CERTIFICATE-----/g, '')
  //     .replace(/\s/g, '');
  //   return Buffer.from(base64, 'base64');
  // }

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

      // // Extract components
      // const tbsCertificate = certificate.valueBlock.value[0];
      // const signatureAlgorithm = certificate.valueBlock.value[1];
      // const signatureValue = certificate.valueBlock.value[2];

      // Get TBS bytes (To Be Signed)
      // Re-encode TBS to get exact DER bytes (most reliable method)
      const tbsDer = tbsCertificate.toBER(false);
      const tbsBuffer = Buffer.from(tbsDer);
      console_log(`certificateValidator parseCertificate tbsBuffer: ${tbsBuffer.toString('hex')}`);

      // Method 1: Get TBS bytes directly from valueBeforeDecode
      // if (tbsCertificate.valueBeforeDecode) {
      //   // valueBeforeDecode is already an ArrayBuffer containing the exact bytes
      //   const tbsView = new Uint8Array(tbsCertificate.valueBeforeDecode);
      //   const tbsBuffer2 = Buffer.from(tbsView);
      //   console_log(`certificateValidator parseCertificate tbsBuffer2: ${tbsBuffer2.toString('hex')}`);
      // }
      // else {
      //   // Method 2: Fallback - calculate TBS bytes from the original buffer
      //   // TBS starts where the tbsCertificate element starts in the original buffer
      //   const tbsStart = tbsCertificate.valueBlock.blockLength > 0
      //     ? tbsCertificate.valueBlock.valueHexView.byteOffset - tbsCertificate.blockLength + tbsCertificate.valueBlock.blockLength
      //     : 0;
      //   const tbsLength = tbsCertificate.blockLength;
      //
      //   // Extract TBS from original buffer
      //   const tbsView = new Uint8Array(derBuffer.buffer, tbsStart, tbsLength);
      //   tbsBuffer = Buffer.from(tbsView);
      // }

      // Alternative Method 3: Re-encode the TBS certificate to get the exact bytes
      // This is the most reliable but requires additional processing
      // if (!tbsBuffer || tbsBuffer.length === 0) {
      //   const tbsDer = tbsCertificate.toBER(false);
      //   tbsBuffer = Buffer.from(tbsDer);
      // }

      // Get TBS bytes (To Be Signed)
      // const tbsView = new Uint8Array(derBuffer.buffer, tbsCertificate.valueBeforeDecode.byteOffset, tbsCertificate.valueBeforeDecode.byteLength);
      // const tbsBuffer = Buffer.from(tbsView);
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

      // const r = sequence.valueBlock.value[0];
      // const s = sequence.valueBlock.value[1];

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

      // const tbsCertificate = certificate.valueBlock.value[0];

      // Navigate to SubjectPublicKeyInfo
      const tbsValues = this.getSequenceValues(tbsCertificate);

      // Navigate to SubjectPublicKeyInfo
      // const tbsSequence = tbsCertificate.valueBlock.value;

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

      // let subjectPublicKeyInfo = null;
      // for (let i = 5; i < tbsSequence.length; i++) {
      //   const element = tbsSequence[i];
      //   if (element instanceof Sequence && element.valueBlock.value.length === 2) {
      //     // Check if this looks like SubjectPublicKeyInfo
      //     const firstElement = element.valueBlock.value[0];
      //     const secondElement = element.valueBlock.value[1];
      //     if (firstElement instanceof Sequence && secondElement instanceof BitString) {
      //       subjectPublicKeyInfo = element;
      //       break;
      //     }
      //   }
      // }

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
      // Install with: npm install elliptic
      // const EC = require('elliptic').ec;
      // const ec = new EC('secp256k1');
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

  // private async verifyCertificateChainObsolete(devicePem, subcaPem, caPem) {
  //   // This code require the following imports, but this can break config!
  //   // import webcrypto from "react-native-quick-crypto"; // Polyfill full WebCrypto API
  //   //globalThis.crypto = webcrypto;  // Make it available globally for pkijs
  //
  //   // convert to DER
  //   const caDer = this.pemToDer(caPem);
  //   const subcaDer = this.pemToDer(subcaPem);
  //   const deviceDer = this.pemToDer(devicePem);
  //   console_log(`_validateChain after DER conversion`);
  //
  //   const caCert = new Certificate({ schema: fromBER(caDer).result });
  //   const subcaCert = new Certificate({ schema: fromBER(subcaDer).result });
  //   const deviceCert = new Certificate({ schema: fromBER(deviceDer).result });
  //   console_log(`_validateChain after certificate parsing`);
  //
  //   // get device pubkey
  //   const spki = deviceCert.subjectPublicKeyInfo; // SubjectPublicKeyInfo ASN.1
  //   const devicePubkey = Buffer.from(spki.subjectPublicKey.valueBlock.valueHexView); // Uint8Array -> Buffer
  //   console_log(`_validateChain devicePubkey: ${devicePubkey}`);
  //   console_log(`_validateChain devicePubkey(hex): ${devicePubkey.toString('hex')}`);
  //
  //   // human readable form
  //   const txtCa = "";
  //   const txtSubca = "";
  //   const txtDevice = "";
  //
  //   const engine = new CertificateChainValidationEngine({
  //     certs: [caCert, subcaCert, deviceCert],
  //     trustedCerts: [caCert],
  //     // date: new Date(), // optional: check against specific date
  //   });
  //   console_log(`_validateChain after engine creation`);
  //
  //   const result = await engine.verify();
  //   console_log('_validateChain Certificate chain valid: ', result.result);
  //   console_log('_validateChain Result code: ', result.resultCode);
  //   console_log('_validateChain Message: ', result.resultMessage);
  //
  //   console_log('Certificate chain validation successful');
  //   return { isValid: result.result, devicePubkey, txtCa, txtSubca, txtDevice, txtError: result.resultMessage };
  // }

}