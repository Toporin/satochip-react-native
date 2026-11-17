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
export declare class CertificateValidator {
    /**
     * Validate certificate chain with fallback to test CA
     *
     * @param devicePem - Device certificate in PEM format
     * @param deviceType - Type of device (SeedKeeper, Satochip, Satodime)
     * @returns Validation result
     */
    validateCertificateChain(devicePem: string, deviceType: DeviceType): Promise<CertificateValidationResult>;
    /**
     * Internal method to validate certificate chain
     *
     * @param devicePem - Device certificate in PEM format
     * @param deviceType - Type of device
     * @param useTest - Whether to use test certificates
     * @returns Validation result
     */
    private _validateChain;
    /**
     * Load certificate from file or asset
     *
     * @param filename - Certificate filename
     * @returns Certificate in PEM format
     */
    private loadCertificate;
    private pemToDer;
    private getSequenceValues;
    private parseCertificate;
    private parseECDSASignature;
    private extractPublicKeyFromCA;
    private verifySignature;
    private verifyCertificateChain;
}
