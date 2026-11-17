/**
 * Check if device supports NFC feature
 */
declare const isNfcSupported: () => Promise<boolean>;
/**
 * Start NFC hardware usage with desired NfcTech on Android and iOS
 */
declare const startConnection: () => Promise<void>;
/**
 * End NFC hardware usage on Android and iOS
 */
declare const closeConnection: () => Promise<void>;
/**
 * iOS only - update message on NFC system dialog
 */
declare const setiOSMessage: (message: string) => Promise<void>;
/**
 * iOS only - show error with message on NFC system dialog
 */
declare const setiOSError: (message: string) => Promise<void>;
export { isNfcSupported, startConnection, closeConnection, setiOSMessage, setiOSError, };
