import NfcManager from 'react-native-nfc-manager';
import { NfcTech } from 'react-native-nfc-manager';

/**
 * Check if device supports NFC feature
 */
const isNfcSupported = async () => NfcManager.isSupported();

/**
 * Start NFC hardware usage with desired NfcTech on Android and iOS
 */
const startConnection = async () => {
  await NfcManager.start();
  await NfcManager.requestTechnology([NfcTech.IsoDep]);
};

/**
 * End NFC hardware usage on Android and iOS
 */
const closeConnection = async () => {
  await NfcManager.cancelTechnologyRequest();
};

/**
 * iOS only - update message on NFC system dialog
 */
const setiOSMessage = async (message: string) =>
  NfcManager.setAlertMessageIOS(message);

/**
 * iOS only - show error with message on NFC system dialog
 */
const setiOSError = async (message: string) =>
  NfcManager.invalidateSessionWithErrorIOS(message);

export {
  isNfcSupported,
  startConnection,
  closeConnection,
  setiOSMessage,
  setiOSError,
};
