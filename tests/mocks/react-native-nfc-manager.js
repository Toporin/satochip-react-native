// Minimal stub of the react-native-nfc-manager peer dependency for unit tests:
// the tests exercise APDU building/parsing and never talk to an NFC tag.
const NfcManager = {
  start: async () => {},
  isSupported: async () => true,
  requestTechnology: async () => {},
  cancelTechnologyRequest: async () => {},
  setTimeout: async () => {},
  setAlertMessageIOS: async () => {},
  invalidateSessionWithErrorIOS: async () => {},
  isoDepHandler: {
    transceive: async () => {
      throw new Error('NFC is not available in unit tests');
    },
  },
};

module.exports = NfcManager;
module.exports.default = NfcManager;
module.exports.NfcTech = { IsoDep: 'IsoDep' };
