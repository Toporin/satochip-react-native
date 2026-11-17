const { Buffer } = require('buffer');
const { install } = require('react-native-quick-crypto');

global.Buffer = Buffer;
install();

require('expo-router/entry');
