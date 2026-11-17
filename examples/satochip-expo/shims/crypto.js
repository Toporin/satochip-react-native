// Map node's `crypto` module to react-native-quick-crypto (see metro.config.js).
//
// react-native-quick-crypto does `module.exports = QuickCrypto` and then
// `module.exports.default = QuickCrypto`, so the object has its own `default`
// key. With `import * as crypto from 'crypto'` (used by the library), Metro's
// namespace interop defines every key as a getter and then assigns `default`,
// which throws "Cannot assign to property 'default' which has only a getter".
// Export a copy without the `default` key: both `import * as crypto` and
// `import crypto from 'crypto'` then resolve to the QuickCrypto API.
const quickCrypto = require('react-native-quick-crypto');

const { default: _default, ...cryptoApi } = quickCrypto;

module.exports = cryptoApi;
