// Map node's `crypto` module to react-native-quick-crypto (see metro.config.js).
// Export a plain object holding the named exports and the default export's
// members, so that `import * as crypto from 'crypto'` (used by the library) and
// `import crypto from 'crypto'` both work.
// Do not include a `default` key: Babel's namespace interop defines every key
// as a getter and then assigns `default`, which throws if the key exists.
const { default: quickCryptoDefault, ...namedExports } = require('react-native-quick-crypto');

module.exports = { ...namedExports, ...(quickCryptoDefault || {}) };
