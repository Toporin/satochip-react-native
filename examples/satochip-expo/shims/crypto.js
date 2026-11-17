// Map node's `crypto` module to react-native-quick-crypto (see metro.config.js).
// Export a plain object holding both the named exports and the default
// export's members, so that `import * as crypto from 'crypto'` (used by the
// library) and `import crypto from 'crypto'` both work.
const quickCrypto = require('react-native-quick-crypto');

module.exports = { ...quickCrypto, ...(quickCrypto.default || {}) };
