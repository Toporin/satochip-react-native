# React Native

## Satochip Protocol library

A React Native JS library to enable easy communication
with **Satochip**.

## Links

* [Official Github account](https://github.com/Toporin)
* [Satochip applet repository](https://github.com/Toporin/SatochipApplet)

# Installation

`yarn add satochip-react-native`

## Supporting node core modules

This library uses a few node core modules like secp256k1, buffer, crypto etc. which react native doesn't support because they probably use C++ code bundled with the Node JS binary, not Javascript.

We suggest using [rn-nodify](https://github.com/tradle/rn-nodeify) to enable using node core modules after `yarn add satochip-react-native`

## Metro Plugin

rn-nodify needs stream-browserify for browser support.

`metro.config.js`

```sh
...
resolver: {
    extraNodeModules: {
      stream: require.resolve('stream-browserify'),
    },
  },
transformer: {
    ...
  },
...
```

## Peer dependencies

[react-native-nfc-manager](https://github.com/revtel/react-native-nfc-manager) is used for the NFC communications with the cards. Please refer to their docs for nfc integration.

## ~TDLR

1. add the post install script in your package.json
   `"postinstall": "rn-nodeify --install fs,dgram,process,path,console,crypto --hack"`

2. install the required modules
   `yarn add satochip-react-native rn-nodify stream-browserify react-native-nfc-manager`

3. update metro config resolver

```sh
extraNodeModules: {
    stream: require.resolve('stream-browserify'),
}
```

4. install respoective cocopod dependencies
   `cd ios && pod install`

## TEST
Run test suits for the library with
```zsh
yarn test
```

## LINT
Lint the library with
```zsh
yarn lint
```

## TYPES
The package ships TypeScript declarations in `types/`, generated from the sources.
Regenerate (and commit) them whenever the public API changes:
```zsh
yarn build:types
```

# Usage Example

```typescript
import { SatochipCard } from 'satochip-react-native';
import * as bip39 from 'bip39';

const satochip = new SatochipCard();

// Basic card interaction
await satochip.nfcWrapper(async () => {
  // Check if card is set up
  const status = await satochip.getStatus();
  console.log('Setup done:', status.setup_done);
  
  // If not set up, perform initial setup
  if (!status.setup_done) {
    const pin= '123456';
    const max_try= 5;
    await satochip.setup(pin, max_try);
  }
  
  // Verify PIN for subsequent operations
  await satochip.verifyPIN(0, '123456');
  
  // import BIP39 seed
  const mnemonic = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
  const passphrase = '';
  // Validate mnemonic using biP39 library
  if (!bip39.validateMnemonic(mnemonic)) {
    throw new Error('Invalid mnemonic');
  }
  // Convert to binary seed & import 
  const seed = bip39.mnemonicToSeedSync(mnemonic, passphrase);
  await card.importSeed(seed);
  
  // derive and get extended key
  let path = `m/44'/0'/0'/0/0`;
  const {pubkey, chaincode} = await card.getExtendedKey(path);
  
});
```

## Android specific usage
* Make sure you call the following command on **android** once the interactions with the card is completed. This is specifically done in android as we do not end the nfc after the wrapper has executed the commands but which is not the case with iOS. 
    This behaviour is different for different platforms since the NFC interaction is blocking in iOS (system dialog) and non-blocking in android. Hence the user can manually add NFC dialogs/interactions in case of android when the communication with the card is done (optionally).
```tsx
// Android-only
await card.endNfcSession(); // either call is on component unmount or post card.nfcWrapper
```

**NOTE**
* Place the card for the NFC scan before **card.nfcWrapper** is called. There is no need to remove the card until the wrapper completes the callback.
* iOS has it's own system NFC interaction to let the user know that the NFC is active. The NFC session is closed automatically when `nfcWrapper` returns or throws.
* Android has no interaction as such. You can use your own modal/interaction which can open and close before/after the callback to card.nfcWrapper.
* See the [Expo example app](examples/satochip-expo) for a complete usage example (card status, setup, Nostr/Schnorr signing, factory reset).

## Crypto shim
The library imports node's `crypto` module (random bytes, AES, SHA-256, RIPEMD-160...). In React Native,
it must be provided by a shim such as `crypto-browserify` (rn-nodeify) or `react-native-quick-crypto`
(see the example app's `metro.config.js` and `shims/crypto.js`).

**react-native-quick-crypto with Expo:** do not map `crypto` directly to the package. It sets
`module.exports.default` to itself, and with Expo's import transform (`expo/metro-config`) the library's
`import * as crypto from 'crypto'` then fails at startup with
`Cannot assign to property 'default' which has only a getter`. Map `crypto` to a small shim that removes
the `default` key instead (harmless with other setups). Bare React Native apps using
`@react-native/babel-preset` are not affected: its interop helper skips the `default` key, so a plain
alias (e.g. babel-plugin-module-resolver `crypto: 'react-native-quick-crypto'`) works.

```js
// shims/crypto.js
const { default: _default, ...cryptoApi } = require('react-native-quick-crypto');
module.exports = cryptoApi;
```

```js
// metro.config.js
config.resolver.resolveRequest = (context, moduleName, platform) => {
  if (moduleName === 'crypto') {
    return { type: 'sourceFile', filePath: path.resolve(__dirname, 'shims/crypto.js') };
  }
  return context.resolveRequest(context, moduleName, platform);
};
```

# Example app

[`examples/satochip-expo`](examples/satochip-expo) is an Expo (development build) app that uses the library
from this repository. It is not part of the published package (see `files` in `package.json`).

# Acknowledgement

This library is based on the [cktap-protocol-react-native library](https://github.com/bithyve/cktap-protocol-react-native).
