# Satochip Expo example

Mobile-only Expo SDK 57 example for `satochip-react-native`. It reads public card status over NFC on iOS and Android.

## Requirements

- Node.js 22.13 or newer
- A physical NFC-capable iOS or Android device
- A Satochip card
- Native iOS/Android build tooling, or an EAS account for cloud builds

This app cannot run in Expo Go because both NFC and the crypto compatibility layer contain native code.

`react-native-nfc-manager` is excluded from Expo Doctor's React Native Directory
metadata check because it is the transport under test and the directory currently
marks it as untested on the New Architecture. Validate NFC on both platforms before
shipping changes.

## Run locally

```sh
npm install
npm run ios
# or
npm run android
```

To select a connected physical iPhone, build the development client, install it,
and launch it:

Set your Apple Developer Team ID in the ignored `.env.local` file first:

```sh
EXPO_APPLE_TEAM_ID=YOUR_TEAM_ID
```

`app.config.ts` reads this value at build time, keeping personal signing details
out of Git. You can also provide it for a single command:

```sh
EXPO_APPLE_TEAM_ID=YOUR_TEAM_ID npm run ios:device
```

Then run:

```sh
npm run ios:device
```

The device must trust this Mac, Developer Mode must be enabled, and the Xcode
project must have a valid signing team.

After the development build is installed, start Metro with:

```sh
npm start
```

The package dependency uses `file:../..`, so app installs and Metro resolve the library directly from this repository.

## Sign a Nostr message

The **Sign message** action derives the NIP-06 account-0 key at
`m/44'/1237'/0'/0/0` and creates a Nostr kind-1 event containing
`Hello World!`. Following NIP-01, the app serializes
`[0, pubkey, created_at, kind, tags, content]`, signs the SHA-256 event ID with
the card's BIP-340 Schnorr signer, and displays the completed event JSON with a
clipboard action. The Satochip key-preparation command explicitly bypasses the
Bitcoin Taproot tweak because Nostr signs with the untweaked x-only public key.

The Schnorr and Nostr feature policies must be enabled. Cards requiring 2FA for
signing are not supported by this example.

## Factory reset

The **Factory Reset** action permanently erases all user data and returns the
card to its uninitialized state. The Satochip applet requires five separate NFC
presentations to protect against accidental erasure. Remove the card completely
between scans and do not use another card command or app until the sequence is
complete, because any intervening command cancels the reset.

Only continue after confirming that the recovery phrase has been backed up and
can restore the wallet.

## Verify

```sh
npm run typecheck
npm run lint
npm run doctor
```
