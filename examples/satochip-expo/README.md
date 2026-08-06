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

## Verify

```sh
npm run typecheck
npm run lint
npm run doctor
```
