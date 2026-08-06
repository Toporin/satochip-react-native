import { useMemo, useState } from 'react';
import { mnemonicToSeedSync } from 'bip39';
import { Buffer } from 'buffer';
import * as Clipboard from 'expo-clipboard';
import { Link } from 'expo-router';
import { sha256 } from 'js-sha256';
import {
  ActivityIndicator,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  View,
} from 'react-native';
import { SatochipCard } from 'satochip-react-native';

import { SetupCardModal } from './setup-card-modal';
import { FactoryResetModal } from './factory-reset-modal';
import { SignMessageModal } from './sign-message-modal';

type CardInfo = Awaited<ReturnType<SatochipCard['getCardInfo']>>;

export function HomeScreen() {
  const card = useMemo(() => new SatochipCard(), []);
  const [cardInfo, setCardInfo] = useState<CardInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [isSetupVisible, setIsSetupVisible] = useState(false);
  const [isResetVisible, setIsResetVisible] = useState(false);
  const [isResetting, setIsResetting] = useState(false);
  const [isSignVisible, setIsSignVisible] = useState(false);
  const [isSigning, setIsSigning] = useState(false);
  const [setupComplete, setSetupComplete] = useState(false);
  const [resetComplete, setResetComplete] = useState(false);
  const [signedEvent, setSignedEvent] = useState<string | null>(null);
  const [copyComplete, setCopyComplete] = useState(false);

  async function scanCard() {
    setError(null);
    setIsScanning(true);

    try {
      const info = await card.nfcWrapper(() => card.getCardInfo());
      setCardInfo(info);
    } catch (scanError) {
      setCardInfo(null);
      setError(scanError instanceof Error ? scanError.message : String(scanError));
    } finally {
      if (process.env.EXPO_OS === 'android') {
        await card.endNfcSession().catch(() => undefined);
      }
      setIsScanning(false);
    }
  }

  async function setupCard(pin: string, mnemonic: string) {
    setError(null);
    setSetupComplete(false);

    try {
      const info = await card.nfcWrapper(async () => {
        const status = await card.getStatus();
        if (status.setup_done) {
          throw new Error('This card is already initialized. Setup was not changed.');
        }

        await card.setup(pin);
        await card.verifyPIN(0, pin);
        const seed = Buffer.from(mnemonicToSeedSync(mnemonic));
        try {
          await card.importSeed(seed);
        } finally {
          seed.fill(0);
        }

        return card.getCardInfo();
      });

      setCardInfo(info);
      setSetupComplete(true);
    } finally {
      if (process.env.EXPO_OS === 'android') {
        await card.endNfcSession().catch(() => undefined);
      }
    }
  }

  async function factoryReset(): Promise<number> {
    setError(null);
    setResetComplete(false);
    setIsResetting(true);

    try {
      const result = await card.nfcWrapper(() => card.factoryReset());
      if (result.complete) {
        setCardInfo(null);
        setSetupComplete(false);
        setResetComplete(true);
      }
      return result.remaining;
    } finally {
      if (process.env.EXPO_OS === 'android') {
        await card.endNfcSession().catch(() => undefined);
      }
      setIsResetting(false);
    }
  }

  async function signNostrMessage(pin: string) {
    setError(null);
    setIsSigning(true);
    setSignedEvent(null);
    setCopyComplete(false);

    try {
      const eventJson = await card.nfcWrapper(async () => {
        const status = await card.getStatus();
        if (!status.setup_done || !status.is_seeded) {
          throw new Error('Set up and seed the card before signing a message.');
        }
        if (status.needs_2fa) {
          throw new Error('This example does not currently support 2FA approval for signing.');
        }
        if (status.schnorr_policy > 0 || status.nostr_policy > 0) {
          throw new Error('Schnorr or Nostr signing is disabled by the card policy.');
        }

        try {
          await card.verifyPIN(0, pin);
        } catch (verificationError) {
          throw new Error(`PIN verification failed: ${getErrorMessage(verificationError)}`);
        }

        const keyNumber = 0xFF;
        let extendedKey: Awaited<ReturnType<SatochipCard['getExtendedKey']>>;
        try {
          extendedKey = await card.getExtendedKey("m/44'/1237'/0'/0/0");
        } catch (derivationError) {
          throw new Error(`Nostr key derivation failed: ${getErrorMessage(derivationError)}`);
        }
        const publicKey = extendedKey.pubkey.slice(1, 33).toString('hex');
        const createdAt = Math.floor(Date.now() / 1000);
        const kind = 1;
        const tags: string[][] = [];
        const content = 'Hello World!';
        const serializedEvent = JSON.stringify([0, publicKey, createdAt, kind, tags, content]);
        const eventId = Buffer.from(sha256.create().update(serializedEvent).digest());

        try {
          await card.prepareSchnorrKey(keyNumber, true);
        } catch (preparationError) {
          throw new Error(`Schnorr key preparation failed: ${getErrorMessage(preparationError)}`);
        }

        let signature: Buffer;
        try {
          signature = await card.signSchnorrHash(keyNumber, eventId);
        } catch (signatureError) {
          throw new Error(`Schnorr signature failed: ${getErrorMessage(signatureError)}`);
        }

        return JSON.stringify(
          {
            id: eventId.toString('hex'),
            pubkey: publicKey,
            created_at: createdAt,
            kind,
            tags,
            content,
            sig: signature.toString('hex'),
          },
          null,
          2,
        );
      });

      setSignedEvent(eventJson);
    } finally {
      if (process.env.EXPO_OS === 'android') {
        await card.endNfcSession().catch(() => undefined);
      }
      setIsSigning(false);
    }
  }

  async function copySignedEvent() {
    if (!signedEvent) return;
    await Clipboard.setStringAsync(signedEvent);
    setCopyComplete(true);
  }

  return (
    <>
      <ScrollView
        contentContainerStyle={styles.content}
        contentInsetAdjustmentBehavior="automatic"
        style={styles.scrollView}
      >
        <View style={styles.hero}>
          <Text style={styles.eyebrow}>NFC HARDWARE WALLET</Text>
          <Text style={styles.title}>Read a Satochip card</Text>
          <Text style={styles.description}>
            Hold your card against this phone while the scan is active. The app
            reads public status information only.
          </Text>
        </View>

        <Pressable
          accessibilityLabel="Scan Satochip card"
          accessibilityRole="button"
          disabled={isScanning}
          onPress={scanCard}
          style={({ pressed }) => [
            styles.button,
            pressed && styles.buttonPressed,
            isScanning && styles.buttonDisabled,
          ]}
          testID="scan-card-button"
        >
          {isScanning ? (
            <ActivityIndicator color="#ffffff" />
          ) : (
            <Text style={styles.buttonText}>Scan card</Text>
          )}
        </Pressable>

        <Pressable
          accessibilityLabel="Sign a Hello World Nostr message"
          accessibilityRole="button"
          disabled={isScanning || isSigning || isResetting}
          onPress={() => setIsSignVisible(true)}
          style={({ pressed }) => [
            styles.button,
            pressed && styles.buttonPressed,
            (isScanning || isSigning || isResetting) && styles.buttonDisabled,
          ]}
          testID="open-sign-message-button"
        >
          {isSigning ? (
            <ActivityIndicator color="#ffffff" />
          ) : (
            <Text style={styles.buttonText}>Sign message</Text>
          )}
        </Pressable>

        <Pressable
          accessibilityLabel="Set up an uninitialized Satochip card"
          accessibilityRole="button"
          disabled={isScanning || cardInfo?.setupDone === true}
          onPress={() => setIsSetupVisible(true)}
          style={({ pressed }) => [
            styles.secondaryButton,
            pressed && styles.buttonPressed,
            (isScanning || cardInfo?.setupDone === true) && styles.buttonDisabled,
          ]}
          testID="open-card-setup-button"
        >
          <Text style={styles.secondaryButtonText}>Set up new card</Text>
        </Pressable>

        <Pressable
          accessibilityLabel="Factory reset a Satochip card"
          accessibilityRole="button"
          disabled={isScanning || isResetting}
          onPress={() => setIsResetVisible(true)}
          style={({ pressed }) => [
            styles.destructiveButton,
            pressed && styles.buttonPressed,
            (isScanning || isResetting) && styles.buttonDisabled,
          ]}
          testID="open-factory-reset-button"
        >
          <Text style={styles.destructiveButtonText}>Factory Reset</Text>
        </Pressable>

        {setupComplete ? (
          <View accessibilityRole="alert" style={styles.successCard} testID="setup-success">
            <Text style={styles.successTitle}>Card setup complete</Text>
            <Text style={styles.successText}>The PIN and recovery seed are now configured.</Text>
          </View>
        ) : null}

        {resetComplete ? (
          <View accessibilityRole="alert" style={styles.successCard} testID="reset-success">
            <Text style={styles.successTitle}>Factory reset complete</Text>
            <Text style={styles.successText}>All user data has been erased and the card is ready to be set up again.</Text>
          </View>
        ) : null}

        {error ? (
          <View accessibilityRole="alert" style={styles.errorCard} testID="scan-error">
            <Text style={styles.errorTitle}>Card scan failed</Text>
            <Text style={styles.errorText}>{error}</Text>
          </View>
        ) : null}

        {signedEvent ? (
          <View style={styles.eventCard} testID="signed-nostr-event">
            <Text style={styles.cardTitle}>Signed Nostr event</Text>
            <Text selectable style={styles.eventJson}>{signedEvent}</Text>
            <Pressable
              accessibilityLabel="Copy signed Nostr event JSON"
              accessibilityRole="button"
              onPress={copySignedEvent}
              style={({ pressed }) => [styles.copyButton, pressed && styles.buttonPressed]}
              testID="copy-signed-event-button"
            >
              <Text style={styles.copyButtonText}>{copyComplete ? 'Copied' : 'Copy JSON'}</Text>
            </Pressable>
            <Link href="https://nostr-tools.com/event-verifier" asChild>
              <Pressable
                accessibilityHint="Opens the Nostr event verifier in your browser"
                accessibilityRole="link"
                style={({ pressed }) => [styles.verifierLink, pressed && styles.buttonPressed]}
                testID="open-nostr-event-verifier"
              >
                <Text style={styles.verifierLinkText}>Verify this event (paste JSON)</Text>
              </Pressable>
            </Link>
          </View>
        ) : null}

        {cardInfo ? (
          <View style={styles.infoCard} testID="card-info">
            <Text style={styles.cardTitle}>Card information</Text>
            <InfoRow label="Applet" value={cardInfo.appletVersion} />
            <InfoRow label="Protocol" value={cardInfo.protocolVersion} />
            <InfoRow label="Setup" value={cardInfo.setupDone ? 'Complete' : 'Required'} />
            <InfoRow label="Seed" value={cardInfo.isSeeded ? 'Present' : 'Not present'} />
            <InfoRow label="2FA" value={cardInfo.needs2FA ? 'Required' : 'Not required'} />
            <InfoRow label="PIN 0 tries" value={String(cardInfo.pinStates.pin0Tries)} />
          </View>
        ) : null}

        <Text style={styles.notice}>
          Requires a physical NFC-capable iOS or Android device and a development build.
          This example does not run in Expo Go.
        </Text>
      </ScrollView>
      <SetupCardModal
        onClose={() => setIsSetupVisible(false)}
        onSubmit={setupCard}
        visible={isSetupVisible}
      />
      <SignMessageModal
        isSigning={isSigning}
        onClose={() => setIsSignVisible(false)}
        onSubmit={signNostrMessage}
        visible={isSignVisible}
      />
      <FactoryResetModal
        isResetting={isResetting}
        onClose={() => setIsResetVisible(false)}
        onReset={factoryReset}
        visible={isResetVisible}
      />
    </>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <View style={styles.infoRow}>
      <Text style={styles.infoLabel}>{label}</Text>
      <Text style={styles.infoValue}>{value}</Text>
    </View>
  );
}

function getErrorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

const styles = StyleSheet.create({
  scrollView: { flex: 1, backgroundColor: '#f4f7fb' },
  content: { padding: 24, paddingBottom: 40, gap: 20 },
  hero: { gap: 10, paddingVertical: 20 },
  eyebrow: { color: '#0b6e4f', fontSize: 12, fontWeight: '800', letterSpacing: 1.4 },
  title: { color: '#14213d', fontSize: 34, fontWeight: '800', letterSpacing: -0.8 },
  description: { color: '#526078', fontSize: 17, lineHeight: 25 },
  button: {
    alignItems: 'center',
    backgroundColor: '#0b6e4f',
    borderRadius: 14,
    minHeight: 54,
    justifyContent: 'center',
    paddingHorizontal: 20,
  },
  buttonPressed: { opacity: 0.8 },
  buttonDisabled: { opacity: 0.65 },
  buttonText: { color: '#ffffff', fontSize: 17, fontWeight: '700' },
  secondaryButton: {
    alignItems: 'center',
    borderColor: '#0b6e4f',
    borderRadius: 14,
    borderWidth: 1.5,
    justifyContent: 'center',
    minHeight: 54,
    paddingHorizontal: 20,
  },
  secondaryButtonText: { color: '#0b6e4f', fontSize: 17, fontWeight: '700' },
  destructiveButton: {
    alignItems: 'center',
    borderColor: '#b42318',
    borderRadius: 14,
    borderWidth: 1.5,
    justifyContent: 'center',
    minHeight: 54,
    paddingHorizontal: 20,
  },
  destructiveButtonText: { color: '#b42318', fontSize: 17, fontWeight: '700' },
  eventCard: { backgroundColor: '#ffffff', borderRadius: 16, gap: 14, padding: 20 },
  eventJson: {
    color: '#24324a',
    fontFamily: process.env.EXPO_OS === 'ios' ? 'Menlo' : 'monospace',
    fontSize: 12,
    lineHeight: 18,
  },
  copyButton: {
    alignItems: 'center',
    backgroundColor: '#e8f7f0',
    borderRadius: 12,
    justifyContent: 'center',
    minHeight: 46,
    paddingHorizontal: 16,
  },
  copyButtonText: { color: '#07583f', fontSize: 16, fontWeight: '700' },
  verifierLink: { alignItems: 'center', justifyContent: 'center', minHeight: 44 },
  verifierLinkText: { color: '#0b6e4f', fontSize: 15, fontWeight: '700', textDecorationLine: 'underline' },
  successCard: { backgroundColor: '#e8f7f0', borderRadius: 14, gap: 6, padding: 18 },
  successTitle: { color: '#07583f', fontSize: 16, fontWeight: '700' },
  successText: { color: '#24634f', fontSize: 14, lineHeight: 20 },
  errorCard: { backgroundColor: '#fff0f0', borderRadius: 14, gap: 6, padding: 18 },
  errorTitle: { color: '#9f2525', fontSize: 16, fontWeight: '700' },
  errorText: { color: '#7b3030', fontSize: 14, lineHeight: 20 },
  infoCard: { backgroundColor: '#ffffff', borderRadius: 16, padding: 20 },
  cardTitle: { color: '#14213d', fontSize: 20, fontWeight: '700', marginBottom: 10 },
  infoRow: {
    alignItems: 'center',
    borderBottomColor: '#e7ebf0',
    borderBottomWidth: StyleSheet.hairlineWidth,
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: 11,
  },
  infoLabel: { color: '#526078', fontSize: 15 },
  infoValue: { color: '#14213d', fontSize: 15, fontWeight: '600' },
  notice: { color: '#69758a', fontSize: 13, lineHeight: 19, textAlign: 'center' },
});
