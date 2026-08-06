import { useMemo, useState } from 'react';
import { mnemonicToSeedSync } from 'bip39';
import { Buffer } from 'buffer';
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

type CardInfo = Awaited<ReturnType<SatochipCard['getCardInfo']>>;

export function HomeScreen() {
  const card = useMemo(() => new SatochipCard(), []);
  const [cardInfo, setCardInfo] = useState<CardInfo | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [isScanning, setIsScanning] = useState(false);
  const [isSetupVisible, setIsSetupVisible] = useState(false);
  const [setupComplete, setSetupComplete] = useState(false);

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

        {setupComplete ? (
          <View accessibilityRole="alert" style={styles.successCard} testID="setup-success">
            <Text style={styles.successTitle}>Card setup complete</Text>
            <Text style={styles.successText}>The PIN and recovery seed are now configured.</Text>
          </View>
        ) : null}

        {error ? (
          <View accessibilityRole="alert" style={styles.errorCard} testID="scan-error">
            <Text style={styles.errorTitle}>Card scan failed</Text>
            <Text style={styles.errorText}>{error}</Text>
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
