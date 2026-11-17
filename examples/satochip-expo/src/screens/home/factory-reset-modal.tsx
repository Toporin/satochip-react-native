import { useState } from 'react';
import {
  ActivityIndicator,
  Alert,
  KeyboardAvoidingView,
  Modal,
  Pressable,
  StyleSheet,
  Text,
  View,
} from 'react-native';

type FactoryResetModalProps = {
  isResetting: boolean;
  onClose: () => void;
  onReset: () => Promise<number>;
  visible: boolean;
};

export function FactoryResetModal({
  isResetting,
  onClose,
  onReset,
  visible,
}: FactoryResetModalProps) {
  const [isConfirmed, setIsConfirmed] = useState(false);
  const [remaining, setRemaining] = useState(5);
  const [error, setError] = useState<string | null>(null);

  function resetAndClose() {
    if (isResetting) return;
    setIsConfirmed(false);
    setRemaining(5);
    setError(null);
    onClose();
  }

  function requestConfirmation() {
    setError(null);
    Alert.alert(
      'Factory reset this card?',
      'This permanently deletes every seed and private key on the card. This operation cannot be undone.',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Erase card',
          style: 'destructive',
          onPress: () => {
            setIsConfirmed(true);
            performReset();
          },
        },
      ],
    );
  }

  async function performReset() {
    try {
      const scansRemaining = await onReset();
      setRemaining(scansRemaining);
      if (scansRemaining === 0) {
        setIsConfirmed(false);
        setError(null);
        onClose();
      }
    } catch (resetError) {
      setError(resetError instanceof Error ? resetError.message : String(resetError));
    }
  }

  return (
    <Modal
      animationType="slide"
      onRequestClose={resetAndClose}
      presentationStyle="pageSheet"
      transparent={false}
      visible={visible}
    >
      <KeyboardAvoidingView behavior={process.env.EXPO_OS === 'ios' ? 'padding' : undefined} style={styles.container}>
        <View style={styles.content}>
          <View style={styles.header}>
            <Text style={styles.eyebrow}>IRREVERSIBLE OPERATION</Text>
            <Text style={styles.title}>Factory reset</Text>
            <Text style={styles.warning}>
              Factory reset permanently removes the seed, private keys, 2FA configuration, label, and PIN. Make sure you have a valid recovery phrase before continuing.
            </Text>
          </View>

          <View style={styles.instructions}>
            <Text style={styles.instructionsTitle}>
              {isConfirmed ? `${remaining} card scans remaining` : 'Five scans are required'}
            </Text>
            <Text style={styles.instructionsText}>
              {isConfirmed
                ? 'Remove the card completely, then tap Continue and present it again. Do not scan or use the card with another app until the reset finishes.'
                : 'The card firmware requires you to remove and present the card five separate times. Any other card operation cancels the reset sequence.'}
            </Text>
          </View>

          {error ? (
            <View accessibilityRole="alert" style={styles.errorCard}>
              <Text selectable style={styles.errorText}>{error}</Text>
            </View>
          ) : null}

          <View style={styles.actions}>
            <Pressable
              accessibilityRole="button"
              disabled={isResetting}
              onPress={resetAndClose}
              style={({ pressed }) => [styles.cancelButton, pressed && styles.pressed]}
            >
              <Text style={styles.cancelButtonText}>Cancel</Text>
            </Pressable>
            <Pressable
              accessibilityLabel="Permanently erase this Satochip card"
              accessibilityRole="button"
              disabled={isResetting}
              onPress={isConfirmed ? performReset : requestConfirmation}
              style={({ pressed }) => [
                styles.resetButton,
                pressed && styles.pressed,
                isResetting && styles.disabled,
              ]}
              testID="confirm-factory-reset-button"
            >
              {isResetting ? (
                <ActivityIndicator color="#ffffff" />
              ) : (
                <Text style={styles.resetButtonText}>
                  {isConfirmed ? 'Scan again' : 'Continue'}
                </Text>
              )}
            </Pressable>
          </View>
        </View>
      </KeyboardAvoidingView>
    </Modal>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#f4f7fb' },
  content: { flex: 1, gap: 24, padding: 24, paddingTop: 48 },
  header: { gap: 10 },
  eyebrow: { color: '#b42318', fontSize: 12, fontWeight: '800', letterSpacing: 1.4 },
  title: { color: '#14213d', fontSize: 32, fontWeight: '800', letterSpacing: -0.6 },
  warning: { color: '#7b3030', fontSize: 16, lineHeight: 24 },
  instructions: { backgroundColor: '#ffffff', borderRadius: 14, gap: 8, padding: 18 },
  instructionsTitle: { color: '#14213d', fontSize: 17, fontWeight: '700' },
  instructionsText: { color: '#526078', fontSize: 15, lineHeight: 22 },
  errorCard: { backgroundColor: '#fff0f0', borderRadius: 12, padding: 14 },
  errorText: { color: '#7b3030', fontSize: 14, lineHeight: 20 },
  actions: { flexDirection: 'row', gap: 12, marginTop: 'auto' },
  cancelButton: {
    alignItems: 'center',
    borderColor: '#aab3c0',
    borderRadius: 14,
    borderWidth: 1.5,
    flex: 1,
    justifyContent: 'center',
    minHeight: 54,
  },
  cancelButtonText: { color: '#526078', fontSize: 17, fontWeight: '700' },
  resetButton: {
    alignItems: 'center',
    backgroundColor: '#b42318',
    borderRadius: 14,
    flex: 1,
    justifyContent: 'center',
    minHeight: 54,
  },
  resetButtonText: { color: '#ffffff', fontSize: 17, fontWeight: '700' },
  pressed: { opacity: 0.8 },
  disabled: { opacity: 0.65 },
});
