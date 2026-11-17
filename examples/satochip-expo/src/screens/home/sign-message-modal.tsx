import { useState } from 'react';
import {
  ActivityIndicator,
  KeyboardAvoidingView,
  Modal,
  Pressable,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';

type SignMessageModalProps = {
  isSigning: boolean;
  onClose: () => void;
  onSubmit: (pin: string) => Promise<void>;
  visible: boolean;
};

export function SignMessageModal({ isSigning, onClose, onSubmit, visible }: SignMessageModalProps) {
  const [pin, setPin] = useState('');
  const [error, setError] = useState<string | null>(null);

  function resetAndClose() {
    if (isSigning) return;
    setPin('');
    setError(null);
    onClose();
  }

  async function submit() {
    if (!pin) {
      setError('Enter the card PIN to sign the event.');
      return;
    }

    setError(null);
    try {
      await onSubmit(pin);
      setPin('');
      onClose();
    } catch (signError) {
      setError(signError instanceof Error ? signError.message : String(signError));
    }
  }

  return (
    <Modal
      animationType="slide"
      onRequestClose={resetAndClose}
      presentationStyle="pageSheet"
      visible={visible}
    >
      <KeyboardAvoidingView behavior={process.env.EXPO_OS === 'ios' ? 'padding' : undefined} style={styles.container}>
        <View style={styles.content}>
          <View style={styles.header}>
            <Text style={styles.eyebrow}>NOSTR KIND 1</Text>
            <Text style={styles.title}>Sign message</Text>
            <Text style={styles.description}>
              Sign a Nostr text note containing “Hello World!” using the card’s BIP-340 Schnorr key.
            </Text>
          </View>

          <View style={styles.field}>
            <Text style={styles.label}>Card PIN</Text>
            <TextInput
              autoCapitalize="none"
              autoCorrect={false}
              editable={!isSigning}
              onChangeText={setPin}
              onSubmitEditing={submit}
              placeholder="Enter the current PIN"
              returnKeyType="done"
              secureTextEntry
              style={styles.input}
              testID="sign-message-pin-input"
              value={pin}
            />
          </View>

          {error ? (
            <View accessibilityRole="alert" style={styles.errorCard}>
              <Text selectable style={styles.errorText}>{error}</Text>
            </View>
          ) : null}

          <View style={styles.actions}>
            <Pressable
              accessibilityRole="button"
              disabled={isSigning}
              onPress={resetAndClose}
              style={({ pressed }) => [styles.cancelButton, pressed && styles.pressed]}
            >
              <Text style={styles.cancelButtonText}>Cancel</Text>
            </Pressable>
            <Pressable
              accessibilityRole="button"
              disabled={isSigning}
              onPress={submit}
              style={({ pressed }) => [styles.signButton, pressed && styles.pressed, isSigning && styles.disabled]}
              testID="confirm-sign-message-button"
            >
              {isSigning ? <ActivityIndicator color="#ffffff" /> : <Text style={styles.signButtonText}>Sign</Text>}
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
  eyebrow: { color: '#0b6e4f', fontSize: 12, fontWeight: '800', letterSpacing: 1.4 },
  title: { color: '#14213d', fontSize: 32, fontWeight: '800', letterSpacing: -0.6 },
  description: { color: '#526078', fontSize: 16, lineHeight: 24 },
  field: { gap: 8 },
  label: { color: '#14213d', fontSize: 15, fontWeight: '700' },
  input: {
    backgroundColor: '#ffffff',
    borderColor: '#d7dde6',
    borderRadius: 12,
    borderWidth: 1,
    color: '#14213d',
    fontSize: 17,
    minHeight: 52,
    paddingHorizontal: 16,
  },
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
  signButton: {
    alignItems: 'center',
    backgroundColor: '#0b6e4f',
    borderRadius: 14,
    flex: 1,
    justifyContent: 'center',
    minHeight: 54,
  },
  signButtonText: { color: '#ffffff', fontSize: 17, fontWeight: '700' },
  pressed: { opacity: 0.8 },
  disabled: { opacity: 0.65 },
});
