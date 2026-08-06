import { useState } from 'react';
import {
  ActivityIndicator,
  Alert,
  KeyboardAvoidingView,
  Modal,
  Pressable,
  ScrollView,
  StyleSheet,
  Text,
  TextInput,
  View,
} from 'react-native';
import { generateMnemonic, validateMnemonic } from 'bip39';
import { Buffer } from 'buffer';
import crypto from 'crypto';

type SetupCardModalProps = {
  visible: boolean;
  onClose: () => void;
  onSubmit: (pin: string, mnemonic: string) => Promise<void>;
};

export function SetupCardModal({ visible, onClose, onSubmit }: SetupCardModalProps) {
  const [pin, setPin] = useState('');
  const [confirmedPin, setConfirmedPin] = useState('');
  const [mnemonic, setMnemonic] = useState('');
  const [formError, setFormError] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [isGeneratedPhrase, setIsGeneratedPhrase] = useState(false);
  const [hasSavedGeneratedPhrase, setHasSavedGeneratedPhrase] = useState(false);

  function resetAndClose() {
    if (isSubmitting) return;
    setPin('');
    setConfirmedPin('');
    setMnemonic('');
    setFormError(null);
    setIsGeneratedPhrase(false);
    setHasSavedGeneratedPhrase(false);
    onClose();
  }

  function createMnemonic() {
    const generatedMnemonic = generateMnemonic(
      128,
      (size) => crypto.randomBytes(size),
    );
    setMnemonic(generatedMnemonic);
    setIsGeneratedPhrase(true);
    setHasSavedGeneratedPhrase(false);
    setFormError(null);
  }

  function requestMnemonicGeneration() {
    if (!mnemonic.trim()) {
      createMnemonic();
      return;
    }

    Alert.alert(
      'Replace recovery phrase?',
      'Generating a phrase will replace the words currently entered.',
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'Replace', style: 'destructive', onPress: createMnemonic },
      ],
    );
  }

  function updateMnemonic(value: string) {
    setMnemonic(value);
    if (isGeneratedPhrase) {
      setHasSavedGeneratedPhrase(false);
    }
  }

  async function submit() {
    const normalizedMnemonic = mnemonic.trim().toLowerCase().replace(/\s+/g, ' ');

    const pinByteLength = Buffer.byteLength(pin, 'utf8');
    if (pinByteLength < 4 || pinByteLength > 32) {
      setFormError('PIN must contain between 4 and 32 characters.');
      return;
    }
    if (pin !== confirmedPin) {
      setFormError('The PIN entries do not match.');
      return;
    }
    if (normalizedMnemonic.split(' ').length !== 12 || !validateMnemonic(normalizedMnemonic)) {
      setFormError('Enter a valid 12-word BIP39 recovery phrase.');
      return;
    }
    if (isGeneratedPhrase && !hasSavedGeneratedPhrase) {
      setFormError('Save the generated recovery phrase before initializing the card.');
      return;
    }

    setFormError(null);
    setIsSubmitting(true);
    try {
      await onSubmit(pin, normalizedMnemonic);
      setPin('');
      setConfirmedPin('');
      setMnemonic('');
      setIsGeneratedPhrase(false);
      setHasSavedGeneratedPhrase(false);
      onClose();
    } catch (setupError) {
      setFormError(setupError instanceof Error ? setupError.message : String(setupError));
    } finally {
      setIsSubmitting(false);
    }
  }

  return (
    <Modal
      animationType="slide"
      onRequestClose={resetAndClose}
      presentationStyle="pageSheet"
      visible={visible}
    >
      <KeyboardAvoidingView
        behavior={process.env.EXPO_OS === 'ios' ? 'padding' : undefined}
        style={styles.container}
      >
        <ScrollView
          contentContainerStyle={styles.content}
          contentInsetAdjustmentBehavior="automatic"
          keyboardShouldPersistTaps="handled"
        >
          <View style={styles.header}>
            <Text style={styles.title}>Set up Satochip</Text>
            <Text style={styles.description}>
              This initializes the card, protects it with your PIN, and imports the
              seed derived from your recovery phrase.
            </Text>
          </View>

          <View style={styles.warning}>
            <Text style={styles.warningTitle}>Keep your recovery phrase private</Text>
            <Text style={styles.warningText}>
              Anyone with these words can control your funds. This example keeps them
              in memory only and never stores or logs them.
            </Text>
          </View>

          <View style={styles.form}>
            <FieldLabel>PIN</FieldLabel>
            <TextInput
              accessibilityLabel="New card PIN"
              autoCapitalize="none"
              autoComplete="new-password"
              editable={!isSubmitting}
              onChangeText={setPin}
              placeholder="4–32 characters"
              secureTextEntry
              style={styles.input}
              testID="setup-pin-input"
              value={pin}
            />

            <FieldLabel>Confirm PIN</FieldLabel>
            <TextInput
              accessibilityLabel="Confirm new card PIN"
              autoCapitalize="none"
              autoComplete="new-password"
              editable={!isSubmitting}
              onChangeText={setConfirmedPin}
              placeholder="Enter the PIN again"
              secureTextEntry
              style={styles.input}
              testID="setup-confirm-pin-input"
              value={confirmedPin}
            />

            <FieldLabel>12-word recovery phrase</FieldLabel>
            <Pressable
              accessibilityLabel="Generate a secure 12-word recovery phrase"
              accessibilityRole="button"
              disabled={isSubmitting}
              onPress={requestMnemonicGeneration}
              style={({ pressed }) => [
                styles.generateButton,
                pressed && styles.pressed,
              ]}
              testID="generate-mnemonic-button"
            >
              <Text style={styles.generateButtonText}>Generate 12 words</Text>
            </Pressable>
            <TextInput
              accessibilityLabel="12-word BIP39 recovery phrase"
              autoCapitalize="none"
              autoCorrect={false}
              editable={!isSubmitting}
              multiline
              onChangeText={updateMnemonic}
              placeholder="word1 word2 word3 … word12"
              spellCheck={false}
              style={[styles.input, styles.mnemonicInput]}
              testID="setup-mnemonic-input"
              textAlignVertical="top"
              value={mnemonic}
            />

            {isGeneratedPhrase ? (
              <View style={styles.generatedWarning} testID="generated-phrase-warning">
                <Text style={styles.generatedWarningTitle}>Save these words now</Text>
                <Text style={styles.generatedWarningText}>
                  Write them down in order and store them offline. They cannot be
                  recovered from this app. This phrase uses 128 bits of cryptographic
                  entropy, the maximum valid entropy for a 12-word BIP39 phrase.
                </Text>
                <Pressable
                  accessibilityLabel="I securely saved the generated recovery phrase"
                  accessibilityRole="checkbox"
                  accessibilityState={{ checked: hasSavedGeneratedPhrase }}
                  disabled={isSubmitting}
                  onPress={() => setHasSavedGeneratedPhrase((saved) => !saved)}
                  style={styles.confirmationRow}
                  testID="confirm-mnemonic-saved"
                >
                  <View style={[
                    styles.checkbox,
                    hasSavedGeneratedPhrase && styles.checkboxChecked,
                  ]}>
                    <Text style={styles.checkmark}>
                      {hasSavedGeneratedPhrase ? '✓' : ''}
                    </Text>
                  </View>
                  <Text style={styles.confirmationText}>
                    I have securely saved this recovery phrase
                  </Text>
                </Pressable>
              </View>
            ) : null}
          </View>

          {formError ? (
            <View accessibilityRole="alert" style={styles.errorCard} testID="setup-error">
              <Text selectable style={styles.errorText}>{formError}</Text>
            </View>
          ) : null}

          <View style={styles.actions}>
            <Pressable
              accessibilityRole="button"
              disabled={isSubmitting || (isGeneratedPhrase && !hasSavedGeneratedPhrase)}
              onPress={resetAndClose}
              style={styles.cancelButton}
            >
              <Text style={styles.cancelButtonText}>Cancel</Text>
            </Pressable>
            <Pressable
              accessibilityLabel="Initialize Satochip card"
              accessibilityRole="button"
              disabled={isSubmitting}
              onPress={submit}
              style={({ pressed }) => [
                styles.submitButton,
                pressed && styles.pressed,
                (isSubmitting || (isGeneratedPhrase && !hasSavedGeneratedPhrase)) && styles.disabled,
              ]}
              testID="confirm-card-setup-button"
            >
              {isSubmitting ? (
                <ActivityIndicator color="#ffffff" />
              ) : (
                <Text style={styles.submitButtonText}>Initialize card</Text>
              )}
            </Pressable>
          </View>
        </ScrollView>
      </KeyboardAvoidingView>
    </Modal>
  );
}

function FieldLabel({ children }: { children: string }) {
  return <Text style={styles.label}>{children}</Text>;
}

const styles = StyleSheet.create({
  container: { backgroundColor: '#f4f7fb', flex: 1 },
  content: { gap: 20, padding: 24 },
  header: { gap: 8 },
  title: { color: '#14213d', fontSize: 30, fontWeight: '800' },
  description: { color: '#526078', fontSize: 16, lineHeight: 23 },
  warning: { backgroundColor: '#fff7df', borderCurve: 'continuous', borderRadius: 14, gap: 6, padding: 16 },
  warningTitle: { color: '#72500a', fontSize: 15, fontWeight: '700' },
  warningText: { color: '#72500a', fontSize: 14, lineHeight: 20 },
  form: { gap: 8 },
  label: { color: '#26344d', fontSize: 15, fontWeight: '700', paddingTop: 8 },
  input: {
    backgroundColor: '#ffffff',
    borderColor: '#cbd3df',
    borderCurve: 'continuous',
    borderRadius: 12,
    borderWidth: 1,
    color: '#14213d',
    fontSize: 16,
    minHeight: 50,
    paddingHorizontal: 14,
    paddingVertical: 12,
  },
  mnemonicInput: { minHeight: 112 },
  generateButton: {
    alignItems: 'center',
    alignSelf: 'flex-start',
    borderColor: '#0b6e4f',
    borderCurve: 'continuous',
    borderRadius: 10,
    borderWidth: 1,
    justifyContent: 'center',
    minHeight: 42,
    paddingHorizontal: 14,
  },
  generateButtonText: { color: '#0b6e4f', fontSize: 15, fontWeight: '700' },
  generatedWarning: {
    backgroundColor: '#fff7df',
    borderCurve: 'continuous',
    borderRadius: 14,
    gap: 8,
    padding: 16,
  },
  generatedWarningTitle: { color: '#72500a', fontSize: 16, fontWeight: '800' },
  generatedWarningText: { color: '#72500a', fontSize: 14, lineHeight: 20 },
  confirmationRow: { alignItems: 'center', flexDirection: 'row', gap: 10, paddingTop: 4 },
  checkbox: {
    alignItems: 'center',
    borderColor: '#8b6b25',
    borderRadius: 5,
    borderWidth: 2,
    height: 24,
    justifyContent: 'center',
    width: 24,
  },
  checkboxChecked: { backgroundColor: '#0b6e4f', borderColor: '#0b6e4f' },
  checkmark: { color: '#ffffff', fontSize: 16, fontWeight: '900', lineHeight: 18 },
  confirmationText: { color: '#5f470f', flex: 1, fontSize: 14, fontWeight: '700' },
  errorCard: { backgroundColor: '#fff0f0', borderCurve: 'continuous', borderRadius: 14, padding: 16 },
  errorText: { color: '#8c2424', fontSize: 14, lineHeight: 20 },
  actions: { flexDirection: 'row', gap: 12 },
  cancelButton: { alignItems: 'center', borderRadius: 12, flex: 1, justifyContent: 'center', minHeight: 52 },
  cancelButtonText: { color: '#526078', fontSize: 16, fontWeight: '700' },
  submitButton: { alignItems: 'center', backgroundColor: '#0b6e4f', borderCurve: 'continuous', borderRadius: 12, flex: 2, justifyContent: 'center', minHeight: 52 },
  submitButtonText: { color: '#ffffff', fontSize: 16, fontWeight: '700' },
  pressed: { opacity: 0.8 },
  disabled: { opacity: 0.65 },
});
