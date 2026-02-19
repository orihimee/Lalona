import * as SecureStore from 'expo-secure-store';
import { NativeModules }  from 'react-native';
import { CRYPTO_CONSTANTS }   from './constants';
import { DeviceBinding }      from './DeviceBinding';
import { MemoryWiper }        from './MemoryWiper';

const { NativeCrypto } = NativeModules;

/** Opaque handle for key buffers. Always pass as Uint8Array internally. */
export type SecureBuffer = Uint8Array;

const STORE_OPTS: SecureStore.SecureStoreOptions = {
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
};

/**
 * RootKeyService — Level 0 key management.
 *
 * Key derivation:
 *   RootSecret = PBKDF2-SHA512(
 *     password = SHA-256(deviceFingerprint) + userId,
 *     salt     = deviceSalt  [SecureStore / WHEN_UNLOCKED_THIS_DEVICE_ONLY],
 *     iter     = 310,000,
 *     dkLen    = 64 bytes
 *   )
 *
 * INVARIANT: RootSecret is NEVER stored anywhere. It is derived on-demand,
 * used atomically within a try/finally block, then wiped via MemoryWiper.
 */
export class RootKeyService {
  private static readonly SALT_BYTES = 32;

  /** Called once on first app launch to initialize the device-bound salt. */
  static async initDeviceSalt(userId: string): Promise<void> {
    const existing = await SecureStore.getItemAsync(
      CRYPTO_CONSTANTS.SECURE_STORE_DEVICE_SALT, STORE_OPTS
    );
    if (!existing) {
      const saltB64: string = await NativeCrypto.randomBytes(this.SALT_BYTES);
      await SecureStore.setItemAsync(
        CRYPTO_CONSTANTS.SECURE_STORE_DEVICE_SALT, saltB64, STORE_OPTS
      );
    }
    await SecureStore.setItemAsync(
      CRYPTO_CONSTANTS.SECURE_STORE_USER_ID, userId, STORE_OPTS
    );
  }

  /**
   * Derive and return RootSecret.
   *
   * ⚠️  CALLER CONTRACT:
   *   const secret = await RootKeyService.deriveRootSecret();
   *   try {
   *     // use secret
   *   } finally {
   *     MemoryWiper.wipeUint8Array(secret);
   *   }
   */
  static async deriveRootSecret(userId?: string): Promise<SecureBuffer> {
    const saltB64 = await SecureStore.getItemAsync(
      CRYPTO_CONSTANTS.SECURE_STORE_DEVICE_SALT, STORE_OPTS
    );
    if (!saltB64) throw new Error('Device salt missing — vault may be corrupted');

    const uid = userId ?? await SecureStore.getItemAsync(
      CRYPTO_CONSTANTS.SECURE_STORE_USER_ID, STORE_OPTS
    );
    if (!uid) throw new Error('User ID missing');

    const fp      = await DeviceBinding.getFingerprint();
    const pwdStr  = fp.hash + uid;
    const pwdB64  = Buffer.from(pwdStr, 'utf8').toString('base64');

    // Delegate expensive PBKDF2 to JNI
    const derivedB64: string = await NativeCrypto.pbkdf2(
      pwdB64,
      saltB64,
      CRYPTO_CONSTANTS.PBKDF2_ITERATIONS,
      CRYPTO_CONSTANTS.PBKDF2_KEY_LENGTH
    );

    DeviceBinding.clearCache();

    return new Uint8Array(Buffer.from(derivedB64, 'base64'));
  }

  /**
   * Irrevocably destroy the device salt.
   * Called on any security violation — permanently destroys all encrypted data.
   */
  static async destroyDeviceSalt(): Promise<void> {
    await Promise.allSettled([
      SecureStore.deleteItemAsync(CRYPTO_CONSTANTS.SECURE_STORE_DEVICE_SALT, STORE_OPTS),
      SecureStore.deleteItemAsync(CRYPTO_CONSTANTS.SECURE_STORE_USER_ID,    STORE_OPTS),
      SecureStore.deleteItemAsync(CRYPTO_CONSTANTS.SECURE_STORE_ROTATION_TS, STORE_OPTS),
    ]);
  }
}
