import * as SecureStore from 'expo-secure-store';
import * as Crypto from 'expo-crypto';
import CryptoJS from 'crypto-js';
import { CRYPTO_CONSTANTS } from './constants';
import { DeviceBinding } from './DeviceBinding';
import { MemoryWiper } from './MemoryWiper';

export type SecureBuffer = Uint8Array;

const STORE_OPTS: SecureStore.SecureStoreOptions = {
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
};

export class RootKeyService {
  private static readonly SALT_BYTES = 32;

  static async initDeviceSalt(userId: string): Promise<void> {
    const existing = await SecureStore.getItemAsync(
      CRYPTO_CONSTANTS.SECURE_STORE_DEVICE_SALT,
      STORE_OPTS
    );

    if (!existing) {
      const saltBytes = await Crypto.getRandomBytesAsync(this.SALT_BYTES);
      const saltB64 = Buffer.from(saltBytes).toString('base64');

      await SecureStore.setItemAsync(
        CRYPTO_CONSTANTS.SECURE_STORE_DEVICE_SALT,
        saltB64,
        STORE_OPTS
      );
    }

    await SecureStore.setItemAsync(
      CRYPTO_CONSTANTS.SECURE_STORE_USER_ID,
      userId,
      STORE_OPTS
    );
  }

  static async deriveRootSecret(userId?: string): Promise<SecureBuffer> {
    const saltB64 = await SecureStore.getItemAsync(
      CRYPTO_CONSTANTS.SECURE_STORE_DEVICE_SALT,
      STORE_OPTS
    );
    if (!saltB64) throw new Error('Device salt missing');

    const uid =
      userId ??
      (await SecureStore.getItemAsync(
        CRYPTO_CONSTANTS.SECURE_STORE_USER_ID,
        STORE_OPTS
      ));
    if (!uid) throw new Error('User ID missing');

    const fp = await DeviceBinding.getFingerprint();
    const pwdStr = fp.hash + uid;

    const saltWordArray = CryptoJS.enc.Base64.parse(saltB64);

    const key = CryptoJS.PBKDF2(pwdStr, saltWordArray, {
      keySize: CRYPTO_CONSTANTS.PBKDF2_KEY_LENGTH / 4,
      iterations: CRYPTO_CONSTANTS.PBKDF2_ITERATIONS,
      hasher: CryptoJS.algo.SHA512,
    });

    DeviceBinding.clearCache();

    const keyBytes = Uint8Array.from(
      Buffer.from(key.toString(CryptoJS.enc.Base64), 'base64')
    );

    return keyBytes;
  }

  static async destroyDeviceSalt(): Promise<void> {
    await Promise.allSettled([
      SecureStore.deleteItemAsync(
        CRYPTO_CONSTANTS.SECURE_STORE_DEVICE_SALT,
        STORE_OPTS
      ),
      SecureStore.deleteItemAsync(
        CRYPTO_CONSTANTS.SECURE_STORE_USER_ID,
        STORE_OPTS
      ),
      SecureStore.deleteItemAsync(
        CRYPTO_CONSTANTS.SECURE_STORE_ROTATION_TS,
        STORE_OPTS
      ),
    ]);
  }
}