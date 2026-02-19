import * as SecureStore           from 'expo-secure-store';
import { NativeModules }          from 'react-native';
import { CRYPTO_CONSTANTS, HKDF_INFO_LABELS } from './constants';
import { RootKeyService, SecureBuffer } from './RootKeyService';
import { MemoryWiper }            from './MemoryWiper';

const { NativeCrypto } = NativeModules;

const STORE_OPTS: SecureStore.SecureStoreOptions = {
  keychainAccessible: SecureStore.WHEN_UNLOCKED_THIS_DEVICE_ONLY,
};

export interface WrappedChapterKey {
  wrappedB64:        string;  // AES-GCM(wrappingKey, chapterRootKey)
  rotationTimestamp: number;
  version:           number;
}

/**
 * KeyRotationService — weekly wrapped-key rotation.
 *
 * Encrypted fragment files are NEVER re-encrypted during rotation.
 * Only the WrappedChapterKey envelope is re-wrapped with new material.
 *
 * Rotation strategy:
 *   - Store a rotation version counter in SecureStore
 *   - WrappingKey = HKDF(RootSecret, "wrap:" + chapterId + ":" + version, "chapter-key-wrap")
 *   - On rotation: increment version, re-derive wrappingKey, re-encrypt stored chapterRootKey
 */
export class KeyRotationService {
  static async isRotationDue(): Promise<boolean> {
    const tsStr = await SecureStore.getItemAsync(
      CRYPTO_CONSTANTS.SECURE_STORE_ROTATION_TS, STORE_OPTS
    );
    if (!tsStr) return true;
    return (Date.now() - parseInt(tsStr, 10)) >= CRYPTO_CONSTANTS.KEY_ROTATION_INTERVAL_MS;
  }

  static async wrapChapterKey(
    chapterRootKey: SecureBuffer,
    rootSecret:     SecureBuffer,
    chapterId:      string,
    version:        number = 1
  ): Promise<WrappedChapterKey> {
    const wrappingKey = await this._deriveWrappingKey(rootSecret, chapterId, version);
    try {
      const keyB64 = Buffer.from(chapterRootKey).toString('base64');
      const encB64 = Buffer.from(wrappingKey).toString('base64');

      const wrappedB64: string = await NativeCrypto.aesGCMEncrypt(encB64, keyB64, null);
      return { wrappedB64, rotationTimestamp: Date.now(), version };
    } finally {
      MemoryWiper.wipeUint8Array(wrappingKey);
    }
  }

  /** Unwrap — caller MUST wipe returned key. */
  static async unwrapChapterKey(
    wrapped:    WrappedChapterKey,
    rootSecret: SecureBuffer,
    chapterId:  string
  ): Promise<SecureBuffer> {
    const wrappingKey = await this._deriveWrappingKey(rootSecret, chapterId, wrapped.version);
    try {
      const encB64  = Buffer.from(wrappingKey).toString('base64');
      const ptB64:  string = await NativeCrypto.aesGCMDecrypt(encB64, wrapped.wrappedB64, null);
      if (!ptB64) throw new Error('Failed to unwrap chapter key — possible version mismatch');
      return new Uint8Array(Buffer.from(ptB64, 'base64'));
    } finally {
      MemoryWiper.wipeUint8Array(wrappingKey);
    }
  }

  static async rotateWrappedKey(
    wrapped:    WrappedChapterKey,
    rootSecret: SecureBuffer,
    chapterId:  string
  ): Promise<WrappedChapterKey> {
    const chapterRootKey = await this.unwrapChapterKey(wrapped, rootSecret, chapterId);
    try {
      return await this.wrapChapterKey(chapterRootKey, rootSecret, chapterId, wrapped.version + 1);
    } finally {
      MemoryWiper.wipeUint8Array(chapterRootKey);
    }
  }

  static async recordRotationTimestamp(): Promise<void> {
    await SecureStore.setItemAsync(
      CRYPTO_CONSTANTS.SECURE_STORE_ROTATION_TS,
      Date.now().toString(),
      STORE_OPTS
    );
  }

  private static async _deriveWrappingKey(
    rootSecret: SecureBuffer,
    chapterId:  string,
    version:    number
  ): Promise<SecureBuffer> {
    const ikmB64  = Buffer.from(rootSecret).toString('base64');
    const saltB64 = Buffer.from(`wrap:${chapterId}:${version}`, 'utf8').toString('base64');

    const b64: string = await NativeCrypto.hkdf(
      ikmB64, saltB64,
      HKDF_INFO_LABELS.KEY_WRAP,
      32
    );
    return new Uint8Array(Buffer.from(b64, 'base64'));
  }
}
