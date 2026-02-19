import { NativeModules } from 'react-native';
import { SecureBuffer }  from './RootKeyService';
import { MemoryWiper }   from './MemoryWiper';

const { NativeCrypto } = NativeModules;

export interface EncryptedBlob {
  data:  string;        // Base64: IV(12) || Ciphertext || GCM-Tag(16)
  aadB64?: string;      // Base64-encoded AAD (stored for verification, not secret)
}

/**
 * CryptoEngine — thin TypeScript wrapper around NativeCryptoModule.
 *
 * All sensitive operations are executed inside JNI stack frames.
 * This layer handles Base64 encoding/decoding and AAD binding.
 */
export class CryptoEngine {
  static async encrypt(
    key:       SecureBuffer,
    plaintext: Uint8Array,
    aad?:      Uint8Array
  ): Promise<EncryptedBlob> {
    const keyB64 = Buffer.from(key).toString('base64');
    const ptB64  = Buffer.from(plaintext).toString('base64');
    const aadB64 = aad ? Buffer.from(aad).toString('base64') : null;

    const data: string = await NativeCrypto.aesGCMEncrypt(keyB64, ptB64, aadB64);
    return { data, aadB64: aadB64 ?? undefined };
  }

  /**
   * Returns a Uint8Array that CALLER MUST WIPE after use.
   * Throws on authentication failure.
   */
  static async decrypt(
    key:  SecureBuffer,
    blob: EncryptedBlob
  ): Promise<Uint8Array> {
    const keyB64  = Buffer.from(key).toString('base64');
    const aadB64  = blob.aadB64 ?? null;

    const ptB64: string = await NativeCrypto.aesGCMDecrypt(keyB64, blob.data, aadB64);
    if (!ptB64) {
      throw new Error('GCM authentication tag mismatch — fragment integrity violated');
    }

    return new Uint8Array(Buffer.from(ptB64, 'base64'));
  }

  /** Returns lowercase hex HMAC-SHA256. */
  static async hmacSHA256(key: SecureBuffer, data: Uint8Array): Promise<string> {
    const keyB64  = Buffer.from(key).toString('base64');
    const dataB64 = Buffer.from(data).toString('base64');
    return NativeCrypto.hmacSHA256(keyB64, dataB64);
  }

  /** Constant-time HMAC verification. */
  static async verifyHMAC(
    key:         SecureBuffer,
    data:        Uint8Array,
    expectedHex: string
  ): Promise<boolean> {
    const computed = await this.hmacSHA256(key, data);
    if (computed.length !== expectedHex.length) return false;
    let diff = 0;
    for (let i = 0; i < computed.length; i++) {
      diff |= computed.charCodeAt(i) ^ expectedHex.charCodeAt(i);
    }
    return diff === 0;
  }

  static async randomBytes(length: number): Promise<Uint8Array> {
    const b64: string = await NativeCrypto.randomBytes(length);
    return new Uint8Array(Buffer.from(b64, 'base64'));
  }
}
