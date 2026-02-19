import { CRYPTO_CONSTANTS }       from './constants';
import { CryptoEngine }           from './CryptoEngine';
import { CanaryService }          from './CanaryService';
import { SecureBuffer }           from './RootKeyService';
import { MemoryWiper }            from './MemoryWiper';

export interface RawFragment {
  index: number;
  data:  Uint8Array;
  size:  number;
}

export interface EncryptedFragment {
  index:         number;
  encryptedData: string;  // Base64: IV(12) || CT || Tag(16)
  aadB64:        string;  // Base64 AAD
  hmac:          string;  // Hex HMAC-SHA256 over encryptedData
  originalSize:  number;
}

export interface FragmentManifest {
  imageId:        string;
  chapterId:      string;
  totalFragments: number;
  totalSize:      number;
  fragments: Array<{
    index:         number;
    filename:      string;
    hmac:          string;
    originalSize:  number;
    encryptedSize: number;
  }>;
}

/**
 * FragmentEngine — deterministic storage layer.
 *
 * Responsibilities:
 *   1. Split raw image into randomized-size fragments
 *   2. Embed canary bytes (derived from ChapterRootKey) before encryption
 *   3. Encrypt each fragment with AES-256-GCM + unique IV, using ChapterRootKey
 *   4. Sign ciphertext with HMAC-SHA256 (encrypt-then-MAC)
 *   5. On decryption: verify MAC → decrypt → verify canary → strip canary
 *
 * The EphemeralKey layer (DisplayMutation) is NOT applied here.
 * FragmentEngine deals exclusively with stable, reproducible storage encryption.
 */
export class FragmentEngine {

  /** Split raw image data into randomized fragments. */
  static async split(raw: Uint8Array): Promise<RawFragment[]> {
    const fragments: RawFragment[] = [];
    let offset = 0, index = 0;

    while (offset < raw.length) {
      const remaining = raw.length - offset;
      const minSz     = Math.min(CRYPTO_CONSTANTS.FRAGMENT_MIN_SIZE, remaining);
      const maxSz     = Math.min(CRYPTO_CONSTANTS.FRAGMENT_MAX_SIZE, remaining);
      const size      = minSz + (maxSz > minSz ? Math.floor(Math.random() * (maxSz - minSz)) : 0);

      fragments.push({
        index,
        data: new Uint8Array(raw.buffer, raw.byteOffset + offset, size),
        size,
      });
      offset += size;
      index++;
    }
    return fragments;
  }

  /**
   * Encrypt a single fragment.
   * Sequence: embed canary → AES-256-GCM(ChapterRootKey) → HMAC(ciphertext)
   */
  static async encryptFragment(
    fragment:        RawFragment,
    chapterRootKey:  SecureBuffer,
    hmacKey:         SecureBuffer,
    imageId:         string
  ): Promise<EncryptedFragment> {
    // 1. Derive and embed canary
    const canary        = await CanaryService.derive(chapterRootKey, fragment.index);
    const dataWithCanary = CanaryService.embed(fragment.data, canary);
    MemoryWiper.wipeUint8Array(canary);

    // 2. Bind to (imageId, fragmentIndex) via AAD — prevents cross-image substitution
    const aadRaw  = Buffer.from(`${imageId}:${fragment.index}`, 'utf8');
    const aadB64  = aadRaw.toString('base64');

    const blob = await CryptoEngine.encrypt(
      chapterRootKey,
      dataWithCanary,
      new Uint8Array(aadRaw)
    );
    MemoryWiper.wipeUint8Array(dataWithCanary);

    // 3. Encrypt-then-MAC
    const encBytes = new Uint8Array(Buffer.from(blob.data, 'base64'));
    const hmac     = await CryptoEngine.hmacSHA256(hmacKey, encBytes);

    return {
      index:         fragment.index,
      encryptedData: blob.data,
      aadB64,
      hmac,
      originalSize:  fragment.size,
    };
  }

  /**
   * Decrypt a single fragment.
   * Sequence: verify HMAC → AES-256-GCM decrypt → verify canary → strip canary
   *
   * Returns raw fragment data. CALLER MUST WIPE with MemoryWiper.wipeUint8Array().
   */
  static async decryptFragment(
    ef:             EncryptedFragment,
    chapterRootKey: SecureBuffer,
    hmacKey:        SecureBuffer,
    imageId:        string
  ): Promise<Uint8Array> {
    // 1. Verify HMAC (fail fast)
    const encBytes = new Uint8Array(Buffer.from(ef.encryptedData, 'base64'));
    const hmacOk   = await CryptoEngine.verifyHMAC(hmacKey, encBytes, ef.hmac);
    if (!hmacOk) throw new Error(`HMAC mismatch on fragment ${ef.index} of ${imageId}`);

    // 2. Verify AAD binding
    const expectedAad = Buffer.from(`${imageId}:${ef.index}`, 'utf8').toString('base64');
    if (ef.aadB64 !== expectedAad) {
      throw new Error(`AAD mismatch on fragment ${ef.index} — possible substitution attack`);
    }

    // 3. AES-256-GCM decrypt (throws on tag mismatch)
    const decrypted = await CryptoEngine.decrypt(chapterRootKey, {
      data:  ef.encryptedData,
      aadB64: ef.aadB64,
    });

    // 4. Verify canary
    const canary   = await CanaryService.derive(chapterRootKey, ef.index);
    const canaryOk = CanaryService.verify(decrypted, canary);
    MemoryWiper.wipeUint8Array(canary);

    if (!canaryOk) {
      MemoryWiper.wipeUint8Array(decrypted);
      throw new Error(`Canary mismatch on fragment ${ef.index} — data tampering detected`);
    }

    // 5. Strip canary overhead
    const result = CanaryService.strip(decrypted);
    MemoryWiper.wipeUint8Array(decrypted);
    return result;
  }
}
