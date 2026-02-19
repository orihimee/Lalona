import { NativeModules }          from 'react-native';
import { HKDF_INFO_LABELS }       from './constants';
import { MemoryWiper }            from './MemoryWiper';
import { RootKeyService, SecureBuffer } from './RootKeyService';

const { NativeCrypto } = NativeModules;

export interface ChapterKeyBundle {
  chapterRootKey:  SecureBuffer;
  hmacKey:         SecureBuffer;
  metadataKey:     SecureBuffer;
  fragmentMapKey:  SecureBuffer;
}

/**
 * ChapterKeyService — Level 1 key management.
 *
 * ChapterRootKey = HKDF-SHA256(
 *   IKM  = RootSecret,
 *   salt = UTF8(chapterId),
 *   info = "chapter-root",
 *   L    = 32
 * )
 *
 * Sub-keys (hmacKey, metadataKey, fragmentMapKey) are derived from
 * ChapterRootKey with distinct info labels and a zero salt — they are
 * domain-separated derivatives, never raw chapterRootKey aliases.
 *
 * No raw key material is ever written to persistent storage.
 */
export class ChapterKeyService {
  private static readonly KEY_LEN = 32; // 256 bits

  static async deriveChapterRootKey(
    rootSecret:  SecureBuffer,
    chapterId:   string
  ): Promise<SecureBuffer> {
    const ikmB64  = Buffer.from(rootSecret).toString('base64');
    const saltB64 = Buffer.from(chapterId, 'utf8').toString('base64');

    const b64: string = await NativeCrypto.hkdf(
      ikmB64, saltB64,
      HKDF_INFO_LABELS.CHAPTER_ROOT,
      this.KEY_LEN
    );

    return new Uint8Array(Buffer.from(b64, 'base64'));
  }

  static async deriveChapterKeyBundle(
    rootSecret: SecureBuffer,
    chapterId:  string
  ): Promise<ChapterKeyBundle> {
    const chapterRootKey = await this.deriveChapterRootKey(rootSecret, chapterId);

    const [hmacKey, metadataKey, fragmentMapKey] = await Promise.all([
      this._subKey(chapterRootKey, HKDF_INFO_LABELS.HMAC_KEY),
      this._subKey(chapterRootKey, HKDF_INFO_LABELS.METADATA_KEY),
      this._subKey(chapterRootKey, HKDF_INFO_LABELS.FRAGMENT_MAP),
    ]);

    return { chapterRootKey, hmacKey, metadataKey, fragmentMapKey };
  }

  /**
   * Convenience: derive full bundle from scratch, wiping RootSecret in finally.
   */
  static async deriveFromScratch(chapterId: string): Promise<ChapterKeyBundle> {
    const rootSecret = await RootKeyService.deriveRootSecret();
    try {
      return await this.deriveChapterKeyBundle(rootSecret, chapterId);
    } finally {
      MemoryWiper.wipeUint8Array(rootSecret);
    }
  }

  static wipeBundle(bundle: ChapterKeyBundle): void {
    MemoryWiper.wipeUint8Array(bundle.chapterRootKey);
    MemoryWiper.wipeUint8Array(bundle.hmacKey);
    MemoryWiper.wipeUint8Array(bundle.metadataKey);
    MemoryWiper.wipeUint8Array(bundle.fragmentMapKey);
    // Clear object references
    (bundle as any).chapterRootKey  = null;
    (bundle as any).hmacKey         = null;
    (bundle as any).metadataKey     = null;
    (bundle as any).fragmentMapKey  = null;
  }

  private static async _subKey(
    parent:    SecureBuffer,
    infoLabel: string
  ): Promise<SecureBuffer> {
    const ikmB64   = Buffer.from(parent).toString('base64');
    const zeroSalt = Buffer.alloc(32).toString('base64');

    const b64: string = await NativeCrypto.hkdf(
      ikmB64, zeroSalt, infoLabel, this.KEY_LEN
    );
    return new Uint8Array(Buffer.from(b64, 'base64'));
  }
}
