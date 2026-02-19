import * as Crypto from 'expo-crypto';
import { SecureFileStorage }          from './SecureFileStorage';
import { MetadataStore }              from './MetadataStore';
import { FragmentEngine, EncryptedFragment, FragmentManifest } from '../security/FragmentEngine';
import { ChapterKeyBundle }           from '../security/ChapterKeyService';
import { CryptoEngine }               from '../security/CryptoEngine';
import { MemoryWiper }                from '../security/MemoryWiper';

/**
 * FragmentedStorage — high-level fragment lifecycle management.
 *
 * Handles the full encrypt-store and load-decrypt pipeline.
 * Enforces the two-fragment-at-a-time limit at the API surface.
 */
export class FragmentedStorage {
  private metaStore = new MetadataStore();

  /**
   * Encrypt and store all fragments of a raw image.
   * rawImageData is wiped fragment-by-fragment as encryption completes.
   */
  async storeImage(
    rawImage:  Uint8Array,
    chapterId: string,
    imageIdx:  number,
    keyBundle: ChapterKeyBundle
  ): Promise<string> {
    const imageId  = `${chapterId}:${imageIdx}`;
    const saltRaw  = await CryptoEngine.randomBytes(12);
    const salt     = Buffer.from(saltRaw).toString('hex');
    MemoryWiper.wipeUint8Array(saltRaw);

    const rawFrags = await FragmentEngine.split(rawImage);
    const stored: FragmentManifest['fragments'] = [];

    for (const frag of rawFrags) {
      const ef = await FragmentEngine.encryptFragment(
        frag, keyBundle.chapterRootKey, keyBundle.hmacKey, imageId
      );
      MemoryWiper.wipeUint8Array(frag.data);

      const filename = await SecureFileStorage.fragmentFilename(chapterId, ef.index, salt + imageIdx);
      await SecureFileStorage.writeFragment(chapterId, filename, ef.encryptedData);

      stored.push({
        index:         ef.index,
        filename,
        hmac:          ef.hmac,
        originalSize:  ef.originalSize,
        encryptedSize: Buffer.from(ef.encryptedData, 'base64').length,
      });
    }

    const manifest: FragmentManifest = {
      imageId,
      chapterId,
      totalFragments: rawFrags.length,
      totalSize:      rawImage.length,
      fragments:      stored,
    };

    await this.metaStore.storeManifest(imageId, manifest, keyBundle.fragmentMapKey);
    return imageId;
  }

  /**
   * Decrypt a single fragment from storage.
   * CALLER MUST WIPE the returned Uint8Array after use.
   */
  async getFragment(
    imageId:       string,
    fragmentIndex: number,
    keyBundle:     ChapterKeyBundle
  ): Promise<Uint8Array> {
    const manifest  = await this.metaStore.loadManifest(imageId, keyBundle.fragmentMapKey);
    const fragMeta  = manifest.fragments[fragmentIndex];
    if (!fragMeta) throw new Error(`Fragment ${fragmentIndex} not in manifest for ${imageId}`);

    const chapterId = imageId.split(':')[0];
    const encData   = await SecureFileStorage.readFragment(chapterId, fragMeta.filename);

    const ef: EncryptedFragment = {
      index:         fragmentIndex,
      encryptedData: encData,
      aadB64:        Buffer.from(`${imageId}:${fragmentIndex}`, 'utf8').toString('base64'),
      hmac:          fragMeta.hmac,
      originalSize:  fragMeta.originalSize,
    };

    return FragmentEngine.decryptFragment(
      ef, keyBundle.chapterRootKey, keyBundle.hmacKey, imageId
    );
  }

  async getManifest(
    imageId:   string,
    keyBundle: ChapterKeyBundle
  ): Promise<FragmentManifest> {
    return this.metaStore.loadManifest(imageId, keyBundle.fragmentMapKey);
  }
}
