import { SecureFileStorage }    from './SecureFileStorage';
import { FragmentedStorage }    from './FragmentedStorage';
import { MetadataStore }        from './MetadataStore';
import { ChapterKeyService }    from '../security/ChapterKeyService';
import { KeyRotationService }   from '../security/KeyRotationService';
import { MemoryWiper }          from '../security/MemoryWiper';

export interface ChapterMetadata {
  chapterId:    string;
  title:        string;
  totalImages:  number;
  imageIds:     string[];
  downloadedAt: number;
}

/**
 * ChapterRepository — top-level chapter management API.
 *
 * Coordinates the full download → encrypt → store pipeline (online flow)
 * and the load → decrypt → display → wipe pipeline (offline flow).
 */
export class ChapterRepository {
  private fragmentedStorage = new FragmentedStorage();
  private metaStore         = new MetadataStore();

  // ── Online flow: ingest raw images ───────────────────────────────────────

  /**
   * Encrypt and store all images of a chapter.
   * rawImages[i] is wiped from memory after its fragments are encrypted.
   * On completion, no plaintext remains — only encrypted .dat files.
   */
  async storeChapter(
    chapterId:  string,
    title:      string,
    rawImages:  Uint8Array[]
  ): Promise<ChapterMetadata> {
    await SecureFileStorage.initialize();

    const keyBundle = await ChapterKeyService.deriveFromScratch(chapterId);
    const imageIds: string[] = [];

    try {
      for (let i = 0; i < rawImages.length; i++) {
        const id = await this.fragmentedStorage.storeImage(
          rawImages[i], chapterId, i, keyBundle
        );
        imageIds.push(id);
        MemoryWiper.wipeUint8Array(rawImages[i]); // wipe raw image immediately
      }
    } finally {
      ChapterKeyService.wipeBundle(keyBundle);
    }

    const meta: ChapterMetadata = {
      chapterId,
      title,
      totalImages:  rawImages.length,
      imageIds,
      downloadedAt: Date.now(),
    };

    // Separately derive bundle just for metadata storage
    const metaBundle = await ChapterKeyService.deriveFromScratch(chapterId);
    try {
      await this.metaStore.storeChapterMeta(
        chapterId,
        meta as unknown as Record<string, unknown>,
        metaBundle.metadataKey
      );
    } finally {
      ChapterKeyService.wipeBundle(metaBundle);
    }

    return meta;
  }

  // ── Offline flow: query stored metadata ──────────────────────────────────

  async getChapterMetadata(chapterId: string): Promise<ChapterMetadata | null> {
    const keyBundle = await ChapterKeyService.deriveFromScratch(chapterId);
    try {
      const raw = await this.metaStore.loadChapterMeta(chapterId, keyBundle.metadataKey);
      return raw as unknown as ChapterMetadata | null;
    } finally {
      ChapterKeyService.wipeBundle(keyBundle);
    }
  }

  async isStored(chapterId: string): Promise<boolean> {
    return SecureFileStorage.chapterExists(chapterId);
  }

  async deleteChapter(chapterId: string): Promise<void> {
    await SecureFileStorage.deleteChapter(chapterId);
  }

  // ── Key rotation ──────────────────────────────────────────────────────────

  async rotateKeyIfDue(chapterId: string): Promise<void> {
    if (!await KeyRotationService.isRotationDue()) return;

    const wrapped = await this.metaStore.loadWrappedKey(chapterId);
    if (!wrapped) return;

    const rootSecret = await (await import('../security/RootKeyService')).RootKeyService.deriveRootSecret();
    try {
      const newWrapped = await KeyRotationService.rotateWrappedKey(wrapped, rootSecret, chapterId);
      await this.metaStore.storeWrappedKey(chapterId, newWrapped);
    } finally {
      MemoryWiper.wipeUint8Array(rootSecret);
      await KeyRotationService.recordRotationTimestamp();
    }
  }
}
