import { useState, useEffect, useCallback, useRef } from 'react';
import { ChapterKeyService, ChapterKeyBundle }  from '../security/ChapterKeyService';
import { FragmentedStorage }                    from '../storage/FragmentedStorage';
import { ChapterRepository, ChapterMetadata }   from '../storage/ChapterRepository';
import { VirtualDecryptor }                     from '../runtime/VirtualDecryptor';
import { DisplayMutation }                      from '../runtime/DisplayMutation';
import { EphemeralKeyService }                  from '../security/EphemeralKeyService';
import { RuntimeEntropy }                       from '../runtime/RuntimeEntropy';
import { MemoryWiper }                          from '../security/MemoryWiper';
import { LifecycleManager }                     from '../core/LifecycleManager';
import { SecurityOrchestrator }                 from '../core/SecurityOrchestrator';
import { CRYPTO_CONSTANTS }                     from '../security/constants';

export interface ImageSlot {
  mutatedData: Uint8Array | null;
  isLoading:   boolean;
  error:       string | null;
  index:       number;
}

export interface UseSecureChapterReturn {
  images:           ImageSlot[];
  metadata:         ChapterMetadata | null;
  isReady:          boolean;
  loadPage:         (pageIdx: number) => Promise<void>;
  releasePage:      (pageIdx: number) => void;
  setScrollVelocity: (v: number) => void;
}

/**
 * useSecureChapter — the single hook that drives secure chapter reading.
 *
 * Memory policy:
 *   - At most MAX_DECRYPTED_FRAGMENTS (2) live buffers at any time
 *   - Each buffer is wiped after 5s regardless of render state
 *   - All buffers wiped on background transition via LifecycleManager
 *   - ChapterKeyBundle wiped on unmount and background
 */
export function useSecureChapter(chapterId: string): UseSecureChapterReturn {
  const [images,   setImages]   = useState<ImageSlot[]>([]);
  const [metadata, setMetadata] = useState<ChapterMetadata | null>(null);
  const [isReady,  setIsReady]  = useState(false);

  const keyBundleRef  = useRef<ChapterKeyBundle | null>(null);
  const storageRef    = useRef(new FragmentedStorage());
  const liveBuffers   = useRef<Map<number, Uint8Array>>(new Map());
  const frameCounter  = useRef(0);
  const bootTime      = useRef(Date.now());
  const scrollVel     = useRef(0);

  // ── Wipe everything ───────────────────────────────────────────────────────
  const wipeAll = useCallback(() => {
    MemoryWiper.wipeAll(liveBuffers.current);
    if (keyBundleRef.current) {
      ChapterKeyService.wipeBundle(keyBundleRef.current);
      keyBundleRef.current = null;
    }
    setImages(prev => prev.map(s => ({ ...s, mutatedData: null })));
  }, []);

  // ── Register background wipe ──────────────────────────────────────────────
  useEffect(() => {
    const unregister = LifecycleManager.onBackground(wipeAll);
    return () => { unregister(); wipeAll(); };
  }, [wipeAll]);

  // ── Initialize chapter ────────────────────────────────────────────────────
  useEffect(() => {
    let cancelled = false;
    (async () => {
      try {
        await SecurityOrchestrator.periodicCheck();

        const repo = new ChapterRepository();
        const meta = await repo.getChapterMetadata(chapterId);
        if (cancelled) return;

        if (!meta) { setIsReady(true); return; }
        setMetadata(meta);
        setImages(meta.imageIds.map((_, i) => ({
          mutatedData: null, isLoading: false, error: null, index: i
        })));

        keyBundleRef.current = await ChapterKeyService.deriveFromScratch(chapterId);
        if (!cancelled) setIsReady(true);
      } catch (e) {
        if (!cancelled) {
          setImages([{ mutatedData: null, isLoading: false,
            error: (e as Error).message, index: 0 }]);
          setIsReady(true);
        }
      }
    })();
    return () => { cancelled = true; };
  }, [chapterId]);

  // ── Page management ───────────────────────────────────────────────────────
  const releasePage = useCallback((idx: number) => {
    const buf = liveBuffers.current.get(idx);
    if (buf) {
      MemoryWiper.wipeUint8Array(buf);
      liveBuffers.current.delete(idx);
      LifecycleManager.untrackBuffer(buf);
    }
    setImages(prev => prev.map((s, i) => i === idx ? { ...s, mutatedData: null } : s));
  }, []);

  const loadPage = useCallback(async (pageIdx: number) => {
    if (!keyBundleRef.current || !metadata) return;
    if (liveBuffers.current.has(pageIdx)) return; // already loaded

    // Enforce max-2-fragments policy — evict oldest
    if (liveBuffers.current.size >= CRYPTO_CONSTANTS.MAX_DECRYPTED_FRAGMENTS) {
      const oldest = liveBuffers.current.keys().next().value as number;
      releasePage(oldest);
    }

    setImages(prev => prev.map((s, i) =>
      i === pageIdx ? { ...s, isLoading: true, error: null } : s
    ));

    try {
      const imageId = metadata.imageIds[pageIdx];

      // Build entropy bundle for this render call
      frameCounter.current++;
      RuntimeEntropy.incrementFrameCounter();
      const entropy = await RuntimeEntropy.buildBundle(0 /* first fragment */);

      // Get encrypted fragment metadata
      const manifest   = await storageRef.current.getManifest(imageId, keyBundleRef.current);
      const firstFragMeta = manifest.fragments[0];
      const encData    = await (await import('../storage/SecureFileStorage')).SecureFileStorage
        .readFragment(metadata.chapterId, firstFragMeta.filename);

      const ef = {
        index: 0,
        encryptedData: encData,
        aadB64: Buffer.from(`${imageId}:0`, 'utf8').toString('base64'),
        hmac: firstFragMeta.hmac,
        originalSize: firstFragMeta.originalSize,
      };

      // Build and execute virtual program
      const program  = VirtualDecryptor.buildProgram(0, entropy);
      const mutated  = await VirtualDecryptor.execute(
        program, ef, keyBundleRef.current, imageId
      );

      liveBuffers.current.set(pageIdx, mutated);
      LifecycleManager.trackBuffer(mutated);

      setImages(prev => prev.map((s, i) =>
        i === pageIdx ? { ...s, mutatedData: mutated, isLoading: false } : s
      ));

      // Auto-release after 5s — prevents long-lived plaintext in heap
      setTimeout(() => releasePage(pageIdx), 5_000);

    } catch (e) {
      setImages(prev => prev.map((s, i) =>
        i === pageIdx ? { ...s, isLoading: false, error: (e as Error).message } : s
      ));
    }
  }, [keyBundleRef, metadata, releasePage]);

  const setScrollVelocity = useCallback((v: number) => {
    scrollVel.current = v;
    RuntimeEntropy.updateScrollVelocity(v);
  }, []);

  return { images, metadata, isReady, loadPage, releasePage, setScrollVelocity };
}
