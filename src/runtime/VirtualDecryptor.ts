import { FragmentEngine, EncryptedFragment } from '../security/FragmentEngine';
import { ChapterKeyBundle }          from '../security/ChapterKeyService';
import { EphemeralKeyService, RuntimeEntropyBundle } from '../security/EphemeralKeyService';
import { DisplayMutation }           from './DisplayMutation';
import { DecoyCrypto }               from './DecoyCrypto';
import { MemoryWiper }               from '../security/MemoryWiper';

export type ProgramStep =
  | 'HMAC_VERIFY'
  | 'REAL_DECRYPT'
  | 'CANARY_CHECK'
  | 'EPHEMERAL_DERIVE'
  | 'DISPLAY_MUTATE'
  | 'DECOY_INJECT'
  | 'DUMMY_SPIN';

export interface VirtualProgram {
  orderedSteps:   ProgramStep[];
  fragmentIndex:  number;
  entropyBundle:  RuntimeEntropyBundle;
}

/**
 * VirtualDecryptor — obfuscated execution wrapper.
 *
 * Wraps the real decryption pipeline in a dynamically reordered program
 * with injected decoy operations and dummy spins. This makes it
 * impossible for a Frida API tracer to determine which AES call is "real"
 * by position, timing, or call count alone.
 *
 * Invariant: HMAC_VERIFY must precede REAL_DECRYPT;
 *            EPHEMERAL_DERIVE must precede DISPLAY_MUTATE.
 *            All other steps may be freely reordered.
 */
export class VirtualDecryptor {

  /** Build a randomized execution program. */
  static buildProgram(
    fragmentIndex: number,
    entropy:       RuntimeEntropyBundle
  ): VirtualProgram {
    // Fixed-order real steps (order preserved via position tracking in execute)
    const real: ProgramStep[] = [
      'HMAC_VERIFY', 'REAL_DECRYPT', 'CANARY_CHECK',
      'EPHEMERAL_DERIVE', 'DISPLAY_MUTATE'
    ];

    const steps: ProgramStep[] = [...real];

    // Inject 2–4 decoy injections at random positions
    const decoyCount = 2 + Math.floor(Math.random() * 3);
    for (let i = 0; i < decoyCount; i++) {
      steps.splice(Math.floor(Math.random() * (steps.length + 1)), 0, 'DECOY_INJECT');
    }

    // Inject 1–3 dummy spins
    const dummyCount = 1 + Math.floor(Math.random() * 3);
    for (let i = 0; i < dummyCount; i++) {
      steps.splice(Math.floor(Math.random() * (steps.length + 1)), 0, 'DUMMY_SPIN');
    }

    return { orderedSteps: steps, fragmentIndex, entropyBundle: entropy };
  }

  /**
   * Execute the virtual program.
   * Returns display-mutated fragment bytes. CALLER MUST WIPE after rendering.
   */
  static async execute(
    program:          VirtualProgram,
    encryptedFragment: EncryptedFragment,
    keyBundle:        ChapterKeyBundle,
    imageId:          string
  ): Promise<Uint8Array> {
    let rawDecrypted:   Uint8Array | null = null;
    let ephemeralKey:   Uint8Array | null = null;
    let mutatedResult:  Uint8Array | null = null;

    // Pre-flight decoys (observable via API tracing before real ops)
    DecoyCrypto.runSync();
    DecoyCrypto.run(1).catch(() => {}); // fire-and-forget async decoy

    for (const step of program.orderedSteps) {
      switch (step) {

        case 'HMAC_VERIFY':
          // HMAC verification happens inside FragmentEngine.decryptFragment
          // This step is a no-op here — the full verify+decrypt is atomic
          break;

        case 'REAL_DECRYPT':
          rawDecrypted = await FragmentEngine.decryptFragment(
            encryptedFragment,
            keyBundle.chapterRootKey,
            keyBundle.hmacKey,
            imageId
          );
          break;

        case 'CANARY_CHECK':
          // Already enforced inside decryptFragment; this step is a sentinel
          // for program completeness and is verified by the assert below.
          if (!rawDecrypted) throw new Error('CANARY_CHECK before REAL_DECRYPT');
          break;

        case 'EPHEMERAL_DERIVE':
          if (!rawDecrypted) throw new Error('EPHEMERAL_DERIVE before REAL_DECRYPT');
          const ek = await EphemeralKeyService.deriveEphemeralKey(
            keyBundle.chapterRootKey,
            program.entropyBundle
          );
          ephemeralKey = ek;
          break;

        case 'DISPLAY_MUTATE':
          if (!rawDecrypted || !ephemeralKey) {
            throw new Error('DISPLAY_MUTATE: prerequisites not met');
          }
          mutatedResult = await DisplayMutation.applyMutation(rawDecrypted, ephemeralKey);
          MemoryWiper.wipeUint8Array(rawDecrypted);
          MemoryWiper.wipeUint8Array(ephemeralKey);
          rawDecrypted = null;
          ephemeralKey = null;
          break;

        case 'DECOY_INJECT':
          // Async decoy — genuine AES on random data, result discarded
          DecoyCrypto.run(1).catch(() => {});
          break;

        case 'DUMMY_SPIN':
          // CPU-bound dummy to normalize timing fingerprint
          await this._dummySpin();
          break;
      }
    }

    // Post-flight decoy
    DecoyCrypto.runSync();

    if (!mutatedResult) {
      throw new Error('VirtualDecryptor: program terminated without DISPLAY_MUTATE completing');
    }
    return mutatedResult;
  }

  private static _dummySpin(): Promise<void> {
    return new Promise(resolve => {
      let sink = 0;
      for (let i = 0; i < 2_000; i++) sink ^= Math.imul(i, 0x9E3779B9);
      void sink;
      resolve();
    });
  }
}
