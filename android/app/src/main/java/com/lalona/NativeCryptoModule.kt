package com.lalona

import com.facebook.react.bridge.*
import com.facebook.react.module.annotations.ReactModule
import java.util.Base64

/**
 * NativeCryptoModule
 *
 * Bridges JS ↔ native crypto operations. All key material crosses the bridge
 * as Base64-encoded strings. Raw byte arrays are constructed only inside
 * JNI stack frames and wiped via secure_wipe() before return.
 *
 * The Kotlin layer additionally fills JVM byte arrays with 0 after encoding
 * to minimize the GC window for key material in the Java heap.
 */
@ReactModule(name = NativeCryptoModule.NAME)
class NativeCryptoModule(reactContext: ReactApplicationContext) :
    NativeCryptoModuleSpec(reactContext) {

    companion object {
        const val NAME = "NativeCrypto"

        init {
            System.loadLibrary("lalona_crypto")
        }
    }

    override fun getName(): String = NAME

    // ── Native declarations (implemented in crypto_core.c) ────────────────

    private external fun nativePBKDF2(
        password:   ByteArray,
        salt:       ByteArray,
        iterations: Int,
        keyLength:  Int
    ): ByteArray?

    private external fun nativeHKDF(
        ikm:       ByteArray,
        salt:      ByteArray,
        info:      ByteArray,
        outLength: Int
    ): ByteArray?

    private external fun nativeAESGCMEncrypt(
        key:       ByteArray,
        plaintext: ByteArray,
        aad:       ByteArray?
    ): ByteArray?

    private external fun nativeAESGCMDecrypt(
        key:   ByteArray,
        blob:  ByteArray,
        aad:   ByteArray?
    ): ByteArray?

    private external fun nativeHMACSHA256(
        key:  ByteArray,
        data: ByteArray
    ): ByteArray?

    private external fun nativeRandomBytes(length: Int): ByteArray?

    // ── Bridge helpers ────────────────────────────────────────────────────

    private fun String.decodeB64(): ByteArray = Base64.getDecoder().decode(this)
    private fun ByteArray.encodeB64(): String = Base64.getEncoder().encodeToString(this)

    /** Encode result to B64, then zero the source array. */
    private fun ByteArray.encodeB64ThenWipe(): String {
        val encoded = this.encodeB64()
        this.fill(0)
        return encoded
    }

    // ── PBKDF2 ────────────────────────────────────────────────────────────

    @ReactMethod
    override fun pbkdf2(
        passwordB64: String,
        saltB64:     String,
        iterations:  Double,
        keyLength:   Double,
        promise:     Promise
    ) {
        try {
            val pwd  = passwordB64.decodeB64()
            val salt = saltB64.decodeB64()

            val result = nativePBKDF2(pwd, salt, iterations.toInt(), keyLength.toInt())

            pwd.fill(0)
            salt.fill(0)

            if (result != null) promise.resolve(result.encodeB64ThenWipe())
            else promise.reject("PBKDF2_FAILED", "Derivation returned null")
        } catch (e: Exception) {
            promise.reject("PBKDF2_ERROR", e.message)
        }
    }

    // ── HKDF ──────────────────────────────────────────────────────────────

    @ReactMethod
    override fun hkdf(
        ikmB64:    String,
        saltB64:   String,
        infoLabel: String,
        outLength: Double,
        promise:   Promise
    ) {
        try {
            val ikm  = ikmB64.decodeB64()
            val salt = saltB64.decodeB64()
            val info = infoLabel.toByteArray(Charsets.UTF_8)

            val result = nativeHKDF(ikm, salt, info, outLength.toInt())

            ikm.fill(0)
            salt.fill(0)

            if (result != null) promise.resolve(result.encodeB64ThenWipe())
            else promise.reject("HKDF_FAILED", "Derivation returned null")
        } catch (e: Exception) {
            promise.reject("HKDF_ERROR", e.message)
        }
    }

    // ── AES-256-GCM Encrypt ───────────────────────────────────────────────

    @ReactMethod
    override fun aesGCMEncrypt(
        keyB64:       String,
        plaintextB64: String,
        aadB64:       String?,
        promise:      Promise
    ) {
        try {
            val key = keyB64.decodeB64()
            val pt  = plaintextB64.decodeB64()
            val aad = aadB64?.decodeB64()

            val result = nativeAESGCMEncrypt(key, pt, aad)

            key.fill(0)
            pt.fill(0)
            aad?.fill(0)

            if (result != null) promise.resolve(result.encodeB64ThenWipe())
            else promise.reject("AES_ENC_FAILED", "Encryption returned null")
        } catch (e: Exception) {
            promise.reject("AES_ENC_ERROR", e.message)
        }
    }

    // ── AES-256-GCM Decrypt ───────────────────────────────────────────────

    @ReactMethod
    override fun aesGCMDecrypt(
        keyB64:   String,
        blobB64:  String,
        aadB64:   String?,
        promise:  Promise
    ) {
        try {
            val key  = keyB64.decodeB64()
            val blob = blobB64.decodeB64()
            val aad  = aadB64?.decodeB64()

            val result = nativeAESGCMDecrypt(key, blob, aad)

            key.fill(0)
            blob.fill(0)
            aad?.fill(0)

            // null means authentication tag mismatch — security event
            if (result != null) promise.resolve(result.encodeB64ThenWipe())
            else promise.reject("AES_AUTH_FAIL", "GCM tag mismatch — integrity violation")
        } catch (e: Exception) {
            promise.reject("AES_DEC_ERROR", e.message)
        }
    }

    // ── HMAC-SHA256 ───────────────────────────────────────────────────────

    @ReactMethod
    override fun hmacSHA256(
        keyB64:  String,
        dataB64: String,
        promise: Promise
    ) {
        try {
            val key  = keyB64.decodeB64()
            val data = dataB64.decodeB64()

            val result = nativeHMACSHA256(key, data)

            key.fill(0)
            data.fill(0)

            if (result != null) {
                val hex = result.joinToString("") { "%02x".format(it) }
                result.fill(0)
                promise.resolve(hex)
            } else {
                promise.reject("HMAC_FAILED", "HMAC returned null")
            }
        } catch (e: Exception) {
            promise.reject("HMAC_ERROR", e.message)
        }
    }

    // ── Random bytes ──────────────────────────────────────────────────────

    @ReactMethod
    override fun randomBytes(length: Double, promise: Promise) {
        try {
            val result = nativeRandomBytes(length.toInt())
            if (result != null) promise.resolve(result.encodeB64ThenWipe())
            else promise.reject("RAND_FAILED", "RNG returned null")
        } catch (e: Exception) {
            promise.reject("RAND_ERROR", e.message)
        }
    }
}
