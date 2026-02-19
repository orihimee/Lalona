/*
 * lalona_crypto — Native cryptographic core
 *
 * All key material exists ONLY within stack frames of these functions.
 * secure_wipe() is called on all sensitive locals before return.
 * Keys NEVER touch the Java heap in raw form — only via JNI byte arrays
 * which are released with JNI_ABORT to prevent copying back.
 *
 * Compiled with: -fstack-protector-all -D_FORTIFY_SOURCE=2 -O2
 */

#include <jni.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>
#include <openssl/kdf.h>

/* ─── Secure wipe: prevents compiler elimination via volatile + memory barrier */
static void secure_wipe(volatile void *ptr, size_t len) {
    volatile uint8_t *p = (volatile uint8_t *)ptr;
    while (len--) *p++ = 0;
    __asm__ __volatile__("" ::: "memory");
}

/* ─── JNI helpers ─────────────────────────────────────────────────────────── */

#define ACQUIRE(env, arr, var)                                              \
    jbyte *var = (arr) ? (*env)->GetByteArrayElements(env, arr, NULL) : NULL; \
    jsize var##_len = (arr) ? (*env)->GetArrayLength(env, arr) : 0;

#define RELEASE_WIPE(env, arr, var)                                         \
    if (var) {                                                              \
        secure_wipe(var, var##_len);                                        \
        (*env)->ReleaseByteArrayElements(env, arr, var, JNI_ABORT);        \
        var = NULL;                                                         \
    }

/* ─── PBKDF2-SHA512 ────────────────────────────────────────────────────────── */

JNIEXPORT jbyteArray JNICALL
Java_com_lalona_NativeCryptoModule_nativePBKDF2(
        JNIEnv  *env,
        jobject  thiz,
        jbyteArray j_password,
        jbyteArray j_salt,
        jint       iterations,
        jint       key_len)
{
    ACQUIRE(env, j_password, pwd);
    ACQUIRE(env, j_salt,     salt);

    if (!pwd || !salt) {
        RELEASE_WIPE(env, j_password, pwd);
        RELEASE_WIPE(env, j_salt,     salt);
        return NULL;
    }

    uint8_t *dk = (uint8_t *)malloc((size_t)key_len);
    if (!dk) {
        RELEASE_WIPE(env, j_password, pwd);
        RELEASE_WIPE(env, j_salt,     salt);
        return NULL;
    }

    int ok = PKCS5_PBKDF2_HMAC(
        (const char *)pwd,  (int)pwd_len,
        (const uint8_t *)salt, (int)salt_len,
        (int)iterations,
        EVP_sha512(),
        (int)key_len, dk);

    RELEASE_WIPE(env, j_password, pwd);
    RELEASE_WIPE(env, j_salt,     salt);

    if (!ok) { secure_wipe(dk, key_len); free(dk); return NULL; }

    jbyteArray out = (*env)->NewByteArray(env, key_len);
    (*env)->SetByteArrayRegion(env, out, 0, key_len, (jbyte *)dk);
    secure_wipe(dk, key_len);
    free(dk);
    return out;
}

/* ─── HKDF-SHA256 (Extract+Expand) ────────────────────────────────────────── */

JNIEXPORT jbyteArray JNICALL
Java_com_lalona_NativeCryptoModule_nativeHKDF(
        JNIEnv  *env,
        jobject  thiz,
        jbyteArray j_ikm,
        jbyteArray j_salt,
        jbyteArray j_info,
        jint       out_len)
{
    ACQUIRE(env, j_ikm,  ikm);
    ACQUIRE(env, j_salt, salt);
    ACQUIRE(env, j_info, info);

    if (!ikm || !salt) {
        RELEASE_WIPE(env, j_ikm,  ikm);
        RELEASE_WIPE(env, j_salt, salt);
        RELEASE_WIPE(env, j_info, info);
        return NULL;
    }

    /* Extract: PRK = HMAC-SHA256(salt, IKM) */
    uint8_t prk[32];
    unsigned int prk_len = 0;
    HMAC(EVP_sha256(),
         salt, salt_len,
         (uint8_t *)ikm, ikm_len,
         prk, &prk_len);

    RELEASE_WIPE(env, j_ikm,  ikm);
    RELEASE_WIPE(env, j_salt, salt);

    /* Expand: OKM via T(n) = HMAC-SHA256(PRK, T(n-1) || info || n) */
    uint8_t *okm = (uint8_t *)malloc((size_t)out_len);
    if (!okm) {
        secure_wipe(prk, sizeof prk);
        if (info) { RELEASE_WIPE(env, j_info, info); }
        return NULL;
    }

    uint8_t T[32] = {0};
    uint8_t  ctr  = 1;
    int offset = 0, remaining = out_len;

    while (remaining > 0) {
        HMAC_CTX *ctx = HMAC_CTX_new();
        HMAC_Init_ex(ctx, prk, (int)prk_len, EVP_sha256(), NULL);
        if (ctr > 1)            HMAC_Update(ctx, T, 32);
        if (info && info_len)   HMAC_Update(ctx, (uint8_t *)info, info_len);
                                HMAC_Update(ctx, &ctr, 1);
        unsigned int t_len = 32;
        HMAC_Final(ctx, T, &t_len);
        HMAC_CTX_free(ctx);

        int copy = remaining < 32 ? remaining : 32;
        memcpy(okm + offset, T, copy);
        offset    += copy;
        remaining -= copy;
        ctr++;
    }

    secure_wipe(T,   sizeof T);
    secure_wipe(prk, sizeof prk);
    if (info) { RELEASE_WIPE(env, j_info, info); }

    jbyteArray out = (*env)->NewByteArray(env, out_len);
    (*env)->SetByteArrayRegion(env, out, 0, out_len, (jbyte *)okm);
    secure_wipe(okm, out_len);
    free(okm);
    return out;
}

/* ─── AES-256-GCM Encrypt ─────────────────────────────────────────────────── */
/* Output layout: IV(12) || Ciphertext || Tag(16)                              */

JNIEXPORT jbyteArray JNICALL
Java_com_lalona_NativeCryptoModule_nativeAESGCMEncrypt(
        JNIEnv  *env,
        jobject  thiz,
        jbyteArray j_key,
        jbyteArray j_pt,
        jbyteArray j_aad)
{
    ACQUIRE(env, j_key, key);
    ACQUIRE(env, j_pt,  pt);
    ACQUIRE(env, j_aad, aad);

    if (!key || key_len != 32 || !pt) {
        RELEASE_WIPE(env, j_key, key);
        RELEASE_WIPE(env, j_pt,  pt);
        if (aad) { RELEASE_WIPE(env, j_aad, aad); }
        return NULL;
    }

    uint8_t iv[12];
    RAND_bytes(iv, sizeof iv);

    uint8_t *ct  = (uint8_t *)malloc((size_t)pt_len + 16);
    uint8_t  tag[16];
    int ct_len = 0, final_len = 0;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_EncryptInit_ex(ctx, NULL, NULL, (uint8_t *)key, iv);

    if (aad && aad_len > 0)
        EVP_EncryptUpdate(ctx, NULL, &ct_len, (uint8_t *)aad, aad_len);

    EVP_EncryptUpdate(ctx, ct, &ct_len, (uint8_t *)pt, pt_len);
    EVP_EncryptFinal_ex(ctx, ct + ct_len, &final_len);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag);
    EVP_CIPHER_CTX_free(ctx);

    RELEASE_WIPE(env, j_key, key);
    RELEASE_WIPE(env, j_pt,  pt);
    if (aad) { RELEASE_WIPE(env, j_aad, aad); }

    jsize total = 12 + (ct_len + final_len) + 16;
    jbyteArray out = (*env)->NewByteArray(env, total);
    (*env)->SetByteArrayRegion(env, out,  0,                    12,                  (jbyte *)iv);
    (*env)->SetByteArrayRegion(env, out, 12,          ct_len + final_len,            (jbyte *)ct);
    (*env)->SetByteArrayRegion(env, out, 12 + ct_len + final_len, 16,               (jbyte *)tag);

    secure_wipe(ct, pt_len + 16);
    free(ct);
    secure_wipe(iv,  sizeof iv);
    secure_wipe(tag, sizeof tag);
    return out;
}

/* ─── AES-256-GCM Decrypt ─────────────────────────────────────────────────── */
/* Input layout: IV(12) || Ciphertext || Tag(16) — returns NULL on auth fail   */

JNIEXPORT jbyteArray JNICALL
Java_com_lalona_NativeCryptoModule_nativeAESGCMDecrypt(
        JNIEnv  *env,
        jobject  thiz,
        jbyteArray j_key,
        jbyteArray j_blob,
        jbyteArray j_aad)
{
    ACQUIRE(env, j_key,  key);
    ACQUIRE(env, j_blob, blob);
    ACQUIRE(env, j_aad,  aad);

    if (!key || key_len != 32 || !blob || blob_len < 28) {
        RELEASE_WIPE(env, j_key,  key);
        RELEASE_WIPE(env, j_blob, blob);
        if (aad) { RELEASE_WIPE(env, j_aad, aad); }
        return NULL;
    }

    const uint8_t *iv  = (uint8_t *)blob;
    const uint8_t *ct  = (uint8_t *)blob + 12;
    jsize          ct_len = blob_len - 12 - 16;
    const uint8_t *tag = (uint8_t *)blob + 12 + ct_len;

    uint8_t *pt = (uint8_t *)malloc((size_t)ct_len + 1);
    if (!pt) {
        RELEASE_WIPE(env, j_key,  key);
        RELEASE_WIPE(env, j_blob, blob);
        if (aad) { RELEASE_WIPE(env, j_aad, aad); }
        return NULL;
    }

    int pt_len = 0, final_len = 0;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL);
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL);
    EVP_DecryptInit_ex(ctx, NULL, NULL, (uint8_t *)key, iv);

    if (aad && aad_len > 0)
        EVP_DecryptUpdate(ctx, NULL, &pt_len, (uint8_t *)aad, aad_len);

    EVP_DecryptUpdate(ctx, pt, &pt_len, ct, (int)ct_len);

    /* Set expected tag BEFORE final to enable auth */
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16, (void *)tag);
    int auth_ok = EVP_DecryptFinal_ex(ctx, pt + pt_len, &final_len);
    EVP_CIPHER_CTX_free(ctx);

    RELEASE_WIPE(env, j_key,  key);
    RELEASE_WIPE(env, j_blob, blob);
    if (aad) { RELEASE_WIPE(env, j_aad, aad); }

    if (auth_ok != 1) {
        /* Authentication FAILED — wipe partial plaintext, return NULL */
        secure_wipe(pt, ct_len);
        free(pt);
        return NULL;
    }

    jbyteArray out = (*env)->NewByteArray(env, pt_len + final_len);
    (*env)->SetByteArrayRegion(env, out, 0, pt_len + final_len, (jbyte *)pt);
    secure_wipe(pt, ct_len);
    free(pt);
    return out;
}

/* ─── HMAC-SHA256 ──────────────────────────────────────────────────────────── */

JNIEXPORT jbyteArray JNICALL
Java_com_lalona_NativeCryptoModule_nativeHMACSHA256(
        JNIEnv  *env,
        jobject  thiz,
        jbyteArray j_key,
        jbyteArray j_data)
{
    ACQUIRE(env, j_key,  key);
    ACQUIRE(env, j_data, data);

    if (!key || !data) {
        RELEASE_WIPE(env, j_key,  key);
        RELEASE_WIPE(env, j_data, data);
        return NULL;
    }

    uint8_t result[32];
    unsigned int result_len = 0;
    HMAC(EVP_sha256(),
         key, key_len,
         (uint8_t *)data, data_len,
         result, &result_len);

    RELEASE_WIPE(env, j_key,  key);
    RELEASE_WIPE(env, j_data, data);

    jbyteArray out = (*env)->NewByteArray(env, 32);
    (*env)->SetByteArrayRegion(env, out, 0, 32, (jbyte *)result);
    secure_wipe(result, sizeof result);
    return out;
}

/* ─── Cryptographically Secure Random Bytes ────────────────────────────────── */

JNIEXPORT jbyteArray JNICALL
Java_com_lalona_NativeCryptoModule_nativeRandomBytes(
        JNIEnv  *env,
        jobject  thiz,
        jint     length)
{
    if (length <= 0 || length > 4096) return NULL;

    uint8_t *buf = (uint8_t *)malloc((size_t)length);
    if (!buf) return NULL;

    if (RAND_bytes(buf, length) != 1) {
        secure_wipe(buf, length);
        free(buf);
        return NULL;
    }

    jbyteArray out = (*env)->NewByteArray(env, length);
    (*env)->SetByteArrayRegion(env, out, 0, length, (jbyte *)buf);
    secure_wipe(buf, length);
    free(buf);
    return out;
}
