#include "file_hash.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>

// --- PLATFORM SELECTION ---
#if defined(__APPLE__)
    // macOS / iOS (Hardware Accelerated)
    #include <CommonCrypto/CommonDigest.h>
    #define USE_APPLE_CC 1

#elif defined(_WIN32)
    // Windows (Hardware Accelerated)
    #include <windows.h>
    #include <bcrypt.h>
    #pragma comment(lib, "bcrypt.lib")
    #define USE_WINDOWS_CNG 1

#elif defined(__ANDROID__)
    // Android: Use ARM crypto intrinsics with fallback to pure-C
    #if defined(__aarch64__) && defined(__ARM_FEATURE_CRYPTO)
        // ARMv8 with crypto extensions - hardware accelerated
        #include <arm_neon.h>
        #define USE_ARM_CRYPTO 1
    #else
        // Fallback to pure-C implementation
        #define USE_BUNDLED_SHA256 1
    #endif

#else
    // Linux (Hardware Accelerated via OpenSSL)
    #include <openssl/evp.h>
    #define USE_OPENSSL 1
#endif

// --- BUNDLED SHA256 IMPLEMENTATION (for Android) ---
#ifdef USE_BUNDLED_SHA256

#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

typedef struct {
    uint32_t state[8];
    uint64_t bitcount;
    uint8_t buffer[SHA256_BLOCK_SIZE];
} SHA256_CTX_BUNDLED;

static const uint32_t K256[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static void sha256_transform_bundled(SHA256_CTX_BUNDLED *ctx, const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h, t1, t2, m[64];
    int i;

    for (i = 0; i < 16; ++i) {
        m[i] = ((uint32_t)data[i * 4] << 24) | ((uint32_t)data[i * 4 + 1] << 16) |
               ((uint32_t)data[i * 4 + 2] << 8) | ((uint32_t)data[i * 4 + 3]);
    }
    for (; i < 64; ++i) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }

    a = ctx->state[0]; b = ctx->state[1]; c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5]; g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + K256[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b; ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f; ctx->state[6] += g; ctx->state[7] += h;
}

static void sha256_init_bundled(SHA256_CTX_BUNDLED *ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->bitcount = 0;
}

static void sha256_update_bundled(SHA256_CTX_BUNDLED *ctx, const uint8_t *data, size_t len) {
    size_t i = 0;
    size_t index = (ctx->bitcount / 8) % SHA256_BLOCK_SIZE;
    ctx->bitcount += len * 8;

    size_t partLen = SHA256_BLOCK_SIZE - index;
    if (len >= partLen) {
        memcpy(&ctx->buffer[index], data, partLen);
        sha256_transform_bundled(ctx, ctx->buffer);
        for (i = partLen; i + SHA256_BLOCK_SIZE <= len; i += SHA256_BLOCK_SIZE) {
            sha256_transform_bundled(ctx, &data[i]);
        }
        index = 0;
    }
    memcpy(&ctx->buffer[index], &data[i], len - i);
}

static void sha256_final_bundled(SHA256_CTX_BUNDLED *ctx, uint8_t hash[32]) {
    uint8_t finalcount[8];
    for (int i = 0; i < 8; i++) {
        finalcount[i] = (uint8_t)(ctx->bitcount >> (56 - i * 8));
    }

    uint8_t pad = 0x80;
    sha256_update_bundled(ctx, &pad, 1);
    while ((ctx->bitcount / 8) % 64 != 56) {
        pad = 0x00;
        sha256_update_bundled(ctx, &pad, 1);
    }
    sha256_update_bundled(ctx, finalcount, 8);

    for (int i = 0; i < 8; i++) {
        hash[i * 4] = (ctx->state[i] >> 24) & 0xff;
        hash[i * 4 + 1] = (ctx->state[i] >> 16) & 0xff;
        hash[i * 4 + 2] = (ctx->state[i] >> 8) & 0xff;
        hash[i * 4 + 3] = ctx->state[i] & 0xff;
    }
}

#endif // USE_BUNDLED_SHA256

// --- ARM CRYPTO INTRINSICS IMPLEMENTATION (for Android ARMv8 with crypto) ---
#ifdef USE_ARM_CRYPTO

static const uint32_t K_ARM[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

typedef struct {
    uint32_t state[8];
    uint64_t bitcount;
    uint8_t buffer[64];
    size_t buflen;
} SHA256_ARM_CTX;

static void sha256_arm_init(SHA256_ARM_CTX *ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->bitcount = 0;
    ctx->buflen = 0;
}

static void sha256_arm_process_block(uint32_t state[8], const uint8_t data[64]) {
    uint32x4_t STATE0, STATE1, ABEF_SAVE, CDGH_SAVE;
    uint32x4_t MSG0, MSG1, MSG2, MSG3;
    uint32x4_t TMP0, TMP1, TMP2;

    // Load state
    STATE0 = vld1q_u32(&state[0]);
    STATE1 = vld1q_u32(&state[4]);

    // Save state
    ABEF_SAVE = STATE0;
    CDGH_SAVE = STATE1;

    // Load message
    MSG0 = vld1q_u32((const uint32_t *)(data +  0));
    MSG1 = vld1q_u32((const uint32_t *)(data + 16));
    MSG2 = vld1q_u32((const uint32_t *)(data + 32));
    MSG3 = vld1q_u32((const uint32_t *)(data + 48));

    // Reverse for little endian
    MSG0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG0)));
    MSG1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG1)));
    MSG2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG2)));
    MSG3 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSG3)));

    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K_ARM[0x00]));

    // Rounds 0-3
    MSG0 = vsha256su0q_u32(MSG0, MSG1);
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG1, vld1q_u32(&K_ARM[0x04]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

    // Rounds 4-7
    MSG1 = vsha256su0q_u32(MSG1, MSG2);
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG2, vld1q_u32(&K_ARM[0x08]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

    // Rounds 8-11
    MSG2 = vsha256su0q_u32(MSG2, MSG3);
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG3, vld1q_u32(&K_ARM[0x0c]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

    // Rounds 12-15
    MSG3 = vsha256su0q_u32(MSG3, MSG0);
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K_ARM[0x10]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

    // Rounds 16-19
    MSG0 = vsha256su0q_u32(MSG0, MSG1);
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG1, vld1q_u32(&K_ARM[0x14]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

    // Rounds 20-23
    MSG1 = vsha256su0q_u32(MSG1, MSG2);
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG2, vld1q_u32(&K_ARM[0x18]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

    // Rounds 24-27
    MSG2 = vsha256su0q_u32(MSG2, MSG3);
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG3, vld1q_u32(&K_ARM[0x1c]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

    // Rounds 28-31
    MSG3 = vsha256su0q_u32(MSG3, MSG0);
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K_ARM[0x20]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

    // Rounds 32-35
    MSG0 = vsha256su0q_u32(MSG0, MSG1);
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG1, vld1q_u32(&K_ARM[0x24]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG0 = vsha256su1q_u32(MSG0, MSG2, MSG3);

    // Rounds 36-39
    MSG1 = vsha256su0q_u32(MSG1, MSG2);
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG2, vld1q_u32(&K_ARM[0x28]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG1 = vsha256su1q_u32(MSG1, MSG3, MSG0);

    // Rounds 40-43
    MSG2 = vsha256su0q_u32(MSG2, MSG3);
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG3, vld1q_u32(&K_ARM[0x2c]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);
    MSG2 = vsha256su1q_u32(MSG2, MSG0, MSG1);

    // Rounds 44-47
    MSG3 = vsha256su0q_u32(MSG3, MSG0);
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG0, vld1q_u32(&K_ARM[0x30]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);
    MSG3 = vsha256su1q_u32(MSG3, MSG1, MSG2);

    // Rounds 48-51
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG1, vld1q_u32(&K_ARM[0x34]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

    // Rounds 52-55
    TMP2 = STATE0;
    TMP0 = vaddq_u32(MSG2, vld1q_u32(&K_ARM[0x38]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);

    // Rounds 56-59
    TMP2 = STATE0;
    TMP1 = vaddq_u32(MSG3, vld1q_u32(&K_ARM[0x3c]));
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP0);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP0);

    // Rounds 60-63
    TMP2 = STATE0;
    STATE0 = vsha256hq_u32(STATE0, STATE1, TMP1);
    STATE1 = vsha256h2q_u32(STATE1, TMP2, TMP1);

    // Combine state
    STATE0 = vaddq_u32(STATE0, ABEF_SAVE);
    STATE1 = vaddq_u32(STATE1, CDGH_SAVE);

    // Save state
    vst1q_u32(&state[0], STATE0);
    vst1q_u32(&state[4], STATE1);
}

static void sha256_arm_update(SHA256_ARM_CTX *ctx, const uint8_t *data, size_t len) {
    ctx->bitcount += len * 8;

    if (ctx->buflen > 0) {
        size_t need = 64 - ctx->buflen;
        if (len < need) {
            memcpy(&ctx->buffer[ctx->buflen], data, len);
            ctx->buflen += len;
            return;
        }
        memcpy(&ctx->buffer[ctx->buflen], data, need);
        sha256_arm_process_block(ctx->state, ctx->buffer);
        data += need;
        len -= need;
        ctx->buflen = 0;
    }

    while (len >= 64) {
        sha256_arm_process_block(ctx->state, data);
        data += 64;
        len -= 64;
    }

    if (len > 0) {
        memcpy(ctx->buffer, data, len);
        ctx->buflen = len;
    }
}

static void sha256_arm_final(SHA256_ARM_CTX *ctx, uint8_t hash[32]) {
    uint8_t pad[64];
    size_t padlen;

    // Padding
    pad[0] = 0x80;
    padlen = (ctx->buflen < 56) ? (56 - ctx->buflen) : (120 - ctx->buflen);
    memset(&pad[1], 0, padlen - 1);

    // Append length in bits (big-endian)
    for (int i = 0; i < 8; i++) {
        pad[padlen + i] = (uint8_t)(ctx->bitcount >> (56 - i * 8));
    }

    sha256_arm_update(ctx, pad, padlen + 8);

    // Output hash (big-endian)
    for (int i = 0; i < 8; i++) {
        hash[i * 4 + 0] = (ctx->state[i] >> 24) & 0xff;
        hash[i * 4 + 1] = (ctx->state[i] >> 16) & 0xff;
        hash[i * 4 + 2] = (ctx->state[i] >>  8) & 0xff;
        hash[i * 4 + 3] = (ctx->state[i] >>  0) & 0xff;
    }
}

#endif // USE_ARM_CRYPTO

// --- EXPORTED FUNCTION ---

FFI_PLUGIN_EXPORT char* sha256_file_native(char* filepath) {
    printf("Native: Opening %s\n", filepath);
    
    FILE *file = fopen(filepath, "rb");
    if (!file) {
        printf("Native Error: Failed to open. errno=%d (%s)\n", errno, strerror(errno));
        return NULL; 
    }

    const size_t BUFFER_SIZE = 64 * 1024;
    uint8_t* buffer = (uint8_t*)malloc(BUFFER_SIZE);
    if (!buffer) {
        fclose(file);
        return NULL;
    }

    uint8_t hash[32];
    size_t bytesRead = 0;

    // --- ENGINE: macOS / iOS ---
    #ifdef USE_APPLE_CC
        printf("Native: Using Apple CommonCrypto (Hardware Accelerated)\n");
        CC_SHA256_CTX ctx;
        CC_SHA256_Init(&ctx);

        while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
            CC_SHA256_Update(&ctx, buffer, (CC_LONG)bytesRead);
        }
        CC_SHA256_Final(hash, &ctx);

    // --- ENGINE: Windows ---
    #elif defined(USE_WINDOWS_CNG)
        printf("Native: Using Windows CNG (Hardware Accelerated)\n");
        BCRYPT_ALG_HANDLE hAlg = NULL;
        BCRYPT_HASH_HANDLE hHash = NULL;

        BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0);
        BCryptCreateHash(hAlg, &hHash, NULL, 0, NULL, 0, 0);

        while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
            BCryptHashData(hHash, buffer, (ULONG)bytesRead, 0);
        }
        BCryptFinishHash(hHash, hash, 32, 0);

        BCryptDestroyHash(hHash);
        BCryptCloseAlgorithmProvider(hAlg, 0);

    // --- ENGINE: Android ARMv8 with Crypto Extensions (Hardware Accelerated) ---
    #elif defined(USE_ARM_CRYPTO)
        printf("Native: Using ARM Crypto Extensions (Hardware Accelerated)\n");
        SHA256_ARM_CTX ctx;
        sha256_arm_init(&ctx);

        while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
            sha256_arm_update(&ctx, buffer, bytesRead);
        }
        sha256_arm_final(&ctx, hash);

    // --- ENGINE: Android Fallback (Pure C) ---
    #elif defined(USE_BUNDLED_SHA256)
        printf("Native: Using Bundled SHA256 (Pure C)\n");
        SHA256_CTX_BUNDLED ctx;
        sha256_init_bundled(&ctx);

        while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
            sha256_update_bundled(&ctx, buffer, bytesRead);
        }
        sha256_final_bundled(&ctx, hash);

    // --- ENGINE: OpenSSL (Linux) ---
    #else
        printf("Native: Using OpenSSL EVP (Hardware Accelerated)\n");
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        if (!ctx) {
            free(buffer);
            fclose(file);
            return NULL;
        }

        if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
            EVP_MD_CTX_free(ctx);
            free(buffer);
            fclose(file);
            return NULL;
        }

        while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
            if (EVP_DigestUpdate(ctx, buffer, bytesRead) != 1) {
                EVP_MD_CTX_free(ctx);
                free(buffer);
                fclose(file);
                return NULL;
            }
        }

        unsigned int hash_len = 0;
        if (EVP_DigestFinal_ex(ctx, hash, &hash_len) != 1) {
            EVP_MD_CTX_free(ctx);
            free(buffer);
            fclose(file);
            return NULL;
        }

        EVP_MD_CTX_free(ctx);
    #endif

    // Cleanup
    free(buffer);
    fclose(file);

    // Convert to Hex
    char* hexString = (char*)malloc(65);
    for (int i = 0; i < 32; i++) {
        sprintf(hexString + (i * 2), "%02x", hash[i]);
    }
    hexString[64] = 0;

    return hexString;
}

FFI_PLUGIN_EXPORT void free_sha256_string(char* ptr) {
    if (ptr) free(ptr);
}