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

#else
    // Android / Linux (Hardware Accelerated via OpenSSL)
    #include <openssl/sha.h>
    #define USE_OPENSSL 1
#endif

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

    // --- ENGINE: OpenSSL (Linux/Android) ---
    #else
        printf("Native: Using OpenSSL (Hardware Accelerated)\n");
        SHA256_CTX ctx;
        SHA256_Init(&ctx);

        while ((bytesRead = fread(buffer, 1, BUFFER_SIZE, file)) > 0) {
            SHA256_Update(&ctx, buffer, bytesRead);
        }
        SHA256_Final(hash, &ctx);
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