#ifndef FILE_HASH_H
#define FILE_HASH_H

#include <stdint.h>
#include <stdlib.h>

// Handle symbol visibility for all platforms
#if _WIN32
    // Windows requires this to export symbols from the DLL
    #define FFI_PLUGIN_EXPORT __declspec(dllexport)
#else
    // Android/iOS/Linux/macOS need this to prevent the linker from stripping the symbol
    #define FFI_PLUGIN_EXPORT __attribute__((visibility("default"))) __attribute__((used))
#endif

// Guard against C++ name mangling if this header is included in a .cpp file
#ifdef __cplusplus
extern "C" {
#endif

    FFI_PLUGIN_EXPORT char* sha256_file_native(char* filepath);
    FFI_PLUGIN_EXPORT void free_sha256_string(char* ptr);

#ifdef __cplusplus
}
#endif

#endif // FILE_HASH_H