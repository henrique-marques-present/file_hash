# file_hash

Hardware-accelerated SHA-256 file hashing for Flutter using native platform APIs.

## Implementation

### Platform-Specific APIs

| Platform             | Implementation         | Hardware Accelerated |
| -------------------- | ---------------------- | -------------------- |
| macOS/iOS            | CommonCrypto           | ✅ Yes               |
| Windows              | CNG (BCrypt)           | ✅ Yes               |
| Linux                | OpenSSL                | ✅ Yes               |
| Android ARM64        | ARM Crypto Extensions  | ✅ Yes               |
| Android (other ABIs) | Pure C                 | ❌ No (fallback)     |

### Hardware Acceleration Details

**macOS/iOS:**
- Uses Apple's CommonCrypto framework
- Hardware acceleration via Secure Enclave on supported devices

**Windows:**
- Uses Cryptography Next Generation (CNG) API via BCrypt
- Hardware acceleration on modern Intel/AMD processors

**Linux:**
- Uses OpenSSL EVP API
- Automatically uses Intel SHA-NI or ARM Crypto Extensions when available
- Supported CPUs: Intel Ice Lake+, Goldmont+, AMD Zen (all generations)

**Android ARM64 (`arm64-v8a`):**
- Uses ARMv8 Cryptography Extensions via NEON intrinsics
- Hardware instructions: `vsha256hq_u32`, `vsha256h2q_u32`, `vsha256su0q_u32`, `vsha256su1q_u32`
- Available on most 64-bit ARM processors (2015+)
- Zero external dependencies - compiled directly into the native library

**Android (other architectures):**
- `armeabi-v7a`, `x86`, `x86_64` fall back to a pure-C SHA256 implementation
- Functionally correct, but not hardware accelerated

### Why Not OpenSSL on Android?

The Android NDK does **not** include a public, linkable cryptography library. Although Android devices contain BoringSSL internally, Google restricts access to it. Linking against the system's `/system/lib64/libcrypto.so` is unsafe because the ABI changes between Android versions.

The ARM intrinsics approach provides:
- **Zero external dependencies** - no need to bundle OpenSSL/BoringSSL
- **Negligible APK size impact** - just a few KB of native code
- **Maximum performance** on ARM64 devices (the vast majority of modern Android devices)

## Dependencies

### Linux

OpenSSL is required for Linux builds. Most systems have it pre-installed.

```bash
# Debian/Ubuntu
sudo apt-get install libssl-dev

# Fedora/RHEL
sudo dnf install openssl-devel

# Arch Linux
sudo pacman -S openssl
```

### macOS/iOS/Windows/Android

No additional dependencies - uses platform-native APIs or bundled implementations.
