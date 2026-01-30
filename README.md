# file_hash

Hardware-accelerated SHA-256 file hashing for Flutter using native platform APIs.

## Implementation

### Platform-Specific APIs

- **macOS/iOS**: CommonCrypto (Apple's hardware-accelerated crypto framework)
- **Windows**: CNG (Cryptography Next Generation) API
- **Linux/Android**: OpenSSL (automatically uses Intel SHA-NI or ARM Crypto Extensions when available)

### Hardware Acceleration Support

**Intel/AMD (x86_64):**

- SHA-NI (SHA New Instructions)
- Supported CPUs: Intel Ice Lake+, Goldmont+, AMD Zen (all generations)

**ARM (Android/Linux):**

- ARMv8 Cryptography Extensions
- Available in most 64-bit ARM processors (2015+)
- Nearly all modern Android devices

OpenSSL automatically detects and enables hardware acceleration at runtime when available.

## Dependencies

### Linux/Android

OpenSSL is required for Linux and Android builds. Most systems have it pre-installed.

**Linux:**

```bash
# Debian/Ubuntu
sudo apt-get install libssl-dev

# Fedora/RHEL
sudo dnf install openssl-devel

# Arch Linux
sudo pacman -S openssl
```

**Android:**

- OpenSSL is included in the Android NDK
- No additional setup required

### macOS/iOS/Windows

No additional dependencies - uses platform-native APIs.
