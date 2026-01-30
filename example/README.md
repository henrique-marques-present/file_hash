# file_hash Example App

This example app demonstrates how to use the `file_hash` plugin to compute SHA-256 hashes of files using hardware-accelerated native implementations.

## Features

- 📁 **File Picker**: Select any file from your device
- 🔐 **SHA-256 Hashing**: Compute cryptographic hash using native code
- ⚡ **Hardware Acceleration**: Uses platform-specific optimized implementations
- 🧪 **Test File**: Automatically creates and hashes a test file on startup
- 📋 **Copy Hash**: Selectable text for easy copying

## Running the Example

### Install Dependencies

```bash
flutter pub get
```

### Run on Different Platforms

```bash
# macOS
flutter run -d macos

# iOS Simulator
flutter run -d iPhone

# Android Emulator
flutter run -d <device-id>

# Linux
flutter run -d linux

# Windows
flutter run -d windows
```

## Running Tests

This example includes comprehensive integration tests:

```bash
# Run integration tests
flutter test integration_test/

# Run on specific platform
flutter test integration_test/ -d macos
```

See [integration_test/README.md](integration_test/README.md) for more details.

## How It Works

1. **Pick a File**: Tap "Pick File to Hash" to select any file
2. **Compute Hash**: The app computes the SHA-256 hash in a background isolate
3. **View Result**: The 64-character hex hash is displayed
4. **Copy Hash**: Select and copy the hash for verification

## Platform-Specific Implementations

- **macOS/iOS**: CommonCrypto (Apple's hardware-accelerated framework)
- **Windows**: CNG (Cryptography Next Generation) API
- **Linux/Android**: OpenSSL (with automatic hardware acceleration)

All implementations produce identical results for the same input.
