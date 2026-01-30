# Integration Tests for file_hash

This directory contains integration tests for the file_hash plugin. These tests run on actual devices/simulators and verify that the native SHA-256 implementation works correctly.

## Running the Tests

### Prerequisites

Make sure you have the dependencies installed:

```bash
cd example
flutter pub get
```

### Run on macOS

```bash
flutter test integration_test/ -d macos
```

### Run on iOS Simulator

```bash
flutter test integration_test/ -d iPhone
```

### Run on Android Emulator

```bash
flutter test integration_test/ -d <device-id>
```

### Run on Linux

```bash
flutter test integration_test/ -d linux
```

### Run on Windows

```bash
flutter test integration_test/ -d windows
```

## Test Coverage

The integration tests verify:

- ✅ **Known Content**: Verifies SHA-256 hash matches expected value for "Hello, World!"
- ✅ **Empty Files**: Correctly hashes empty files
- ✅ **Binary Data**: Handles binary data correctly
- ✅ **Large Files**: Can process large files (1MB+)
- ✅ **Non-existent Files**: Returns null for files that don't exist
- ✅ **Consistency**: Same content produces same hash
- ✅ **Uniqueness**: Different content produces different hashes
- ✅ **Format Validation**: Hash is 64 lowercase hex characters
- ✅ **Special Characters**: Handles paths with special characters
- ✅ **Concurrency**: Can hash multiple files simultaneously

## Expected Results

All tests should pass on all platforms (macOS, iOS, Android, Linux, Windows).

The plugin uses platform-specific hardware-accelerated SHA-256 implementations:
- **macOS/iOS**: CommonCrypto
- **Windows**: CNG (Cryptography Next Generation)
- **Linux/Android**: OpenSSL

All implementations should produce identical results for the same input.

