# Testing file_hash Plugin

## Unit Tests

The unit tests in `file_hash_test.dart` are designed to test the plugin's functionality but require the native library to be built. Since this is an FFI plugin, the native code needs to be compiled for the target platform.

### Running Tests

**Option 1: Integration Tests (Recommended)**

Run the integration tests in the example app, which will build the native code:

```bash
cd example
flutter test integration_test/
```

**Option 2: Build and Test on Device**

For more comprehensive testing on actual devices:

```bash
cd example
# For iOS
flutter test integration_test/ -d iPhone

# For Android
flutter test integration_test/ -d <android-device-id>

# For macOS
flutter test integration_test/ -d macos

# For Linux
flutter test integration_test/ -d linux

# For Windows
flutter test integration_test/ -d windows
```

## Test Coverage

The tests cover:
- ✅ Correct SHA-256 computation for known content
- ✅ Empty file handling
- ✅ Binary data hashing
- ✅ Large file handling
- ✅ Non-existent file handling
- ✅ Consistency checks
- ✅ Hash format validation
- ✅ Special characters in file paths
- ✅ Concurrent hashing operations

## Known Limitations

- Unit tests cannot run with `flutter test` alone because the native library isn't available in the Dart VM test environment
- Use integration tests for actual validation
- The example app provides a visual way to test the plugin

