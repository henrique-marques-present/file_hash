import 'dart:async';
import 'dart:ffi';
import 'dart:io';
import 'dart:isolate';

import 'package:ffi/ffi.dart';

// --- FFI Typedefs (Must be top-level for Isolate access) ---
typedef NativeHashFunc = Pointer<Utf8> Function(Pointer<Utf8>);
typedef DartHashFunc = Pointer<Utf8> Function(Pointer<Utf8>);

typedef NativeFreeFunc = Void Function(Pointer<Utf8>);
typedef DartFreeFunc = void Function(Pointer<Utf8>);

class FileHash {
  /// Hashes a file in a separate background thread (Isolate).
  /// This prevents the UI from freezing.
  static Future<String?> hashFile(String filePath) async {
    // Isolate.run automatically spawns a thread, runs the code,
    // returns the result, and closes the thread.
    return await Isolate.run(() {
      return _hashFileSynchronous(filePath);
    });
  }

  /// This private function runs inside the Background Isolate.
  static String? _hashFileSynchronous(String filePath) {
    // Note: We check file existence here in the isolate to avoid race conditions
    // but you can also do it in the main thread if you prefer.
    final file = File(filePath);
    if (!file.existsSync()) return null;

    // 1. Re-open the library inside the Isolate
    // (DynamicLibraries cannot be passed between Isolates, so we load it here)
    final DynamicLibrary lib = _loadLibrary();

    // 2. Lookup functions
    final DartHashFunc nativeHashFile = lib
        .lookup<NativeFunction<NativeHashFunc>>('sha256_file_native')
        .asFunction();

    final DartFreeFunc nativeFreeHash = lib
        .lookup<NativeFunction<NativeFreeFunc>>('free_sha256_string')
        .asFunction();

    // 3. Prepare Memory
    final pathPtr = filePath.toNativeUtf8();

    try {
      // 4. BLOCKING CALL (This is fine now, because we are in an Isolate)
      final resultPtr = nativeHashFile(pathPtr);

      if (resultPtr == nullptr) return null;

      final hash = resultPtr.toDartString();

      // 5. Free the C string memory
      nativeFreeHash(resultPtr);

      return hash;
    } finally {
      // 6. Free the path string memory
      calloc.free(pathPtr);
    }
  }

  /// Helper to load the library based on the platform.
  /// This is called inside the Isolate.
  static DynamicLibrary _loadLibrary() {
    if (Platform.isWindows) {
      return DynamicLibrary.open('file_hash.dll');
    } else if (Platform.isLinux || Platform.isAndroid) {
      return DynamicLibrary.open('libfile_hash.so');
    } else if (Platform.isIOS || Platform.isMacOS) {
      // iOS/macOS often link plugins statically or as frameworks where symbols
      // are globally available. .process() is the safest default here.
      return DynamicLibrary.process();
    }
    throw UnsupportedError('Unknown platform: ${Platform.operatingSystem}');
  }
}
