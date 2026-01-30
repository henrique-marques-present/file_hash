import 'dart:io';

import 'package:file_hash/file_hash.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:path/path.dart' as path;

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('FileHash.computeSha256', () {
    late Directory tempDir;

    setUp(() async {
      // Create a temporary directory for test files
      tempDir = await Directory.systemTemp.createTemp('file_hash_test_');
    });

    tearDown(() async {
      // Clean up temporary directory
      if (await tempDir.exists()) {
        await tempDir.delete(recursive: true);
      }
    });

    test('computes correct SHA-256 hash for known content', () async {
      // Create a test file with known content
      final testFile = File(path.join(tempDir.path, 'test.txt'));
      await testFile.writeAsString('Hello, World!');

      // Compute hash
      final hash = await FileHash.computeSha256(testFile.path);

      // Expected SHA-256 hash of "Hello, World!"
      // You can verify this with: echo -n "Hello, World!" | shasum -a 256
      const expectedHash =
          'dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f';

      expect(hash, equals(expectedHash));
    });

    test('computes correct SHA-256 hash for empty file', () async {
      // Create an empty file
      final testFile = File(path.join(tempDir.path, 'empty.txt'));
      await testFile.writeAsString('');

      // Compute hash
      final hash = await FileHash.computeSha256(testFile.path);

      // Expected SHA-256 hash of empty string
      // echo -n "" | shasum -a 256
      const expectedHash =
          'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

      expect(hash, equals(expectedHash));
    });

    test('computes correct SHA-256 hash for binary data', () async {
      // Create a file with binary data
      final testFile = File(path.join(tempDir.path, 'binary.bin'));
      await testFile.writeAsBytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);

      // Compute hash
      final hash = await FileHash.computeSha256(testFile.path);

      // Expected SHA-256 hash of bytes [0,1,2,3,4,5,6,7,8,9]
      const expectedHash =
          '1f825aa2f0020ef7cf91dfa30da4668d791c5d4824fc8e41354b89ec05795ab3';

      expect(hash, equals(expectedHash));
    });

    test('computes correct SHA-256 hash for large file', () async {
      // Create a larger file (1MB of repeated data)
      final testFile = File(path.join(tempDir.path, 'large.bin'));
      final data = List<int>.filled(1024 * 1024, 65); // 1MB of 'A' characters
      await testFile.writeAsBytes(data);

      // Compute hash
      final hash = await FileHash.computeSha256(testFile.path);

      // This should complete without errors
      expect(hash, isNotNull);
      expect(hash, hasLength(64)); // SHA-256 produces 64 hex characters
      expect(hash, matches(RegExp(r'^[a-f0-9]{64}$')));
    });

    test('returns null for non-existent file', () async {
      final nonExistentPath = path.join(tempDir.path, 'does_not_exist.txt');

      // Compute hash
      final hash = await FileHash.computeSha256(nonExistentPath);

      expect(hash, isNull);
    });

    test('produces consistent results for same content', () async {
      // Create two files with identical content
      final testFile1 = File(path.join(tempDir.path, 'file1.txt'));
      final testFile2 = File(path.join(tempDir.path, 'file2.txt'));
      const content = 'Identical content for testing';
      await testFile1.writeAsString(content);
      await testFile2.writeAsString(content);

      // Compute hashes
      final hash1 = await FileHash.computeSha256(testFile1.path);
      final hash2 = await FileHash.computeSha256(testFile2.path);

      expect(hash1, equals(hash2));
    });

    test('produces different results for different content', () async {
      // Create two files with different content
      final testFile1 = File(path.join(tempDir.path, 'file1.txt'));
      final testFile2 = File(path.join(tempDir.path, 'file2.txt'));
      await testFile1.writeAsString('Content A');
      await testFile2.writeAsString('Content B');

      // Compute hashes
      final hash1 = await FileHash.computeSha256(testFile1.path);
      final hash2 = await FileHash.computeSha256(testFile2.path);

      expect(hash1, isNot(equals(hash2)));
    });

    test('hash format is valid (64 lowercase hex characters)', () async {
      final testFile = File(path.join(tempDir.path, 'test.txt'));
      await testFile.writeAsString('Test content');

      final hash = await FileHash.computeSha256(testFile.path);

      expect(hash, isNotNull);
      expect(hash, hasLength(64));
      expect(hash, matches(RegExp(r'^[a-f0-9]{64}$')));
    });

    test('handles files with special characters in path', () async {
      final specialDir = await Directory(
        path.join(tempDir.path, 'special dir!@#'),
      ).create(recursive: true);
      final testFile = File(path.join(specialDir.path, 'test file.txt'));
      await testFile.writeAsString('Special path test');

      final hash = await FileHash.computeSha256(testFile.path);

      expect(hash, isNotNull);
      expect(hash, hasLength(64));
    });

    test('can hash multiple files concurrently', () async {
      // Create multiple test files
      final files = <File>[];
      for (int i = 0; i < 5; i++) {
        final file = File(path.join(tempDir.path, 'file_$i.txt'));
        await file.writeAsString('Content $i');
        files.add(file);
      }

      // Compute hashes concurrently
      final futures = files
          .map((file) => FileHash.computeSha256(file.path))
          .toList();
      final hashes = await Future.wait(futures);

      // All hashes should be computed successfully
      expect(hashes.length, equals(5));
      for (final hash in hashes) {
        expect(hash, isNotNull);
        expect(hash, hasLength(64));
      }

      // All hashes should be different (different content)
      final uniqueHashes = hashes.toSet();
      expect(uniqueHashes.length, equals(5));
    });
  });
}
