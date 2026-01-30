import 'dart:io';

import 'package:file_hash/file_hash.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:integration_test/integration_test.dart';
import 'package:path/path.dart' as path;
import 'package:path_provider/path_provider.dart';

void main() {
  IntegrationTestWidgetsFlutterBinding.ensureInitialized();

  group('FileHash Integration Tests', () {
    late Directory tempDir;

    setUp(() async {
      // Create a temporary directory for test files
      final baseDir = await getTemporaryDirectory();
      tempDir = await Directory(
        path.join(
          baseDir.path,
          'file_hash_test_${DateTime.now().millisecondsSinceEpoch}',
        ),
      ).create(recursive: true);
    });

    tearDown(() async {
      // Clean up temporary directory
      if (await tempDir.exists()) {
        await tempDir.delete(recursive: true);
      }
    });

    testWidgets('computes correct SHA-256 hash for known content', (
      tester,
    ) async {
      // Create a test file with known content
      final testFile = File(path.join(tempDir.path, 'test.txt'));
      await testFile.writeAsString('Hello, World!');

      // Compute hash
      final hash = await FileHash.computeSha256(testFile.path);

      // Expected SHA-256 hash of "Hello, World!"
      const expectedHash =
          'dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f';

      expect(hash, equals(expectedHash));
    });

    testWidgets('computes correct SHA-256 hash for empty file', (tester) async {
      final testFile = File(path.join(tempDir.path, 'empty.txt'));
      await testFile.writeAsString('');

      final hash = await FileHash.computeSha256(testFile.path);

      // Expected SHA-256 hash of empty string
      const expectedHash =
          'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

      expect(hash, equals(expectedHash));
    });

    testWidgets('computes correct SHA-256 hash for binary data', (
      tester,
    ) async {
      final testFile = File(path.join(tempDir.path, 'binary.bin'));
      await testFile.writeAsBytes([0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);

      final hash = await FileHash.computeSha256(testFile.path);

      const expectedHash =
          '1f825aa2f0020ef7cf91dfa30da4668d791c5d4824fc8e41354b89ec05795ab3';

      expect(hash, equals(expectedHash));
    });

    testWidgets('handles large files correctly', (tester) async {
      final testFile = File(path.join(tempDir.path, 'large.bin'));
      // Create 1MB file
      final data = List<int>.filled(1024 * 1024, 65);
      await testFile.writeAsBytes(data);

      final hash = await FileHash.computeSha256(testFile.path);

      expect(hash, isNotNull);
      expect(hash, hasLength(64));
      expect(hash, matches(RegExp(r'^[a-f0-9]{64}$')));
    });

    testWidgets('returns null for non-existent file', (tester) async {
      final nonExistentPath = path.join(tempDir.path, 'does_not_exist.txt');

      final hash = await FileHash.computeSha256(nonExistentPath);

      expect(hash, isNull);
    });

    testWidgets('produces consistent results for same content', (tester) async {
      final testFile1 = File(path.join(tempDir.path, 'file1.txt'));
      final testFile2 = File(path.join(tempDir.path, 'file2.txt'));
      const content = 'Identical content for testing';
      await testFile1.writeAsString(content);
      await testFile2.writeAsString(content);

      final hash1 = await FileHash.computeSha256(testFile1.path);
      final hash2 = await FileHash.computeSha256(testFile2.path);

      expect(hash1, equals(hash2));
    });

    testWidgets('produces different results for different content', (
      tester,
    ) async {
      final testFile1 = File(path.join(tempDir.path, 'file1.txt'));
      final testFile2 = File(path.join(tempDir.path, 'file2.txt'));
      await testFile1.writeAsString('Content A');
      await testFile2.writeAsString('Content B');

      final hash1 = await FileHash.computeSha256(testFile1.path);
      final hash2 = await FileHash.computeSha256(testFile2.path);

      expect(hash1, isNot(equals(hash2)));
    });

    testWidgets('hash format is valid', (tester) async {
      final testFile = File(path.join(tempDir.path, 'test.txt'));
      await testFile.writeAsString('Test content');

      final hash = await FileHash.computeSha256(testFile.path);

      expect(hash, isNotNull);
      expect(hash, hasLength(64));
      expect(hash, matches(RegExp(r'^[a-f0-9]{64}$')));
    });

    testWidgets('handles files with special characters in path', (
      tester,
    ) async {
      final specialDir = await Directory(
        path.join(tempDir.path, 'special dir!@#'),
      ).create(recursive: true);
      final testFile = File(path.join(specialDir.path, 'test file.txt'));
      await testFile.writeAsString('Special path test');

      final hash = await FileHash.computeSha256(testFile.path);

      expect(hash, isNotNull);
      expect(hash, hasLength(64));
    });

    testWidgets('can hash multiple files concurrently', (tester) async {
      final files = <File>[];
      for (int i = 0; i < 5; i++) {
        final file = File(path.join(tempDir.path, 'file_$i.txt'));
        await file.writeAsString('Content $i');
        files.add(file);
      }

      final futures = files
          .map((file) => FileHash.computeSha256(file.path))
          .toList();
      final hashes = await Future.wait(futures);

      expect(hashes.length, equals(5));
      for (final hash in hashes) {
        expect(hash, isNotNull);
        expect(hash, hasLength(64));
      }

      final uniqueHashes = hashes.toSet();
      expect(uniqueHashes.length, equals(5));
    });
  });
}
