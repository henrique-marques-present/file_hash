import 'dart:io';

import 'package:file_hash/file_hash.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/material.dart';
import 'package:path_provider/path_provider.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'File Hash Demo',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
      home: const FileHashDemo(),
    );
  }
}

class FileHashDemo extends StatefulWidget {
  const FileHashDemo({super.key});

  @override
  State<FileHashDemo> createState() => _FileHashDemoState();
}

class _FileHashDemoState extends State<FileHashDemo> {
  String? _selectedFilePath;
  String? _hashResult;
  bool _isHashing = false;
  String? _errorMessage;
  String? _testFileHash;
  int? _hashTimeMs; // Time taken to compute hash in milliseconds
  int? _fileSizeBytes; // Size of the file in bytes

  @override
  void initState() {
    super.initState();
    _createAndHashTestFile();
  }

  /// Creates a test file and computes its hash on startup
  Future<void> _createAndHashTestFile() async {
    try {
      final tempDir = await getTemporaryDirectory();
      final testFile = File('${tempDir.path}/test_file.txt');

      // Create a test file with known content
      await testFile.writeAsString('Hello, SHA-256!');

      // Compute its hash
      final hash = await FileHash.computeSha256(testFile.path);

      setState(() {
        _testFileHash = hash;
      });
    } catch (e) {
      debugPrint('Error creating test file: $e');
    }
  }

  Future<void> _pickAndHashFile() async {
    setState(() {
      _isHashing = false;
      _hashResult = null;
      _errorMessage = null;
      _selectedFilePath = null;
      _hashTimeMs = null;
      _fileSizeBytes = null;
    });

    try {
      // Pick a file - allow all file types
      final result = await FilePicker.platform.pickFiles(
        type: FileType.any,
        allowMultiple: false,
      );

      if (result == null || result.files.isEmpty) {
        return; // User cancelled
      }

      final filePath = result.files.single.path;
      if (filePath == null) {
        setState(() {
          _errorMessage = 'Could not get file path';
        });
        return;
      }

      // Get file size
      final file = File(filePath);
      final fileSize = await file.length();

      setState(() {
        _selectedFilePath = filePath;
        _fileSizeBytes = fileSize;
        _isHashing = true;
      });

      // Compute SHA-256 hash with timing
      final stopwatch = Stopwatch()..start();
      final hash = await FileHash.computeSha256(filePath);
      stopwatch.stop();

      setState(() {
        _hashResult = hash;
        _hashTimeMs = stopwatch.elapsedMilliseconds;
        _isHashing = false;
      });
    } catch (e) {
      setState(() {
        _errorMessage = 'Error: $e';
        _isHashing = false;
      });
    }
  }

  /// Format file size in human-readable format
  String _formatFileSize(int bytes) {
    if (bytes < 1024) return '$bytes B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(2)} KB';
    if (bytes < 1024 * 1024 * 1024) {
      return '${(bytes / (1024 * 1024)).toStringAsFixed(2)} MB';
    }
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(2)} GB';
  }

  /// Format time in human-readable format
  String _formatTime(int milliseconds) {
    if (milliseconds < 1000) return '${milliseconds}ms';
    if (milliseconds < 60000) {
      return '${(milliseconds / 1000).toStringAsFixed(2)}s';
    }
    final minutes = milliseconds ~/ 60000;
    final seconds = (milliseconds % 60000) / 1000;
    return '${minutes}m ${seconds.toStringAsFixed(1)}s';
  }

  /// Calculate and format hashing speed
  String _formatSpeed(int bytes, int milliseconds) {
    if (milliseconds == 0) return 'N/A';
    final bytesPerSecond = (bytes / milliseconds) * 1000;
    if (bytesPerSecond < 1024 * 1024) {
      return '${(bytesPerSecond / 1024).toStringAsFixed(2)} KB/s';
    }
    return '${(bytesPerSecond / (1024 * 1024)).toStringAsFixed(2)} MB/s';
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        backgroundColor: Theme.of(context).colorScheme.inversePrimary,
        title: const Text('SHA-256 File Hash Demo'),
      ),
      body: Padding(
        padding: const EdgeInsets.all(16.0),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Info card
            Card(
              child: Padding(
                padding: const EdgeInsets.all(16.0),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Text(
                      'Hardware-Accelerated SHA-256',
                      style: TextStyle(
                        fontSize: 18,
                        fontWeight: FontWeight.bold,
                      ),
                    ),
                    const SizedBox(height: 8),
                    Text(
                      'Platform: ${Platform.operatingSystem}',
                      style: TextStyle(color: Colors.grey[600]),
                    ),
                    if (_testFileHash != null) ...[
                      const SizedBox(height: 8),
                      const Text(
                        'Test file hash (known content):',
                        style: TextStyle(fontSize: 12),
                      ),
                      SelectableText(
                        _testFileHash!,
                        style: TextStyle(
                          fontFamily: 'monospace',
                          fontSize: 11,
                          color: Colors.green[700],
                        ),
                      ),
                    ],
                  ],
                ),
              ),
            ),
            const SizedBox(height: 24),

            // Pick file button
            ElevatedButton.icon(
              onPressed: _isHashing ? null : _pickAndHashFile,
              icon: const Icon(Icons.folder_open),
              label: const Text('Pick File to Hash'),
              style: ElevatedButton.styleFrom(
                padding: const EdgeInsets.all(16),
              ),
            ),

            const SizedBox(height: 24),

            // Results
            if (_selectedFilePath != null) ...[
              Card(
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      const Text(
                        'Selected File:',
                        style: TextStyle(fontWeight: FontWeight.bold),
                      ),
                      const SizedBox(height: 4),
                      Text(
                        _selectedFilePath!,
                        style: const TextStyle(fontSize: 12),
                      ),
                      if (_fileSizeBytes != null) ...[
                        const SizedBox(height: 8),
                        Text(
                          'Size: ${_formatFileSize(_fileSizeBytes!)}',
                          style: TextStyle(
                            fontSize: 12,
                            color: Colors.grey[700],
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),
            ],

            if (_isHashing)
              const Card(
                child: Padding(
                  padding: EdgeInsets.all(16.0),
                  child: Row(
                    children: [
                      CircularProgressIndicator(),
                      SizedBox(width: 16),
                      Text('Computing SHA-256 hash...'),
                    ],
                  ),
                ),
              ),

            if (_hashResult != null)
              Card(
                color: Colors.green[50],
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          const Icon(Icons.check_circle, color: Colors.green),
                          const SizedBox(width: 8),
                          const Text(
                            'SHA-256 Hash:',
                            style: TextStyle(fontWeight: FontWeight.bold),
                          ),
                          const Spacer(),
                          if (_hashTimeMs != null)
                            Container(
                              padding: const EdgeInsets.symmetric(
                                horizontal: 12,
                                vertical: 6,
                              ),
                              decoration: BoxDecoration(
                                color: Colors.blue[100],
                                borderRadius: BorderRadius.circular(12),
                              ),
                              child: Row(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  Icon(
                                    Icons.timer,
                                    size: 16,
                                    color: Colors.blue[900],
                                  ),
                                  const SizedBox(width: 4),
                                  Text(
                                    _formatTime(_hashTimeMs!),
                                    style: TextStyle(
                                      fontSize: 12,
                                      fontWeight: FontWeight.bold,
                                      color: Colors.blue[900],
                                    ),
                                  ),
                                ],
                              ),
                            ),
                        ],
                      ),
                      const SizedBox(height: 8),
                      SelectableText(
                        _hashResult!,
                        style: const TextStyle(
                          fontFamily: 'monospace',
                          fontSize: 14,
                        ),
                      ),
                      if (_hashTimeMs != null && _fileSizeBytes != null) ...[
                        const SizedBox(height: 8),
                        Text(
                          'Speed: ${_formatSpeed(_fileSizeBytes!, _hashTimeMs!)}',
                          style: TextStyle(
                            fontSize: 11,
                            color: Colors.grey[700],
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
              ),

            if (_errorMessage != null)
              Card(
                color: Colors.red[50],
                child: Padding(
                  padding: const EdgeInsets.all(16.0),
                  child: Row(
                    children: [
                      const Icon(Icons.error, color: Colors.red),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          _errorMessage!,
                          style: const TextStyle(color: Colors.red),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }
}
