import 'dart:typed_data';

/// Fallback stub for unsupported platforms.
Future<String?> saveFileBytesPlatform(String fileName, Uint8List bytes) async {
  throw UnsupportedError('Saving files is not supported on this platform.');
}
