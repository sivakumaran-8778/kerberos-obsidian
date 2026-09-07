import 'dart:io';
import 'dart:typed_data';
import 'package:file_picker/file_picker.dart';
import 'package:path_provider/path_provider.dart';
import 'package:path/path.dart' as p;

/// Desktop / Mobile implementation: prompts native Save File Dialog or saves to Downloads directory.
Future<String?> saveFileBytesPlatform(String fileName, Uint8List bytes) async {
  String? savedPath;
  try {
    savedPath = await FilePicker.platform.saveFile(
      dialogTitle: 'Save $fileName',
      fileName: fileName,
      bytes: bytes,
    );
  } catch (_) {
    savedPath = null;
  }

  if (savedPath != null) {
    final file = File(savedPath);
    await file.writeAsBytes(bytes);
    return savedPath;
  } else {
    // Fallback: If user canceled dialog or platform did not return path, write to system Downloads
    String? downloadsPath;
    if (Platform.isWindows && Platform.environment.containsKey('USERPROFILE')) {
      final userProfile = Platform.environment['USERPROFILE']!;
      final winDownloads = p.join(userProfile, 'Downloads');
      if (Directory(winDownloads).existsSync()) {
        downloadsPath = winDownloads;
      }
    }
    if (downloadsPath == null) {
      try {
        final dir = await getDownloadsDirectory();
        downloadsPath = dir?.path;
      } catch (_) {}
    }
    if (downloadsPath == null) {
      try {
        final dir = await getApplicationDocumentsDirectory();
        downloadsPath = dir.path;
      } catch (_) {}
    }
    downloadsPath ??= Directory.systemTemp.path;

    final fallbackPath = p.join(downloadsPath, fileName);
    final file = File(fallbackPath);
    await file.writeAsBytes(bytes);
    return fallbackPath;
  }
}
