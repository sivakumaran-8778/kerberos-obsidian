import 'dart:io';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:kerberos_client/features/radar/services/file_download_io.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('file_download_io saves bytes correctly to fallback path when dialog is not interacted', () async {
    final testBytes = Uint8List.fromList([0xDE, 0xAD, 0xBE, 0xEF]);
    const fileName = 'test_enclave_asset.bin';

    final savedPath = await saveFileBytesPlatform(fileName, testBytes);

    expect(savedPath, isNotNull);
    final file = File(savedPath!);
    expect(file.existsSync(), isTrue);
    expect(await file.readAsBytes(), equals(testBytes));

    // Cleanup
    await file.delete();
  });
}
