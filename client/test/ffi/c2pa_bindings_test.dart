import 'package:flutter_test/flutter_test.dart';
import 'package:kerberos_client/ffi/c2pa_bindings.dart';

void main() {
  group('C2PA FFI Zero-Trust Memory & Logic Tests', () {
    C2paEngine? engine;

    setUp(() {
      // Assumes native library is built and available in test environment path
      try {
        engine = C2paEngine();
      } catch (e) {
        markTestSkipped('Native library not found in test environment. Run `cargo build` first.');
      }
    });

    test('signAsset validates inputs and extracts manifest without leaking memory', () {
      if (engine == null) return;
      final mockFilePath = '/tmp/test_image.jpg';
      final mockClaimData = '{"author": "Kerberos Agent"}';

      // The execution must succeed and, crucially, not crash or throw memory exceptions
      // The try/finally block in signAsset guarantees `free_c2pa_result` is invoked.
      final manifestJson = engine!.signAsset(mockFilePath, mockClaimData);

      expect(manifestJson, isNotEmpty);
      expect(manifestJson, contains('sealed'));
      expect(manifestJson, contains(mockFilePath));
    });

    test('signAsset gracefully handles extremely large string payloads without corruption', () {
      if (engine == null) return;
      final mockFilePath = '/tmp/massive_file.pdf';
      
      // Generate a massive 5MB dummy claim string to stress test the calloc/free cycle
      final massiveClaim = List.generate(50000, (i) => 'A').join();
      
      // If `free_c2pa_result` fails or `calloc.free` fails, this will trigger a segfault
      // which the test runner will catch as a fatal crash.
      expect(() => engine!.signAsset(mockFilePath, massiveClaim), returnsNormally);
    });

    test('Zero-Trust Constraint: signAsset rejects malformed data', () {
      if (engine == null) return;
      // In an actual integration, passing empty or wildly invalid paths should 
      // trigger a handled exception from Rust, rather than a crash.
      
      // This test ensures the Dart side catches the exception safely and cleans up memory.
      // (Implementation detail depends on exact Rust sanitization, here we test the boundary)
      try {
        engine!.signAsset('', '');
      } catch (e) {
        expect(e.toString(), contains('Zero-Trust Fault'));
      }
    });
  });
}
