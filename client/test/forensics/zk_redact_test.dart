import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:image/image.dart' as img;
import 'package:kerberos_client/features/forensics/services/crypto_engine.dart';

void main() {
  group('Zero-Knowledge Selective Disclosure (zk-Redact) Tests', () {
    late Uint8List testImageBytes;

    setUp(() {
      // Create a solid white 50x50 PNG image for testing
      final image = img.Image(width: 50, height: 50);
      for (int y = 0; y < 50; y++) {
        for (int x = 0; x < 50; x++) {
          image.setPixelRgb(x, y, 255, 255, 255);
        }
      }
      testImageBytes = Uint8List.fromList(img.encodePng(image));
    });

    test('applyPixelBlackout permanently zeroes pixels in target region', () {
      final coords = {
        'x': 10,
        'y': 10,
        'width': 20,
        'height': 20,
      };

      final redactedBytes = CryptoEngineWeb.applyPixelBlackout(testImageBytes, coords);
      expect(redactedBytes, isNotEmpty);
      expect(redactedBytes, isNot(equals(testImageBytes)));

      final decoded = img.decodeImage(redactedBytes);
      expect(decoded, isNotNull);

      // Verify targeted pixels are strictly (0, 0, 0) black
      final redactedPixel = decoded!.getPixel(15, 15);
      expect(redactedPixel.r, equals(0));
      expect(redactedPixel.g, equals(0));
      expect(redactedPixel.b, equals(0));

      // Verify unredacted pixels outside the box remain white (255, 255, 255)
      final intactPixel = decoded.getPixel(5, 5);
      expect(intactPixel.r, equals(255));
      expect(intactPixel.g, equals(255));
      expect(intactPixel.b, equals(255));
    });

    test('generateRedactionProof creates Groth16 zk-SNARK proof package', () async {
      final coords = {
        'x': 10,
        'y': 10,
        'width': 20,
        'height': 20,
      };

      final result = await CryptoEngineWeb.generateRedactionProof(testImageBytes, coords);

      expect(result['redactedFileBuffer'], isNotNull);
      expect(result['originalHash'], isNotEmpty);
      expect(result['redactedHash'], isNotEmpty);
      expect(result['originalHash'], isNot(equals(result['redactedHash'])));

      final zkProof = result['zkProof'] as Map<dynamic, dynamic>;
      expect(zkProof['protocol'], equals('groth16'));
      expect(zkProof['curve'], equals('bn128'));
      expect(zkProof['pi_a'], isNotEmpty);
      expect(zkProof['pi_b'], isNotEmpty);
      expect(zkProof['pi_c'], isNotEmpty);

      final signals = result['publicSignals'] as List<dynamic>;
      expect(signals.first, equals(result['originalHash']));

      final logs = result['executionLog'] as List<dynamic>;
      expect(logs.any((log) => log.toString().contains('zk-SNARK proof successfully generated')), isTrue);
    });

    test('verifyRedactionProof validates authentic redacted proof and detects ledger mismatch', () async {
      final coords = {'x': 5, 'y': 5, 'width': 10, 'height': 10};
      final proofData = await CryptoEngineWeb.generateRedactionProof(testImageBytes, coords);

      final redactedBytes = proofData['redactedFileBuffer'] as Uint8List;
      final zkProof = (proofData['zkProof'] as Map).cast<String, dynamic>();
      final publicSignals = (proofData['publicSignals'] as List).map((e) => e.toString()).toList();
      final originalHash = proofData['originalHash'] as String;

      // 1. Legitimate verification
      final verification = await CryptoEngineWeb.verifyRedactionProof(
        redactedBytes,
        zkProof,
        publicSignals,
        {'protocol': 'groth16', 'curve': 'bn128'},
        originalHash,
      );

      expect(verification['status'], equals('OK'));
      expect(verification['message'], contains('VALID ZERO-KNOWLEDGE PROOF DETECTED'));

      // 2. Tampered expected ledger hash produces Provenance Paradox
      expect(
        () async => await CryptoEngineWeb.verifyRedactionProof(
          redactedBytes,
          zkProof,
          publicSignals,
          {'protocol': 'groth16', 'curve': 'bn128'},
          'tampered_ledger_hash_0000000000000000000000000000000000000000',
        ),
        throwsA(isA<Map<dynamic, dynamic>>()),
      );
    });

    test('evaluateProvenance evaluates trust anchor, hash binding, and blind forensics', () async {
      final validManifest = {
        'issuer': 'Content Authenticity Initiative',
        'manifestHash': 'expected_test_hash',
      };

      // Manifest hash mismatch should fail
      final result1 = await CryptoEngineWeb.evaluateProvenance(testImageBytes, validManifest);
      expect(result1['verdict'], isFalse);

      // Untrusted issuer should fail
      final untrustedManifest = {
        'issuer': 'Malicious Red Team CA',
        'manifestHash': '',
      };
      final result2 = await CryptoEngineWeb.evaluateProvenance(testImageBytes, untrustedManifest);
      expect(result2['verdict'], isFalse);
    });
  });
}
