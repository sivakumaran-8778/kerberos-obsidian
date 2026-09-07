import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:crypto/crypto.dart';
import 'package:kerberos_client/features/ledger/models/provenance_record.dart';
import 'package:kerberos_client/features/verification/models/verification_models.dart';
import 'package:kerberos_client/features/verification/services/verification_service.dart';

void main() {
  group('Zero-Trust Forensic Diagnostics & Evaluation Tests', () {
    late Uint8List originalBytes;
    late String originalHash;
    late ProvenanceRecord sealedRecord;

    setUp(() {
      originalBytes = Uint8List.fromList(utf8.encode('CONFIDENTIAL_OBSIDIAN_PAYLOAD_V2_DATA'));
      originalHash = sha256.convert(originalBytes).toString();

      sealedRecord = ProvenanceRecord(
        id: 'rec-uuid-001',
        originalFileHash: originalHash,
        c2paManifestUri: 'urn:c2pa:obsidian:${originalHash.substring(0, 12)}',
        timestamp: DateTime.now().subtract(const Duration(hours: 1)),
        signature: 'ed25519-signature-token',
        filePath: 'quarterly_financials_2026.pdf',
      );
    });

    test('Unsealed file diagnosis: identifies missing ledger baseline and missing C2PA envelope', () {
      final unsealedBytes = Uint8List.fromList(utf8.encode('RANDOM_UNSEALED_IMAGE_FILE'));
      final report = VerificationService.analyzeAsset(
        bytes: unsealedBytes,
        fileName: 'unsealed_photo.png',
        ledgerHistory: [], // Empty ledger - unsealed asset
      );

      expect(report.verdict, equals(VerificationVerdict.unsealed));
      expect(report.matchedRecord, isNull);
      expect(report.metadataScrub.hasJumbfPayload, isFalse);
    });

    test('Bitstream shattered diagnosis: identifies hex editing / byte alteration after sealing', () {
      final tamperedBytes = Uint8List.fromList(originalBytes);
      tamperedBytes[2] = tamperedBytes[2] ^ 0xFF; // Modify 1 byte

      final report = VerificationService.analyzeAsset(
        bytes: tamperedBytes,
        fileName: 'quarterly_financials_2026.pdf',
        ledgerHistory: [sealedRecord],
      );

      expect(report.verdict, equals(VerificationVerdict.bitstreamShattered));
      expect(report.bitstream.isMatch, isFalse);
      expect(report.bitstream.flippedBytesCount, greaterThan(0));
      expect(report.matchedRecord?.id, equals('rec-uuid-001'));
    });

    test('Metadata scrub diagnosis: identifies social media proxy stripping of C2PA manifest', () {
      final pristineReport = VerificationService.analyzeAsset(
        bytes: originalBytes,
        fileName: 'quarterly_financials_2026.pdf',
        ledgerHistory: [sealedRecord],
      );

      final scrubbedReport = VerificationService.simulateMetadataScrub(pristineReport);

      expect(scrubbedReport.verdict, equals(VerificationVerdict.metadataScrubbed));
      expect(scrubbedReport.metadataScrub.isScrubbed, isTrue);
      expect(scrubbedReport.metadataScrub.hasJumbfPayload, isFalse);
      expect(scrubbedReport.metadataScrub.interceptorDiagnosis?.toLowerCase(), contains('stripped'));
    });

    test('Steganography altered diagnosis: detects perceptual tensor drift across 16x16 grid', () {
      final pristineReport = VerificationService.analyzeAsset(
        bytes: originalBytes,
        fileName: 'quarterly_financials_2026.pdf',
        ledgerHistory: [sealedRecord],
      );

      final stegoReport = VerificationService.simulateSteganographyAttack(pristineReport);

      expect(stegoReport.verdict, equals(VerificationVerdict.steganographyAltered));
      expect(stegoReport.steganography.isAltered, isTrue);
      expect(stegoReport.steganography.perceptualDrift, greaterThan(0.0));
      expect(stegoReport.steganography.heatmapVector.length, equals(256));
    });

    test('Pristine sealed diagnosis: all 4 Zero-Trust pillars verified bit-for-bit', () {
      final report = VerificationService.analyzeAsset(
        bytes: originalBytes,
        fileName: 'quarterly_financials_2026.pdf',
        ledgerHistory: [sealedRecord],
      );

      expect(report.verdict, equals(VerificationVerdict.pristineSealed));
      expect(report.bitstream.isMatch, isTrue);
      expect(report.steganography.isAltered, isFalse);
      expect(report.steganography.perceptualDrift, equals(0.00));
      expect(report.metadataScrub.originCertificateValid, isTrue);
      expect(report.matchedRecord?.id, equals('rec-uuid-001'));
    });
  });
}
