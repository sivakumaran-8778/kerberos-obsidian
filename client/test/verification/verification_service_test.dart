import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:crypto/crypto.dart';
import 'package:kerberos_client/features/ledger/models/provenance_record.dart';
import 'package:kerberos_client/features/verification/models/verification_models.dart';
import 'package:kerberos_client/features/verification/services/verification_service.dart';

void main() {
  group('Zero-Trust Content-Addressable Verification Tests', () {
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

    test('Identifies renamed file with identical bitstream as pristineSealed', () {
      final report = VerificationService.analyzeAsset(
        bytes: originalBytes,
        fileName: 'renamed_copy_financials.pdf', // Renamed by user!
        ledgerHistory: [sealedRecord],
      );

      expect(report.verdict, equals(VerificationVerdict.pristineSealed));
      expect(report.bitstream.isMatch, isTrue);
      expect(report.isRenamed, isTrue);
      expect(report.originalSealedName, equals('quarterly_financials_2026.pdf'));
      expect(report.fileName, equals('renamed_copy_financials.pdf'));
      expect(report.matchedRecord?.id, equals('rec-uuid-001'));
      expect(report.matchReason, contains('File was renamed from "quarterly_financials_2026.pdf"'));
    });

    test('Identifies tampered bitstream when 1 byte is flipped (Hex attack)', () {
      final pristineReport = VerificationService.analyzeAsset(
        bytes: originalBytes,
        fileName: 'quarterly_financials_2026.pdf',
        ledgerHistory: [sealedRecord],
      );

      final tamperedReport = VerificationService.simulateHexEditorAttack(pristineReport);

      expect(tamperedReport.verdict, equals(VerificationVerdict.bitstreamShattered));
      expect(tamperedReport.bitstream.isMatch, isFalse);
      expect(tamperedReport.bitstream.flippedBytesCount, equals(1));
      expect(tamperedReport.bitstream.stealthAlertTriggered, isTrue);
    });

    test('Explicit targetRecordId successfully detects bitstream divergence for renamed tampered file', () {
      // Simulate 1 byte change
      final tamperedBytes = Uint8List.fromList(originalBytes);
      tamperedBytes[5] = tamperedBytes[5] ^ 0x01;

      final report = VerificationService.analyzeAsset(
        bytes: tamperedBytes,
        fileName: 'attacker_altered.pdf',
        ledgerHistory: [sealedRecord],
        targetRecordId: 'rec-uuid-001',
      );

      expect(report.verdict, equals(VerificationVerdict.bitstreamShattered));
      expect(report.bitstream.isMatch, isFalse);
      expect(report.matchedRecord?.id, equals('rec-uuid-001'));
      expect(report.originalSealedName, equals('quarterly_financials_2026.pdf'));
    });

    test('Marks unsealed files as unsealed when no match exists in ledger and no C2PA envelope', () {
      final foreignBytes = Uint8List.fromList(utf8.encode('COMPLETELY_UNRELATED_FILE_FROM_INTERNET'));
      final report = VerificationService.analyzeAsset(
        bytes: foreignBytes,
        fileName: 'cat_picture.jpg',
        ledgerHistory: [], // Empty ledger
      );

      expect(report.verdict, equals(VerificationVerdict.unsealed));
      expect(report.matchedRecord, isNull);
    });

    test('Recognizes edited file with exact same filename and detects tampering (bitstreamShattered)', () {
      final editedBytes = Uint8List.fromList(utf8.encode('CONFIDENTIAL_OBSIDIAN_PAYLOAD_V2_DATA_EDITED_BY_RECIPIENT'));
      final report = VerificationService.analyzeAsset(
        bytes: editedBytes,
        fileName: 'quarterly_financials_2026.pdf',
        ledgerHistory: [sealedRecord],
        targetRecordId: null, // Auto-Detect
      );

      expect(report.verdict, equals(VerificationVerdict.bitstreamShattered));
      expect(report.bitstream.isMatch, isFalse);
      expect(report.matchedRecord?.id, equals('rec-uuid-001'));
      expect(report.originalSealedName, equals('quarterly_financials_2026.pdf'));
      expect(report.matchReason, contains('Identical file identifier'));
    });

    test('Recognizes edited file downloaded from mail with duplicate name (e.g. "quarterly_financials_2026 (1).pdf")', () {
      final editedBytes = Uint8List.fromList(utf8.encode('MODIFIED_CONTENT_FROM_EMAIL'));
      final report = VerificationService.analyzeAsset(
        bytes: editedBytes,
        fileName: 'quarterly_financials_2026 (1).pdf',
        ledgerHistory: [sealedRecord],
        targetRecordId: null, // Auto-Detect
      );

      expect(report.verdict, equals(VerificationVerdict.bitstreamShattered));
      expect(report.bitstream.isMatch, isFalse);
      expect(report.matchedRecord?.id, equals('rec-uuid-001'));
      expect(report.originalSealedName, equals('quarterly_financials_2026.pdf'));
      expect(report.matchReason, contains('Lineage verified'));
    });

    test('Recognizes edited file with revision suffix (e.g. "_edited.pdf", "_signed.pdf", "_v2.pdf")', () {
      final editedBytes = Uint8List.fromList(utf8.encode('MODIFIED_DOCUMENT_CONTENT'));
      for (final variant in [
        'quarterly_financials_2026_edited.pdf',
        'quarterly_financials_2026_signed.pdf',
        'quarterly_financials_2026_v2.pdf',
        'quarterly_financials_2026_final.pdf',
      ]) {
        final report = VerificationService.analyzeAsset(
          bytes: editedBytes,
          fileName: variant,
          ledgerHistory: [sealedRecord],
          targetRecordId: null,
        );

        expect(report.verdict, equals(VerificationVerdict.bitstreamShattered), reason: 'Failed for $variant');
        expect(report.matchedRecord?.id, equals('rec-uuid-001'));
      }
    });

    test('Supports all media and document types (DOCX, PPTX, MP4 video, M4A audio, PNG image)', () {
      final docxRecord = ProvenanceRecord(
        id: 'docx-uuid',
        originalFileHash: sha256.convert(utf8.encode('ORIGINAL_DOCX')).toString(),
        c2paManifestUri: 'urn:c2pa:obsidian:docx',
        timestamp: DateTime.now(),
        signature: 'sig',
        filePath: 'legal_agreement.docx',
      );

      final pptxRecord = ProvenanceRecord(
        id: 'pptx-uuid',
        originalFileHash: sha256.convert(utf8.encode('ORIGINAL_PPTX')).toString(),
        c2paManifestUri: 'urn:c2pa:obsidian:pptx',
        timestamp: DateTime.now(),
        signature: 'sig',
        filePath: 'executive_pitch.pptx',
      );

      final videoRecord = ProvenanceRecord(
        id: 'video-uuid',
        originalFileHash: sha256.convert(utf8.encode('ORIGINAL_VIDEO')).toString(),
        c2paManifestUri: 'urn:c2pa:obsidian:video',
        timestamp: DateTime.now(),
        signature: 'sig',
        filePath: 'security_cam_01.mp4',
      );

      final audioRecord = ProvenanceRecord(
        id: 'audio-uuid',
        originalFileHash: sha256.convert(utf8.encode('ORIGINAL_AUDIO')).toString(),
        c2paManifestUri: 'urn:c2pa:obsidian:audio',
        timestamp: DateTime.now(),
        signature: 'sig',
        filePath: 'board_meeting_audio.m4a',
      );

      final allRecords = [docxRecord, pptxRecord, videoRecord, audioRecord];

      // Test DOCX edit
      final docxReport = VerificationService.analyzeAsset(
        bytes: Uint8List.fromList(utf8.encode('MODIFIED_DOCX')),
        fileName: 'legal_agreement_v2.docx',
        ledgerHistory: allRecords,
      );
      expect(docxReport.verdict, equals(VerificationVerdict.bitstreamShattered));
      expect(docxReport.matchedRecord?.id, equals('docx-uuid'));

      // Test PPTX edit
      final pptxReport = VerificationService.analyzeAsset(
        bytes: Uint8List.fromList(utf8.encode('MODIFIED_PPTX')),
        fileName: 'executive_pitch_final.pptx',
        ledgerHistory: allRecords,
      );
      expect(pptxReport.verdict, equals(VerificationVerdict.bitstreamShattered));
      expect(pptxReport.matchedRecord?.id, equals('pptx-uuid'));

      // Test Video edit
      final videoReport = VerificationService.analyzeAsset(
        bytes: Uint8List.fromList(utf8.encode('MODIFIED_VIDEO')),
        fileName: 'security_cam_01_edited.mp4',
        ledgerHistory: allRecords,
      );
      expect(videoReport.verdict, equals(VerificationVerdict.bitstreamShattered));
      expect(videoReport.matchedRecord?.id, equals('video-uuid'));

      // Test Audio edit
      final audioReport = VerificationService.analyzeAsset(
        bytes: Uint8List.fromList(utf8.encode('MODIFIED_AUDIO')),
        fileName: 'board_meeting_audio (1).m4a',
        ledgerHistory: allRecords,
      );
      expect(audioReport.verdict, equals(VerificationVerdict.bitstreamShattered));
      expect(audioReport.matchedRecord?.id, equals('audio-uuid'));
    });

    test('Disambiguates between multiple sealed assets and avoids false matches to sample records', () {
      final sampleRecord = ProvenanceRecord(
        id: 'sample-satellite-01',
        originalFileHash: 'sample-hash-1234567890',
        c2paManifestUri: 'urn:c2pa:obsidian:sample',
        timestamp: DateTime.now().subtract(const Duration(days: 1)),
        signature: 'sig',
        filePath: 'satellite_recon_delta_09.png',
      );

      final myContract = ProvenanceRecord(
        id: 'my-contract-uuid',
        originalFileHash: 'contract-hash-9876543210',
        c2paManifestUri: 'urn:c2pa:obsidian:contract',
        timestamp: DateTime.now(),
        signature: 'sig',
        filePath: 'vendor_agreement_signed.pdf',
      );

      final editedContractBytes = Uint8List.fromList(utf8.encode('EDITED_CONTRACT_DATA'));
      final report = VerificationService.analyzeAsset(
        bytes: editedContractBytes,
        fileName: 'vendor_agreement_signed.pdf',
        ledgerHistory: [sampleRecord, myContract],
      );

      expect(report.verdict, equals(VerificationVerdict.bitstreamShattered));
      expect(report.matchedRecord?.id, equals('my-contract-uuid'));
      expect(report.matchedRecord?.id, isNot(equals('sample-satellite-01')));
    });

    test('Identifies lineage when file has embedded C2PA manifest URI even if renamed', () {
      final editedWithUri = Uint8List.fromList(
        utf8.encode('TAMPERED_BYTES...urn:c2pa:obsidian:${originalHash.substring(0, 12)}...MORE_BYTES'),
      );

      final report = VerificationService.analyzeAsset(
        bytes: editedWithUri,
        fileName: 'completely_different_name.pdf',
        ledgerHistory: [sealedRecord],
      );

      expect(report.verdict, equals(VerificationVerdict.bitstreamShattered));
      expect(report.matchedRecord?.id, equals('rec-uuid-001'));
      expect(report.matchReason, contains('Embedded C2PA envelope detected'));
    });
  });
}
