import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:image/image.dart' as img;
import 'package:kerberos_client/features/forensics/models/document_forensic_models.dart';
import 'package:kerberos_client/features/forensics/services/document_forensic_service.dart';

void main() {
  group('DocumentForensicService - Deep Binary Forensic Inspection', () {
    test('Detects clean single-generation authentic PDF', () {
      final cleanPdfContent = '''
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R >>
endobj
xref
0 4
0000000000 65535 f 
0000000010 00000 n 
0000000060 00000 n 
0000000115 00000 n 
trailer
<< /Size 4 /Root 1 0 R /Producer (HealthCare Billing Portal) /CreationDate (D:20240101120000Z) /ModDate (D:20240101120000Z) >>
startxref
170
%%EOF
''';
      final bytes = Uint8List.fromList(utf8.encode(cleanPdfContent));
      final report = DocumentForensicService.analyzeDocument(
        bytes: bytes,
        fileName: 'hospital_bill_jan2024.pdf',
      );

      expect(report.verdict, equals(DocumentForensicVerdict.authenticOriginal));
      expect(report.isOriginal, isTrue);
      expect(report.isTampered, isFalse);
      expect(report.isScrambled, isFalse);
      expect(report.revisionCount, equals(1));
      expect(report.history.length, equals(1));
      expect(report.history.first.title, contains('v1'));
      expect(report.isMagicByteValid, isTrue);
      expect(report.hasTrailingPayload, isFalse);
    });

    test('Detects incremental revision tampering (multiple %%EOF & /Prev pointer)', () {
      final tamperedPdf = '''
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
xref
0 2
0000000000 65535 f 
0000000010 00000 n 
trailer
<< /Size 2 /Root 1 0 R /Producer (Gov Portal Official) /CreationDate (D:20240101100000Z) >>
startxref
60
%%EOF
3 0 obj
<< /Type /Page /Contents (Altered Tax Exemption Total: \$99,999) >>
endobj
xref
3 1
0000000120 00000 n 
trailer
<< /Size 4 /Prev 60 /Producer (Adobe Acrobat Pro 2024) /ModDate (D:20240315140000Z) >>
startxref
240
%%EOF
''';
      final bytes = Uint8List.fromList(utf8.encode(tamperedPdf));
      final report = DocumentForensicService.analyzeDocument(
        bytes: bytes,
        fileName: 'tax_clearance_certificate.pdf',
      );

      expect(report.verdict, equals(DocumentForensicVerdict.tamperedEdited));
      expect(report.isTampered, isTrue);
      expect(report.isOriginal, isFalse);
      expect(report.revisionCount, equals(2));
      expect(report.history.length, equals(2));
      expect(report.history[0].title, contains('v1'));
      expect(report.history[1].title, contains('v2'));
      expect(report.history[1].isTamperOrAppended, isTrue);
      expect(report.anomalies.any((a) => a.title.contains('Incremental Revision')), isTrue);
      expect(report.editingSoftwareDetected, contains('Adobe Acrobat Pro'));
    });

    test('Detects Photoshop 8BIM signatures on medical bill scan image', () {
      final header = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01];
      final photoshopPayload = utf8.encode('RawScanData...Photoshop 3.0...8BIM...Adobe Photoshop 2024...RasterLayer');
      final footer = [0xFF, 0xD9]; // JPEG EOI
      final bytes = Uint8List.fromList([...header, ...photoshopPayload, ...footer]);

      final report = DocumentForensicService.analyzeDocument(
        bytes: bytes,
        fileName: 'mri_scan_report.jpg',
      );

      expect(report.verdict, equals(DocumentForensicVerdict.tamperedEdited));
      expect(report.isTampered, isTrue);
      expect(report.editingSoftwareDetected, contains('Adobe Photoshop'));
      expect(report.anomalies.any((a) => a.title.contains('Photoshop 8BIM')), isTrue);
    });

    test('Detects Canva design footprint on altered document', () {
      final pngHeader = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
      final canvaPayload = utf8.encode('tEXtSoftware\x00Canva Graphic Studio canvas element IEND\xAE\x42\x60\x82');
      final bytes = Uint8List.fromList([...pngHeader, ...canvaPayload]);

      final report = DocumentForensicService.analyzeDocument(
        bytes: bytes,
        fileName: 'income_certificate.png',
      );

      expect(report.verdict, equals(DocumentForensicVerdict.tamperedEdited));
      expect(report.editingSoftwareDetected, contains('Canva Graphic Studio'));
    });

    test('Detects scrambled bitstream with invalid magic bytes', () {
      final scrambledBytes = Uint8List.fromList(List.generate(128, (i) => (i * 37) % 256));
      final report = DocumentForensicService.analyzeDocument(
        bytes: scrambledBytes,
        fileName: 'government_id.pdf',
      );

      expect(report.verdict, equals(DocumentForensicVerdict.scrambledCorrupted));
      expect(report.isScrambled, isTrue);
      expect(report.isMagicByteValid, isFalse);
      expect(report.anomalies.any((a) => a.title.contains('Magic Byte')), isTrue);
    });

    test('Detects trailing injected payload after PDF EOF', () {
      final validPdf = '''
%PDF-1.4
1 0 obj
<< /Type /Catalog >>
endobj
trailer
<< /Size 1 /Root 1 0 R >>
%%EOF
''';
      final trailingPayload = 'EXTRANEOUS_HIDDEN_PAYLOAD_MALICIOUS_ATTACHMENT_INJECTED_BYTES_1234567890_PADDING_DATA';
      final bytes = Uint8List.fromList(utf8.encode(validPdf + trailingPayload));

      final report = DocumentForensicService.analyzeDocument(
        bytes: bytes,
        fileName: 'lab_results.pdf',
      );

      expect(report.hasTrailingPayload, isTrue);
      expect(report.trailingPayloadBytes, greaterThan(32));
      expect(report.isTampered, isTrue);
      expect(report.anomalies.any((a) => a.title.contains('Trailing Injected Payload')), isTrue);
    });

    // ==========================================
    // ADVANCED HARDENED FLAW TESTS
    // ==========================================

    test('Flaw 1: Detects Virtual Printer Flattening & Missing UIDAI Signature on Aadhaar', () {
      final flattenedAadhaarPdf = '''
%PDF-1.4
1 0 obj
<< /Title (Government of India - Unique Identification Authority of India - Aadhaar Card)
   /Producer (Microsoft: Print to PDF) >>
endobj
trailer
<< /Size 1 /Root 1 0 R >>
%%EOF
''';
      final bytes = Uint8List.fromList(utf8.encode(flattenedAadhaarPdf));
      final report = DocumentForensicService.analyzeDocument(
        bytes: bytes,
        fileName: 'my_aadhaar_card.pdf',
      );

      expect(report.verdict, equals(DocumentForensicVerdict.tamperedEdited));
      expect(report.isGovernmentOrAadhaarDoc, isTrue);
      expect(report.isVirtualPrinterFlattened, isTrue);
      expect(report.isDigitalSignaturePresent, isFalse);
      expect(report.anomalies.any((a) => a.title.contains('Missing Statutory UIDAI Digital Signature')), isTrue);
      expect(report.anomalies.any((a) => a.title.contains('Virtual Printer Laundering Detected')), isTrue);
    });

    test('Flaw 1: Validates Genuine e-Aadhaar with PKCS#7 Digital Signature Container', () {
      final genuineAadhaarPdf = '''
%PDF-1.4
1 0 obj
<< /Title (Unique Identification Authority of India - e-Aadhaar)
   /Producer (iText 5.5 UIDAI HSM Server) >>
endobj
2 0 obj
<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached /ByteRange [0 100 200 300] >>
endobj
trailer
<< /Size 2 /Root 1 0 R >>
%%EOF
''';
      final bytes = Uint8List.fromList(utf8.encode(genuineAadhaarPdf));
      final report = DocumentForensicService.analyzeDocument(
        bytes: bytes,
        fileName: 'eaadhaar_official.pdf',
      );

      expect(report.verdict, equals(DocumentForensicVerdict.authenticOriginal));
      expect(report.isGovernmentOrAadhaarDoc, isTrue);
      expect(report.isDigitalSignaturePresent, isTrue);
      expect(report.digitalSignatureAlgorithm, contains('PKCS#7'));
      expect(report.isVirtualPrinterFlattened, isFalse);
      expect(report.isTampered, isFalse);
    });

    test('Flaw 1: Detects Medical Bill Laundering via Virtual PDF Printer', () {
      final launderedMedicalPdf = '''
%PDF-1.4
1 0 obj
<< /Title (Hospital Patient Inpatient Bill)
   /Producer (Foxit Reader PDF Printer) >>
endobj
trailer
<< /Size 1 /Root 1 0 R >>
%%EOF
''';
      final bytes = Uint8List.fromList(utf8.encode(launderedMedicalPdf));
      final report = DocumentForensicService.analyzeDocument(
        bytes: bytes,
        fileName: 'apollo_hospital_discharge_bill.pdf',
      );

      expect(report.verdict, equals(DocumentForensicVerdict.tamperedEdited));
      expect(report.isVirtualPrinterFlattened, isTrue);
      expect(report.anomalies.any((a) => a.title.contains('Virtual Printer Flattening Detected')), isTrue);
    });

    test('Flaw 2: Detects Screen Capture / Snipping Tool Ingestion', () {
      final pngHeader = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
      final screenshotPayload = utf8.encode('tEXtSoftware\x00Greenshot Window Capture IEND\xAE\x42\x60\x82');
      final bytes = Uint8List.fromList([...pngHeader, ...screenshotPayload]);

      final report = DocumentForensicService.analyzeDocument(
        bytes: bytes,
        fileName: 'Screenshot_2024-03-01_Aadhaar.png',
      );

      expect(report.isScreenshotOrScreenCapture, isTrue);
      expect(report.anomalies.any((a) => a.title.contains('Screen Capture')), isTrue);
    });

    test('Flaw 3: Classifies WhatsApp / Telegram Transcoding Accurately without False Tamper Accusation', () {
      final header = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01];
      final footer = [0xFF, 0xD9]; // JPEG EOI
      final bytes = Uint8List.fromList([...header, ...footer]);

      final report = DocumentForensicService.analyzeDocument(
        bytes: bytes,
        fileName: 'IMG-20240301-WA0001.jpg',
      );

      expect(report.verdict, equals(DocumentForensicVerdict.socialMediaTranscoded));
      expect(report.isTranscoded, isTrue);
      expect(report.isSocialMediaCompressed, isTrue);
      expect(report.isTampered, isFalse);
      expect(report.anomalies.any((a) => a.title.contains('Social Platform Metadata Stripping')), isTrue);
    });

    test('Flaw 4: Detects Font Subset Discrepancy on Injected Numerical Fields', () {
      final fontInconsistentPdf = '''
%PDF-1.4
1 0 obj
<< /Type /Page /Resources << /Font <<
   /F1 << /Type /Font /BaseFont /ABCDEF+Helvetica >>
   /F2 << /Type /Font /BaseFont /GHIJKL+TimesNewRoman >>
   /F3 << /Type /Font /BaseFont /MNOPQR+ArialMT >>
>> >> >>
endobj
trailer
<< /Size 1 /Root 1 0 R >>
%%EOF
''';
      final bytes = Uint8List.fromList(utf8.encode(fontInconsistentPdf));
      final report = DocumentForensicService.analyzeDocument(
        bytes: bytes,
        fileName: 'inconsistent_invoice.pdf',
      );

      expect(report.verdict, equals(DocumentForensicVerdict.tamperedEdited));
      expect(report.anomalies.any((a) => a.title.contains('Font Subset Inconsistency')), isTrue);
    });

    // ==========================================
    // NEXT-GEN FEATURES (1, 2, 4) TESTS
    // ==========================================

    test('Feature 1: Computes 256-cell ELA Heatmap Tensor with Splicing Anomaly Detection', () {
      // 1. Clean document ELA
      final cleanBytes = Uint8List.fromList(utf8.encode('%PDF-1.4\n1 0 obj\n<< /Title (Invoice) >>\nendobj\ntrailer\n<< /Size 1 /Root 1 0 R >>\n%%EOF\n'));
      final cleanReport = DocumentForensicService.analyzeDocument(
        bytes: cleanBytes,
        fileName: 'clean_receipt.pdf',
      );

      expect(cleanReport.elaAnalysis, isNotNull);
      expect(cleanReport.elaAnalysis!.heatmapTensor.length, equals(256));
      expect(cleanReport.elaAnalysis!.hasSplicingAnomaly, isFalse);
      expect(cleanReport.elaAnalysis!.peakErrorRate, lessThan(0.30));
      expect(cleanReport.elaAnalysis!.anomalyCoordinates, contains('Uniform Sensor Baseline'));

      // 2. Tampered document ELA
      final tamperedHeader = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10, 0x4A, 0x46, 0x49, 0x46, 0x00, 0x01];
      final tamperedPayload = utf8.encode('ScannedRecord...Photoshop 3.0 8BIM SplicedLayer');
      final tamperedFooter = [0xFF, 0xD9];
      final tamperedBytes = Uint8List.fromList([...tamperedHeader, ...tamperedPayload, ...tamperedFooter]);

      final tamperedReport = DocumentForensicService.analyzeDocument(
        bytes: tamperedBytes,
        fileName: 'spliced_medical_bill.jpg',
      );

      expect(tamperedReport.elaAnalysis, isNotNull);
      expect(tamperedReport.elaAnalysis!.heatmapTensor.length, equals(256));
      expect(tamperedReport.elaAnalysis!.hasSplicingAnomaly, isTrue);
      expect(tamperedReport.elaAnalysis!.peakErrorRate, greaterThan(0.70));
      expect(tamperedReport.elaAnalysis!.anomalyCoordinates, contains('Quadrant B'));
    });

    test('Feature 2: Validates UIDAI Secure QR Code and Detects Surface vs QR Mismatches', () {
      // 1. Genuine Aadhaar with signed QR
      final genuineAadhaar = '''
%PDF-1.4
1 0 obj
<< /Title (Government of India - Aadhaar Card)
   /Producer (UIDAI Production Server) >>
endobj
2 0 obj
<< /Type /XObject /Subtype /Image /Width 300 /Height 300 /Length 50000 /Filter /FlateDecode >>
stream
QRCode uidai:V2 SignatureV2
endstream
endobj
3 0 obj
<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /adbe.pkcs7.detached >>
endobj
trailer
<< /Size 3 /Root 1 0 R >>
%%EOF
''';
      final genReport = DocumentForensicService.analyzeDocument(
        bytes: Uint8List.fromList(utf8.encode(genuineAadhaar)),
        fileName: 'my_genuine_aadhaar.pdf',
      );

      expect(genReport.qrValidation, isNotNull);
      expect(genReport.qrValidation!.hasQrCode, isTrue);
      expect(genReport.qrValidation!.isUidaiSigned, isTrue);
      expect(genReport.qrValidation!.isTextMatchingQr, isTrue);
      expect(genReport.qrValidation!.qrDiscrepancyDetail, isNull);

      // 2. Tampered Aadhaar with surface-to-QR demographic mismatch
      final mismatchedAadhaar = '''
%PDF-1.4
1 0 obj
<< /Title (Aadhaar Card) /Producer (Adobe Photoshop) >>
endobj
2 0 obj
<< /Type /XObject /Subtype /Image >>
stream
QRCode Altered Mismatch qr_mismatch
endstream
endobj
trailer
<< /Size 2 /Root 1 0 R >>
%%EOF
''';
      final mismatchReport = DocumentForensicService.analyzeDocument(
        bytes: Uint8List.fromList(utf8.encode(mismatchedAadhaar)),
        fileName: 'forged_aadhaar_card.pdf',
      );

      expect(mismatchReport.qrValidation, isNotNull);
      expect(mismatchReport.qrValidation!.hasQrCode, isTrue);
      expect(mismatchReport.qrValidation!.isTextMatchingQr, isFalse);
      expect(mismatchReport.qrValidation!.qrDiscrepancyDetail, contains('Surface text or photo was altered independently'));
    });

    test('Feature 4: Incremental PDF Stream Diff Extractor isolates removed and added tokens', () {
      final multiRevisionPdf = '''
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Page /Contents (Invoice Total: \$250.00 Paid Cash) >>
endobj
xref
0 3
trailer
<< /Size 3 /Root 1 0 R >>
startxref
120
%%EOF
3 0 obj
<< /Type /Page /Contents (Invoice Total: \$2,500.00 Overdue Urgent Charges) >>
endobj
xref
3 1
trailer
<< /Size 4 /Prev 120 >>
startxref
240
%%EOF
''';
      final report = DocumentForensicService.analyzeDocument(
        bytes: Uint8List.fromList(utf8.encode(multiRevisionPdf)),
        fileName: 'hospital_bill_tampered_amount.pdf',
      );

      expect(report.revisionCount, equals(2));
      expect(report.revisionDiff, isNotNull);
      expect(report.revisionDiff!.hasChanges, isTrue);
      expect(report.revisionDiff!.removedTokens, contains('\$250.00'));
      expect(report.revisionDiff!.addedTokens, contains('\$2,500.00'));
      expect(report.revisionDiff!.summary, contains('modifications detected'));
    });
  });

  group('Multi-Format Forensics - Audio, Video, & Text/Data', () {
    // ----------------------------------------------------
    // Audio Forensics
    // ----------------------------------------------------
    Uint8List createWavBytes({
      List<String> softwareFootprints = const [],
      bool addSilenceDrop = false,
      int trailingBytesCount = 0,
    }) {
      final bytes = BytesBuilder();
      final pcmData = Uint8List(512);
      for (int i = 0; i < pcmData.length; i++) {
        pcmData[i] = (i % 250) + 1;
      }
      if (addSilenceDrop) {
        for (int i = 100; i < 400; i++) {
          pcmData[i] = 0x00; // 300 consecutive zero-bytes
        }
      }

      final fmtSize = 16;
      final listSize = softwareFootprints.isNotEmpty ? 40 : 0;
      final totalData = 4 + (8 + fmtSize) + (8 + pcmData.length) + (softwareFootprints.isNotEmpty ? (8 + listSize) : 0);

      // RIFF header
      bytes.add(utf8.encode('RIFF'));
      final sizeBytes = ByteData(4)..setUint32(0, totalData, Endian.little);
      bytes.add(sizeBytes.buffer.asUint8List());
      bytes.add(utf8.encode('WAVE'));

      // fmt chunk
      bytes.add(utf8.encode('fmt '));
      final fmtSizeBytes = ByteData(4)..setUint32(0, fmtSize, Endian.little);
      bytes.add(fmtSizeBytes.buffer.asUint8List());
      bytes.add([0x01, 0x00]); // PCM
      bytes.add([0x01, 0x00]); // mono
      final sampleRate = ByteData(4)..setUint32(0, 44100, Endian.little);
      bytes.add(sampleRate.buffer.asUint8List());
      final byteRate = ByteData(4)..setUint32(0, 88200, Endian.little);
      bytes.add(byteRate.buffer.asUint8List());
      bytes.add([0x02, 0x00]); // block align
      bytes.add([0x10, 0x00]); // 16-bit

      // data chunk
      bytes.add(utf8.encode('data'));
      final dataSizeBytes = ByteData(4)..setUint32(0, pcmData.length, Endian.little);
      bytes.add(dataSizeBytes.buffer.asUint8List());
      bytes.add(pcmData);

      if (softwareFootprints.isNotEmpty) {
        bytes.add(utf8.encode('LIST'));
        final listPayload = utf8.encode('INFOISFT${softwareFootprints.join(" ")}');
        final lSizeBytes = ByteData(4)..setUint32(0, listSize, Endian.little);
        bytes.add(lSizeBytes.buffer.asUint8List());
        bytes.add(listPayload);
        if (listPayload.length < listSize) {
          bytes.add(Uint8List(listSize - listPayload.length));
        }
      }

      if (trailingBytesCount > 0) {
        bytes.add(Uint8List(trailingBytesCount));
      }

      return bytes.toBytes();
    }

    test('Audio: Detects clean authentic WAV recording', () {
      final cleanWav = createWavBytes();
      final report = DocumentForensicService.analyzeDocument(
        bytes: cleanWav,
        fileName: 'recorded_deposition.wav',
      );

      expect(report.fileCategory, equals(ForensicFileCategory.audio));
      expect(report.verdict, equals(DocumentForensicVerdict.authenticOriginal));
      expect(report.audioForensics, isNotNull);
      expect(report.audioForensics!.audioFormat, contains('WAV'));
      expect(report.audioForensics!.dawFootprints, isEmpty);
      expect(report.audioForensics!.hasSilenceSplicing, isFalse);
      expect(report.audioForensics!.hasTrailingAudioPayload, isFalse);
      expect(report.isTampered, isFalse);
    });

    test('Audio: Detects Audacity DAW footprint and trailing stego payload', () {
      final tamperedWav = createWavBytes(
        softwareFootprints: ['Audacity 3.4.2 Project Export'],
        trailingBytesCount: 128,
      );
      final report = DocumentForensicService.analyzeDocument(
        bytes: tamperedWav,
        fileName: 'wiretap_evidence_edited.wav',
      );

      expect(report.fileCategory, equals(ForensicFileCategory.audio));
      expect(report.verdict, equals(DocumentForensicVerdict.tamperedEdited));
      expect(report.audioForensics, isNotNull);
      expect(report.audioForensics!.dawFootprints, contains('Audacity Audio Editor'));
      expect(report.audioForensics!.hasTrailingAudioPayload, isTrue);
      expect(report.audioForensics!.trailingBytes, greaterThan(64));
      expect(report.anomalies.any((a) => a.title.contains('Audacity DAW')), isTrue);
      expect(report.anomalies.any((a) => a.title.contains('Trailing Payload')), isTrue);
    });

    test('Audio: Detects digital silence acoustic splicing dropout', () {
      final splicedWav = createWavBytes(addSilenceDrop: true);
      final report = DocumentForensicService.analyzeDocument(
        bytes: splicedWav,
        fileName: 'call_center_audio_excised.wav',
      );

      expect(report.fileCategory, equals(ForensicFileCategory.audio));
      expect(report.audioForensics, isNotNull);
      expect(report.audioForensics!.hasSilenceSplicing, isTrue);
      expect(report.anomalies.any((a) => a.title.contains('Acoustic Silence Splicing')), isTrue);
      expect(report.isTampered, isTrue);
    });

    // ----------------------------------------------------
    // Video Forensics
    // ----------------------------------------------------
    Uint8List createMp4Bytes({
      List<String> editorFootprints = const [],
      bool includeDesync = false,
      int trailingBytesCount = 0,
    }) {
      final bytes = BytesBuilder();

      // ftyp atom
      final ftypPayload = utf8.encode('mp42\x00\x00\x02\x00isommp42');
      final ftypSize = ByteData(4)..setUint32(0, 8 + ftypPayload.length, Endian.big);
      bytes.add(ftypSize.buffer.asUint8List());
      bytes.add(utf8.encode('ftyp'));
      bytes.add(ftypPayload);

      // moov atom
      String moovString = 'mvhd...trak...mdia...minf...stbl';
      if (editorFootprints.isNotEmpty) {
        moovString += '...${editorFootprints.join(" ")}...';
      }
      if (includeDesync) {
        moovString += '...desync...cut_frames...';
      }
      final moovPayload = utf8.encode(moovString);
      final moovSize = ByteData(4)..setUint32(0, 8 + moovPayload.length, Endian.big);
      bytes.add(moovSize.buffer.asUint8List());
      bytes.add(utf8.encode('moov'));
      bytes.add(moovPayload);

      // mdat atom
      final mdatPayload = Uint8List(120);
      final mdatSize = ByteData(4)..setUint32(0, 8 + mdatPayload.length, Endian.big);
      bytes.add(mdatSize.buffer.asUint8List());
      bytes.add(utf8.encode('mdat'));
      bytes.add(mdatPayload);

      if (trailingBytesCount > 0) {
        bytes.add(Uint8List(trailingBytesCount));
      }

      return bytes.toBytes();
    }

    test('Video: Detects clean authentic MP4 container', () {
      final cleanMp4 = createMp4Bytes();
      final report = DocumentForensicService.analyzeDocument(
        bytes: cleanMp4,
        fileName: 'dashcam_footage_original.mp4',
      );

      expect(report.fileCategory, equals(ForensicFileCategory.video));
      expect(report.verdict, equals(DocumentForensicVerdict.authenticOriginal));
      expect(report.videoForensics, isNotNull);
      expect(report.videoForensics!.editorFootprints, isEmpty);
      expect(report.videoForensics!.isMoovAtomValid, isTrue);
      expect(report.videoForensics!.hasAudioVideoDesync, isFalse);
      expect(report.isTampered, isFalse);
    });

    test('Video: Detects Adobe Premiere Pro NLE footprints and A/V track desync', () {
      final tamperedMp4 = createMp4Bytes(
        editorFootprints: ['Adobe Premiere Pro CC 2024 (Macintosh)'],
        includeDesync: true,
      );
      final report = DocumentForensicService.analyzeDocument(
        bytes: tamperedMp4,
        fileName: 'cctv_surveillance_spliced.mp4',
      );

      expect(report.fileCategory, equals(ForensicFileCategory.video));
      expect(report.verdict, equals(DocumentForensicVerdict.tamperedEdited));
      expect(report.videoForensics, isNotNull);
      expect(report.videoForensics!.editorFootprints, contains('Adobe Premiere Pro'));
      expect(report.videoForensics!.hasAudioVideoDesync, isTrue);
      expect(report.anomalies.any((a) => a.title.contains('Adobe Premiere Pro')), isTrue);
      expect(report.anomalies.any((a) => a.title.contains('Audio/Video Track Timeline Asymmetry')), isTrue);
    });

    test('Video: Detects trailing stego payload past container atoms', () {
      final trailingMp4 = createMp4Bytes(trailingBytesCount: 200);
      final report = DocumentForensicService.analyzeDocument(
        bytes: trailingMp4,
        fileName: 'police_bodycam_injected.mp4',
      );

      expect(report.fileCategory, equals(ForensicFileCategory.video));
      expect(report.videoForensics, isNotNull);
      expect(report.videoForensics!.hasTrailingPayload, isTrue);
      expect(report.videoForensics!.trailingBytes, greaterThan(64));
      expect(report.anomalies.any((a) => a.title.contains('Trailing Injected Video Payload')), isTrue);
    });

    // ----------------------------------------------------
    // Text & Structured Data Forensics
    // ----------------------------------------------------
    test('Text: Detects clean authentic plain text document', () {
      final cleanText = 'Project Kerberos Security Audit\nAll system hashes verified.\nMonitored ledger active.\n';
      final report = DocumentForensicService.analyzeDocument(
        bytes: Uint8List.fromList(utf8.encode(cleanText)),
        fileName: 'security_brief.txt',
      );

      expect(report.fileCategory, equals(ForensicFileCategory.textData));
      expect(report.verdict, equals(DocumentForensicVerdict.authenticOriginal));
      expect(report.textForensics, isNotNull);
      expect(report.textForensics!.hasMixedLineEndings, isFalse);
      expect(report.textForensics!.hasInvisibleOrZeroWidthChars, isFalse);
      expect(report.isTampered, isFalse);
    });

    test('Text: Detects mixed CRLF & LF line-ending injection anomaly', () {
      final mixedText = 'Line 1 Windows CRLF\r\nLine 2 Windows CRLF\r\nLine 3 Injected Unix LF\nLine 4 Windows CRLF\r\n';
      final report = DocumentForensicService.analyzeDocument(
        bytes: Uint8List.fromList(utf8.encode(mixedText)),
        fileName: 'contract_terms.txt',
      );

      expect(report.fileCategory, equals(ForensicFileCategory.textData));
      expect(report.verdict, equals(DocumentForensicVerdict.tamperedEdited));
      expect(report.textForensics, isNotNull);
      expect(report.textForensics!.hasMixedLineEndings, isTrue);
      expect(report.textForensics!.crlfCount, greaterThan(0));
      expect(report.textForensics!.lfCount, greaterThan(0));
      expect(report.anomalies.any((a) => a.title.contains('Mixed Line-Ending Injection')), isTrue);
    });

    test('Text: Detects zero-width steganography and Trojan Source characters', () {
      final stegoText = 'Verified payment to account 123456\u200B\u200C\u202E malicious hidden code payload';
      final report = DocumentForensicService.analyzeDocument(
        bytes: Uint8List.fromList(utf8.encode(stegoText)),
        fileName: 'payment_instruction.txt',
      );

      expect(report.fileCategory, equals(ForensicFileCategory.textData));
      expect(report.verdict, equals(DocumentForensicVerdict.tamperedEdited));
      expect(report.textForensics, isNotNull);
      expect(report.textForensics!.hasInvisibleOrZeroWidthChars, isTrue);
      expect(report.textForensics!.invisibleCharCount, equals(3));
      expect(report.anomalies.any((a) => a.title.contains('Invisible Unicode')), isTrue);
    });

    test('Text: Detects CSV column count regularity drift on injected row', () {
      final csvText = 'Date,Description,Amount,Status\n2024-01-01,Service Fee,150.00,PAID\n2024-01-02,Consultation,300.00,PAID\n2024-01-03,Embezzled Refund,50000.00,INJECTED,EXTRA_UNAUTHORIZED_COL\n';
      final report = DocumentForensicService.analyzeDocument(
        bytes: Uint8List.fromList(utf8.encode(csvText)),
        fileName: 'financial_ledger.csv',
      );

      expect(report.fileCategory, equals(ForensicFileCategory.textData));
      expect(report.verdict, equals(DocumentForensicVerdict.tamperedEdited));
      expect(report.textForensics, isNotNull);
      expect(report.textForensics!.isCsvOrTable, isTrue);
      expect(report.textForensics!.hasCsvColumnDrift, isTrue);
      expect(report.textForensics!.anomalousRows, contains(4));
      expect(report.anomalies.any((a) => a.title.contains('CSV Delimiter / Column Count Drift')), isTrue);
    });

    test('Text: Detects log timestamp chronological inversion', () {
      final logText = '''
2024-03-01 10:00:00 [INFO] System boot initialised
2024-03-01 10:15:00 [INFO] User admin logged in
2024-03-01 09:45:00 [WARN] Out-of-order spliced tamper attempt
2024-03-01 10:30:00 [INFO] Backup routine completed
''';
      final report = DocumentForensicService.analyzeDocument(
        bytes: Uint8List.fromList(utf8.encode(logText)),
        fileName: 'audit_trail.log',
      );

      expect(report.fileCategory, equals(ForensicFileCategory.textData));
      expect(report.verdict, equals(DocumentForensicVerdict.tamperedEdited));
      expect(report.textForensics, isNotNull);
      expect(report.textForensics!.isLogFile, isTrue);
      expect(report.textForensics!.hasTimestampReversal, isTrue);
      expect(report.anomalies.any((a) => a.title.contains('Chronological Inversion')), isTrue);
    });
  });

  group('Accurate PDF Revision & Generation Count (ISO 32000-1)', () {
    test('Accurately counts single generation when literal %%EOF occurs inside stream', () {
      final pdfWithEmbeddedEofStream = '''
%PDF-1.5
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Page /Contents 3 0 R >>
endobj
3 0 obj
<< /Length 45 >>
stream
BT /F1 12 Tf (Hello World with %%EOF inside stream) ET
endstream
endobj
xref
0 4
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
trailer
<< /Size 4 /Root 1 0 R >>
startxref
220
%%EOF
''';
      final report = DocumentForensicService.analyzeDocument(
        bytes: Uint8List.fromList(utf8.encode(pdfWithEmbeddedEofStream)),
        fileName: 'single_gen_stream_eof.pdf',
      );

      expect(report.revisionCount, equals(1));
      expect(report.history.length, equals(1));
      expect(report.isTampered, isFalse);
      expect(report.verdict, equals(DocumentForensicVerdict.authenticOriginal));
    });

    test('Linearized PDF (Fast Web View) reports 1 generation without false tampering flag', () {
      final linearizedPdf = '''
%PDF-1.6
%âãÏÓ
1 0 obj
<< /Linearized 1 /L 25600 /H [ 800 200 ] /O 4 /E 12000 /N 1 /T 24000 >>
endobj
2 0 obj
<< /Type /Catalog /Pages 3 0 R >>
endobj
xref
1 2
0000000050 00000 n 
0000000150 00000 n 
trailer
<< /Size 3 /Root 2 0 R >>
startxref
250
%%EOF
3 0 obj
<< /Type /Pages /Kids [ 4 0 R ] /Count 1 >>
endobj
4 0 obj
<< /Type /Page /Parent 3 0 R >>
endobj
xref
3 2
0000000400 00000 n 
0000000550 00000 n 
trailer
<< /Size 5 /Prev 250 /Root 2 0 R >>
startxref
700
%%EOF
''';
      final report = DocumentForensicService.analyzeDocument(
        bytes: Uint8List.fromList(utf8.encode(linearizedPdf)),
        fileName: 'fast_web_view_linearized.pdf',
      );

      expect(report.revisionCount, equals(1));
      expect(report.history.length, equals(1));
      expect(report.isTampered, isFalse);
      expect(report.verdict, equals(DocumentForensicVerdict.authenticOriginal));
      expect(report.anomalies.any((a) => a.title.contains('Incremental Revision')), isFalse);
    });

    test('Linearized PDF with post-linearization appended edit reports 2 generations and detects tamper', () {
      final linearizedEditedPdf = '''
%PDF-1.6
1 0 obj
<< /Linearized 1 /L 25600 /H [ 800 200 ] /O 4 /E 12000 /N 1 /T 24000 >>
endobj
2 0 obj
<< /Type /Catalog /Pages 3 0 R >>
endobj
xref
1 2
trailer
<< /Size 3 /Root 2 0 R >>
startxref
250
%%EOF
3 0 obj
<< /Type /Pages /Kids [ 4 0 R ] /Count 1 >>
endobj
xref
3 1
trailer
<< /Size 4 /Prev 250 /Root 2 0 R >>
startxref
500
%%EOF
5 0 obj
<< /Type /Page /Contents (Appended unauthorized modification) >>
endobj
xref
5 1
trailer
<< /Size 6 /Prev 500 /Root 2 0 R >>
startxref
750
%%EOF
''';
      final report = DocumentForensicService.analyzeDocument(
        bytes: Uint8List.fromList(utf8.encode(linearizedEditedPdf)),
        fileName: 'linearized_with_injected_edit.pdf',
      );

      expect(report.revisionCount, equals(2));
      expect(report.isTampered, isTrue);
      expect(report.verdict, equals(DocumentForensicVerdict.tamperedEdited));
      expect(report.anomalies.any((a) => a.title.contains('Incremental Revision Tampering')), isTrue);
    });

    test('Accurately tracks 3 generations with distinct per-revision tools and metadata', () {
      final threeGenPdf = '''
%PDF-1.4
1 0 obj
<< /Title (Contract Agreement) /Producer (Acrobat Distiller 11.0) /CreationDate (D:20240101100000Z) >>
endobj
xref
0 2
trailer
<< /Size 2 /Root 1 0 R >>
startxref
150
%%EOF
2 0 obj
<< /Title (Contract Agreement - Rev 1) /Producer (Adobe Photoshop CC 2023) /ModDate (D:20240102120000Z) >>
endobj
xref
2 1
trailer
<< /Size 3 /Prev 150 /Root 1 0 R >>
startxref
350
%%EOF
3 0 obj
<< /Title (Contract Agreement - Rev 2) /Producer (LibreOffice 7.5) /ModDate (D:20240103140000Z) >>
endobj
xref
3 1
trailer
<< /Size 4 /Prev 350 /Root 1 0 R >>
startxref
550
%%EOF
''';
      final report = DocumentForensicService.analyzeDocument(
        bytes: Uint8List.fromList(utf8.encode(threeGenPdf)),
        fileName: 'three_generation_audit.pdf',
      );

      expect(report.revisionCount, equals(3));
      expect(report.history.length, equals(3));
      expect(report.history[0].revisionIndex, equals(1));
      expect(report.history[0].softwareOrProducer, contains('Acrobat Distiller'));
      expect(report.history[1].revisionIndex, equals(2));
      expect(report.history[1].softwareOrProducer, contains('Adobe Photoshop'));
      expect(report.history[2].revisionIndex, equals(3));
      expect(report.history[2].softwareOrProducer, contains('LibreOffice'));
      expect(report.isTampered, isTrue);
    });

    test('Accurately handles duplicate consecutive %%EOF tokens at end without false generation increment', () {
      final duplicateEofPdf = '''
%PDF-1.4
1 0 obj
<< /Title (Standard Single Rev) /Producer (Word to PDF) >>
endobj
xref
0 2
trailer
<< /Size 2 /Root 1 0 R >>
startxref
150
%%EOF

%%EOF
''';
      final report = DocumentForensicService.analyzeDocument(
        bytes: Uint8List.fromList(utf8.encode(duplicateEofPdf)),
        fileName: 'duplicate_eof_file.pdf',
      );

      expect(report.revisionCount, equals(1));
      expect(report.history.length, equals(1));
      expect(report.isTampered, isFalse);
      expect(report.verdict, equals(DocumentForensicVerdict.authenticOriginal));
      // Ensure no trailing payload flag for harmless duplicate EOF
      expect(report.anomalies.any((a) => a.title.contains('Trailing Injected Payload')), isFalse);
    });
  });

  group('Zero-Garbage PDF Diff & Real ELA Quantization', () {
    test('Strictly rejects PDF keywords and binary garbage from revision diff', () {
      final garbagePdf = '''
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Page /Contents (Genuine Original Total: \$500.00) >>
endobj
xref
0 3
trailer
<< /Size 3 /Root 1 0 R >>
startxref
120
%%EOF
11 0 obj
<< /Filter /FlateDecode /Length 83 >>
stream
*J% \\ 76 "no. ,> endstream endobj
16 0 obj << /Type /XObject /Subtype /Image >>
stream
x c endstream endobj
(Modified Authorized Total: \$1,500.00)
xref
3 2
trailer
<< /Size 5 /Prev 120 /Root 1 0 R >>
startxref
400
%%EOF
''';
      final report = DocumentForensicService.analyzeDocument(
        bytes: Uint8List.fromList(utf8.encode(garbagePdf)),
        fileName: 'sanitized_diff_test.pdf',
      );

      expect(report.revisionDiff, isNotNull);
      // Removed must contain genuine currency, not binary noise
      expect(report.revisionDiff!.removedTokens, contains('\$500.00'));
      expect(report.revisionDiff!.addedTokens, contains('\$1,500.00'));

      // Ensure NO bytecode or PDF structural keywords leaked into removed or added tokens
      final allTokens = [...report.revisionDiff!.removedTokens, ...report.revisionDiff!.addedTokens];
      expect(allTokens.any((t) => t.contains('endstream')), isFalse);
      expect(allTokens.any((t) => t.contains('endobj')), isFalse);
      expect(allTokens.any((t) => t.contains('/Filter')), isFalse);
      expect(allTokens.any((t) => t.contains('/XObject')), isFalse);
      expect(allTokens.any((t) => t.contains('11 0 obj')), isFalse);
      expect(allTokens.any((t) => t.contains('*J%')), isFalse);
    });

    test('Real ELA on real image generates genuine 256-cell quantization without dummy data', () {
      // Create a genuine 64x64 PNG image with img.Image
      final testImg = img.Image(width: 64, height: 64);
      // Uniform gradient
      for (int y = 0; y < 64; y++) {
        for (int x = 0; x < 64; x++) {
          testImg.setPixelRgb(x, y, 100 + (x % 30), 120 + (y % 20), 140);
        }
      }
      final pngBytes = Uint8List.fromList(img.encodePng(testImg));

      final report = DocumentForensicService.analyzeDocument(
        bytes: pngBytes,
        fileName: 'real_camera_scan.png',
      );

      expect(report.elaAnalysis, isNotNull);
      expect(report.elaAnalysis!.heatmapTensor.length, equals(256));
      expect(report.elaAnalysis!.baselineErrorRate, greaterThan(0.0));
      expect(report.elaAnalysis!.peakErrorRate, greaterThan(0.0));
      // All cells must have real computed numbers
      expect(report.elaAnalysis!.heatmapTensor.every((v) => v >= 0.04 && v <= 1.0), isTrue);
      // Uniform image should not have false splicing
      expect(report.elaAnalysis!.hasSplicingAnomaly, isFalse);
    });

    test('Crash Resilience: High Resolution Image (2000x2000) downscales smoothly and completes ELA without OOM', () {
      // Generate a 1200x1200 high-res image (simulates high-res camera capture)
      final hiResImg = img.Image(width: 1200, height: 1200);
      for (int y = 0; y < 1200; y += 40) {
        for (int x = 0; x < 1200; x += 40) {
          hiResImg.setPixelRgb(x, y, 180, 190, 200);
        }
      }
      final hiResJpeg = Uint8List.fromList(img.encodeJpg(hiResImg, quality: 85));

      final stopwatch = Stopwatch()..start();
      final report = DocumentForensicService.analyzeDocument(
        bytes: hiResJpeg,
        fileName: 'high_res_satellite_orbit_capture.jpg',
      );
      stopwatch.stop();

      expect(report.elaAnalysis, isNotNull);
      expect(report.elaAnalysis!.heatmapTensor.length, equals(256));
      expect(report.fileCategory, equals(ForensicFileCategory.image));
      expect(report.verdict, isNotNull);
      // Ensure processing completes rapidly (sub-second) due to smart downscaling
      expect(stopwatch.elapsedMilliseconds, lessThan(3500));
    });

    test('Crash Resilience: Large MB file (12MB simulated video stream) parses without memory exhaustion', () {
      // Create a 12MB MP4 binary stream
      final headerBuilder = BytesBuilder();
      final ftypPayload = utf8.encode('mp42\x00\x00\x02\x00isommp42');
      final ftypSize = ByteData(4)..setUint32(0, 8 + ftypPayload.length, Endian.big);
      headerBuilder.add(ftypSize.buffer.asUint8List());
      headerBuilder.add(utf8.encode('ftyp'));
      headerBuilder.add(ftypPayload);
      final moovPayload = utf8.encode('mvhd...Adobe Premiere Pro CC 2024...trak...mdat');
      final moovSize = ByteData(4)..setUint32(0, 8 + moovPayload.length, Endian.big);
      headerBuilder.add(moovSize.buffer.asUint8List());
      headerBuilder.add(utf8.encode('moov'));
      headerBuilder.add(moovPayload);
      final header = headerBuilder.toBytes();

      final largeBytes = Uint8List(12 * 1024 * 1024); // 12 MB
      largeBytes.setRange(0, header.length, header);

      final stopwatch = Stopwatch()..start();
      final report = DocumentForensicService.analyzeDocument(
        bytes: largeBytes,
        fileName: 'drone_surveillance_raw_1080p.mp4',
      );
      stopwatch.stop();

      expect(report.fileCategory, equals(ForensicFileCategory.video));
      expect(report.fileSizeBytes, equals(12 * 1024 * 1024));
      expect(report.videoForensics, isNotNull);
      expect(report.videoForensics!.editorFootprints, contains('Adobe Premiere Pro'));
      // Windowed bitstream probe ensures 12MB scans in under 1500ms
      expect(stopwatch.elapsedMilliseconds, lessThan(2000));
    });

    test('Integrated Forensic Heatmap: Generates real pixel-level ELA residuals, false-color thermal overlay, and preview bytes', () {
      // Generate an authentic 64x64 raster image with two distinct regions (simulating spliced text)
      final rawImage = img.Image(width: 64, height: 64);
      for (int y = 0; y < 64; y++) {
        for (int x = 0; x < 64; x++) {
          if (x >= 20 && x <= 40 && y >= 20 && y <= 40) {
            rawImage.setPixelRgb(x, y, 255, 0, 0); // Spliced region
          } else {
            rawImage.setPixelRgb(x, y, 200, 200, 200); // Background region
          }
        }
      }
      final pngBytes = Uint8List.fromList(img.encodePng(rawImage));

      final report = DocumentForensicService.analyzeDocument(
        bytes: pngBytes,
        fileName: 'bank_statement_spliced.png',
      );

      expect(report.fileCategory, equals(ForensicFileCategory.image));
      expect(report.elaAnalysis, isNotNull);

      final ela = report.elaAnalysis!;
      expect(ela.imageWidth, equals(64));
      expect(ela.imageHeight, equals(64));
      expect(ela.previewImageBytes, isNotNull);
      expect(ela.previewImageBytes!.isNotEmpty, isTrue);
      expect(ela.elaImageBytes, isNotNull);
      expect(ela.elaImageBytes!.isNotEmpty, isTrue);
      expect(ela.thermalImageBytes, isNotNull);
      expect(ela.thermalImageBytes!.isNotEmpty, isTrue);

      // Verify encoded PNG validity
      final decodedPreview = img.decodePng(ela.previewImageBytes!);
      expect(decodedPreview, isNotNull);
      expect(decodedPreview!.width, equals(64));
      expect(decodedPreview.height, equals(64));

      final decodedEla = img.decodePng(ela.elaImageBytes!);
      expect(decodedEla, isNotNull);
      expect(decodedEla!.width, equals(64));
      expect(decodedEla.height, equals(64));

      final decodedThermal = img.decodePng(ela.thermalImageBytes!);
      expect(decodedThermal, isNotNull);
      expect(decodedThermal!.width, equals(64));
      expect(decodedThermal.height, equals(64));

      // 16x16 tensor verification
      expect(ela.heatmapTensor.length, equals(256));
      expect(ela.baselineErrorRate, greaterThan(0.0));
      expect(ela.peakErrorRate, greaterThanOrEqualTo(0.0));
    });

    test('Cybersecurity Assertion: Detects C2PA JUMBF manifests & Ed25519 hardware assertion seal in image streams', () {
      final header = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]; // PNG signature
      final c2paPayload = utf8.encode('IHDR...jumb/c2pa/manifest...Ed25519 Hardware Assertion Seal...IDAT...IEND');
      final bytes = Uint8List.fromList([...header, ...c2paPayload]);

      final report = DocumentForensicService.analyzeDocument(
        bytes: bytes,
        fileName: 'certified_notarized_scan.png',
      );

      expect(report.isDigitalSignaturePresent, isTrue);
      expect(report.digitalSignatureAlgorithm, equals('Ed25519 Hardware Assertion Seal'));
      expect(report.isMagicByteValid, isTrue);
      expect(report.hasTrailingPayload, isFalse);
    });

    test('6 Security Functions Parity: All 6 forensic security metrics reflect true zero-trust properties', () {
      final cleanPdf = '''
%PDF-1.7
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R >>
endobj
xref
0 4
0000000000 65535 f 
0000000010 00000 n 
0000000060 00000 n 
0000000115 00000 n 
trailer
<< /Size 4 /Root 1 0 R /Producer (Kerberos Direct Issue Compiler v2.4) >>
startxref
170
%%EOF
''';
      final bytes = Uint8List.fromList(utf8.encode(cleanPdf));
      final report = DocumentForensicService.analyzeDocument(
        bytes: bytes,
        fileName: 'statutory_original_contract.pdf',
      );

      // 1. PDF REVISION COUNT: 1 Generation • Single generation original
      expect(report.revisionCount, equals(1));
      expect(report.isOriginal, isTrue);

      // 2. EDITOR FOOTPRINTS: Clean • None (Unmodified Clean Stream)
      expect(report.editingSoftwareDetected.isEmpty, isTrue);

      // 3. DIGITAL SIGNATURE: Valid fallback or assertion
      expect(report.isGovernmentOrAadhaarDoc, isFalse);

      // 4. ORIGIN PIPELINE: Direct Issue / Scan
      expect(report.isVirtualPrinterFlattened, isFalse);
      expect(report.isScreenshotOrScreenCapture, isFalse);
      expect(report.isSocialMediaCompressed, isFalse);

      // 5. MAGIC HEADER PARITY: RFC Valid • application/pdf
      expect(report.isMagicByteValid, isTrue);
      expect(report.mimeType, equals('application/pdf'));

      // 6. TRAILING STEGO PAYLOAD: None • Clean file termination
      expect(report.hasTrailingPayload, isFalse);
      expect(report.trailingPayloadBytes, equals(0));
    });

    // ----------------------------------------------------
    // Spatial ELA Heatmap: Changes, Overlapped & Hidden Content
    // ----------------------------------------------------
    group('Spatial Residual Matrix - Changes, Overlaps, & Hidden Content Accuracy', () {
      test('Accurately detects altered/spliced content and maps to high-residual changed cells (~95% peak)', () {
        final pdfWithAlteredRevision = '''
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 50 >>
stream
BT /F1 12 Tf 72 700 Td (Original Contract Amount: \$1,000) Tj ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000200 00000 n 
trailer
<< /Size 5 /Root 1 0 R >>
startxref
300
%%EOF
5 0 obj
<< /Length 55 >>
stream
BT /F1 12 Tf 380 600 Tm (Altered Amount: \$95,000) Tj ET
endstream
endobj
xref
0 1
0000000000 65535 f 
5 1
0000000350 00000 n 
trailer
<< /Size 6 /Root 1 0 R /Prev 300 >>
startxref
450
%%EOF
''';
        final bytes = Uint8List.fromList(utf8.encode(pdfWithAlteredRevision));
        final report = DocumentForensicService.analyzeDocument(
          bytes: bytes,
          fileName: 'contract_tampered_amount.pdf',
        );

        expect(report.elaAnalysis, isNotNull);
        final ela = report.elaAnalysis!;
        expect(ela.hasSplicingAnomaly, isTrue);
        expect(ela.changedContentCount, greaterThan(0));
        expect(ela.changedCellIndices.isNotEmpty, isTrue);
        expect(ela.peakErrorRate, greaterThanOrEqualTo(0.90));
        expect(ela.anomalyCoordinates, contains('Quadrant'));
        expect(ela.hotspotDescriptions.any((d) => d.contains('Spatial Residual Cluster')), isTrue);
      });

      test('Accurately detects overlapped content (whiteout masks, annotations, layered streams)', () {
        final pdfWithWhiteoutAndLayering = '''
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents [4 0 R 5 0 R] /Annots [6 0 R] >>
endobj
4 0 obj
<< /Length 70 >>
stream
BT /F1 12 Tf 100 500 Td (Confidential Baseline Text) Tj ET
endstream
endobj
5 0 obj
<< /Length 80 >>
stream
1 1 1 rg 95 495 200 25 re f
1 1 1 rg 95 495 200 25 re f
BT /F1 12 Tf 100 500 Td (Forged Replaced Text) Tj ET
endstream
endobj
6 0 obj
<< /Type /Annot /Subtype /Widget /Rect [100 400 300 450] >>
endobj
xref
0 7
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000220 00000 n 
0000000340 00000 n 
0000000470 00000 n 
trailer
<< /Size 7 /Root 1 0 R >>
startxref
550
%%EOF
''';
        final bytes = Uint8List.fromList(utf8.encode(pdfWithWhiteoutAndLayering));
        final report = DocumentForensicService.analyzeDocument(
          bytes: bytes,
          fileName: 'covered_stamp_whiteout.pdf',
        );

        expect(report.elaAnalysis, isNotNull);
        final ela = report.elaAnalysis!;
        expect(ela.overlappedContentCount, greaterThan(0));
        expect(ela.overlappedCellIndices.isNotEmpty, isTrue);
        expect(ela.hotspotDescriptions.any((d) => d.contains('Multi-Layer Delta Overlap Detected')), isTrue);
      });

      test('Accurately detects hidden content (invisible rendering mode 3 Tr and trailing stego payload)', () {
        final pdfWithHiddenTextAndStego = '''
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
2 0 obj
<< /Type /Pages /Kids [3 0 R] /Count 1 >>
endobj
3 0 obj
<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R >>
endobj
4 0 obj
<< /Length 85 >>
stream
BT 3 Tr /F1 12 Tf 200 300 1 1 1 1 Tm (HIDDEN WATERMARK NEVER PRINTED) Tj ET
endstream
endobj
xref
0 5
0000000000 65535 f 
0000000009 00000 n 
0000000058 00000 n 
0000000115 00000 n 
0000000200 00000 n 
trailer
<< /Size 5 /Root 1 0 R >>
startxref
340
%%EOF
TRAILLING_CONCEALED_STEGO_PAYLOAD_EXFILTRATION_DATA_BLOCK
''';
        final bytes = Uint8List.fromList(utf8.encode(pdfWithHiddenTextAndStego));
        final report = DocumentForensicService.analyzeDocument(
          bytes: bytes,
          fileName: 'hidden_trojan_document.pdf',
        );

        expect(report.elaAnalysis, isNotNull);
        final ela = report.elaAnalysis!;
        expect(ela.hiddenContentCount, greaterThan(0));
        expect(ela.hiddenCellIndices.isNotEmpty, isTrue);
        expect(report.hasTrailingPayload, isTrue);
      });
    });
  });
}



