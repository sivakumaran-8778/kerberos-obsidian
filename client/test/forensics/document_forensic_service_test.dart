import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
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
}
