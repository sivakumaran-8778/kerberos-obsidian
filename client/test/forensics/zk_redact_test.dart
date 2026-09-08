import 'dart:typed_data';
import 'dart:ui' show Rect;
import 'package:flutter_test/flutter_test.dart';
import 'package:image/image.dart' as img;
import 'package:syncfusion_flutter_pdf/pdf.dart';
import 'package:kerberos_client/features/forensics/services/crypto_engine.dart';
import 'package:kerberos_client/features/forensics/services/document_forensic_service.dart';

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

    test('applyPdfBlackout and multi-page ELA analysis on PDF files', () async {
      // 1. Generate a valid 2-page PDF
      final doc = PdfDocument();
      final page1 = doc.pages.add();
      page1.graphics.drawString(
        'PAGE 1: SENSITIVE AADHAAR 9999-8888-7777 CONFIDENTIAL DATA',
        PdfStandardFont(PdfFontFamily.helvetica, 12),
        bounds: const Rect.fromLTWH(20, 20, 400, 20),
      );
      final page2 = doc.pages.add();
      page2.graphics.drawString(
        'PAGE 2: SECOND PAGE RECORD AUDIT DETAILS',
        PdfStandardFont(PdfFontFamily.helvetica, 12),
        bounds: const Rect.fromLTWH(20, 20, 400, 20),
      );
      final pdfBytes = Uint8List.fromList(doc.saveSync());
      doc.dispose();

      // 2. Perform forensic multi-page ELA audit
      final report = DocumentForensicService.analyzeDocument(
        bytes: pdfBytes,
        fileName: 'multi_page_sample.pdf',
      );
      expect(report.totalPages, equals(2));
      expect(report.pageElaAnalyses.length, equals(2));
      expect(report.pageElaAnalyses[0].pageNumber, equals(1));
      expect(report.pageElaAnalyses[1].pageNumber, equals(2));
      expect(report.pageElaAnalyses[0].previewImageBytes, isNotNull);
      expect(report.pageElaAnalyses[1].previewImageBytes, isNotNull);

      // 3. Apply destructive blackout to Page 1
      final coords = {
        'x': 20,
        'y': 20,
        'width': 200,
        'height': 20,
        'canvasWidth': 612.0,
        'canvasHeight': 792.0,
        'pageIndex': 0,
      };
      final redactedPdfBytes = CryptoEngineWeb.applyPdfBlackout(pdfBytes, coords);
      expect(redactedPdfBytes, isNotEmpty);
      expect(redactedPdfBytes, isNot(equals(pdfBytes)));

      // 4. Validate resulting buffer is a valid PDF
      final redactedDoc = PdfDocument(inputBytes: redactedPdfBytes);
      expect(redactedDoc.pages.count, equals(2));
      redactedDoc.dispose();

      // 5. Generate Groth16 zero-knowledge proof binding
      final proofData = await CryptoEngineWeb.generateRedactionProof(pdfBytes, coords);
      expect(proofData['redactedFileBuffer'], isNotNull);
      expect(proofData['originalHash'], isNotEmpty);
      expect(proofData['redactedHash'], isNotEmpty);
      expect(proofData['originalHash'], isNot(equals(proofData['redactedHash'])));

      // 6. Verify proof validates
      final verification = await CryptoEngineWeb.verifyRedactionProof(
        proofData['redactedFileBuffer'],
        (proofData['zkProof'] as Map).cast<String, dynamic>(),
        (proofData['publicSignals'] as List).map((e) => e.toString()).toList(),
        {'protocol': 'groth16', 'curve': 'bn128'},
        proofData['originalHash'],
      );
      expect(verification['status'], equals('OK'));
    });

    test('multi-page PDF analysis with per-page raster injection and Page 2 blackout targeting', () async {
      // 1. Generate 2-page PDF
      final doc = PdfDocument();
      doc.pages.add().graphics.drawString(
        'PAGE 1 ORIGINAL CONTENT',
        PdfStandardFont(PdfFontFamily.helvetica, 12),
        bounds: const Rect.fromLTWH(30, 30, 300, 20),
      );
      doc.pages.add().graphics.drawString(
        'PAGE 2 TARGET FOR REDACTION',
        PdfStandardFont(PdfFontFamily.helvetica, 12),
        bounds: const Rect.fromLTWH(30, 30, 300, 20),
      );
      final pdfBytes = Uint8List.fromList(doc.saveSync());
      doc.dispose();

      // Create two distinct raster images for Page 1 and Page 2
      final raster1 = img.Image(width: 200, height: 260);
      img.fill(raster1, color: img.ColorRgb8(240, 240, 240));
      final raster2 = img.Image(width: 200, height: 260);
      img.fill(raster2, color: img.ColorRgb8(220, 220, 230));

      final rasterBytes1 = Uint8List.fromList(img.encodePng(raster1));
      final rasterBytes2 = Uint8List.fromList(img.encodePng(raster2));

      // 2. Analyze document passing per-page rasters
      final report = DocumentForensicService.analyzeDocument(
        bytes: pdfBytes,
        fileName: 'multipage_target.pdf',
        rasterPages: [rasterBytes1, rasterBytes2],
      );

      expect(report.totalPages, equals(2));
      expect(report.pageElaAnalyses.length, equals(2));
      expect(report.pageElaAnalyses[0].pageNumber, equals(1));
      expect(report.pageElaAnalyses[1].pageNumber, equals(2));
      expect(report.pageElaAnalyses[0].totalPageCount, equals(2));
      expect(report.pageElaAnalyses[1].totalPageCount, equals(2));

      // 3. Blackout targeting Page 2 specifically (pageIndex = 1)
      final coords = {
        'x': 30,
        'y': 30,
        'width': 150,
        'height': 25,
        'canvasWidth': 612.0,
        'canvasHeight': 792.0,
        'pageIndex': 1,
      };

      final redactedBytes = CryptoEngineWeb.applyPdfBlackout(
        pdfBytes,
        coords,
        targetPageIndex: 1,
      );

      expect(redactedBytes, isNotEmpty);
      expect(redactedBytes, isNot(equals(pdfBytes)));
      final verifyDoc = PdfDocument(inputBytes: redactedBytes);
      expect(verifyDoc.pages.count, equals(2));
      verifyDoc.dispose();
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
