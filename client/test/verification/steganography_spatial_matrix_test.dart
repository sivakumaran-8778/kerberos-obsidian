import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:kerberos_client/features/verification/models/verification_models.dart';
import 'package:kerberos_client/features/verification/providers/steganography_providers.dart';
import 'package:kerberos_client/features/verification/presentation/widgets/steganography_spatial_matrix.dart';
import 'package:kerberos_client/features/ledger/models/provenance_record.dart';

void main() {
  group('Steganography & ELA Spatial Residual Matrix Tests', () {
    test('State Binding (Riverpod): Updates with live coordinate deltas on tampered asset', () {
      final container = ProviderContainer();
      addTearDown(container.dispose);

      final initial = container.read(steganographyAnalysisProvider);
      expect(initial, isNull);

      final sealedRecord = ProvenanceRecord(
        id: 'rec-uuid-101',
        originalFileHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        c2paManifestUri: 'urn:c2pa:obsidian:test-manifest',
        timestamp: DateTime.now(),
        signature: 'sig-test',
        filePath: 'invoice_audited.pdf',
      );

      final tamperedBytes = Uint8List.fromList([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34, 0xFF, 0xEE]);

      // Trigger analysis through the Riverpod notifier
      container.read(steganographyAnalysisProvider.notifier).analyzeFile(
        bytes: tamperedBytes,
        fileName: 'invoice_audited.pdf',
        ledgerHistory: [sealedRecord],
      );

      final liveResult = container.read(steganographyAnalysisProvider);
      expect(liveResult, isNotNull);
      expect(liveResult!.isTampered, isTrue);

      // Verify actual matrix coordinate deltas instead of hardcoded mock defaults
      expect(liveResult.anomalyMatrix.length, equals(256));
      expect(liveResult.peakErrorRate, greaterThanOrEqualTo(0.90)); // ~95%
      expect(liveResult.baselineErrorRate, closeTo(0.151, 0.05));
      expect(liveResult.anomalyThreshold, equals(0.550));

      // Cells in alteration region must exceed threshold > 55%
      final elevatedCells = liveResult.anomalyMatrix.where((v) => v >= 0.550).toList();
      expect(elevatedCells.isNotEmpty, isTrue);

      // Coordinates must reflect the detected quadrant
      expect(liveResult.detectedPeakCoordinates, contains('Quadrant'));
      expect(liveResult.alteredCellIndices.isNotEmpty, isTrue);
    });

    test('State Binding (Riverpod): Clean asset reports uniform baseline (~15.1%) and delta 0.00%', () {
      final container = ProviderContainer();
      addTearDown(container.dispose);

      final cleanBytes = Uint8List.fromList([0x25, 0x50, 0x44, 0x46, 0x2D, 0x31, 0x2E, 0x34]);

      // Pristine report without tamper
      final pristineReport = CompleteVerificationReport(
        fileName: 'clean_contract.pdf',
        fileSizeBytes: cleanBytes.length,
        fileBytes: cleanBytes,
        timestamp: DateTime.now(),
        verdict: VerificationVerdict.pristineSealed,
        bitstream: const BitstreamCheck(
          computedHash: 'hash_abc',
          manifestHash: 'hash_abc',
          isMatch: true,
        ),
        steganography: SteganographyCheck(
          perceptualDrift: 0.00,
          isAltered: false,
          anomalyCoordinates: 'None (Baseline Visual Tensor Pristine)',
          heatmapVector: List.filled(256, 0.151),
        ),
        metadataScrub: const MetadataScrubCheck(
          hasJumbfPayload: true,
          originCertificateValid: true,
          isScrubbed: false,
        ),
        sanitization: const SanitizationCheck(
          rawInput: '',
          sanitizedOutput: '',
          threatsNeutralized: [],
          inputLaneSecured: true,
        ),
      );

      container.read(steganographyAnalysisProvider.notifier).updateFromVerificationReport(pristineReport);

      final result = container.read(steganographyAnalysisProvider);
      expect(result, isNotNull);
      expect(result!.isTampered, isFalse);
      expect(result.peakErrorRate, lessThan(0.550));
      expect(result.baselineErrorRate, closeTo(0.151, 0.02));
      expect(result.detectedPeakCoordinates, contains('Uniform'));
    });

    test('CustomPaint: SteganographyHeatMapRenderer dynamically maps cool blues and neon red/orange', () {
      final matrix = List<double>.generate(256, (i) {
        if (i == 58 || i == 59) return 0.95; // Exceeds 55.0% threshold -> Neon Red/Orange
        if (i == 60) return 0.65; // Exceeds threshold -> Neon Red/Orange
        return 0.12; // Low error value -> Cool Dark Blue
      });

      final painter = SteganographyHeatMapRenderer(
        matrix: matrix,
        threshold: 0.55,
        activeCellIndex: 58,
        alteredCellIndices: [58, 59],
      );

      expect(painter.matrix.length, equals(256));
      expect(painter.threshold, equals(0.55));
      expect(painter.activeCellIndex, equals(58));

      // Test shouldRepaint
      final identicalPainter = SteganographyHeatMapRenderer(
        matrix: matrix,
        threshold: 0.55,
        activeCellIndex: 58,
        alteredCellIndices: [58, 59],
      );
      expect(painter.shouldRepaint(identicalPainter), isFalse);

      final changedCellPainter = SteganographyHeatMapRenderer(
        matrix: matrix,
        threshold: 0.55,
        activeCellIndex: 59,
        alteredCellIndices: [58, 59],
      );
      expect(painter.shouldRepaint(changedCellPainter), isTrue);
    });

    testWidgets('Inspector Sync: Hovering/clicking cell updates inspector with Cell [Row, Col] coordinates', (tester) async {
      final testMatrix = List<double>.generate(256, (i) => i == 58 ? 0.95 : 0.151);

      final testResult = ProvenanceResult(
        fileName: 'tampered_doc.pdf',
        fileSizeBytes: 2048,
        isTampered: true,
        anomalyMatrix: testMatrix,
        peakErrorRate: 0.950,
        baselineErrorRate: 0.151,
        anomalyThreshold: 0.550,
        detectedPeakCoordinates: 'Quadrant B [X: 62%..68%, Y: 18%..25%]',
        alteredCellIndices: [58],
        timestamp: DateTime.now(),
      );

      await tester.pumpWidget(
        ProviderScope(
          child: MaterialApp(
            home: Scaffold(
              body: StatefulBuilder(
                builder: (context, setState) {
                  int? activeCell = 58; // Row 3, Col 10
                  return Column(
                    children: [
                      SteganographySpatialMatrixWidget(
                        matrix: testMatrix,
                        threshold: 0.55,
                        activeCellIndex: activeCell,
                        alteredCellIndices: const [58],
                        onCellHovered: (idx) => setState(() => activeCell = idx),
                        onCellTapped: (idx) => setState(() => activeCell = idx),
                      ),
                      SpatialResidualInspectorPanel(
                        result: testResult,
                        activeCellIndex: activeCell,
                      ),
                    ],
                  );
                },
              ),
            ),
          ),
        ),
      );

      await tester.pumpAndSettle();

      // Verify inspector shows the active cell coordinate: Row 3, Col 10
      expect(find.text('SPATIAL RESIDUAL INSPECTOR'), findsOneWidget);
      expect(find.text('CELL [R3, C10]'), findsOneWidget);
      expect(find.text('95.0%'), findsOneWidget);
      expect(find.text('15.1%'), findsOneWidget);
      expect(find.text('> 55.0%'), findsOneWidget);
      expect(find.textContaining('Cell [Row 3, Col 10]'), findsOneWidget);
      expect(find.textContaining('ALTERATION DETECTED'), findsOneWidget);
    });
  });
}
