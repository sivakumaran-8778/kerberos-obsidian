import 'dart:convert';
import 'dart:typed_data';
import 'package:flutter_test/flutter_test.dart';
import 'package:kerberos_client/features/ai_detection/models/ai_detection_models.dart';
import 'package:kerberos_client/features/ai_detection/services/ai_detection_service.dart';
import 'package:kerberos_client/features/ai_detection/services/gemini_ai_client.dart';

void main() {
  group('Enterprise AI Content & Deepfake Detection Engine Tests', () {
    test('Detects synthetic AI document with dense LLM boilerplate and low burstiness', () async {
      const syntheticDocument = '''
In conclusion, it is important to note that the tapestry of modern technological transformation fosters a pivotal role across organizational workflows.
Furthermore, delving into the nuances of artificial intelligence serves as a reminder of the ever-evolving landscape we navigate today.
Moreover, this crucial aspect underscores the multifaceted nature of digital adoption.
At its core, the seamless integration of distributed ledgers represents a profound impact on provenance verification.
In summary, harnessing the power of cryptographic algorithms provides a beacon of transparency and an indispensable tool for forward-looking enterprises.
''';

      final bytes = Uint8List.fromList(utf8.encode(syntheticDocument));
      final report = await AiDetectionService.analyzeFile(
        bytes: bytes,
        fileName: 'synthetic_briefing.txt',
        enableGeminiNeural: false, // test edge engine directly
      );

      expect(report.modality, equals(AiDetectionModality.document));
      expect(report.overallAiProbability, greaterThanOrEqualTo(60.0));
      expect(report.verdict, equals(AiDetectionVerdict.aiGenerated));
      expect(report.detectedBoilerplatePhrases, isNotEmpty);
      expect(report.detectedBoilerplatePhrases, contains('in conclusion'));
      expect(report.detectedBoilerplatePhrases, contains('delving into'));
      expect(report.detectedBoilerplatePhrases, contains('pivotal role'));
      expect(report.textSegments.length, greaterThanOrEqualTo(4));
      expect(report.textSegments.any((s) => s.isFlagged), isTrue);

      final burstinessCheck =
          report.checkpoints.firstWhere((c) => c.id == 'doc_burstiness');
      expect(
          burstinessCheck.status,
          anyOf(equals(AiCheckpointStatus.flagged),
              equals(AiCheckpointStatus.warning)));
    });

    test('Validates authentic human authored document with high burstiness and zero AI markers', () async {
      const humanDocument = '''
I woke up at 5am today because the server fan was screaming.
Turned out the intake filter was completely choked with dust from the hallway construction.
Cleaned it with compressed air, plugged the cable back in, and went back to bed.
At noon, Sarah asked me why the database connection dropped for twenty seconds last night.
I told her about the dust. We laughed, got sandwiches from across the street, and spent the rest of the afternoon fixing broken unit tests in the crypto module.
''';

      final bytes = Uint8List.fromList(utf8.encode(humanDocument));
      final report = await AiDetectionService.analyzeFile(
        bytes: bytes,
        fileName: 'engineering_daily_notes.txt',
        enableGeminiNeural: false,
      );

      expect(report.modality, equals(AiDetectionModality.document));
      expect(report.overallAiProbability, lessThan(40.0));
      expect(report.verdict, equals(AiDetectionVerdict.humanAuthored));
      expect(report.detectedBoilerplatePhrases, isEmpty);
      expect(report.detectedModelFamily, contains('Human'));

      final stylometricsCheck =
          report.checkpoints.firstWhere((c) => c.id == 'doc_stylometrics');
      expect(stylometricsCheck.status, equals(AiCheckpointStatus.passed));
    });

    test('Detects AI generated image with embedded Stable Diffusion generation parameters in PNG chunks', () async {
      // Construct a valid mock PNG with embedded tEXtparameters chunk
      final pngHeader = <int>[
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
        ...utf8.encode(
            'tEXtparameters\x00cyberpunk samurai in rain, 8k resolution, cinematic lighting Steps: 30, Sampler: DPM++ 2M Karras, CFG scale: 7.5, Seed: 49201938, Model: SDXL-v1.0-base\x00'),
        0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
      ];

      final bytes = Uint8List.fromList(pngHeader);
      final report = await AiDetectionService.analyzeFile(
        bytes: bytes,
        fileName: 'cyberpunk_samurai_sdxl.png',
        enableGeminiNeural: false,
      );

      expect(report.modality, equals(AiDetectionModality.image));
      expect(report.overallAiProbability, greaterThanOrEqualTo(95.0));
      expect(report.verdict, equals(AiDetectionVerdict.aiGenerated));
      expect(report.extractedGenerativeMetadata.containsKey('GenerativeEngine'), isTrue);
      expect(report.detectedModelFamily, contains('Stable Diffusion'));

      final provenanceCheck =
          report.checkpoints.firstWhere((c) => c.id == 'img_c2pa');
      expect(provenanceCheck.status, equals(AiCheckpointStatus.flagged));
    });

    test('Detects AI video with container generator signatures and flags deepfake manipulation', () async {
      final mockVideoBytes = Uint8List.fromList([
        ...utf8.encode('ftypmp42\x00\x00\x00\x00'),
        ...utf8.encode('moov\x00udtaRunway Gen-3 Alpha AI Generative Video Engine\x00'),
        ...List<int>.filled(512, 0x7F),
      ]);

      final report = await AiDetectionService.analyzeFile(
        bytes: mockVideoBytes,
        fileName: 'synthetic_scene_runway.mp4',
        enableGeminiNeural: false,
      );

      expect(report.modality, equals(AiDetectionModality.video));
      expect(report.overallAiProbability, greaterThanOrEqualTo(70.0));
      expect(report.verdict, equals(AiDetectionVerdict.deepfakeManipulated));
      expect(report.detectedModelFamily, contains('Runway'));

      final containerCheck =
          report.checkpoints.firstWhere((c) => c.id == 'vid_container');
      expect(containerCheck.status, equals(AiCheckpointStatus.flagged));
    });

    test('GeminiAiClient handles missing API key gracefully without crashing', () async {
      final result = await GeminiAiClient.evaluateText(
        text: 'Sample test text without API key',
        overrideApiKey: '', // empty key
      );

      expect(result.isSuccess, isFalse);
      expect(result.errorMessage, isNotNull);
      expect(result.errorMessage, contains('GEMINI_API_KEY is not configured'));
    });
  });
}
