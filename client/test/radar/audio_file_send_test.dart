import 'dart:typed_data';
import 'package:cross_file/cross_file.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:kerberos_client/features/radar/services/p2p_session_service.dart';
import 'package:kerberos_client/features/network/services/webrtc_service.dart';
import 'package:kerberos_client/features/network/services/signaling_service.dart';
import 'package:kerberos_client/features/ledger/services/ledger_service.dart';
import 'package:kerberos_client/features/ledger/models/provenance_record.dart';

class MockWebRTCService extends Fake implements WebRTCService {
  @override
  bool get isConnected => true;
  @override
  Function(String text)? onTextMessageReceived;
  @override
  Function(Uint8List chunk)? onFileChunkReceived;
  @override
  Function(double progress)? onTransferProgress;
  @override
  Function()? onTransferComplete;
  @override
  Function(RTCDataChannelState state)? onDataChannelStateChanged;
  @override
  Function(String error)? onRemoteErrorOccurred;
  @override
  Function()? onHandshakeAccepted;

  String? lastSentTextMessage;
  Uint8List? lastSentBinaryBytes;

  @override
  Future<void> sendTextMessage(String text) async {
    lastSentTextMessage = text;
  }

  @override
  Future<void> sendFileBytes(Uint8List bytes) async {
    lastSentBinaryBytes = bytes;
  }

  @override
  void closeConnection() {}
}

class MockSignalingService extends Fake implements SignalingService {}

class MockLedgerService extends Fake implements LedgerService {
  final List<ProvenanceRecord> savedRecords = [];

  @override
  Future<void> addRecord(ProvenanceRecord record) async {
    savedRecords.add(record);
  }

  List<ProvenanceRecord> get records => savedRecords;

  Future<void> clearAll() async {
    savedRecords.clear();
  }

  Future<void> init() async {}
}

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  group('Audio File Auto-Detection and Sealing Tests', () {
    late P2PSessionService sessionService;
    late MockWebRTCService mockWebRtc;
    late MockSignalingService mockSignaling;
    late MockLedgerService mockLedger;

    setUp(() {
      mockWebRtc = MockWebRTCService();
      mockSignaling = MockSignalingService();
      mockLedger = MockLedgerService();

      sessionService = P2PSessionService(
        webrtc: mockWebRtc,
        signaling: mockSignaling,
        ledger: mockLedger,
      );
    });

    test('sealAndSendFile identifies .mp3 as voice note and creates voice manifest URI', () async {
      final audioBytes = Uint8List.fromList([0x49, 0x44, 0x33, 0x04, 0x00, 0x00, 0x00]); // ID3 dummy
      final xFile = XFile.fromData(audioBytes, name: 'recording.mp3', path: 'recording.mp3');

      await sessionService.sealAndSendFile(xFile);

      expect(sessionService.messages, isNotEmpty);
      final sentMsg = sessionService.messages.first;
      expect(sentMsg.fileAttachment, isNotNull);
      expect(sentMsg.fileAttachment!.isVoiceNote, isTrue);
      expect(sentMsg.fileAttachment!.c2paManifestUri, startsWith('urn:c2pa:obsidian:voice:'));
      expect(mockLedger.savedRecords, hasLength(1));
      expect(mockLedger.savedRecords.first.c2paManifestUri, startsWith('urn:c2pa:obsidian:voice:'));
    });

    test('sealAndSendFile treats .pdf as standard sealed asset without voice flag', () async {
      final pdfBytes = Uint8List.fromList([0x25, 0x50, 0x44, 0x46, 0x2D]); // %PDF-
      final xFile = XFile.fromData(pdfBytes, name: 'document.pdf', path: 'document.pdf');

      await sessionService.sealAndSendFile(xFile);

      expect(sessionService.messages, isNotEmpty);
      final sentMsg = sessionService.messages.first;
      expect(sentMsg.fileAttachment, isNotNull);
      expect(sentMsg.fileAttachment!.isVoiceNote, isFalse);
      expect(sentMsg.fileAttachment!.c2paManifestUri, startsWith('urn:c2pa:obsidian:'));
      expect(sentMsg.fileAttachment!.c2paManifestUri, isNot(contains(':voice:')));
    });

    test('sealAndSendFile supports all standard audio extensions', () async {
      final extensions = ['m4a', 'mp3', 'wav', 'aac', 'ogg', 'webm', 'opus', 'flac'];
      for (final ext in extensions) {
        final bytes = Uint8List.fromList([0x00, 0x01, 0x02, 0x03]);
        final xFile = XFile.fromData(bytes, name: 'audio_sample.$ext', path: 'audio_sample.$ext');

        await sessionService.sealAndSendFile(xFile);

        final lastMsg = sessionService.messages.last;
        expect(lastMsg.fileAttachment!.isVoiceNote, isTrue, reason: 'Failed for extension: $ext');
        expect(lastMsg.fileAttachment!.c2paManifestUri, startsWith('urn:c2pa:obsidian:voice:'));
      }
    });
  });
}
