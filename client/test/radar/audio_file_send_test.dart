import 'dart:typed_data';
import 'package:crypto/crypto.dart';
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

class MockSignalingService extends Fake implements SignalingService {
  @override
  Function(String senderId, String senderName, Map<String, dynamic> messagePayload)? onP2PChatFallbackReceived;
  @override
  Function(String senderId)? onSessionLeaveReceived;
  @override
  Function(String senderId, Map<String, dynamic> chunkPayload)? onP2PFileChunkReceived;
  @override
  String get userEmail => 'agent@enclave.local';
  @override
  String get displayName => 'Test Agent';

  @override
  Future<void> sendSignal({
    required String targetId,
    required String type,
    required Map<String, dynamic> payload,
  }) async {}
}

class MockLedgerService extends Fake implements LedgerService {
  final List<ProvenanceRecord> savedRecords = [];

  @override
  Future<void> addRecord(ProvenanceRecord record) async {
    savedRecords.add(record);
  }

  @override
  ProvenanceRecord? getRecordByHash(String sha256Hash, {String? filterEmail}) {
    return savedRecords.cast<ProvenanceRecord?>().firstWhere(
      (r) => r?.originalFileHash.toLowerCase() == sha256Hash.toLowerCase(),
      orElse: () => null,
    );
  }

  @override
  ProvenanceRecord? getRecordByFileName(String fileName, {String? filterEmail}) {
    final target = fileName.split(RegExp(r'[\\/]')).last.trim().toLowerCase();
    return savedRecords.cast<ProvenanceRecord?>().firstWhere(
      (r) => r != null && r.filePath.split(RegExp(r'[\\/]')).last.trim().toLowerCase() == target,
      orElse: () => null,
    );
  }

  @override
  List<ProvenanceRecord> getHistory({String? filterEmail}) => savedRecords;

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

    test('sealAndSendFile identifies .mp3 as voice note without re-sealing into ledger', () async {
      final audioBytes = Uint8List.fromList([0x49, 0x44, 0x33, 0x04, 0x00, 0x00, 0x00]); // ID3 dummy
      final xFile = XFile.fromData(audioBytes, name: 'recording.mp3', path: 'recording.mp3');

      await sessionService.sealAndSendFile(xFile);

      expect(sessionService.messages, isNotEmpty);
      final sentMsg = sessionService.messages.first;
      expect(sentMsg.fileAttachment, isNotNull);
      expect(sentMsg.fileAttachment!.isVoiceNote, isTrue);
      expect(sentMsg.fileAttachment!.c2paManifestUri, startsWith('urn:c2pa:obsidian:voice:'));
      // Does not re-seal into ledger when sending in chat
      expect(mockLedger.savedRecords, isEmpty);
    });

    test('sealAndSendFile preserves existing sealed ledger manifest if file was previously sealed', () async {
      final pdfBytes = Uint8List.fromList([0x25, 0x50, 0x44, 0x46, 0x2D]); // %PDF-
      final xFile = XFile.fromData(pdfBytes, name: 'document.pdf', path: 'document.pdf');
      final pdfHash = sha256.convert(pdfBytes).toString();
      
      // Pre-seed mock ledger with existing sealed record matching authentic hash
      mockLedger.savedRecords.add(ProvenanceRecord(
        id: 'orig-doc-id',
        originalFileHash: pdfHash,
        c2paManifestUri: 'urn:c2pa:obsidian:presealed123',
        timestamp: DateTime.now(),
        signature: 'sig',
        filePath: 'document.pdf',
      ));

      await sessionService.sealAndSendFile(xFile);

      expect(sessionService.messages, isNotEmpty);
      final sentMsg = sessionService.messages.first;
      expect(sentMsg.fileAttachment, isNotNull);
      expect(sentMsg.fileAttachment!.isVoiceNote, isFalse);
      expect(sentMsg.fileAttachment!.isSealed, isTrue);
      expect(sentMsg.fileAttachment!.c2paManifestUri, equals('urn:c2pa:obsidian:presealed123'));
      // Exactly 1 existing record retained, not re-sealed again
      expect(mockLedger.savedRecords, hasLength(1));
    });

    test('sealAndSendFile supports all standard audio extensions without adding ledger records', () async {
      final extensions = ['m4a', 'mp3', 'wav', 'aac', 'ogg', 'webm', 'opus', 'flac'];
      for (final ext in extensions) {
        final bytes = Uint8List.fromList([0x00, 0x01, 0x02, 0x03]);
        final xFile = XFile.fromData(bytes, name: 'audio_sample.$ext', path: 'audio_sample.$ext');

        await sessionService.sealAndSendFile(xFile);

        final lastMsg = sessionService.messages.last;
        expect(lastMsg.fileAttachment!.isVoiceNote, isTrue, reason: 'Failed for extension: $ext');
        expect(lastMsg.fileAttachment!.c2paManifestUri, startsWith('urn:c2pa:obsidian:voice:'));
      }
      expect(mockLedger.savedRecords, isEmpty);
    });
  });
}
