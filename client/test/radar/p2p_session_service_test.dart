import 'dart:convert';
import 'package:cross_file/cross_file.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:kerberos_client/features/radar/models/radar_models.dart';
import 'package:kerberos_client/features/radar/providers/radar_providers.dart';
import 'package:kerberos_client/features/radar/services/p2p_session_service.dart';
import 'package:kerberos_client/features/network/providers/network_providers.dart';
import 'package:kerberos_client/features/network/services/webrtc_service.dart';
import 'package:kerberos_client/features/network/services/signaling_service.dart';
import 'package:kerberos_client/features/ledger/services/ledger_service.dart';
import 'package:kerberos_client/features/ledger/models/provenance_record.dart';
import 'package:kerberos_client/main.dart';

class MockWebRTCService extends Fake implements WebRTCService {
  @override
  bool get isConnected => true;
  @override
  void Function(String text)? onTextMessageReceived;
  @override
  Function(Uint8List data)? onFileChunkReceived;
  @override
  Function(double progress)? onTransferProgress;
  @override
  Function()? onTransferComplete;
  @override
  Function(RTCDataChannelState state)? onDataChannelStateChanged;
  @override
  Function(String error)? onRemoteErrorOccurred;
  @override
  Function(String senderId)? onCancelReceived;
  @override
  Function()? onHandshakeAccepted;

  final List<String> sentTextMessages = [];

  @override
  Future<void> sendTextMessage(String text) async {
    sentTextMessages.add(text);
  }

  @override
  Future<void> sendFileBytes(Uint8List bytes) async {}

  @override
  Future<void> initiateTransfer(String targetId) async {}

  @override
  void closeConnection() {}
}

class MockSignalingService extends Fake implements SignalingService {
  @override
  List<Map<String, dynamic>> getDiscoveredPeers() => [];
  @override
  Function(String senderId)? onAcceptReceived;
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

  final List<Map<String, dynamic>> sentSignals = [];

  @override
  Future<void> sendSignal({
    required String targetId,
    required String type,
    required Map<String, dynamic> payload,
  }) async {
    sentSignals.add({
      'targetId': targetId,
      'type': type,
      'payload': payload,
    });
  }
}

class MockLedgerService extends Fake with ChangeNotifier implements LedgerService {
  final Map<String, ProvenanceRecord> recordsByHash = {};
  final Map<String, ProvenanceRecord> recordsByName = {};

  @override
  Future<void> addRecord(dynamic record) async {
    if (record is ProvenanceRecord) {
      recordsByHash[record.originalFileHash.toLowerCase()] = record;
      recordsByName[record.filePath.toLowerCase()] = record;
    }
    notifyListeners();
  }

  @override
  ProvenanceRecord? getRecordByHash(String sha256Hash, {String? filterEmail}) =>
      recordsByHash[sha256Hash.toLowerCase()];

  @override
  ProvenanceRecord? getRecordByFileName(String fileName, {String? filterEmail}) =>
      recordsByName[fileName.toLowerCase()];

  @override
  List<ProvenanceRecord> getHistory({String? filterEmail}) =>
      recordsByHash.values.toList();
}

void main() {
  group('P2P Radar & Session Logic Tests', () {
    test('RadarPeer model properties and copyWith', () {
      const peer = RadarPeer(
        uuid: 'test-peer-1',
        displayName: 'MacBook Pro Node',
        email: 'alex@domain.test',
        platform: 'macOS',
        pingMs: 12,
        isSimulated: true,
      );

      expect(peer.uuid, 'test-peer-1');
      expect(peer.displayName, 'MacBook Pro Node');
      expect(peer.isSimulated, isTrue);

      final updated = peer.copyWith(pingMs: 15);
      expect(updated.pingMs, 15);
      expect(updated.displayName, 'MacBook Pro Node');
    });

    test('P2PFileAttachment serialization round-trip', () {
      final attachment = P2PFileAttachment(
        fileId: 'f-123',
        fileName: 'classified_briefing.pdf',
        fileSizeBytes: 2048576,
        sha256Hash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        c2paManifestUri: 'urn:c2pa:obsidian:e3b0c44298fc',
        isSealed: true,
      );

      final jsonMap = attachment.toJson();
      expect(jsonMap['fileId'], 'f-123');
      expect(jsonMap['fileName'], 'classified_briefing.pdf');
      expect(jsonMap['isSealed'], isTrue);

      final reconstructed = P2PFileAttachment.fromJson(jsonMap);
      expect(reconstructed.fileId, 'f-123');
      expect(reconstructed.sha256Hash, attachment.sha256Hash);
      expect(reconstructed.c2paManifestUri, attachment.c2paManifestUri);
    });

    test('P2PSessionService connection and simulated handshake lifecycle', () async {
      final session = P2PSessionService(
        webrtc: MockWebRTCService(),
        signaling: MockSignalingService(),
        ledger: MockLedgerService(),
      );

      expect(session.sessionState, P2PSessionState.discovery);
      expect(session.hasActiveTransfer, isFalse);

      const simPeer = RadarPeer(
        uuid: 'sim-mac',
        displayName: 'MacBook Pro M3 Max',
        email: 'alex@mac.internal',
        platform: 'macOS',
        isSimulated: true,
      );

      // Connect to simulated peer
      await session.connectToPeer(simPeer);
      expect(session.sessionState, P2PSessionState.connected);
      expect(session.activePeer?.displayName, 'MacBook Pro M3 Max');
      expect(session.messages.isNotEmpty, isTrue);

      // Send text message
      await session.sendTextMessage('Hello from enclave node');
      expect(session.messages.any((m) => m.text == 'Hello from enclave node' && m.isSelf), isTrue);

      // Clean disconnect
      await session.disconnect();
      expect(session.sessionState, P2PSessionState.discovery);
      expect(session.activePeer, isNull);
      expect(session.messages.isEmpty, isTrue);

      session.dispose();
    });

    test('User 1 initiates connection and cancels while awaiting handshake', () async {
      final session = P2PSessionService(
        webrtc: MockWebRTCService(),
        signaling: MockSignalingService(),
        ledger: MockLedgerService(),
      );

      const remotePeer = RadarPeer(
        uuid: 'remote-user-2',
        displayName: 'Sivakumaran',
        email: 'siva@enclave.io',
        platform: 'Windows Enclave',
        isSimulated: false,
      );

      // Start connecting (async)
      final future = session.connectToPeer(remotePeer);
      expect(session.sessionState, P2PSessionState.awaitingHandshake);
      expect(session.activePeer?.displayName, 'Sivakumaran');

      // User 1 decides to cancel
      await session.cancelHandshake();
      expect(session.sessionState, P2PSessionState.discovery);
      expect(session.activePeer, isNull);

      await future;
      session.dispose();
    });

    test('User 1 initiates connection and remote peer declines', () async {
      final mockWebRTC = MockWebRTCService();
      final session = P2PSessionService(
        webrtc: mockWebRTC,
        signaling: MockSignalingService(),
        ledger: MockLedgerService(),
      );

      String? declinedName;
      session.onHandshakeDeclined = (name, reason) {
        declinedName = name;
      };

      const remotePeer = RadarPeer(
        uuid: 'remote-user-2',
        displayName: 'Elena Rostova',
        email: 'elena@vault.io',
        platform: 'macOS Node',
        isSimulated: false,
      );

      final future = session.connectToPeer(remotePeer);
      expect(session.sessionState, P2PSessionState.awaitingHandshake);

      // Remote peer declines
      mockWebRTC.onRemoteErrorOccurred?.call('Recipient declined connection request');
      expect(session.sessionState, P2PSessionState.discovery);
      expect(session.activePeer, isNull);
      expect(declinedName, 'Elena Rostova');

      await future;
      session.dispose();
    });

    test('User 2 accepts incoming handshake and remains connected through DataChannelConnecting to Open', () async {
      final mockWebRTC = MockWebRTCService();
      final mockSignaling = MockSignalingService();
      final session = P2PSessionService(
        webrtc: mockWebRTC,
        signaling: mockSignaling,
        ledger: MockLedgerService(),
      );

      const senderPeer = RadarPeer(
        uuid: 'sender-user-1',
        displayName: 'Sivakumaran',
        email: 'siva@enclave.io',
        platform: 'Windows Enclave',
        isSimulated: false,
      );

      // User 2 accepts invitation
      session.handleIncomingSessionAccepted(senderPeer);
      expect(session.sessionState, P2PSessionState.connected);
      expect(session.activePeer?.displayName, 'Sivakumaran');

      // Intermediate RTCDataChannelConnecting MUST NOT disconnect User 2
      mockWebRTC.onDataChannelStateChanged?.call(RTCDataChannelState.RTCDataChannelConnecting);
      expect(session.sessionState, P2PSessionState.connected);

      // RTCDataChannelOpen confirms tunnel
      mockWebRTC.onDataChannelStateChanged?.call(RTCDataChannelState.RTCDataChannelOpen);
      expect(session.sessionState, P2PSessionState.connected);

      // RTCDataChannelClosed must NOT drop the session; it falls back to signaling relay tunnel
      mockWebRTC.onDataChannelStateChanged?.call(RTCDataChannelState.RTCDataChannelClosed);
      expect(session.sessionState, P2PSessionState.connected);

      // Receiving session_leave cleanly ends session
      mockSignaling.onSessionLeaveReceived?.call('sender-user-1');
      expect(session.sessionState, P2PSessionState.discovery);

      session.dispose();
    });

    test('P2PFileAttachment voice note properties and serialization', () {
      final voiceAttachment = P2PFileAttachment(
        fileId: 'vn-101',
        fileName: 'voice_note_123.m4a',
        fileSizeBytes: 65536,
        sha256Hash: 'a1b2c3d4e5f67890123456789abcdef0123456789abcdef0123456789abcdef0',
        c2paManifestUri: 'urn:c2pa:obsidian:voice:a1b2c3d4e5f6',
        isVoiceNote: true,
        durationSeconds: 14,
      );

      expect(voiceAttachment.isVoiceNote, isTrue);
      expect(voiceAttachment.durationSeconds, 14);

      final json = voiceAttachment.toJson();
      expect(json['isVoiceNote'], isTrue);
      expect(json['durationSeconds'], 14);

      final deserialized = P2PFileAttachment.fromJson(json);
      expect(deserialized.isVoiceNote, isTrue);
      expect(deserialized.durationSeconds, 14);
      expect(deserialized.fileName, 'voice_note_123.m4a');
    });

    test('P2PSessionService dispatches and seals voice notes over DataChannel', () async {
      final mockWebRTC = MockWebRTCService();
      final session = P2PSessionService(
        webrtc: mockWebRTC,
        signaling: MockSignalingService(),
        ledger: MockLedgerService(),
      );

      const remotePeer = RadarPeer(
        uuid: 'remote-user-2',
        displayName: 'Sivakumaran',
        email: 'siva@enclave.io',
        platform: 'Windows Enclave',
        isSimulated: false,
      );

      session.handleIncomingSessionAccepted(remotePeer);
      expect(session.sessionState, P2PSessionState.connected);

      final dummyAudioBytes = Uint8List.fromList([0, 1, 2, 3, 4, 5, 6, 7]);
      await session.sendVoiceNote(audioBytes: dummyAudioBytes, durationSeconds: 8);

      expect(session.messages.isNotEmpty, isTrue);
      final lastMsg = session.messages.last;
      expect(lastMsg.fileAttachment, isNotNull);
      expect(lastMsg.fileAttachment!.isVoiceNote, isTrue);
      expect(lastMsg.fileAttachment!.durationSeconds, 8);
      expect(lastMsg.fileAttachment!.isCompleted, isTrue);
      expect(lastMsg.fileAttachment!.isSealed, isTrue);
      expect(lastMsg.fileAttachment!.isLiveRecorded, isTrue);

      session.dispose();
    });

    test('P2PFileAttachment handles isLiveRecorded serialization correctly', () {
      final recordedVoice = P2PFileAttachment(
        fileId: 'rec-1',
        fileName: 'mic_record.opus',
        fileSizeBytes: 1024,
        sha256Hash: 'hash1',
        c2paManifestUri: 'urn:c2pa:obsidian:voice:rec1',
        isVoiceNote: true,
        isLiveRecorded: true,
      );

      final selectedAudio = P2PFileAttachment(
        fileId: 'sel-1',
        fileName: 'song.mp3',
        fileSizeBytes: 2048,
        sha256Hash: 'hash2',
        c2paManifestUri: 'urn:c2pa:obsidian:voice:sel1',
        isVoiceNote: true,
        isLiveRecorded: false,
      );

      final recJson = recordedVoice.toJson();
      final selJson = selectedAudio.toJson();

      expect(recJson['isLiveRecorded'], isTrue);
      expect(selJson['isLiveRecorded'], isFalse);

      final recReconstructed = P2PFileAttachment.fromJson(recJson);
      final selReconstructed = P2PFileAttachment.fromJson(selJson);

      expect(recReconstructed.isLiveRecorded, isTrue);
      expect(selReconstructed.isLiveRecorded, isFalse);
    });

    test('P2PSessionService enqueueFiles processes multiple files sequentially', () async {
      final mockWebRTC = MockWebRTCService();
      final session = P2PSessionService(
        webrtc: mockWebRTC,
        signaling: MockSignalingService(),
        ledger: MockLedgerService(),
      );

      const remotePeer = RadarPeer(
        uuid: 'remote-user-queue',
        displayName: 'Queue Peer',
        email: 'queue@test.com',
        platform: 'macOS',
        isSimulated: true,
      );

      await session.connectToPeer(remotePeer);

      final file1 = XFile.fromData(Uint8List.fromList([1, 2, 3]), name: 'file1.bin', path: 'file1.bin');
      final file2 = XFile.fromData(Uint8List.fromList([4, 5, 6]), name: 'file2.bin', path: 'file2.bin');
      final file3 = XFile.fromData(Uint8List.fromList([7, 8, 9]), name: 'file3.bin', path: 'file3.bin');

      await session.enqueueFiles([file1, file2, file3]);

      final fileMessages = session.messages.where((m) => m.fileAttachment != null).toList();
      expect(fileMessages.length, 3);
      expect(fileMessages[0].fileAttachment!.fileName, 'file1.bin');
      expect(fileMessages[1].fileAttachment!.fileName, 'file2.bin');
      expect(fileMessages[2].fileAttachment!.fileName, 'file3.bin');
      expect(session.transferQueueCount, 0);

      session.dispose();
    });

    test('P2PChatMessage serialization includes seen and quote reply fields', () {
      final now = DateTime.now();
      final msg = P2PChatMessage(
        id: 'msg-reply-1',
        senderId: 'user-1',
        senderName: 'Sivakumaran',
        text: 'I agree with this clause',
        timestamp: now,
        isSelf: true,
        isSeen: true,
        seenAt: now,
        replyToId: 'msg-orig-1',
        replyToSender: 'Elena Rostova',
        replyToText: 'Shall we seal the agreement?',
      );

      final json = msg.toJson();
      expect(json['id'], 'msg-reply-1');
      expect(json['isSeen'], isTrue);
      expect(json['seenAt'], isNotNull);
      expect(json['replyToId'], 'msg-orig-1');
      expect(json['replyToSender'], 'Elena Rostova');
      expect(json['replyToText'], 'Shall we seal the agreement?');

      final deserialized = P2PChatMessage.fromJson(json, isSelf: true);
      expect(deserialized.id, 'msg-reply-1');
      expect(deserialized.isSeen, isTrue);
      expect(deserialized.seenAt, isNotNull);
      expect(deserialized.replyToId, 'msg-orig-1');
      expect(deserialized.replyToSender, 'Elena Rostova');
      expect(deserialized.replyToText, 'Shall we seal the agreement?');
    });

    test('P2PSessionService typing indicator state and dispatch', () async {
      final mockWebRTC = MockWebRTCService();
      // Override sendTextMessage to capture outgoing string
      final session = P2PSessionService(
        webrtc: mockWebRTC,
        signaling: MockSignalingService(),
        ledger: MockLedgerService(),
      );

      const remotePeer = RadarPeer(
        uuid: 'remote-user-2',
        displayName: 'Sivakumaran',
        email: 'siva@enclave.io',
        platform: 'Windows Enclave',
        isSimulated: false,
      );

      session.handleIncomingSessionAccepted(remotePeer);

      // Verify typing indicator starts false
      expect(session.isPeerTyping, isFalse);

      // Simulate incoming typing event from peer
      mockWebRTC.onTextMessageReceived?.call('{"type":"typing","isTyping":true}');
      expect(session.isPeerTyping, isTrue);

      // Simulate incoming typing stops
      mockWebRTC.onTextMessageReceived?.call('{"type":"typing","isTyping":false}');
      expect(session.isPeerTyping, isFalse);

      session.dispose();
    });

    test('P2PSessionService seen receipts updates message state', () async {
      final mockWebRTC = MockWebRTCService();
      final session = P2PSessionService(
        webrtc: mockWebRTC,
        signaling: MockSignalingService(),
        ledger: MockLedgerService(),
      );

      const remotePeer = RadarPeer(
        uuid: 'remote-user-2',
        displayName: 'Sivakumaran',
        email: 'siva@enclave.io',
        platform: 'Windows Enclave',
        isSimulated: false,
      );

      session.handleIncomingSessionAccepted(remotePeer);

      // Send message from self
      await session.sendTextMessage('Confidential payload ready');
      final sentMsg = session.messages.last;
      final sentId = sentMsg.id;
      expect(sentMsg.isSeen, isFalse);

      // Remote peer sends seen receipt
      mockWebRTC.onTextMessageReceived?.call('{"type":"seen","messageId":"$sentId"}');
      expect(session.messages.last.isSeen, isTrue);
      expect(session.messages.last.seenAt, isNotNull);

      session.dispose();
    });

    test('P2PSessionService sending quoted reply attaches metadata to chat packet', () async {
      final mockWebRTC = MockWebRTCService();
      final session = P2PSessionService(
        webrtc: mockWebRTC,
        signaling: MockSignalingService(),
        ledger: MockLedgerService(),
      );

      const remotePeer = RadarPeer(
        uuid: 'remote-user-2',
        displayName: 'Elena',
        email: 'elena@vault.io',
        platform: 'macOS',
        isSimulated: false,
      );

      session.handleIncomingSessionAccepted(remotePeer);

      await session.sendTextMessage(
        'Here is the verified manifest',
        replyToId: 'orig-123',
        replyToSender: 'Elena',
        replyToText: 'Please verify the hash',
      );

      final msg = session.messages.last;
      expect(msg.text, 'Here is the verified manifest');
      expect(msg.replyToId, 'orig-123');
      expect(msg.replyToSender, 'Elena');
      expect(msg.replyToText, 'Please verify the hash');

      session.dispose();
    });

    test('P2PSessionService gates seen receipts on isChatScreenVisible', () async {
      final mockWebRTC = MockWebRTCService();
      final session = P2PSessionService(
        webrtc: mockWebRTC,
        signaling: MockSignalingService(),
        ledger: MockLedgerService(),
      );

      const remotePeer = RadarPeer(
        uuid: 'remote-user-2',
        displayName: 'Sivakumaran',
        email: 'siva@enclave.io',
        platform: 'Windows Enclave',
        isSimulated: false,
      );

      session.handleIncomingSessionAccepted(remotePeer);

      // By default isChatScreenVisible is false
      expect(session.isChatScreenVisible, isFalse);

      // Incoming message while user is NOT on chat screen
      mockWebRTC.onTextMessageReceived?.call('{"type":"chat","id":"msg-in-1","text":"Are you there?"}');
      expect(session.messages.last.text, 'Are you there?');

      // User enters chat screen
      session.setChatScreenVisible(true);
      expect(session.isChatScreenVisible, isTrue);

      session.dispose();
    });

    test('User 1 transitions from awaitingHandshake to connected immediately when onHandshakeAccepted triggers', () async {
      final mockWebRTC = MockWebRTCService();
      final session = P2PSessionService(
        webrtc: mockWebRTC,
        signaling: MockSignalingService(),
        ledger: MockLedgerService(),
      );

      const remotePeer = RadarPeer(
        uuid: 'remote-user-2',
        displayName: 'User Two',
        email: 'user2@enclave.io',
        platform: 'Windows Enclave',
        isSimulated: false,
      );

      // User 1 initiates connection
      session.connectToPeer(remotePeer);
      expect(session.sessionState, P2PSessionState.awaitingHandshake);

      // Remote peer approves and sends answer / accept signal
      mockWebRTC.onHandshakeAccepted?.call();

      // User 1 immediately transitions to connected
      expect(session.sessionState, P2PSessionState.connected);
      expect(session.activePeer?.displayName, 'User Two');

      session.dispose();
    });

    test('markMessagesAsSeen does not dispatch packets when there are no unseen peer messages (ping-pong prevention)', () async {
      final mockWebRTC = MockWebRTCService();
      final mockSignaling = MockSignalingService();
      final session = P2PSessionService(
        webrtc: mockWebRTC,
        signaling: mockSignaling,
        ledger: MockLedgerService(),
      );

      const remotePeer = RadarPeer(
        uuid: 'peer-loop-test',
        displayName: 'Test Remote',
        email: 'test@enclave.local',
        platform: 'Windows Enclave',
        isSimulated: false,
      );

      session.handleIncomingSessionAccepted(remotePeer);
      session.setChatScreenVisible(false);

      // Initially no unseen chat messages - calling markMessagesAsSeen should send NOTHING
      await session.markMessagesAsSeen();
      expect(mockWebRTC.sentTextMessages.where((m) => m.contains('"seen"')), isEmpty);
      expect(mockSignaling.sentSignals.where((s) => s['payload']['type'] == 'seen'), isEmpty);

      // Remote peer sends an incoming message while screen is not visible
      mockWebRTC.onTextMessageReceived?.call('{"type":"chat","id":"msg-1","text":"Hello Enclave"}');
      expect(session.messages.length, 2); // System notice + chat message
      expect(session.messages.last.isSeen, isFalse);

      // User enters chat screen and markMessagesAsSeen is triggered
      session.setChatScreenVisible(true);
      await session.markMessagesAsSeen();
      expect(session.messages.last.isSeen, isTrue);
      final sentCount1 = mockWebRTC.sentTextMessages.where((m) => m.contains('"seen"')).length;
      expect(sentCount1, 1);

      // Subsequent calls to markMessagesAsSeen (e.g. from UI update loops or keystrokes) must be ignored
      await session.markMessagesAsSeen();
      await session.markMessagesAsSeen();
      final sentCount2 = mockWebRTC.sentTextMessages.where((m) => m.contains('"seen"')).length;
      expect(sentCount2, 1); // Absolutely no redundant packets sent!

      session.dispose();
    });

    test('p2pSessionServiceProvider preserves active session when ledgerProvider notifies (ref.read verification)', () async {
      final mockLedger = MockLedgerService();
      final container = ProviderContainer(
        overrides: [
          webRtcServiceProvider.overrideWithValue(MockWebRTCService()),
          signalingServiceProvider.overrideWithValue(MockSignalingService()),
          ledgerProvider.overrideWith((ref) => mockLedger),
        ],
      );
      addTearDown(container.dispose);

      // Read session service and establish a connected session
      final session1 = container.read(p2pSessionServiceProvider);
      const peer = RadarPeer(
        uuid: 'peer-retain-test',
        displayName: 'Retained Peer',
        email: 'retain@enclave.local',
        platform: 'macOS Node',
        isSimulated: false,
      );
      session1.handleIncomingSessionAccepted(peer);
      expect(session1.sessionState, P2PSessionState.connected);
      expect(session1.activePeer?.displayName, 'Retained Peer');

      // Add a sealed file record to the ledger (which calls notifyListeners)
      await mockLedger.addRecord('test-record');

      // The active session service MUST be the exact same instance and remain connected
      final session2 = container.read(p2pSessionServiceProvider);
      expect(identical(session1, session2), isTrue);
      expect(session2.sessionState, P2PSessionState.connected);
      expect(session2.activePeer?.displayName, 'Retained Peer');
    });

    test('Zero-Trust Guard: User 1 attempts to send ledger-tampered file: transmission aborted and 0 packets sent to User 2', () async {
      final mockWebRTC = MockWebRTCService();
      final mockSignaling = MockSignalingService();
      final mockLedger = MockLedgerService();

      final session = P2PSessionService(
        webrtc: mockWebRTC,
        signaling: mockSignaling,
        ledger: mockLedger,
      );

      const peer = RadarPeer(
        uuid: 'peer-user-2',
        displayName: 'User 2',
        email: 'user2@enclave.local',
        platform: 'Windows Node',
        isSimulated: false,
      );
      session.handleIncomingSessionAccepted(peer);
      expect(session.sessionState, P2PSessionState.connected);

      // 1. Seed ledger with an immutable sealed record for "financial_audit.pdf"
      const authenticHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
      final sealedRecord = ProvenanceRecord(
        id: 'rec-financial-01',
        originalFileHash: authenticHash,
        c2paManifestUri: 'urn:c2pa:obsidian:test:financial',
        timestamp: DateTime.now(),
        signature: 'ED25519-SIG-1234',
        filePath: 'financial_audit.pdf',
        ownerEmail: 'user1@enclave.local',
      );
      await mockLedger.addRecord(sealedRecord);

      // 2. User 1 now attempts to send a TAMPERED version of "financial_audit.pdf"
      // (different bytes, meaning different hash)
      final tamperedBytes = Uint8List.fromList(utf8.encode('MODIFIED TAMPERED CONTENT'));
      final tamperedFile = XFile.fromData(
        tamperedBytes,
        name: 'financial_audit.pdf',
        path: 'financial_audit.pdf',
      );

      await session.enqueueFiles([tamperedFile]);

      // 3. VERIFY ZERO-TRUST ENFORCEMENT:
      // A) No file_start packet was dispatched across WebRTC or Signaling
      final fileStartWebRTC = mockWebRTC.sentTextMessages.where((m) => m.contains('"file_start"')).toList();
      final fileStartSignaling = mockSignaling.sentSignals.where((s) => s['type'] == 'p2p_file_start').toList();
      expect(fileStartWebRTC, isEmpty);
      expect(fileStartSignaling, isEmpty);

      // B) No file message was added to chat (User 2 gets nothing)
      final fileMessages = session.messages.where((m) => m.fileAttachment != null).toList();
      expect(fileMessages, isEmpty);

      // C) User 1 sees an immediate local security alert
      final systemAlerts = session.messages.where((m) => m.isSystemNotice && m.text.contains('ZERO-TRUST ALERT')).toList();
      expect(systemAlerts, isNotEmpty);
      expect(systemAlerts.first.text, contains('ABORTED'));
      expect(systemAlerts.first.text, contains('Tampering detected'));
      expect(systemAlerts.first.text, contains('financial_audit.pdf'));

      session.dispose();
    });

    test('Zero-Trust Guard: User 1 attempts to send forensically tampered PDF: transmission aborted and quarantined', () async {
      final mockWebRTC = MockWebRTCService();
      final mockSignaling = MockSignalingService();
      final mockLedger = MockLedgerService();

      final session = P2PSessionService(
        webrtc: mockWebRTC,
        signaling: mockSignaling,
        ledger: mockLedger,
      );

      const peer = RadarPeer(
        uuid: 'peer-user-2-forensic',
        displayName: 'User 2',
        email: 'user2@enclave.local',
        platform: 'Android Node',
        isSimulated: false,
      );
      session.handleIncomingSessionAccepted(peer);

      // Construct a mock PDF with an appended incremental revision post %%EOF
      const tamperedPdfContent = '''
%PDF-1.4
1 0 obj
<< /Type /Catalog /Pages 2 0 R >>
endobj
xref
0 2
0000000000 65535 f 
0000000009 00000 n 
trailer
<< /Size 2 /Root 1 0 R >>
startxref
74
%%EOF
% Appended malicious incremental revision
2 0 obj
<< /ModDate (D:20260908120000) >>
endobj
trailer
<< /Prev 74 >>
%%EOF
''';

      final tamperedPdf = XFile.fromData(
        Uint8List.fromList(utf8.encode(tamperedPdfContent)),
        name: 'invoice_tampered.pdf',
        path: 'invoice_tampered.pdf',
      );

      await session.enqueueFiles([tamperedPdf]);

      // Transfer must be aborted
      final fileStartWebRTC = mockWebRTC.sentTextMessages.where((m) => m.contains('"file_start"')).toList();
      expect(fileStartWebRTC, isEmpty);

      final systemAlerts = session.messages.where((m) => m.isSystemNotice && m.text.contains('ZERO-TRUST ALERT')).toList();
      expect(systemAlerts, isNotEmpty);
      expect(systemAlerts.first.text, contains('invoice_tampered.pdf'));

      session.dispose();
    });
  });
}

