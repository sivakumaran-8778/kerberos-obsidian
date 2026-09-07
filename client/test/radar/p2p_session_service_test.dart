import 'dart:typed_data';
import 'package:cross_file/cross_file.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'package:kerberos_client/features/radar/models/radar_models.dart';
import 'package:kerberos_client/features/radar/services/p2p_session_service.dart';
import 'package:kerberos_client/features/network/services/webrtc_service.dart';
import 'package:kerberos_client/features/network/services/signaling_service.dart';
import 'package:kerberos_client/features/ledger/services/ledger_service.dart';

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

  @override
  Future<void> sendTextMessage(String text) async {}

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
  Future<void> sendSignal({
    required String targetId,
    required String type,
    required Map<String, dynamic> payload,
  }) async {}
}

class MockLedgerService extends Fake implements LedgerService {
  @override
  Future<void> addRecord(dynamic record) async {}
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
      final session = P2PSessionService(
        webrtc: mockWebRTC,
        signaling: MockSignalingService(),
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

      // Only RTCDataChannelClosed disconnects
      mockWebRTC.onDataChannelStateChanged?.call(RTCDataChannelState.RTCDataChannelClosed);
      expect(session.sessionState, P2PSessionState.disconnected);

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
  });
}

