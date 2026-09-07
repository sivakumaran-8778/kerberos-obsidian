import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:flutter_webrtc/flutter_webrtc.dart';
import 'signaling_service.dart';

/// Pure Zero-Trust WebRTC Service.
/// Establishes an encrypted peer-to-peer DTLS/SCTP DataChannel tunnel between endpoints.
/// Uses Supabase strictly for signaling (SDP offer/answer and ICE candidate exchange).
class WebRTCService {
  final SignalingService _signaling;
  RTCPeerConnection? _peerConnection;
  RTCDataChannel? _dataChannel;
  
  final List<RTCIceCandidate> _remoteCandidatesQueue = [];
  bool _isRemoteDescriptionSet = false;
  String? _currentTargetId;
  RTCIceConnectionState? _currentIceState;
  String? _lastTechnicalError;

  // Auto-Accept toggle & incoming request hook
  bool autoAccept = false;
  Function(String senderId, String senderName, String senderEmail, Map<String, dynamic> offerPayload)? onIncomingOfferRequest;

  // Lifecycle & Transfer Callbacks
  Function(Uint8List data)? onFileChunkReceived;
  Function()? onTransferComplete;
  Function(double progress)? onTransferProgress;
  Function(String status)? onStatusUpdate;
  Function(String text)? onTextMessageReceived;
  Function(RTCDataChannelState state)? onDataChannelStateChanged;
  Function(String error)? onRemoteErrorOccurred;
  Function(String senderId)? onCancelReceived;
  Function()? onHandshakeAccepted;

  bool get isConnected => _dataChannel?.state == RTCDataChannelState.RTCDataChannelOpen;
  RTCDataChannelState? get dataChannelState => _dataChannel?.state;

  // WebRTC ICE Configuration: Standard W3C STUN + OpenRelay TURN
  static const Map<String, dynamic> _iceConfiguration = {
    'sdpSemantics': 'unified-plan',
    'iceCandidatePoolSize': 10,
    'iceTransportPolicy': 'all',
    'iceServers': [
      // 1. Google Public STUN
      {
        'urls': [
          'stun:stun.l.google.com:19302',
          'stun:stun1.l.google.com:19302',
          'stun:stun2.l.google.com:19302',
          'stun:stun.cloudflare.com:3478',
        ],
      },
      // 2. Metered OpenRelay Free Public TURN (UDP & TCP)
      {
        'urls': [
          'turn:openrelay.metered.ca:80',
          'turn:openrelay.metered.ca:443',
          'turn:openrelay.metered.ca:443?transport=tcp',
        ],
        'username': 'openrelayproject',
        'credential': 'openrelayproject',
      },
    ],
  };

  WebRTCService(this._signaling) {
    _signaling.onOfferReceived = (payload, senderId, senderName, senderEmail) {
      print(">> [WebRTC] onOfferReceived triggered! sender: $senderName ($senderId), autoAccept: $autoAccept");
      if (autoAccept) {
        acceptIncomingTransfer(senderId, payload);
      } else {
        onStatusUpdate?.call("Incoming handshake request from $senderName. Awaiting confirmation...");
        if (onIncomingOfferRequest != null) {
          print(">> [WebRTC] Triggering onIncomingOfferRequest callback...");
          onIncomingOfferRequest!.call(senderId, senderName, senderEmail, payload);
        } else {
          print(">> [WebRTC] Notice: onIncomingOfferRequest listener not registered yet. Auto-accepting to guarantee connection.");
          acceptIncomingTransfer(senderId, payload);
        }
      }
    };

    _signaling.onAnswerReceived = _handleAnswer;
    _signaling.onIceCandidateReceived = _handleIceCandidate;
    _signaling.onRemoteErrorReceived = (error) {
      print(">> [WebRTC] Remote peer reported error: $error");
      _lastTechnicalError = "Remote Peer Fault: $error";
      onStatusUpdate?.call("Remote peer error: $error");
      onRemoteErrorOccurred?.call(error);
    };
    _signaling.onCancelReceived = (senderId) {
      print(">> [WebRTC] Remote peer cancelled handshake: $senderId");
      onCancelReceived?.call(senderId);
    };
    _signaling.onAcceptReceived = (senderId) {
      print(">> [WebRTC] Remote peer accepted handshake: $senderId");
      onStatusUpdate?.call("Remote peer approved handshake. Entering secure session...");
      onHandshakeAccepted?.call();
    };
  }

  /// Initializes RTCPeerConnection and binds ICE and DataChannel listeners.
  Future<void> _initializeConnection(String targetId) async {
    _currentTargetId = targetId;
    _lastTechnicalError = null;

    if (_peerConnection != null) {
      _isRemoteDescriptionSet = false;
      try {
        await _peerConnection?.close();
      } catch (_) {}
      _peerConnection = null;
    }

    onStatusUpdate?.call("Initializing cryptographic peer connection...");
    _peerConnection = await createPeerConnection(_iceConfiguration);

    // Trickle ICE: stream discovered local candidates to the remote peer
    _peerConnection!.onIceCandidate = (RTCIceCandidate candidate) {
      if (candidate.candidate == null || candidate.candidate!.trim().isEmpty) {
        return; // End of candidates
      }
      _signaling.sendSignal(
        targetId: targetId,
        type: 'ice',
        payload: {
          'candidate': candidate.candidate,
          'sdpMid': candidate.sdpMid,
          'sdpMLineIndex': candidate.sdpMLineIndex,
        },
      );
    };

    // Monitor ICE Connection State
    _peerConnection!.onIceConnectionState = (RTCIceConnectionState state) {
      print(">> [WebRTC] ICE Connection State: $state");
      _currentIceState = state;
      switch (state) {
        case RTCIceConnectionState.RTCIceConnectionStateChecking:
          onStatusUpdate?.call("ICE Checking: Negotiating direct & TURN relay candidate pairs...");
          break;
        case RTCIceConnectionState.RTCIceConnectionStateConnected:
        case RTCIceConnectionState.RTCIceConnectionStateCompleted:
          onStatusUpdate?.call("ICE Connected: Secure DTLS route verified.");
          break;
        case RTCIceConnectionState.RTCIceConnectionStateFailed:
          _lastTechnicalError = "ICE Connection Failed: All candidate pairs (Local, STUN, TURN) were rejected or blocked by firewall/symmetric NAT.";
          onStatusUpdate?.call("ICE Failed: Direct and relay routes blocked by network.");
          break;
        case RTCIceConnectionState.RTCIceConnectionStateDisconnected:
          onStatusUpdate?.call("ICE Disconnected: Network path temporarily interrupted.");
          break;
        default:
          break;
      }
    };

    // Monitor ICE Gathering State
    _peerConnection!.onIceGatheringState = (RTCIceGatheringState state) {
      print(">> [WebRTC] ICE Gathering State: $state");
      if (state == RTCIceGatheringState.RTCIceGatheringStateGathering) {
        onStatusUpdate?.call("Gathering ICE candidates (Local IP & TURN Relays)...");
      } else if (state == RTCIceGatheringState.RTCIceGatheringStateComplete) {
        onStatusUpdate?.call("ICE candidate collection finalized.");
      }
    };

    // Receiver listener for incoming DataChannel
    _peerConnection!.onDataChannel = (RTCDataChannel channel) {
      print(">> [WebRTC] RECEIVER: DataChannel received!");
      _dataChannel = channel;
      _setupDataChannelListeners(channel);
      onStatusUpdate?.call("DataChannel opened! Ready to receive asset payload.");
    };
  }

  /// Initiator (Sender): Creates DataChannel and dispatches SDP Offer via signaling.
  Future<void> initiateTransfer(String targetId) async {
    print(">> [WebRTC] SENDER: Initiating transfer to target: $targetId");
    onStatusUpdate?.call("Initiating handshake with peer $targetId...");
    
    await _initializeConnection(targetId);

    // Standard reliable, ordered SCTP DataChannel for byte streaming
    final dcInit = RTCDataChannelInit()
      ..ordered = true;

    _dataChannel = await _peerConnection!.createDataChannel('secure_file_transfer', dcInit);
    _setupDataChannelListeners(_dataChannel!);

    // Create and dispatch SDP Offer
    final offer = await _peerConnection!.createOffer();
    await _peerConnection!.setLocalDescription(offer);

    onStatusUpdate?.call("SDP Offer dispatched. Awaiting remote peer response...");
    await _signaling.sendSignal(
      targetId: targetId,
      type: 'offer',
      payload: {'sdp': offer.sdp, 'type': offer.type},
    );
  }

  /// Receiver Action: Called when the user clicks 'ACCEPT TRANSFER'
  Future<void> acceptIncomingTransfer(String senderId, Map<String, dynamic> payload) async {
    print(">> [WebRTC] RECEIVER: Transfer accepted by user for sender: $senderId");
    onStatusUpdate?.call("Handshake accepted. Negotiating cryptographic tunnel...");

    try {
      await _initializeConnection(senderId);

      final rawSdp = payload['sdp'] as String?;
      final rawType = payload['type'] as String? ?? 'offer';
      
      if (rawSdp == null || rawSdp.isEmpty) {
        throw Exception("Invalid Offer: Empty SDP payload received.");
      }

      final offer = RTCSessionDescription(rawSdp, rawType);
      await _peerConnection!.setRemoteDescription(offer);
      _isRemoteDescriptionSet = true;

      // Process any remote ICE candidates that arrived before the offer
      await _processQueuedCandidates();

      // Create and send SDP Answer
      final answer = await _peerConnection!.createAnswer();
      await _peerConnection!.setLocalDescription(answer);

      print(">> [WebRTC] RECEIVER: SDP Answer generated. Sending back to $senderId");
      onStatusUpdate?.call("SDP Answer dispatched. Opening DTLS tunnel...");

      // 1. Dispatch explicit accept signal so Sender immediately transitions into chat session
      await _signaling.sendSignal(
        targetId: senderId,
        type: 'accept',
        payload: {'accepted': true},
      );

      // 2. Dispatch SDP Answer
      await _signaling.sendSignal(
        targetId: senderId,
        type: 'answer',
        payload: {'sdp': answer.sdp, 'type': answer.type},
      );
    } catch (e, st) {
      print(">> [WebRTC] RECEIVER FAULT in acceptIncomingTransfer: $e\n$st");
      final faultMessage = e.toString().replaceFirst(RegExp(r'^Exception:\s*'), '');
      onStatusUpdate?.call("Receiver Error: $faultMessage");
      try {
        await _signaling.sendSignal(
          targetId: senderId,
          type: 'error',
          payload: {'error': faultMessage},
        );
      } catch (_) {}
    }
  }

  /// Receiver Action: Called when the user clicks 'DECLINE'
  Future<void> declineIncomingTransfer(String senderId) async {
    print(">> [WebRTC] RECEIVER: Transfer declined by user for sender: $senderId");
    onStatusUpdate?.call("Incoming handshake from $senderId declined.");
    try {
      await _signaling.sendSignal(
        targetId: senderId,
        type: 'error',
        payload: {'error': 'Transfer was declined by the recipient.'},
      );
    } catch (_) {}
  }

  /// Initiator (Sender): Receives SDP Answer from Receiver and flushes queued ICE.
  Future<void> _handleAnswer(Map<String, dynamic> payload) async {
    print(">> [WebRTC] SENDER: SDP Answer received from remote peer.");
    onStatusUpdate?.call("Remote SDP Answer accepted. Establishing P2P link...");

    if (_peerConnection == null) {
      print(">> [WebRTC] SENDER: PeerConnection is null when answer arrived.");
      return;
    }

    try {
      final rawSdp = payload['sdp'] as String?;
      final rawType = payload['type'] as String? ?? 'answer';
      if (rawSdp == null || rawSdp.isEmpty) return;

      final answer = RTCSessionDescription(rawSdp, rawType);
      await _peerConnection!.setRemoteDescription(answer);
      _isRemoteDescriptionSet = true;

      // Remote peer answer received = Handshake approved!
      onHandshakeAccepted?.call();

      await _processQueuedCandidates();
    } catch (e) {
      print(">> [WebRTC] SENDER FAULT in _handleAnswer: $e");
      _lastTechnicalError = "Invalid SDP Answer from peer: $e";
    }
  }

  /// Both: Handles incoming remote ICE candidates with queueing support to prevent race conditions.
  Future<void> _handleIceCandidate(Map<String, dynamic> payload) async {
    final rawCandidate = payload['candidate'] as String?;
    if (rawCandidate == null || rawCandidate.trim().isEmpty) return;

    final sdpMid = payload['sdpMid'] as String?;
    final sdpMLineIndex = payload['sdpMLineIndex'] as int?;
    final candidate = RTCIceCandidate(rawCandidate, sdpMid, sdpMLineIndex);

    if (_isRemoteDescriptionSet && _peerConnection != null) {
      try {
        await _peerConnection!.addCandidate(candidate);
      } catch (e) {
        print(">> [WebRTC] Notice: Skipped redundant ICE candidate: $e");
      }
    } else {
      _remoteCandidatesQueue.add(candidate);
    }
  }

  /// Flushes queued remote ICE candidates sequentially once remote description is active.
  Future<void> _processQueuedCandidates() async {
    if (_peerConnection == null || !_isRemoteDescriptionSet) return;
    
    final candidates = List<RTCIceCandidate>.from(_remoteCandidatesQueue);
    _remoteCandidatesQueue.clear();

    for (final candidate in candidates) {
      try {
        await _peerConnection!.addCandidate(candidate);
      } catch (e) {
        print(">> [WebRTC] Notice: Error adding queued candidate: $e");
      }
    }
  }

  /// Configures message and lifecycle listeners on the SCTP DataChannel.
  void _setupDataChannelListeners(RTCDataChannel channel) {
    channel.onMessage = (RTCDataChannelMessage message) {
      if (message.isBinary) {
        onFileChunkReceived?.call(message.binary);
      } else {
        if (message.text == 'EOF') {
          print(">> [WebRTC] RECEIVER: EOF received. Asset transfer complete.");
          onStatusUpdate?.call("Asset received and verified successfully.");
          onTransferComplete?.call();
        } else {
          onTextMessageReceived?.call(message.text);
        }
      }
    };

    channel.onDataChannelState = (RTCDataChannelState state) {
      print(">> [WebRTC] DATA CHANNEL STATE: $state");
      onDataChannelStateChanged?.call(state);
      if (state == RTCDataChannelState.RTCDataChannelOpen) {
        onStatusUpdate?.call("DataChannel Open! Ready for transmission.");
      } else if (state == RTCDataChannelState.RTCDataChannelClosed) {
        onStatusUpdate?.call("DataChannel Closed.");
      }
    };

    // If channel is already open upon binding, trigger state callback immediately
    if (channel.state == RTCDataChannelState.RTCDataChannelOpen) {
      print(">> [WebRTC] DataChannel is already OPEN upon setup. Notifying listeners.");
      onDataChannelStateChanged?.call(channel.state!);
    }
  }

  /// Sends a UTF-8 text message or JSON packet across the active DataChannel.
  Future<void> sendTextMessage(String text) async {
    if (_dataChannel == null || _dataChannel!.state != RTCDataChannelState.RTCDataChannelOpen) {
      throw Exception("DataChannel is not open (current state: ${_dataChannel?.state})");
    }
    await _dataChannel!.send(RTCDataChannelMessage(text));
  }

  /// Streams binary payload over the DataChannel in 16KB chunks.
  /// Throws granular, highly specific technical exceptions on any failure.
  Future<void> sendFileBytes(Uint8List fileBytes) async {
    onStatusUpdate?.call("Waiting for peer to accept and open DataChannel...");

    int elapsedMs = 0;
    const int intervalMs = 100;
    const int timeoutMs = 45000; // 45s timeout to allow remote user to click Accept

    while ((_dataChannel == null || _dataChannel!.state != RTCDataChannelState.RTCDataChannelOpen) && elapsedMs < timeoutMs) {
      if (_lastTechnicalError != null) {
        throw Exception(_lastTechnicalError!);
      }
      if (_currentIceState == RTCIceConnectionState.RTCIceConnectionStateFailed) {
        throw Exception(
          "WebRTC ICE Connection Failed: Direct UDP and TURN relay routes were blocked by network firewall or symmetric NAT.\n"
          "Troubleshooting:\n"
          "1. Ensure both devices have Kerberos open.\n"
          "2. If on same Wi-Fi, router may block client-to-client traffic (AP Isolation).\n"
          "3. Verify outbound ports 80/443/3478 are permitted."
        );
      }
      await Future.delayed(const Duration(milliseconds: intervalMs));
      elapsedMs += intervalMs;

      if (elapsedMs % 2000 == 0) {
        if (!_isRemoteDescriptionSet) {
          onStatusUpdate?.call("Awaiting recipient acceptance (${elapsedMs ~/ 1000}s/45s)...");
        } else {
          onStatusUpdate?.call("Connecting DataChannel (${elapsedMs ~/ 1000}s/45s)... State: ${_dataChannel?.state ?? 'null'}, ICE: ${_currentIceState ?? 'none'}");
        }
      }
    }

    if (_dataChannel == null || _dataChannel!.state != RTCDataChannelState.RTCDataChannelOpen) {
      if (_lastTechnicalError != null) {
        throw Exception(_lastTechnicalError!);
      }
      if (!_isRemoteDescriptionSet) {
        throw Exception(
          "Handshake Timeout: Recipient ${_currentTargetId ?? 'target'} did not accept the incoming transfer within 45s.\n"
          "Resolution: Ensure the recipient taps 'ACCEPT TRANSFER' on their device or turns on Auto-Accept."
        );
      }
      if (_currentIceState == RTCIceConnectionState.RTCIceConnectionStateChecking) {
        throw Exception(
          "ICE Negotiation Timeout: ICE is still 'Checking' candidate pairs.\n"
          "Cause: Neither direct P2P nor TURN relay candidates could be verified.\n"
          "Resolution: Check network firewall settings or try switching networks."
        );
      }
      throw Exception(
        "DataChannel Timeout: Peer accepted, but SCTP DataChannel failed to enter 'open' state.\n"
        "Current DataChannel: ${_dataChannel?.state ?? 'null'}, ICE: ${_currentIceState ?? 'none'}."
      );
    }

    onStatusUpdate?.call("DataChannel Open! Transmitting encrypted payload...");
    print(">> [WebRTC] SENDER: DataChannel Open! Transmitting payload (${fileBytes.length} bytes)...");

    const int chunkSize = 16384; // 16KB chunks
    int offset = 0;
    final totalBytes = fileBytes.length;

    while (offset < totalBytes) {
      if (_dataChannel == null || _dataChannel!.state != RTCDataChannelState.RTCDataChannelOpen) {
        throw Exception("Transfer Aborted: DataChannel disconnected prematurely during transmission.");
      }

      // Backpressure throttling: prevent buffer overflow on slow networks
      while (_dataChannel != null &&
          _dataChannel!.state == RTCDataChannelState.RTCDataChannelOpen &&
          (_dataChannel!.bufferedAmount ?? 0) > 65536) {
        await Future.delayed(const Duration(milliseconds: 10));
      }

      final end = (offset + chunkSize < totalBytes) ? offset + chunkSize : totalBytes;
      final chunk = fileBytes.sublist(offset, end);

      await _dataChannel!.send(RTCDataChannelMessage.fromBinary(chunk));
      offset += chunk.length;

      final progress = offset / totalBytes;
      onTransferProgress?.call(progress);

      // Adaptive throttle to prevent buffer overflow
      if (kIsWeb) {
        await Future.delayed(const Duration(milliseconds: 4));
      } else {
        await Future.delayed(const Duration(milliseconds: 1));
      }
    }

    // Wait until buffered amount drains before sending EOF
    while (_dataChannel != null &&
        _dataChannel!.state == RTCDataChannelState.RTCDataChannelOpen &&
        (_dataChannel!.bufferedAmount ?? 0) > 0) {
      await Future.delayed(const Duration(milliseconds: 10));
    }

    // Send string EOF sentinel
    await _dataChannel!.send(RTCDataChannelMessage("EOF"));
    print(">> [WebRTC] SENDER: EOF sent. Transfer completed successfully.");
    onStatusUpdate?.call("Payload transmission complete.");
    onTransferProgress?.call(1.0);
    onTransferComplete?.call();
  }

  /// Closes the current connection and resets candidate queues.
  void closeConnection() {
    _isRemoteDescriptionSet = false;
    _remoteCandidatesQueue.clear();
    _currentTargetId = null;
    _currentIceState = null;
    _lastTechnicalError = null;
    try {
      _dataChannel?.close();
    } catch (_) {}
    try {
      _peerConnection?.close();
    } catch (_) {}
    _dataChannel = null;
    _peerConnection = null;
  }
}
