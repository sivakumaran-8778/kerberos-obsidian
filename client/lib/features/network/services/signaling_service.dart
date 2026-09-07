import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

/// Zero-Trust Signaling Service using Supabase Realtime Channels.
/// Bypasses database tables entirely. Uses Broadcast for WebRTC signaling
/// and Presence for AirDrop-style Peer Discovery.
class SignalingService {
  final SupabaseClient _supabase;
  RealtimeChannel? _channel;
  
  // Callbacks for WebRTC layer
  Function(Map<String, dynamic> offer, String senderId, String senderName, String senderEmail)? onOfferReceived;
  Function(Map<String, dynamic> answer)? onAnswerReceived;
  Function(Map<String, dynamic> iceCandidate)? onIceCandidateReceived;
  Function(String error)? onRemoteErrorReceived;
  Function(String senderId)? onCancelReceived;
  Function(String senderId)? onAcceptReceived;
  
  // Callback for Peer Discovery
  Function(List<Map<String, dynamic>> peers)? onPeersUpdated;

  // Cached active peers in the enclave
  List<Map<String, dynamic>> currentPeers = [];

  final String _myUuid;
  String _displayName;
  String _userEmail;
  bool _isInRadar = false;
  bool _isSubscribed = false;
  Completer<void> _subCompleter = Completer<void>();

  SignalingService(
    this._supabase,
    this._myUuid, {
    String displayName = 'Agent',
    String userEmail = '',
  })  : _displayName = displayName,
        _userEmail = userEmail;

  bool get isInRadar => _isInRadar;

  /// Updates local presence status when user enters or leaves the radar portal
  void setInRadar(bool inRadar) {
    if (_isInRadar == inRadar) return;
    _isInRadar = inRadar;
    print(">> [Signaling] User in_radar state changed: $_isInRadar");
    _trackCurrentPresence();
  }

  void updateIdentity(String displayName, String email) {
    _displayName = displayName;
    _userEmail = email;
    _trackCurrentPresence();
  }

  Future<void> _trackCurrentPresence() async {
    if (!_isSubscribed || _channel == null) return;
    final platformName = kIsWeb ? 'Web Enclave' : 'Windows Enclave';
    try {
      await _channel!.track({
        'uuid': _myUuid,
        'platform': platformName,
        'display_name': _displayName,
        'email': _userEmail,
        'in_radar': _isInRadar,
        'online_at': DateTime.now().toIso8601String(),
      });
      print(">> [Signaling] Presence tracked successfully (in_radar: $_isInRadar)");
    } catch (e) {
      print(">> [Signaling] Error tracking presence: $e");
    }
  }

  List<Map<String, dynamic>> getDiscoveredPeers() {
    if (_channel == null) return currentPeers;
    try {
      final state = _channel!.presenceState();
      final List<Map<String, dynamic>> discovered = [];
      for (final client in state) {
        for (final presence in client.presences) {
          final payload = presence.payload;
          final uuid = payload['uuid']?.toString();
          final inRadar = payload['in_radar'] == true;

          // Only display peers currently active in the Radar portal
          if (uuid != null && uuid.toLowerCase() != _myUuid.toLowerCase() && inRadar) {
            String name = payload['display_name']?.toString() ??
                payload['displayName']?.toString() ??
                payload['name']?.toString() ??
                '';
            final email = payload['email']?.toString() ?? payload['userEmail']?.toString() ?? '';

            if (name.trim().isEmpty || name.toLowerCase() == 'agent') {
              if (email.contains('@')) {
                final userPart = email.split('@').first;
                name = userPart.isNotEmpty ? userPart[0].toUpperCase() + userPart.substring(1) : userPart;
              } else {
                name = 'Agent ${uuid.length >= 4 ? uuid.substring(0, 4) : uuid}';
              }
            }

            discovered.add({
              'uuid': uuid,
              'platform': payload['platform'] ?? 'Enclave Node',
              'display_name': name,
              'displayName': name,
              'email': email,
              'userEmail': email,
              'in_radar': true,
              'online_at': payload['online_at'],
            });
          }
        }
      }
      if (discovered.isNotEmpty || currentPeers.isNotEmpty) {
        currentPeers = discovered;
      }
    } catch (_) {}
    return currentPeers;
  }

  void connect() {
    print(">> [Signaling] Booting Supabase enclave for UUID: $_myUuid (Identity: $_displayName <$_userEmail>, in_radar: $_isInRadar)");
    _channel = _supabase.channel('kerberos_enclave');

    // 1. Listen for Peer Discovery (Presence)
    _channel!.onPresenceSync((_) {
      final state = _channel!.presenceState();
      final List<Map<String, dynamic>> discoveredPeers = [];
      
      for (final client in state) {
        for (final presence in client.presences) {
          final payload = presence.payload;
          final uuid = payload['uuid']?.toString();
          final inRadar = payload['in_radar'] == true;

          // ONLY include peers who are currently in the Radar portal!
          if (uuid != null && uuid.toLowerCase() != _myUuid.toLowerCase() && inRadar) {
            String name = payload['display_name']?.toString() ??
                payload['displayName']?.toString() ??
                payload['name']?.toString() ??
                '';
            final email = payload['email']?.toString() ?? payload['userEmail']?.toString() ?? '';

            if (name.trim().isEmpty || name.toLowerCase() == 'agent') {
              if (email.contains('@')) {
                final userPart = email.split('@').first;
                name = userPart.isNotEmpty ? userPart[0].toUpperCase() + userPart.substring(1) : userPart;
              } else {
                name = 'Agent ${uuid.length >= 4 ? uuid.substring(0, 4) : uuid}';
              }
            }

            discoveredPeers.add({
              'uuid': uuid,
              'platform': payload['platform'] ?? 'Enclave Node',
              'display_name': name,
              'displayName': name,
              'email': email,
              'userEmail': email,
              'in_radar': true,
              'online_at': payload['online_at'],
            });
          }
        }
      }
      currentPeers = discoveredPeers;
      print(">> [Signaling] Discovered peers in radar portal updated (${currentPeers.length} active): $currentPeers");
      onPeersUpdated?.call(currentPeers);
    });

    // 2. Listen for Secure Handshakes (Broadcast)
    _channel!.onBroadcast(
      event: 'signal',
      callback: (Map<String, dynamic> raw) {
        print(">> [Signaling] Broadcast payload received: $raw");

        // Normalize payload in case realtime-client wraps or unwraps it
        Map<String, dynamic> msg = raw;
        if (raw.containsKey('payload') && raw['payload'] is Map<String, dynamic>) {
          final inner = raw['payload'] as Map<String, dynamic>;
          if (inner.containsKey('target_id') || inner.containsKey('signal_type') || inner.containsKey('sender_id')) {
            msg = inner;
          }
        }

        final rawTargetId = msg['target_id']?.toString();
        if (rawTargetId == null) {
          print(">> [Signaling] Broadcast ignored: missing 'target_id'. Msg: $msg");
          return;
        }

        final targetId = rawTargetId.trim().toLowerCase();
        final myId = _myUuid.trim().toLowerCase();

        print(">> [Signaling] Checking targetId: '$targetId' vs myUuid: '$myId'");
        if (targetId != myId) {
          print(">> [Signaling] Signal intended for $targetId, not $myId. Ignored.");
          return;
        }

        final signalPayload = msg['payload'] is Map<String, dynamic>
            ? msg['payload'] as Map<String, dynamic>
            : <String, dynamic>{};

        // Detect signal type reliably even if Supabase Realtime injects type: "broadcast"
        String? type = msg['signal_type']?.toString();
        if (type == null || type == 'broadcast') {
          if (msg['type'] != null && msg['type'] != 'broadcast') {
            type = msg['type'].toString();
          } else if (signalPayload.containsKey('sdp')) {
            type = signalPayload['type']?.toString() ?? 'offer';
          } else if (signalPayload.containsKey('candidate')) {
            type = 'ice';
          } else if (signalPayload.containsKey('error')) {
            type = 'error';
          }
        }

        final senderId = msg['sender_id']?.toString() ?? 'unknown';
        final senderName = msg['sender_name']?.toString() ?? 'Remote Agent';
        final senderEmail = msg['sender_email']?.toString() ?? '';

        print(">> [Signaling] MATCH! Dispatching '$type' signal from $senderName ($senderId)");

        switch (type) {
          case 'offer':
            print(">> [Signaling] Firing onOfferReceived for $senderName ($senderId)");
            onOfferReceived?.call(signalPayload, senderId, senderName, senderEmail);
            break;
          case 'answer':
            print(">> [Signaling] Firing onAnswerReceived");
            onAnswerReceived?.call(signalPayload);
            break;
          case 'ice':
            onIceCandidateReceived?.call(signalPayload);
            break;
          case 'error':
            onRemoteErrorReceived?.call(signalPayload['error']?.toString() ?? 'Remote fault');
            break;
          case 'cancel':
            print(">> [Signaling] Connection request cancelled by $senderName ($senderId)");
            onCancelReceived?.call(senderId);
            break;
          case 'accept':
            print(">> [Signaling] Connection request accepted by $senderName ($senderId)");
            onAcceptReceived?.call(senderId);
            break;
          default:
            print(">> [Signaling] Unrecognized signal type: '$type'");
            break;
        }
      }
    );

    // 3. Connect and broadcast our identity
    _channel!.subscribe((status, [error]) async {
      print(">> [Signaling] Channel subscription status: $status (error: $error)");
      if (status == RealtimeSubscribeStatus.subscribed) {
        _isSubscribed = true;
        if (!_subCompleter.isCompleted) {
          _subCompleter.complete();
        }
        await _trackCurrentPresence();
      } else if (status == RealtimeSubscribeStatus.closed || status == RealtimeSubscribeStatus.channelError) {
        _isSubscribed = false;
        if (_subCompleter.isCompleted) {
          _subCompleter = Completer<void>();
        }
      }
    });
  }

  /// Sends a signaling payload (SDP or ICE) directly through the broadcast tunnel.
  Future<void> sendSignal({
    required String targetId,
    required String type,
    required Map<String, dynamic> payload,
  }) async {
    if (_channel == null) {
      throw Exception("Zero-Trust Fault: Signaling channel not established.");
    }

    if (!_isSubscribed) {
      print(">> [Signaling] Awaiting channel subscription before dispatching '$type'...");
      try {
        await _subCompleter.future.timeout(const Duration(seconds: 4));
      } catch (_) {
        print(">> [Signaling] Notice: Proceeding with signal dispatch...");
      }
    }

    print(">> [Signaling] Outbound '$type' signal to $targetId from $_displayName");
    final response = await _channel!.sendBroadcastMessage(
      event: 'signal',
      payload: {
        'sender_id': _myUuid,
        'sender_name': _displayName,
        'sender_email': _userEmail,
        'target_id': targetId,
        'signal_type': type,
        'type': type,
        'payload': payload,
      },
    );
    print(">> [Signaling] sendBroadcastMessage response: $response");
    if (response != ChannelResponse.ok) {
      throw Exception("Signaling delivery failed: Supabase returned $response. Ensure remote peer is online.");
    }
  }

  void dispose() {
    _channel?.unsubscribe();
  }
}
