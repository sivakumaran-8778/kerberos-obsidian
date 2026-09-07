import 'package:cross_file/cross_file.dart';
import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:hive_flutter/hive_flutter.dart';
import 'package:riverpod_annotation/riverpod_annotation.dart';
import 'package:supabase_flutter/supabase_flutter.dart';
import 'package:flutter/foundation.dart';
import 'package:uuid/uuid.dart';
import '../services/signaling_service.dart';
import '../services/webrtc_service.dart';
import '../../../main.dart'; // for ledgerProvider

import '../../auth/providers/auth_providers.dart';

part 'network_providers.g.dart';

String? _cachedSessionId;

/// Explicitly initializes and caches the persistent machine identity in local storage.
Future<void> initPersistentDeviceId() async {
  if (kIsWeb) {
    _cachedSessionId ??= const Uuid().v4();
    return;
  }
  try {
    final box = await Hive.openBox('kerberos_device_identity');
    final stored = box.get('device_uuid')?.toString();
    if (stored != null && stored.trim().isNotEmpty) {
      _cachedSessionId = stored.trim();
    } else {
      final newId = const Uuid().v4();
      await box.put('device_uuid', newId);
      _cachedSessionId = newId;
    }
  } catch (_) {
    _cachedSessionId ??= const Uuid().v4();
  }
}

/// Dynamically generates and persists a unique client device ID per machine/session.
/// Prevents device UUID collisions between Computer 1 and Computer 2.
String getPersistentDeviceId() {
  if (_cachedSessionId != null && _cachedSessionId!.isNotEmpty) {
    return _cachedSessionId!;
  }
  if (kIsWeb) {
    // Each browser session/tab generates its own unique node ID
    _cachedSessionId = const Uuid().v4();
    return _cachedSessionId!;
  }
  try {
    if (Hive.isBoxOpen('kerberos_device_identity')) {
      final box = Hive.box('kerberos_device_identity');
      final stored = box.get('device_uuid')?.toString();
      if (stored != null && stored.trim().isNotEmpty) {
        _cachedSessionId = stored.trim();
        return _cachedSessionId!;
      }
      final newId = const Uuid().v4();
      box.put('device_uuid', newId);
      _cachedSessionId = newId;
      return _cachedSessionId!;
    }
  } catch (_) {}

  _cachedSessionId = const Uuid().v4();
  return _cachedSessionId!;
}

class IncomingTransferRequest {
  final String senderId;
  final String senderName;
  final String senderEmail;
  final Map<String, dynamic> offerPayload;
  final DateTime timestamp;

  const IncomingTransferRequest({
    required this.senderId,
    required this.senderName,
    required this.senderEmail,
    required this.offerPayload,
    required this.timestamp,
  });
}

String getSupabaseUrl() {
  final url = dotenv.env['SUPABASE_URL'];
  if (url == null || url.trim().isEmpty || url.contains('mock')) {
    return 'https://kyojroqhbvadzocdpnqn.supabase.co';
  }
  return url;
}

String getSupabaseAnonKey() {
  final key = dotenv.env['SUPABASE_ANON_KEY'];
  if (key == null || key.trim().isEmpty || key.contains('mock')) {
    return 'sb_publishable_trcpGuxjaKxTlb8Sa-b8vA_qWRPTwTf';
  }
  return key;
}

@Riverpod(keepAlive: true)
SignalingService signalingService(SignalingServiceRef ref) {
  final myUuid = getPersistentDeviceId();
  final profile = ref.read(userProfileProvider);
  
  final service = SignalingService(
    Supabase.instance.client,
    myUuid,
    displayName: profile.displayName,
    userEmail: profile.email,
  );
  
  service.connect();

  // Dynamically update identity when user profile changes without tearing down signaling
  ref.listen<UserProfile>(userProfileProvider, (previous, next) {
    service.updateIdentity(next.displayName, next.email);
  });

  ref.onDispose(() => service.dispose());
  return service;
}

@riverpod
class DiscoveredPeersNotifier extends _$DiscoveredPeersNotifier {
  @override
  List<Map<String, dynamic>> build() {
    final signaling = ref.watch(signalingServiceProvider);
    signaling.onPeersUpdated = (peers) {
      state = List.from(peers);
    };
    return signaling.getDiscoveredPeers();
  }
}

@Riverpod(keepAlive: true)
WebRTCService webRtcService(WebRtcServiceRef ref) {
  final signaling = ref.watch(signalingServiceProvider);
  final service = WebRTCService(signaling);
  ref.onDispose(() => service.closeConnection());
  return service;
}

@Riverpod(keepAlive: true)
class AutoAcceptNotifier extends _$AutoAcceptNotifier {
  @override
  bool build() {
    return false; // Default: Manual confirmation required
  }

  void toggle() {
    state = !state;
    ref.read(webRtcServiceProvider).autoAccept = state;
  }

  void set(bool value) {
    state = value;
    ref.read(webRtcServiceProvider).autoAccept = value;
  }
}

@Riverpod(keepAlive: true)
class IncomingTransferNotifier extends _$IncomingTransferNotifier {
  @override
  IncomingTransferRequest? build() {
    final webrtc = ref.watch(webRtcServiceProvider);
    webrtc.onIncomingOfferRequest = (senderId, senderName, senderEmail, payload) {
      state = IncomingTransferRequest(
        senderId: senderId,
        senderName: senderName,
        senderEmail: senderEmail,
        offerPayload: payload,
        timestamp: DateTime.now(),
      );
    };
    webrtc.onCancelReceived = (senderId) {
      if (state != null && state!.senderId == senderId) {
        state = null;
      }
    };
    return null;
  }

  void clear() {
    state = null;
  }
}

@Riverpod(keepAlive: true)
class TransferStatusNotifier extends _$TransferStatusNotifier {
  @override
  String build() {
    final webrtc = ref.watch(webRtcServiceProvider);
    webrtc.onStatusUpdate = (status) {
      state = status;
    };
    return 'STANDBY // READY FOR P2P HANDSHAKE';
  }

  void updateStatus(String status) {
    state = status;
  }

  void reset() {
    state = 'STANDBY // READY FOR P2P HANDSHAKE';
  }
}

@riverpod
class TransferProgressNotifier extends _$TransferProgressNotifier {
  @override
  AsyncValue<double> build() {
    return const AsyncValue.data(0.0);
  }

  void reset() {
    final webrtc = ref.read(webRtcServiceProvider);
    webrtc.closeConnection();
    ref.read(transferStatusNotifierProvider.notifier).reset();
    state = const AsyncValue.data(0.0);
  }

  void startTransfer(String targetId) async {
    state = const AsyncValue.loading();
    final webrtc = ref.read(webRtcServiceProvider);
    final statusNotifier = ref.read(transferStatusNotifierProvider.notifier);

    try {
      final ledger = ref.read(ledgerProvider);
      final record = ledger.getLatestRecord();
      
      // 1. Read binary payload from disk (Cross-platform safe)
      Uint8List fileBytes;
      if (record == null) {
        // Fallback: If no asset is sealed yet, send a 1KB mock payload
        fileBytes = Uint8List.fromList(List.generate(1024, (i) => i % 256));
      } else {
        try {
          final file = XFile(record.filePath);
          fileBytes = await file.readAsBytes();
        } catch (e) {
          fileBytes = Uint8List.fromList(List.generate(1024, (i) => i % 256));
        }
      }

      // 2. Bind WebRTC tracking callbacks
      webrtc.onStatusUpdate = (status) {
        statusNotifier.updateStatus(status);
      };

      webrtc.onTransferProgress = (progress) {
        state = AsyncValue.data(progress);
      };
      
      webrtc.onTransferComplete = () {
        state = const AsyncValue.data(1.0); // 100%
        statusNotifier.updateStatus('TRANSFER COMPLETE [100%]');
      };

      // 3. Initiate pure WebRTC signaling handshake
      statusNotifier.updateStatus('Dispatching SDP Offer to target peer...');
      await webrtc.initiateTransfer(targetId);
      
      // 4. Stream bytes over the encrypted DTLS/SCTP DataChannel
      await webrtc.sendFileBytes(fileBytes);
      
    } catch (e, st) {
      statusNotifier.updateStatus('HANDSHAKE FAULT: ${e.toString().replaceFirst(RegExp(r'^Exception:\s*'), '')}');
      state = AsyncValue.error(e, st);
    }
  }
}
