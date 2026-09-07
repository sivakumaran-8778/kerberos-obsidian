import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../network/providers/network_providers.dart';
import '../../../main.dart'; // for ledgerProvider
import '../models/radar_models.dart';
import '../services/p2p_session_service.dart';

/// Provider for the active P2PSessionService
final p2pSessionServiceProvider = ChangeNotifierProvider<P2PSessionService>((ref) {
  final webrtc = ref.read(webRtcServiceProvider);
  final signaling = ref.read(signalingServiceProvider);
  final ledger = ref.read(ledgerProvider);

  return P2PSessionService(
    webrtc: webrtc,
    signaling: signaling,
    ledger: ledger,
  );
});

/// List of active mesh peers discovered via Supabase real-time presence signaling
final radarPeersListProvider = Provider<List<RadarPeer>>((ref) {
  final realPeers = ref.watch(discoveredPeersNotifierProvider);

  final List<RadarPeer> peers = [];

  // Map real peers from Supabase signaling
  for (int i = 0; i < realPeers.length; i++) {
    final p = realPeers[i];
    final uuid = p['uuid']?.toString() ?? 'peer-$i';
    
    // Resolve clean human name - never generic "Node ..."
    String name = p['display_name']?.toString() ??
        p['displayName']?.toString() ??
        p['name']?.toString() ??
        '';
    final email = p['email']?.toString() ?? p['userEmail']?.toString() ?? '';

    if (name.trim().isEmpty || name.toLowerCase() == 'agent') {
      if (email.contains('@')) {
        final userPart = email.split('@').first;
        name = userPart.isNotEmpty ? userPart[0].toUpperCase() + userPart.substring(1) : userPart;
      } else {
        name = 'Agent ${uuid.length >= 4 ? uuid.substring(0, 4) : uuid}';
      }
    }

    final platform = p['platform']?.toString() ?? 'Enclave Node';

    peers.add(
      RadarPeer(
        uuid: uuid,
        displayName: name,
        email: email,
        platform: platform,
        pingMs: 12 + (i * 4),
        isSimulated: false,
        orbitRadius: 170.0 + ((i % 3) * 55.0),
        initialPhase: (i * 1.4),
        floatSpeed: 0.9 + ((i % 3) * 0.25),
      ),
    );
  }

  return peers;
});
