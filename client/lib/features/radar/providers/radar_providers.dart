import 'package:flutter_riverpod/flutter_riverpod.dart';

import '../../network/providers/network_providers.dart';
import '../../../main.dart'; // for ledgerProvider
import '../models/radar_models.dart';
import '../services/p2p_session_service.dart';

/// Provider for the active P2PSessionService
final p2pSessionServiceProvider = ChangeNotifierProvider<P2PSessionService>((ref) {
  final webrtc = ref.watch(webRtcServiceProvider);
  final signaling = ref.watch(signalingServiceProvider);
  final ledger = ref.watch(ledgerProvider);

  return P2PSessionService(
    webrtc: webrtc,
    signaling: signaling,
    ledger: ledger,
  );
});

/// State toggle for whether demo/simulated nodes are active in the mesh (defaults to false)
final simulatedPeersEnabledProvider = StateProvider<bool>((ref) => false);

/// Combined list of active mesh peers (real signaling peers + optional simulated demo nodes)
final radarPeersListProvider = Provider<List<RadarPeer>>((ref) {
  final realPeers = ref.watch(discoveredPeersNotifierProvider);
  final showSimulated = ref.watch(simulatedPeersEnabledProvider);

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

  // If simulated nodes are active, supplement mesh
  if (showSimulated) {
    const simulatedCatalog = [
      RadarPeer(
        uuid: 'sim-macbook-m3',
        displayName: 'MacBook Pro M3 Max',
        email: 'alex.chen@studio.internal',
        platform: 'macOS',
        pingMs: 9,
        isSimulated: true,
        orbitRadius: 180.0,
        initialPhase: 0.6,
        floatSpeed: 1.1,
      ),
      RadarPeer(
        uuid: 'sim-thinkpad-p1',
        displayName: 'ThinkPad P1 Enclave',
        email: 'elena.rostova@vault.internal',
        platform: 'Windows',
        pingMs: 14,
        isSimulated: true,
        orbitRadius: 245.0,
        initialPhase: 2.1,
        floatSpeed: 0.85,
      ),
      RadarPeer(
        uuid: 'sim-pixel-9-pro',
        displayName: 'Pixel 9 Pro Hardware Vault',
        email: 'marcus.vance@mobile.mesh',
        platform: 'Android',
        pingMs: 22,
        isSimulated: true,
        orbitRadius: 160.0,
        initialPhase: 3.7,
        floatSpeed: 1.3,
      ),
      RadarPeer(
        uuid: 'sim-ipad-pro-m4',
        displayName: 'iPad Pro Studio Node',
        email: 'design.lead@creative.enclave',
        platform: 'iOS',
        pingMs: 18,
        isSimulated: true,
        orbitRadius: 285.0,
        initialPhase: 5.2,
        floatSpeed: 0.75,
      ),
    ];

    peers.addAll(simulatedCatalog);
  }

  return peers;
});
