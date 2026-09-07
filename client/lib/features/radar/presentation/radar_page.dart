import 'dart:io' show Platform;
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:google_fonts/google_fonts.dart';

import '../../../shared/theme/cyber_theme.dart';
import '../../../shared/widgets/cyber_button.dart';
import '../../auth/providers/auth_providers.dart';
import '../../network/providers/network_providers.dart';
import '../models/radar_models.dart';
import '../providers/radar_providers.dart';
import '../services/p2p_session_service.dart';
import 'widgets/mentimeter_peer_mesh.dart';
import 'widgets/navigation_guard_dialog.dart';
import 'widgets/p2p_chat_screen.dart';

/// The Next-Generation Enclave Radar Page:
/// - Only users actively in the Radar Portal are visible in the mesh
/// - Displays authentic user names (never generic "Node...")
/// - Initiator waits with high-end authorization loading screen until recipient confirms
/// - Recipient receives an incoming connection request card
/// - Both users log into the P2P chat screen only after confirmation
class RadarPage extends ConsumerStatefulWidget {
  final Function(int targetTab)? onNavigateToTab;
  final Function(String fileName, Uint8List bytes)? onAuditInVerification;

  const RadarPage({
    super.key,
    this.onNavigateToTab,
    this.onAuditInVerification,
  });

  @override
  ConsumerState<RadarPage> createState() => _RadarPageState();
}

class _RadarPageState extends ConsumerState<RadarPage> with SingleTickerProviderStateMixin {
  late AnimationController _pulseController;

  @override
  void initState() {
    super.initState();
    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 2200),
    )..repeat();

    WidgetsBinding.instance.addPostFrameCallback((_) {
      // Mark local user as present in the radar portal
      ref.read(signalingServiceProvider).setInRadar(true);

      // Handle handshake decline notification for User 1
      ref.read(p2pSessionServiceProvider).onHandshakeDeclined = (peerName, reason) {
        if (mounted) {
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              content: Row(
                children: [
                  const Icon(Icons.cancel_outlined, color: Colors.white, size: 18),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Text(
                      '$peerName declined the connection invitation ($reason).',
                      style: GoogleFonts.plusJakartaSans(fontSize: 13, fontWeight: FontWeight.w600),
                    ),
                  ),
                ],
              ),
              backgroundColor: const Color(0xFFF43F5E),
              behavior: SnackBarBehavior.floating,
              duration: const Duration(seconds: 4),
            ),
          );
        }
      };
    });
  }

  @override
  void dispose() {
    // When leaving the radar page, announce exit so user disappears from others' radar
    ref.read(signalingServiceProvider).setInRadar(false);
    _pulseController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final sessionService = ref.watch(p2pSessionServiceProvider);
    final peers = ref.watch(radarPeersListProvider);
    final userProfile = ref.watch(userProfileProvider);
    final showSimulated = ref.watch(simulatedPeersEnabledProvider);
    final incomingRequest = ref.watch(incomingTransferNotifierProvider);

    // Only switch to chat screen when fully connected
    final isSessionActive = sessionService.sessionState == P2PSessionState.connected;
    final isAwaitingHandshake = sessionService.sessionState == P2PSessionState.awaitingHandshake &&
        sessionService.activePeer != null;

    String currentPlatform = 'Desktop Node';
    try {
      if (kIsWeb) {
        currentPlatform = 'Web Browser';
      } else if (Platform.isWindows) {
        currentPlatform = 'Windows Enclave';
      } else if (Platform.isMacOS) {
        currentPlatform = 'macOS Node';
      } else if (Platform.isLinux) {
        currentPlatform = 'Linux Station';
      } else if (Platform.isAndroid) {
        currentPlatform = 'Android Vault';
      } else if (Platform.isIOS) {
        currentPlatform = 'iOS Hardware';
      }
    } catch (_) {}

    return Stack(
      children: [
        // 1. Main Content: Mentimeter Mesh vs P2P Chat Screen (Chat ONLY when connected)
        AnimatedSwitcher(
          duration: const Duration(milliseconds: 350),
          switchInCurve: Curves.easeOutCubic,
          switchOutCurve: Curves.easeInCubic,
          child: isSessionActive
              ? P2PChatScreen(
                  key: const ValueKey('p2p_chat_screen'),
                  sessionService: sessionService,
                  onDisconnect: () => _handleDisconnect(sessionService),
                  onAuditInVerification: (fileName, bytes) {
                    if (widget.onAuditInVerification != null) {
                      widget.onAuditInVerification!(fileName, bytes);
                    }
                    if (widget.onNavigateToTab != null) {
                      widget.onNavigateToTab!(2); // Switch to Verify Tab
                    }
                  },
                )
              : MentimeterPeerMesh(
                  key: const ValueKey('mentimeter_peer_mesh'),
                  peers: peers,
                  myName: userProfile.displayName.isNotEmpty ? userProfile.displayName : 'Local Enclave',
                  myPlatform: currentPlatform,
                  isSimulatedActive: showSimulated,
                  onToggleSimulated: (val) {
                    ref.read(simulatedPeersEnabledProvider.notifier).state = val;
                  },
                  onRefresh: () {
                    ref.invalidate(discoveredPeersNotifierProvider);
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(
                        content: Text(
                          'MESH SCAN DISPATCHED // REFRESHING PEER TELEMETRY',
                          style: GoogleFonts.jetBrainsMono(fontSize: 12, fontWeight: FontWeight.bold),
                        ),
                        backgroundColor: CyberTheme.cyan,
                        duration: const Duration(milliseconds: 1400),
                      ),
                    );
                  },
                  onPeerSelected: (peer) async {
                    await sessionService.connectToPeer(peer);
                  },
                ),
        ),

        // 2. User 1: High-End Waiting Authorization Screen while awaiting remote peer confirmation
        if (isAwaitingHandshake)
          _buildAwaitingHandshakeOverlay(sessionService.activePeer!, sessionService),

        // 3. User 2: Incoming Transfer / Handshake Modal Overlay for the Radar Screen
        if (incomingRequest != null && !isSessionActive && !isAwaitingHandshake)
          Positioned(
            top: 20,
            left: 20,
            right: 20,
            child: _buildIncomingInvitationCard(incomingRequest, sessionService),
          ),
      ],
    );
  }

  // ==========================================
  // USER 1: WAITING AUTHORIZATION MODAL
  // ==========================================
  Widget _buildAwaitingHandshakeOverlay(
    RadarPeer peer,
    P2PSessionService sessionService,
  ) {
    return Positioned.fill(
      child: Container(
        color: Colors.black.withValues(alpha: 0.72),
        padding: const EdgeInsets.all(24),
        child: Center(
          child: Container(
            width: 480,
            padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 34),
            decoration: BoxDecoration(
              color: const Color(0xFB140D24),
              borderRadius: BorderRadius.circular(28),
              border: Border.all(color: const Color(0x60A855F7), width: 1.5),
              boxShadow: [
                BoxShadow(
                  color: const Color(0xFFC084FC).withValues(alpha: 0.35),
                  blurRadius: 40,
                  spreadRadius: 2,
                ),
                BoxShadow(
                  color: Colors.black.withValues(alpha: 0.9),
                  blurRadius: 30,
                  offset: const Offset(0, 15),
                ),
              ],
            ),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                // Animated Pulsing Ripple Radar with Target Peer Avatar
                SizedBox(
                  width: 100,
                  height: 100,
                  child: Stack(
                    alignment: Alignment.center,
                    children: [
                      // Outer animated expanding pulse wave
                      AnimatedBuilder(
                        animation: _pulseController,
                        builder: (context, child) {
                          return Container(
                            width: 60 + (_pulseController.value * 40),
                            height: 60 + (_pulseController.value * 40),
                            decoration: BoxDecoration(
                              shape: BoxShape.circle,
                              border: Border.all(
                                color: const Color(0xFFC084FC).withValues(
                                  alpha: (1.0 - _pulseController.value).clamp(0.0, 1.0) * 0.6,
                                ),
                                width: 1.5,
                              ),
                            ),
                          );
                        },
                      ),
                      // Inner glowing avatar
                      Container(
                        width: 62,
                        height: 62,
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          gradient: const RadialGradient(
                            colors: [Color(0xFFC084FC), Color(0xFF6B21A8)],
                          ),
                          border: Border.all(color: Colors.white, width: 2),
                          boxShadow: [
                            BoxShadow(
                              color: const Color(0xFFC084FC).withValues(alpha: 0.5),
                              blurRadius: 20,
                            ),
                          ],
                        ),
                        child: Center(
                          child: Text(
                            peer.displayName.isNotEmpty
                                ? peer.displayName.substring(0, 1).toUpperCase()
                                : 'P',
                            style: GoogleFonts.plusJakartaSans(
                              color: Colors.white,
                              fontSize: 24,
                              fontWeight: FontWeight.w900,
                            ),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 20),

                // Title
                Text(
                  'WAITING FOR AUTHORIZATION',
                  style: GoogleFonts.plusJakartaSans(
                    fontSize: 16,
                    fontWeight: FontWeight.w900,
                    letterSpacing: 1.2,
                    color: Colors.white,
                  ),
                ),
                const SizedBox(height: 6),

                // Target Node Badge
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                  decoration: BoxDecoration(
                    color: const Color(0x30C084FC),
                    borderRadius: BorderRadius.circular(100),
                    border: Border.all(color: const Color(0x60C084FC)),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Container(
                        width: 6,
                        height: 6,
                        decoration: const BoxDecoration(
                          shape: BoxShape.circle,
                          color: Color(0xFF34D399),
                        ),
                      ),
                      const SizedBox(width: 6),
                      Text(
                        peer.displayName,
                        style: GoogleFonts.jetBrainsMono(
                          fontSize: 11,
                          fontWeight: FontWeight.w700,
                          color: const Color(0xFFF3E8FF),
                        ),
                      ),
                      if (peer.platform.isNotEmpty) ...[
                        const SizedBox(width: 6),
                        Text(
                          '• ${peer.platform}',
                          style: GoogleFonts.jetBrainsMono(
                            fontSize: 10,
                            color: const Color(0xFFD8B4FE),
                          ),
                        ),
                      ],
                    ],
                  ),
                ),
                const SizedBox(height: 16),

                // Subtitle / Explainer
                Text(
                  'A secure DTLS 1.3 cryptographic handshake invitation has been dispatched. Please wait for ${peer.displayName} to accept in their Radar portal.\nBoth of you will enter the encrypted session together once confirmed.',
                  textAlign: TextAlign.center,
                  style: GoogleFonts.plusJakartaSans(
                    fontSize: 12.5,
                    color: const Color(0xFFCBD5E1),
                    height: 1.5,
                  ),
                ),
                const SizedBox(height: 24),

                // Loading bar
                ClipRRect(
                  borderRadius: BorderRadius.circular(4),
                  child: const SizedBox(
                    width: 200,
                    height: 3,
                    child: LinearProgressIndicator(
                      backgroundColor: Color(0x20FFFFFF),
                      valueColor: AlwaysStoppedAnimation<Color>(Color(0xFFC084FC)),
                    ),
                  ),
                ),
                const SizedBox(height: 26),

                // Cancel button
                CyberButton(
                  variant: CyberButtonVariant.glassPill,
                  height: 40,
                  padding: const EdgeInsets.symmetric(horizontal: 26),
                  onTap: () async {
                    await sessionService.cancelHandshake();
                  },
                  child: Text(
                    'Cancel Invitation',
                    style: GoogleFonts.plusJakartaSans(
                      fontSize: 13,
                      fontWeight: FontWeight.w700,
                      color: const Color(0xFFF87171),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  // ==========================================
  // USER 2: INCOMING INVITATION PROMPT
  // ==========================================
  Widget _buildIncomingInvitationCard(
    IncomingTransferRequest request,
    P2PSessionService sessionService,
  ) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 16),
      decoration: BoxDecoration(
        color: const Color(0xF0130D22),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: CyberTheme.emeraldLight, width: 1.5),
        boxShadow: [
          BoxShadow(
            color: CyberTheme.emerald.withValues(alpha: 0.3),
            blurRadius: 30,
            spreadRadius: 2,
          ),
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.8),
            blurRadius: 20,
            offset: const Offset(0, 10),
          ),
        ],
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: CyberTheme.emerald.withValues(alpha: 0.2),
              border: Border.all(color: CyberTheme.emerald, width: 1.5),
            ),
            child: const Icon(Icons.wifi_tethering, color: CyberTheme.emerald, size: 24),
          ),
          const SizedBox(width: 16),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Row(
                  children: [
                    Text(
                      'INCOMING P2P ENCLAVE INVITATION',
                      style: GoogleFonts.plusJakartaSans(
                        color: CyberTheme.emerald,
                        fontSize: 12,
                        fontWeight: FontWeight.w900,
                        letterSpacing: 0.8,
                      ),
                    ),
                    const SizedBox(width: 8),
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                      decoration: BoxDecoration(
                        color: CyberTheme.emerald.withValues(alpha: 0.2),
                        borderRadius: BorderRadius.circular(4),
                      ),
                      child: Text(
                        'DTLS 1.3',
                        style: GoogleFonts.jetBrainsMono(
                          fontSize: 9,
                          fontWeight: FontWeight.w800,
                          color: CyberTheme.emerald,
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 4),
                Text(
                  'Agent ${request.senderName} (${request.senderEmail.isNotEmpty ? request.senderEmail : request.senderId.substring(0, 8)}) is requesting a direct P2P connection to exchange C2PA sealed assets.',
                  style: GoogleFonts.plusJakartaSans(
                    color: CyberTheme.textPrimary,
                    fontSize: 13,
                    fontWeight: FontWeight.w500,
                    height: 1.3,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(width: 16),
          CyberButton(
            variant: CyberButtonVariant.danger,
            height: 38,
            padding: const EdgeInsets.symmetric(horizontal: 18),
            onTap: () {
              ref.read(webRtcServiceProvider).declineIncomingTransfer(request.senderId);
              ref.read(incomingTransferNotifierProvider.notifier).clear();
            },
            child: const Text('DECLINE'),
          ),
          const SizedBox(width: 10),
          CyberButton(
            variant: CyberButtonVariant.emerald,
            height: 38,
            padding: const EdgeInsets.symmetric(horizontal: 22),
            onTap: () {
              final peer = RadarPeer(
                uuid: request.senderId,
                displayName: request.senderName,
                email: request.senderEmail,
                platform: 'Mesh Node',
                pingMs: 16,
              );
              sessionService.handleIncomingSessionAccepted(peer);
              ref.read(incomingTransferNotifierProvider.notifier).clear();
              ref.read(webRtcServiceProvider).acceptIncomingTransfer(request.senderId, request.offerPayload);
            },
            child: const Text('ACCEPT & CONNECT'),
          ),
        ],
      ),
    );
  }

  Future<void> _handleDisconnect(P2PSessionService sessionService) async {
    if (sessionService.hasActiveTransfer) {
      final shouldLeave = await NavigationGuardDialog.show(
        context,
        fileName: sessionService.activeTransferringFileName ?? 'digital asset',
        progress: sessionService.transferProgress,
      );

      if (shouldLeave) {
        await sessionService.disconnect();
      }
    } else {
      await sessionService.disconnect();
    }
  }
}
