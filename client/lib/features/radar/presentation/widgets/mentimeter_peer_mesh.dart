import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

import '../../../../shared/theme/cyber_theme.dart';
import '../../../../shared/widgets/cyber_button.dart';
import '../../models/radar_models.dart';

/// Mentimeter-style interactive floating & orbiting peer mesh
class MentimeterPeerMesh extends StatefulWidget {
  final List<RadarPeer> peers;
  final String myName;
  final String myPlatform;
  final Function(RadarPeer peer) onPeerSelected;
  final VoidCallback onRefresh;
  final bool isSimulatedActive;
  final ValueChanged<bool> onToggleSimulated;

  const MentimeterPeerMesh({
    super.key,
    required this.peers,
    required this.myName,
    required this.myPlatform,
    required this.onPeerSelected,
    required this.onRefresh,
    required this.isSimulatedActive,
    required this.onToggleSimulated,
  });

  @override
  State<MentimeterPeerMesh> createState() => _MentimeterPeerMeshState();
}

class _MentimeterPeerMeshState extends State<MentimeterPeerMesh> with SingleTickerProviderStateMixin {
  late AnimationController _floatController;
  int? _hoveredPeerIndex;

  @override
  void initState() {
    super.initState();
    _floatController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 8),
    )..repeat();
  }

  @override
  void dispose() {
    _floatController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    final totalNodes = widget.peers.length;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // 1. Mesh Header & Real-Time Counter Banner
        _buildMeshHeader(totalNodes),
        const SizedBox(height: 18),

        // 2. Mentimeter-Style Floating Orbital Canvas
        Expanded(
          child: Container(
            clipBehavior: Clip.antiAlias,
            decoration: BoxDecoration(
              color: const Color(0x10FFFFFF),
              borderRadius: BorderRadius.circular(24),
              border: Border.all(color: const Color(0x28FFFFFF), width: 1.2),
              gradient: RadialGradient(
                center: Alignment.center,
                radius: 1.1,
                colors: [
                  const Color(0x20A855F7),
                  const Color(0x100C0814),
                  Colors.transparent,
                ],
              ),
            ),
            child: totalNodes == 0
                ? _buildEmptyRadarScanner()
                : _buildFloatingConstellation(totalNodes),
          ),
        ),
      ],
    );
  }

  // ==========================================
  // 1. MESH HEADER & NODE COUNTER
  // ==========================================
  Widget _buildMeshHeader(int totalNodes) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
      decoration: BoxDecoration(
        color: const Color(0x14FFFFFF),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: const Color(0x28FFFFFF), width: 1.2),
        boxShadow: [
          BoxShadow(
            color: CyberTheme.accentColor.withValues(alpha: 0.14),
            blurRadius: 24,
            spreadRadius: -4,
          ),
        ],
      ),
      child: Row(
        children: [
          // Glowing Pulse Dot
          Container(
            width: 14,
            height: 14,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: const Color(0xFF10B981),
              boxShadow: [
                BoxShadow(
                  color: const Color(0xFF10B981).withValues(alpha: 0.8),
                  blurRadius: 12,
                  spreadRadius: 2,
                ),
              ],
            ),
          ),
          const SizedBox(width: 14),

          // Discovered Node Counter
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Text(
                      '$totalNodes ${totalNodes == 1 ? "NODE" : "NODES"} DISCOVERED IN SECURE MESH',
                      style: GoogleFonts.plusJakartaSans(
                        fontSize: 14.5,
                        fontWeight: FontWeight.w900,
                        letterSpacing: 0.8,
                        color: Colors.white,
                      ),
                    ),
                    const SizedBox(width: 10),
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                      decoration: BoxDecoration(
                        color: const Color(0x2234D399),
                        borderRadius: BorderRadius.circular(100),
                        border: Border.all(color: const Color(0x5034D399)),
                      ),
                      child: Text(
                        'AIRDROP ACTIVE',
                        style: GoogleFonts.jetBrainsMono(
                          fontSize: 9,
                          fontWeight: FontWeight.w800,
                          color: const Color(0xFF34D399),
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 3),
                Text(
                  'Mentimeter-Style Enclave Mesh • Click any node to establish an encrypted P2P channel',
                  style: GoogleFonts.plusJakartaSans(
                    fontSize: 11.5,
                    color: CyberTheme.textSecondary,
                  ),
                ),
              ],
            ),
          ),

          // Simulation Toggle
          InkWell(
            onTap: () => widget.onToggleSimulated(!widget.isSimulatedActive),
            borderRadius: BorderRadius.circular(100),
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
              decoration: BoxDecoration(
                color: widget.isSimulatedActive ? const Color(0x28A855F7) : const Color(0x10FFFFFF),
                borderRadius: BorderRadius.circular(100),
                border: Border.all(
                  color: widget.isSimulatedActive ? const Color(0xFFC084FC) : const Color(0x20FFFFFF),
                ),
              ),
              child: Row(
                children: [
                  Icon(
                    widget.isSimulatedActive ? Icons.science_rounded : Icons.science_outlined,
                    size: 14,
                    color: widget.isSimulatedActive ? const Color(0xFFC084FC) : const Color(0xFF94A3B8),
                  ),
                  const SizedBox(width: 6),
                  Text(
                    'Demo Nodes',
                    style: GoogleFonts.plusJakartaSans(
                      fontSize: 11,
                      fontWeight: FontWeight.w700,
                      color: widget.isSimulatedActive ? Colors.white : const Color(0xFF94A3B8),
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(width: 10),

          // Rescan Button
          CyberButton(
            variant: CyberButtonVariant.glassPill,
            height: 38,
            padding: const EdgeInsets.symmetric(horizontal: 16),
            icon: Icons.radar,
            onTap: widget.onRefresh,
            child: const Text('Rescan Mesh'),
          ),
        ],
      ),
    );
  }

  // ==========================================
  // 2. MENTIMETER FLOATING CONSTELLATION
  // ==========================================
  Widget _buildFloatingConstellation(int count) {
    return LayoutBuilder(
      builder: (context, constraints) {
        final centerX = constraints.maxWidth / 2;
        final centerY = constraints.maxHeight / 2;

        return AnimatedBuilder(
          animation: _floatController,
          builder: (context, child) {
            final t = _floatController.value * 2 * math.pi;

            return Stack(
              clipBehavior: Clip.none,
              children: [
                // Concentric Radar Distance Rings
                CustomPaint(
                  size: Size(constraints.maxWidth, constraints.maxHeight),
                  painter: _RadarBackgroundPainter(t: _floatController.value),
                ),

                // Center Node: You (Current Enclave Node)
                Positioned(
                  left: centerX - 54,
                  top: centerY - 54,
                  child: _buildCenterSelfNode(),
                ),

                // Floating Peer Bubbles (Mentimeter style orbiting & sinusoidal bobbing)
                ...List.generate(count, (index) {
                  final peer = widget.peers[index];
                  final isHovered = _hoveredPeerIndex == index;

                  // Distribute nodes evenly in an orbit + sinusoidal offset
                  final baseAngle = (index / count) * 2 * math.pi;
                  final orbitRadius = math.min(constraints.maxWidth, constraints.maxHeight) * 0.35;
                  
                  // Gentle Mentimeter sinusoidal floating physics
                  final bobOffset = math.sin(t * peer.floatSpeed + peer.initialPhase) * 14.0;
                  final swayOffset = math.cos(t * peer.floatSpeed * 0.8 + peer.initialPhase) * 10.0;

                  final nodeX = centerX + math.cos(baseAngle) * orbitRadius + swayOffset - 68;
                  final nodeY = centerY + math.sin(baseAngle) * orbitRadius + bobOffset - 68;

                  return Positioned(
                    left: nodeX,
                    top: nodeY,
                    child: MouseRegion(
                      onEnter: (_) => setState(() => _hoveredPeerIndex = index),
                      onExit: (_) => setState(() => _hoveredPeerIndex = null),
                      child: GestureDetector(
                        onTap: () => widget.onPeerSelected(peer),
                        child: _buildPeerBubble(peer, isHovered),
                      ),
                    ),
                  );
                }),
              ],
            );
          },
        );
      },
    );
  }

  // ==========================================
  // 3. PEER BUBBLE CARD (MENTIMETER STYLE)
  // ==========================================
  Widget _buildPeerBubble(RadarPeer peer, bool isHovered) {
    final avatarColors = [
      [const Color(0xFFC084FC), const Color(0xFF9333EA)],
      [const Color(0xFF38BDF8), const Color(0xFF0284C7)],
      [const Color(0xFF34D399), const Color(0xFF059669)],
      [const Color(0xFFF43F5E), const Color(0xFFE11D48)],
      [const Color(0xFFFBBF24), const Color(0xFFD97706)],
    ];
    final colorPair = avatarColors[peer.displayName.hashCode.abs() % avatarColors.length];

    return AnimatedScale(
      scale: isHovered ? 1.08 : 1.0,
      duration: const Duration(milliseconds: 220),
      curve: Curves.easeOutCubic,
      child: Container(
        width: 136,
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 12),
        decoration: BoxDecoration(
          color: isHovered
              ? const Color(0xEE1E1533)
              : const Color(0xCC130D22),
          borderRadius: BorderRadius.circular(22),
          border: Border.all(
            color: isHovered ? const Color(0xFFC084FC) : const Color(0x35FFFFFF),
            width: isHovered ? 1.8 : 1.2,
          ),
          boxShadow: [
            BoxShadow(
              color: isHovered
                  ? const Color(0xFFA855F7).withValues(alpha: 0.45)
                  : Colors.black.withValues(alpha: 0.35),
              blurRadius: isHovered ? 28 : 16,
              offset: const Offset(0, 8),
            ),
          ],
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Avatar with Glowing Ring
            Stack(
              clipBehavior: Clip.none,
              children: [
                Container(
                  width: 48,
                  height: 48,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    gradient: LinearGradient(
                      colors: colorPair,
                      begin: Alignment.topLeft,
                      end: Alignment.bottomRight,
                    ),
                    boxShadow: [
                      BoxShadow(
                        color: colorPair.first.withValues(alpha: 0.4),
                        blurRadius: 12,
                      ),
                    ],
                  ),
                  child: Center(
                    child: Text(
                      peer.displayName.isNotEmpty ? peer.displayName[0].toUpperCase() : 'A',
                      style: GoogleFonts.plusJakartaSans(
                        fontSize: 20,
                        fontWeight: FontWeight.w900,
                        color: Colors.white,
                      ),
                    ),
                  ),
                ),
                // Live Green Dot
                Positioned(
                  right: 0,
                  bottom: 0,
                  child: Container(
                    width: 13,
                    height: 13,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: const Color(0xFF10B981),
                      border: Border.all(color: const Color(0xFF130D22), width: 2),
                    ),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 8),

            // Peer Name
            Text(
              peer.displayName,
              style: GoogleFonts.plusJakartaSans(
                fontSize: 12,
                fontWeight: FontWeight.w800,
                color: Colors.white,
              ),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 4),

            // Device Platform & Ping Pill
            Row(
              mainAxisAlignment: MainAxisAlignment.center,
              children: [
                Icon(
                  _getPlatformIcon(peer.platform),
                  size: 11,
                  color: const Color(0xFF94A3B8),
                ),
                const SizedBox(width: 4),
                Text(
                  '${peer.pingMs}ms',
                  style: GoogleFonts.jetBrainsMono(
                    fontSize: 9.5,
                    fontWeight: FontWeight.w700,
                    color: const Color(0xFF94A3B8),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 6),

            // Connect Action Pill
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
              decoration: BoxDecoration(
                color: isHovered ? const Color(0xFFC084FC) : const Color(0x18FFFFFF),
                borderRadius: BorderRadius.circular(100),
              ),
              child: Text(
                isHovered ? 'CONNECT ➔' : 'READY',
                style: GoogleFonts.jetBrainsMono(
                  fontSize: 8.5,
                  fontWeight: FontWeight.w900,
                  color: isHovered ? Colors.black : const Color(0xFFE2E8F0),
                  letterSpacing: 0.6,
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ==========================================
  // 4. CENTER SELF NODE (YOU)
  // ==========================================
  Widget _buildCenterSelfNode() {
    return Container(
      width: 108,
      height: 108,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        color: const Color(0xDD160F2B),
        border: Border.all(color: const Color(0xFFC084FC), width: 2),
        boxShadow: [
          BoxShadow(
            color: CyberTheme.accentColor.withValues(alpha: 0.35),
            blurRadius: 32,
            spreadRadius: 4,
          ),
        ],
      ),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Container(
            width: 38,
            height: 38,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              gradient: CyberTheme.shardGradient,
            ),
            child: const Icon(Icons.hub_rounded, color: Colors.white, size: 20),
          ),
          const SizedBox(height: 6),
          Text(
            'YOU',
            style: GoogleFonts.plusJakartaSans(
              fontSize: 11,
              fontWeight: FontWeight.w900,
              letterSpacing: 1.0,
              color: Colors.white,
            ),
          ),
          Text(
            'LOCAL NODE',
            style: GoogleFonts.jetBrainsMono(
              fontSize: 8,
              fontWeight: FontWeight.w800,
              color: const Color(0xFFC084FC),
            ),
          ),
        ],
      ),
    );
  }

  // ==========================================
  // 5. EMPTY RADAR SCANNER
  // ==========================================
  Widget _buildEmptyRadarScanner() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Container(
            width: 68,
            height: 68,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: const Color(0x18C084FC),
              border: Border.all(color: const Color(0x40C084FC), width: 1.5),
            ),
            child: const Icon(Icons.radar, color: Color(0xFFC084FC), size: 32),
          ),
          const SizedBox(height: 16),
          Text(
            'NO NODES CURRENTLY DETECTED',
            style: GoogleFonts.plusJakartaSans(
              fontSize: 14,
              fontWeight: FontWeight.w800,
              letterSpacing: 0.8,
              color: Colors.white,
            ),
          ),
          const SizedBox(height: 6),
          Text(
            'Turn on "Demo Nodes" above to test interactive P2P AirDrop & Chat simulation.',
            style: GoogleFonts.plusJakartaSans(fontSize: 12, color: CyberTheme.textSecondary),
          ),
          const SizedBox(height: 16),
          CyberButton(
            variant: CyberButtonVariant.whitePill,
            height: 38,
            icon: Icons.science_rounded,
            onTap: () => widget.onToggleSimulated(true),
            child: const Text('Spawn Simulated Nodes'),
          ),
        ],
      ),
    );
  }

  IconData _getPlatformIcon(String platform) {
    final p = platform.toLowerCase();
    if (p.contains('win')) return Icons.laptop_windows;
    if (p.contains('mac') || p.contains('apple') || p.contains('darwin')) return Icons.laptop_mac;
    if (p.contains('ios') || p.contains('iphone') || p.contains('phone')) return Icons.phone_iphone;
    if (p.contains('android')) return Icons.phone_android;
    return Icons.language;
  }
}

/// Custom painter rendering the concentric glowing radar rings & crosshairs
class _RadarBackgroundPainter extends CustomPainter {
  final double t;

  _RadarBackgroundPainter({required this.t});

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    final maxRadius = math.min(size.width, size.height) * 0.44;

    final linePaint = Paint()
      ..color = const Color(0x15FFFFFF)
      ..strokeWidth = 1.0
      ..style = PaintingStyle.stroke;

    final ringPaint = Paint()
      ..color = const Color(0x18C084FC)
      ..strokeWidth = 1.2
      ..style = PaintingStyle.stroke;

    // Crosshairs
    canvas.drawLine(Offset(center.dx, 0), Offset(center.dx, size.height), linePaint);
    canvas.drawLine(Offset(0, center.dy), Offset(size.width, center.dy), linePaint);

    // 4 Concentric Circles
    for (int i = 1; i <= 4; i++) {
      final r = maxRadius * (i / 4.0);
      canvas.drawCircle(center, r, ringPaint);
    }

    // Animated sweeping radar wave
    final sweepPaint = Paint()
      ..shader = SweepGradient(
        center: Alignment.center,
        startAngle: 0,
        endAngle: math.pi * 2,
        colors: [
          Colors.transparent,
          const Color(0x35C084FC),
          Colors.transparent,
        ],
        transform: GradientRotation(t * 2 * math.pi),
      ).createShader(Rect.fromCircle(center: center, radius: maxRadius))
      ..style = PaintingStyle.fill;

    canvas.drawCircle(center, maxRadius, sweepPaint);
  }

  @override
  bool shouldRepaint(covariant _RadarBackgroundPainter oldDelegate) {
    return oldDelegate.t != t;
  }
}
