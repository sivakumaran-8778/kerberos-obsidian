import 'dart:math' as math;
import 'package:flutter/material.dart';

/// Ethereal Living Aurora Background with Ambient Pulsing Glow, Stardust, & Heavy Edge Vignette.
/// - Dynamic breathing animation brings continuous liveliness to prevent the application from feeling frozen or stuck.
/// - Deep midnight obsidian canvas (#06030A) maintaining rich contrast.
/// - Undulating radial theme glows (#8B5CF6 / #7C3AED / #6366F1) that gently breathe and drift.
/// - Floating luminous cosmic stardust particles with organic sine-wave motion and soft alpha twinkle.
/// - Heavy multi-pass screen-edge vignette falloff on all edges (top, bottom, left, right, and corners).
class ShardsBackground extends StatefulWidget {
  final Widget? child;

  const ShardsBackground({
    super.key,
    this.child,
    int? shardCount,
  });

  @override
  State<ShardsBackground> createState() => _ShardsBackgroundState();
}

class _ShardsBackgroundState extends State<ShardsBackground> with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late List<_StardustParticle> _particles;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 12),
    )..repeat();

    // Deterministic pseudo-random particles for organic stardust
    final rng = math.Random(1337);
    const particleColors = [
      Color(0xFFC084FC), // Electric lavender
      Color(0xFFA855F7), // Vibrant purple
      Color(0xFF818CF8), // Indigo
      Color(0xFF67E8F9), // Subtle cyan ice
      Color(0xFFFFFFFF), // Crystal white
    ];

    _particles = List.generate(28, (i) {
      return _StardustParticle(
        x: rng.nextDouble(),
        y: rng.nextDouble(),
        size: 1.2 + rng.nextDouble() * 2.2,
        speed: 0.02 + rng.nextDouble() * 0.04,
        baseOpacity: 0.18 + rng.nextDouble() * 0.45,
        phase: rng.nextDouble() * 2 * math.pi,
        color: particleColors[rng.nextInt(particleColors.length)],
      );
    });
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Stack(
      children: [
        // 1. Ultra-Dark Midnight Obsidian Base Canvas
        Positioned.fill(
          child: Container(
            color: const Color(0xFF06030A),
          ),
        ),

        // 2. Dynamic Breathing Aurora Glows (Center-Stage Halo & Lower Drift)
        Positioned.fill(
          child: AnimatedBuilder(
            animation: _controller,
            builder: (context, _) {
              final double t = _controller.value;
              final double sinT = math.sin(t * 2 * math.pi);
              final double cosT = math.cos(t * 2 * math.pi);

              // Center glow breathing & subtle drift
              final Alignment centerAlign = Alignment(
                0.08 * sinT,
                -0.15 + 0.05 * cosT,
              );
              final double centerRadius = 0.88 + 0.14 * sinT;

              // Secondary lower horizon glow drift
              final Alignment lowerAlign = Alignment(
                -0.10 * cosT,
                0.55 + 0.07 * sinT,
              );
              final double lowerRadius = 0.92 + 0.10 * cosT;

              return Stack(
                children: [
                  // Center Primary Theme Glow
                  Positioned.fill(
                    child: IgnorePointer(
                      child: Container(
                        decoration: BoxDecoration(
                          gradient: RadialGradient(
                            center: centerAlign,
                            radius: centerRadius,
                            colors: [
                              Color.lerp(const Color(0x248B5CF6), const Color(0x30A855F7), (sinT + 1) / 2)!,
                              Color.lerp(const Color(0x147C3AED), const Color(0x1E6D28D9), (cosT + 1) / 2)!,
                              Color.lerp(const Color(0x084C1D95), const Color(0x10581C87), (sinT + 1) / 2)!,
                              Colors.transparent,
                            ],
                            stops: const [0.0, 0.35, 0.68, 1.0],
                          ),
                        ),
                      ),
                    ),
                  ),

                  // Lower Horizon Subtle Indigo Glow
                  Positioned.fill(
                    child: IgnorePointer(
                      child: Container(
                        decoration: BoxDecoration(
                          gradient: RadialGradient(
                            center: lowerAlign,
                            radius: lowerRadius,
                            colors: [
                              Color.lerp(const Color(0x1A7C3AED), const Color(0x246366F1), (cosT + 1) / 2)!,
                              Color.lerp(const Color(0x0A4C1D95), const Color(0x124338CA), (sinT + 1) / 2)!,
                              Colors.transparent,
                            ],
                            stops: const [0.0, 0.48, 1.0],
                          ),
                        ),
                      ),
                    ),
                  ),
                ],
              );
            },
          ),
        ),

        // 3. Lively Ambient Cosmic Stardust Particles
        Positioned.fill(
          child: AnimatedBuilder(
            animation: _controller,
            builder: (context, _) {
              return IgnorePointer(
                child: CustomPaint(
                  painter: _StardustPainter(
                    progress: _controller.value,
                    particles: _particles,
                  ),
                ),
              );
            },
          ),
        ),

        // 4. Heavy Screen-Edge Vignette: Multi-stop Radial Edge Falloff
        Positioned.fill(
          child: IgnorePointer(
            child: Container(
              decoration: const BoxDecoration(
                gradient: RadialGradient(
                  center: Alignment.center,
                  radius: 0.95,
                  colors: [
                    Colors.transparent,
                    Colors.transparent,
                    Color(0x55000000),
                    Color(0xCC040108),
                    Color(0xFA020005),
                    Color(0xFF000000),
                  ],
                  stops: [0.0, 0.32, 0.62, 0.82, 0.94, 1.0],
                ),
              ),
            ),
          ),
        ),

        // 5. Heavy Edge Vignette: Top Screen Edge Shadow
        Positioned(
          top: 0,
          left: 0,
          right: 0,
          height: 190,
          child: IgnorePointer(
            child: Container(
              decoration: const BoxDecoration(
                gradient: LinearGradient(
                  begin: Alignment.topCenter,
                  end: Alignment.bottomCenter,
                  colors: [
                    Color(0xF5020105),
                    Color(0xB2020105),
                    Color(0x44020105),
                    Colors.transparent,
                  ],
                  stops: [0.0, 0.35, 0.7, 1.0],
                ),
              ),
            ),
          ),
        ),

        // 6. Heavy Edge Vignette: Bottom Screen Edge Shadow
        Positioned(
          bottom: 0,
          left: 0,
          right: 0,
          height: 210,
          child: IgnorePointer(
            child: Container(
              decoration: const BoxDecoration(
                gradient: LinearGradient(
                  begin: Alignment.bottomCenter,
                  end: Alignment.topCenter,
                  colors: [
                    Color(0xFC020105),
                    Color(0xD0020105),
                    Color(0x55020105),
                    Colors.transparent,
                  ],
                  stops: [0.0, 0.35, 0.7, 1.0],
                ),
              ),
            ),
          ),
        ),

        // 7. Heavy Edge Vignette: Left Screen Edge Shadow
        Positioned(
          top: 0,
          bottom: 0,
          left: 0,
          width: 190,
          child: IgnorePointer(
            child: Container(
              decoration: const BoxDecoration(
                gradient: LinearGradient(
                  begin: Alignment.centerLeft,
                  end: Alignment.centerRight,
                  colors: [
                    Color(0xF5020105),
                    Color(0xA6020105),
                    Colors.transparent,
                  ],
                  stops: [0.0, 0.5, 1.0],
                ),
              ),
            ),
          ),
        ),

        // 8. Heavy Edge Vignette: Right Screen Edge Shadow
        Positioned(
          top: 0,
          bottom: 0,
          right: 0,
          width: 190,
          child: IgnorePointer(
            child: Container(
              decoration: const BoxDecoration(
                gradient: LinearGradient(
                  begin: Alignment.centerRight,
                  end: Alignment.centerLeft,
                  colors: [
                    Color(0xF5020105),
                    Color(0xA6020105),
                    Colors.transparent,
                  ],
                  stops: [0.0, 0.5, 1.0],
                ),
              ),
            ),
          ),
        ),

        // Optional Child Content
        if (widget.child != null) widget.child!,
      ],
    );
  }
}

class _StardustParticle {
  final double x;
  final double y;
  final double size;
  final double speed;
  final double baseOpacity;
  final double phase;
  final Color color;

  const _StardustParticle({
    required this.x,
    required this.y,
    required this.size,
    required this.speed,
    required this.baseOpacity,
    required this.phase,
    required this.color,
  });
}

class _StardustPainter extends CustomPainter {
  final double progress;
  final List<_StardustParticle> particles;

  _StardustPainter({
    required this.progress,
    required this.particles,
  });

  @override
  void paint(Canvas canvas, Size size) {
    final paint = Paint()..style = PaintingStyle.fill;

    for (final p in particles) {
      // Gentle upward flow with seamless wrap
      final double currentY = (p.y - progress * p.speed) % 1.0;
      // Gentle horizontal wave oscillation
      final double currentX = (p.x + 0.018 * math.sin(progress * 2 * math.pi + p.phase)) % 1.0;
      // Soft breathing twinkle
      final double opacity = (p.baseOpacity * (0.55 + 0.45 * math.sin(progress * 4 * math.pi + p.phase)))
          .clamp(0.0, 1.0);

      final double px = (currentX < 0 ? currentX + 1.0 : currentX) * size.width;
      final double py = (currentY < 0 ? currentY + 1.0 : currentY) * size.height;

      // Soft glow aura
      paint.color = p.color.withValues(alpha: opacity * 0.4);
      paint.maskFilter = MaskFilter.blur(BlurStyle.normal, p.size * 1.5);
      canvas.drawCircle(Offset(px, py), p.size * 1.6, paint);

      // Sharp luminous core
      paint.maskFilter = null;
      paint.color = p.color.withValues(alpha: opacity);
      canvas.drawCircle(Offset(px, py), p.size * 0.75, paint);
    }
  }

  @override
  bool shouldRepaint(covariant _StardustPainter oldDelegate) {
    return oldDelegate.progress != progress;
  }
}
