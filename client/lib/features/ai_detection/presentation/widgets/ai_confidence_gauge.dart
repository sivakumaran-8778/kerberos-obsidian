import 'dart:math' as math;
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

import '../../../../shared/theme/cyber_theme.dart';
import '../../models/ai_detection_models.dart';

/// Flagship circular animated confidence gauge for AI content probability.
class AiConfidenceGauge extends StatefulWidget {
  final double probability; // 0.0 to 100.0%
  final AiDetectionVerdict verdict;
  final AiRiskLevel riskLevel;
  final double size;

  const AiConfidenceGauge({
    super.key,
    required this.probability,
    required this.verdict,
    required this.riskLevel,
    this.size = 240,
  });

  @override
  State<AiConfidenceGauge> createState() => _AiConfidenceGaugeState();
}

class _AiConfidenceGaugeState extends State<AiConfidenceGauge>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double> _animation;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1400),
    );
    _animation = Tween<double>(begin: 0.0, end: widget.probability).animate(
      CurvedAnimation(parent: _controller, curve: Curves.easeOutCubic),
    );
    _controller.forward();
  }

  @override
  void didUpdateWidget(AiConfidenceGauge oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.probability != widget.probability) {
      _animation = Tween<double>(
        begin: oldWidget.probability,
        end: widget.probability,
      ).animate(
        CurvedAnimation(parent: _controller, curve: Curves.easeOutCubic),
      );
      _controller
        ..reset()
        ..forward();
    }
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  Color _getColorForProbability(double prob) {
    if (prob >= 65.0) {
      return const Color(0xFFF43F5E); // Coral / Crimson for high synthetic
    } else if (prob >= 35.0) {
      return const Color(0xFFF59E0B); // Amber for hybrid / uncertain
    } else {
      return const Color(0xFF10B981); // Emerald for authentic human
    }
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: _animation,
      builder: (context, child) {
        final currentVal = _animation.value;
        final color = _getColorForProbability(currentVal);

        return SizedBox(
          width: widget.size,
          height: widget.size,
          child: Stack(
            alignment: Alignment.center,
            children: [
              // Custom arc painter
              CustomPaint(
                size: Size(widget.size, widget.size),
                painter: _GaugeArcPainter(
                  value: currentVal / 100.0,
                  activeColor: color,
                ),
              ),

              // Central text display
              Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Row(
                    mainAxisSize: MainAxisSize.min,
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        currentVal.toStringAsFixed(1),
                        style: GoogleFonts.spaceGrotesk(
                          fontSize: widget.size * 0.19,
                          fontWeight: FontWeight.w900,
                          color: Colors.white,
                          letterSpacing: -1.0,
                          shadows: [
                            Shadow(
                              color: color.withValues(alpha: 0.6),
                              blurRadius: 16,
                            ),
                          ],
                        ),
                      ),
                      Text(
                        '%',
                        style: GoogleFonts.spaceGrotesk(
                          fontSize: widget.size * 0.08,
                          fontWeight: FontWeight.w700,
                          color: color,
                        ),
                      ),
                    ],
                  ),
                  const SizedBox(height: 2),
                  Text(
                    'SYNTHETIC PROBABILITY',
                    style: GoogleFonts.plusJakartaSans(
                      fontSize: widget.size * 0.044,
                      fontWeight: FontWeight.w800,
                      letterSpacing: 1.2,
                      color: CyberTheme.textMuted,
                    ),
                  ),
                  const SizedBox(height: 8),
                  // Risk pill
                  Container(
                    padding: const EdgeInsets.symmetric(
                      horizontal: 10,
                      vertical: 4,
                    ),
                    decoration: BoxDecoration(
                      color: color.withValues(alpha: 0.15),
                      borderRadius: BorderRadius.circular(100),
                      border: Border.all(
                        color: color.withValues(alpha: 0.5),
                        width: 1.0,
                      ),
                    ),
                    child: Text(
                      widget.riskLevel.name.toUpperCase(),
                      style: GoogleFonts.spaceGrotesk(
                        fontSize: 10,
                        fontWeight: FontWeight.w800,
                        color: color,
                        letterSpacing: 0.8,
                      ),
                    ),
                  ),
                ],
              ),
            ],
          ),
        );
      },
    );
  }
}

class _GaugeArcPainter extends CustomPainter {
  final double value; // 0.0 to 1.0
  final Color activeColor;

  _GaugeArcPainter({
    required this.value,
    required this.activeColor,
  });

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    final radius = (size.width - 28) / 2;
    const startAngle = 0.75 * math.pi; // 135 deg
    const sweepAngle = 1.5 * math.pi; // 270 deg

    // Background track arc
    final trackPaint = Paint()
      ..color = const Color(0x22FFFFFF)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 10.0
      ..strokeCap = StrokeCap.round;

    canvas.drawArc(
      Rect.fromCircle(center: center, radius: radius),
      startAngle,
      sweepAngle,
      false,
      trackPaint,
    );

    // Active progress arc
    final activePaint = Paint()
      ..color = activeColor
      ..style = PaintingStyle.stroke
      ..strokeWidth = 10.0
      ..strokeCap = StrokeCap.round;

    final glowPaint = Paint()
      ..color = activeColor.withValues(alpha: 0.4)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 18.0
      ..strokeCap = StrokeCap.round
      ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 8);

    final currentSweep = sweepAngle * value.clamp(0.0, 1.0);

    // Draw glow first
    canvas.drawArc(
      Rect.fromCircle(center: center, radius: radius),
      startAngle,
      currentSweep,
      false,
      glowPaint,
    );

    // Draw sharp active line
    canvas.drawArc(
      Rect.fromCircle(center: center, radius: radius),
      startAngle,
      currentSweep,
      false,
      activePaint,
    );

    // Draw pointer tick at current progress end
    final pointerAngle = startAngle + currentSweep;
    final px = center.dx + radius * math.cos(pointerAngle);
    final py = center.dy + radius * math.sin(pointerAngle);

    final pointPaint = Paint()
      ..color = Colors.white
      ..style = PaintingStyle.fill;

    canvas.drawCircle(Offset(px, py), 6.0, pointPaint);
    canvas.drawCircle(
      Offset(px, py),
      9.0,
      Paint()
        ..color = activeColor.withValues(alpha: 0.8)
        ..style = PaintingStyle.stroke
        ..strokeWidth = 2.0,
    );
  }

  @override
  bool shouldRepaint(covariant _GaugeArcPainter oldDelegate) {
    return oldDelegate.value != value || oldDelegate.activeColor != activeColor;
  }
}
