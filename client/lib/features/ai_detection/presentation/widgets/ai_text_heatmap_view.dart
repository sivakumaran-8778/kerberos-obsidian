import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

import '../../../../shared/theme/cyber_theme.dart';
import '../../../../shared/widgets/glass_container.dart';
import '../../models/ai_detection_models.dart';

/// Interactive sentence-level heatmap inspector for documents.
class AiTextHeatmapView extends StatefulWidget {
  final List<AiTextSpanSegment> segments;
  final double burstinessVariance;
  final double lexicalDiversityTtr;
  final List<String> detectedBoilerplatePhrases;

  const AiTextHeatmapView({
    super.key,
    required this.segments,
    required this.burstinessVariance,
    required this.lexicalDiversityTtr,
    required this.detectedBoilerplatePhrases,
  });

  @override
  State<AiTextHeatmapView> createState() => _AiTextHeatmapViewState();
}

class _AiTextHeatmapViewState extends State<AiTextHeatmapView> {
  int? _hoveredIndex;
  int? _selectedIndex;

  Color _getSegmentColor(double prob) {
    if (prob >= 0.60) {
      return const Color(0xFFF43F5E); // Coral / Crimson
    } else if (prob >= 0.35) {
      return const Color(0xFFF59E0B); // Amber
    } else {
      return const Color(0xFF10B981); // Emerald
    }
  }

  @override
  Widget build(BuildContext context) {
    final activeSegment = _selectedIndex != null &&
            _selectedIndex! < widget.segments.length
        ? widget.segments[_selectedIndex!]
        : (_hoveredIndex != null && _hoveredIndex! < widget.segments.length
            ? widget.segments[_hoveredIndex!]
            : null);

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // 1. Metric Summary Chips
        Wrap(
          spacing: 12,
          runSpacing: 8,
          children: [
            _buildMetricChip(
              icon: Icons.graphic_eq_rounded,
              label: 'Burstiness (σ)',
              value: widget.burstinessVariance.toStringAsFixed(2),
              color: widget.burstinessVariance < 5.0
                  ? const Color(0xFFF43F5E)
                  : const Color(0xFF10B981),
            ),
            _buildMetricChip(
              icon: Icons.auto_stories_rounded,
              label: 'Lexical TTR',
              value: '${(widget.lexicalDiversityTtr * 100).toStringAsFixed(1)}%',
              color: widget.lexicalDiversityTtr < 0.45
                  ? const Color(0xFFF59E0B)
                  : const Color(0xFF10B981),
            ),
            _buildMetricChip(
              icon: Icons.find_in_page_rounded,
              label: 'LLM Phrase Hits',
              value: '${widget.detectedBoilerplatePhrases.length}',
              color: widget.detectedBoilerplatePhrases.isNotEmpty
                  ? const Color(0xFFF43F5E)
                  : const Color(0xFF10B981),
            ),
          ],
        ),

        const SizedBox(height: 14),

        // 2. Legend
        Row(
          children: [
            _buildLegendItem(const Color(0xFF10B981), 'Human (<35%)'),
            const SizedBox(width: 14),
            _buildLegendItem(const Color(0xFFF59E0B), 'Mixed/Hybrid (35-60%)'),
            const SizedBox(width: 14),
            _buildLegendItem(const Color(0xFFF43F5E), 'AI Generated (>60%)'),
          ],
        ),

        const SizedBox(height: 14),

        // 3. Document Sentence Stream
        GlassContainer(
          borderRadius: 14,
          padding: const EdgeInsets.all(16),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxHeight: 360),
            child: SingleChildScrollView(
              child: Wrap(
                spacing: 6,
                runSpacing: 6,
                children: widget.segments.map((segment) {
                  final idx = segment.sentenceIndex - 1;
                  final isHovered = _hoveredIndex == idx;
                  final isSelected = _selectedIndex == idx;
                  final color = _getSegmentColor(segment.aiProbability);

                  return MouseRegion(
                    onEnter: (_) => setState(() => _hoveredIndex = idx),
                    onExit: (_) => setState(() {
                      if (_hoveredIndex == idx) _hoveredIndex = null;
                    }),
                    child: GestureDetector(
                      onTap: () => setState(() => _selectedIndex = idx),
                      child: AnimatedContainer(
                        duration: const Duration(milliseconds: 160),
                        padding: const EdgeInsets.symmetric(
                          horizontal: 8,
                          vertical: 4,
                        ),
                        decoration: BoxDecoration(
                          color: isSelected
                              ? color.withValues(alpha: 0.35)
                              : isHovered
                                  ? color.withValues(alpha: 0.25)
                                  : color.withValues(alpha: 0.12),
                          borderRadius: BorderRadius.circular(6),
                          border: Border.all(
                            color: isSelected || isHovered
                                ? color
                                : color.withValues(alpha: 0.4),
                            width: isSelected ? 1.5 : 1.0,
                          ),
                        ),
                        child: Text(
                          segment.text,
                          style: GoogleFonts.plusJakartaSans(
                            fontSize: 13,
                            height: 1.4,
                            color: Colors.white.withValues(alpha: 0.95),
                          ),
                        ),
                      ),
                    ),
                  );
                }).toList(),
              ),
            ),
          ),
        ),

        // 4. Hover Inspector Card
        if (activeSegment != null) ...[
          const SizedBox(height: 12),
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color: const Color(0x22120B24),
              borderRadius: BorderRadius.circular(10),
              border: Border.all(
                color: _getSegmentColor(activeSegment.aiProbability)
                    .withValues(alpha: 0.6),
                width: 1.0,
              ),
            ),
            child: Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(8),
                  decoration: BoxDecoration(
                    color: _getSegmentColor(activeSegment.aiProbability)
                        .withValues(alpha: 0.2),
                    shape: BoxShape.circle,
                  ),
                  child: Icon(
                    activeSegment.isFlagged
                        ? Icons.warning_amber_rounded
                        : Icons.check_circle_outline_rounded,
                    color: _getSegmentColor(activeSegment.aiProbability),
                    size: 18,
                  ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Text(
                            'SENTENCE #${activeSegment.sentenceIndex}',
                            style: GoogleFonts.spaceGrotesk(
                              fontSize: 11,
                              fontWeight: FontWeight.w800,
                              color: _getSegmentColor(activeSegment.aiProbability),
                              letterSpacing: 0.6,
                            ),
                          ),
                          const Spacer(),
                          Text(
                            'AI Likelihood: ${(activeSegment.aiProbability * 100).toStringAsFixed(1)}%',
                            style: GoogleFonts.spaceGrotesk(
                              fontSize: 11,
                              fontWeight: FontWeight.w700,
                              color: Colors.white,
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 3),
                      Text(
                        activeSegment.reason,
                        style: GoogleFonts.plusJakartaSans(
                          fontSize: 12,
                          color: CyberTheme.textMuted,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ],
      ],
    );
  }

  Widget _buildMetricChip({
    required IconData icon,
    required String label,
    required String value,
    required Color color,
  }) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
      decoration: BoxDecoration(
        color: const Color(0x18FFFFFF),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: const Color(0x22FFFFFF), width: 1.0),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 14, color: color),
          const SizedBox(width: 6),
          Text(
            '$label: ',
            style: GoogleFonts.plusJakartaSans(
              fontSize: 11,
              fontWeight: FontWeight.w600,
              color: CyberTheme.textMuted,
            ),
          ),
          Text(
            value,
            style: GoogleFonts.spaceGrotesk(
              fontSize: 11,
              fontWeight: FontWeight.w800,
              color: color,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildLegendItem(Color color, String label) {
    return Row(
      mainAxisSize: MainAxisSize.min,
      children: [
        Container(
          width: 10,
          height: 10,
          decoration: BoxDecoration(
            color: color,
            shape: BoxShape.circle,
          ),
        ),
        const SizedBox(width: 6),
        Text(
          label,
          style: GoogleFonts.plusJakartaSans(
            fontSize: 11,
            fontWeight: FontWeight.w600,
            color: CyberTheme.textMuted,
          ),
        ),
      ],
    );
  }
}
