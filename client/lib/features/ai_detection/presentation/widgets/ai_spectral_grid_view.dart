import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

import '../../../../shared/theme/cyber_theme.dart';
import '../../../../shared/widgets/glass_container.dart';

/// 16x16 interactive 2D Fast Fourier Transform / Spectral Deconvolution Grid.
class AiSpectralGridView extends StatefulWidget {
  final List<double> spectralGrid; // 256 normalized values
  final double highFrequencyAnomalyScore;
  final Map<String, String> extractedMetadata;
  final bool hasC2pa;

  const AiSpectralGridView({
    super.key,
    required this.spectralGrid,
    required this.highFrequencyAnomalyScore,
    required this.extractedMetadata,
    required this.hasC2pa,
  });

  @override
  State<AiSpectralGridView> createState() => _AiSpectralGridViewState();
}

class _AiSpectralGridViewState extends State<AiSpectralGridView> {
  int? _hoveredIndex;

  Color _getCellColor(double value) {
    if (value > 0.70) {
      return const Color(0xFFF43F5E); // Crimson peak
    } else if (value > 0.45) {
      return const Color(0xFFF59E0B); // Amber
    } else if (value > 0.25) {
      return const Color(0xFF38BDF8); // Cyan
    } else {
      return const Color(0xFF312E81); // Deep Indigo
    }
  }

  @override
  Widget build(BuildContext context) {
    final values = widget.spectralGrid.length == 256
        ? widget.spectralGrid
        : List<double>.filled(256, 0.1);

    final hoveredVal = _hoveredIndex != null && _hoveredIndex! < values.length
        ? values[_hoveredIndex!]
        : null;

    final hoveredX = _hoveredIndex != null ? _hoveredIndex! % 16 : 0;
    final hoveredY = _hoveredIndex != null ? _hoveredIndex! ~/ 16 : 0;

    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // Top summary
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Row(
              children: [
                const Icon(Icons.blur_linear_rounded,
                    color: Color(0xFF38BDF8), size: 18),
                const SizedBox(width: 8),
                Text(
                  '2D SPECTRAL FOURIER DECONVOLUTION GRID (16x16)',
                  style: GoogleFonts.spaceGrotesk(
                    fontSize: 12,
                    fontWeight: FontWeight.w800,
                    letterSpacing: 0.6,
                    color: Colors.white,
                  ),
                ),
              ],
            ),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              decoration: BoxDecoration(
                color: widget.highFrequencyAnomalyScore > 0.60
                    ? const Color(0x33F43F5E)
                    : const Color(0x3310B981),
                borderRadius: BorderRadius.circular(6),
                border: Border.all(
                  color: widget.highFrequencyAnomalyScore > 0.60
                      ? const Color(0xFFF43F5E)
                      : const Color(0xFF10B981),
                  width: 1.0,
                ),
              ),
              child: Text(
                'HARMONIC FALLOFF: ${(widget.highFrequencyAnomalyScore * 100).toStringAsFixed(1)}%',
                style: GoogleFonts.spaceGrotesk(
                  fontSize: 10,
                  fontWeight: FontWeight.w800,
                  color: widget.highFrequencyAnomalyScore > 0.60
                      ? const Color(0xFFF43F5E)
                      : const Color(0xFF10B981),
                ),
              ),
            ),
          ],
        ),

        const SizedBox(height: 12),

        // Grid & Metadata Inspector
        Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Left: The 16x16 interactive matrix
            SizedBox(
              width: 256,
              height: 256,
              child: Container(
                padding: const EdgeInsets.all(4),
                decoration: BoxDecoration(
                  color: const Color(0x18000000),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: const Color(0x33FFFFFF)),
                ),
                child: GridView.builder(
                  physics: const NeverScrollableScrollPhysics(),
                  itemCount: 256,
                  gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
                    crossAxisCount: 16,
                    crossAxisSpacing: 2,
                    mainAxisSpacing: 2,
                  ),
                  itemBuilder: (context, idx) {
                    final val = values[idx];
                    final isHovered = _hoveredIndex == idx;
                    final cellColor = _getCellColor(val);

                    return MouseRegion(
                      onEnter: (_) => setState(() => _hoveredIndex = idx),
                      onExit: (_) => setState(() {
                        if (_hoveredIndex == idx) _hoveredIndex = null;
                      }),
                      child: AnimatedContainer(
                        duration: const Duration(milliseconds: 100),
                        decoration: BoxDecoration(
                          color: cellColor,
                          borderRadius: BorderRadius.circular(2),
                          border: isHovered
                              ? Border.all(color: Colors.white, width: 1.5)
                              : null,
                          boxShadow: isHovered
                              ? [
                                  BoxShadow(
                                    color: cellColor.withValues(alpha: 0.8),
                                    blurRadius: 6,
                                  )
                                ]
                              : null,
                        ),
                      ),
                    );
                  },
                ),
              ),
            ),

            const SizedBox(width: 16),

            // Right: Inspector Telemetry
            Expanded(
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  GlassContainer(
                    borderRadius: 10,
                    padding: const EdgeInsets.all(12),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'HARMONIC CELL INSPECTOR',
                          style: GoogleFonts.spaceGrotesk(
                            fontSize: 10,
                            fontWeight: FontWeight.w800,
                            letterSpacing: 0.6,
                            color: CyberTheme.textMuted,
                          ),
                        ),
                        const SizedBox(height: 6),
                        if (_hoveredIndex != null && hoveredVal != null) ...[
                          Row(
                            children: [
                              Text(
                                'Coordinate [X: $hoveredX, Y: $hoveredY]',
                                style: GoogleFonts.spaceGrotesk(
                                  fontSize: 12,
                                  fontWeight: FontWeight.w700,
                                  color: Colors.white,
                                ),
                              ),
                              const Spacer(),
                              Text(
                                'Power: ${(hoveredVal * 100).toStringAsFixed(1)}%',
                                style: GoogleFonts.spaceGrotesk(
                                  fontSize: 12,
                                  fontWeight: FontWeight.w800,
                                  color: _getCellColor(hoveredVal),
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 4),
                          Text(
                            hoveredVal > 0.65
                                ? 'Anomalous diffusion deconvolution harmonic spike.'
                                : 'Consistent sensor gradient response.',
                            style: GoogleFonts.plusJakartaSans(
                              fontSize: 11,
                              color: CyberTheme.textMuted,
                            ),
                          ),
                        ] else ...[
                          Text(
                            'Hover over any frequency block in the 16x16 Fourier matrix to inspect localized spectral energy density.',
                            style: GoogleFonts.plusJakartaSans(
                              fontSize: 11,
                              color: CyberTheme.textMuted,
                            ),
                          ),
                        ],
                      ],
                    ),
                  ),

                  const SizedBox(height: 10),

                  // Metadata summary
                  GlassContainer(
                    borderRadius: 10,
                    padding: const EdgeInsets.all(12),
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'PROVENANCE & GENERATOR METADATA',
                          style: GoogleFonts.spaceGrotesk(
                            fontSize: 10,
                            fontWeight: FontWeight.w800,
                            letterSpacing: 0.6,
                            color: CyberTheme.textMuted,
                          ),
                        ),
                        const SizedBox(height: 6),
                        if (widget.hasC2pa)
                          _buildMetaRow(
                            'C2PA Manifest',
                            'Cryptographic SynthID / CAI Watermark Present',
                            const Color(0xFFF43F5E),
                          ),
                        if (widget.extractedMetadata.isNotEmpty) ...[
                          ...widget.extractedMetadata.entries.map((e) =>
                              _buildMetaRow(e.key, e.value, const Color(0xFFF59E0B))),
                        ] else if (!widget.hasC2pa) ...[
                          Text(
                            'No generation prompts or C2PA synthetic markers found in header chunks.',
                            style: GoogleFonts.plusJakartaSans(
                              fontSize: 11,
                              color: CyberTheme.textMuted,
                            ),
                          ),
                        ],
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildMetaRow(String label, String val, Color color) {
    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 2.0),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            '$label: ',
            style: GoogleFonts.spaceGrotesk(
              fontSize: 11,
              fontWeight: FontWeight.w700,
              color: color,
            ),
          ),
          Expanded(
            child: Text(
              val,
              style: GoogleFonts.plusJakartaSans(
                fontSize: 11,
                color: Colors.white.withValues(alpha: 0.9),
              ),
              overflow: TextOverflow.ellipsis,
              maxLines: 2,
            ),
          ),
        ],
      ),
    );
  }
}
