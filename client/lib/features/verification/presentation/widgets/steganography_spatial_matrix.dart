import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:google_fonts/google_fonts.dart';
import '../../../../shared/theme/cyber_theme.dart';
import '../../models/verification_models.dart';
import '../../providers/steganography_providers.dart';

/// Hardware-accelerated CustomPainter rendering the 16x16 ELA spatial residual matrix.
/// Dynamically maps error percentage values (0.0 to 1.0) to cool dark blues for normal noise,
/// and high-contrast neon red/orange for values exceeding the threshold (> 55.0%).
class SteganographyHeatMapRenderer extends CustomPainter {
  /// 256 normalized float values (0.0 to 1.0) corresponding to each matrix cell
  final List<double> matrix;

  /// Anomaly threshold percentage (e.g. 0.55 for 55.0%)
  final double threshold;

  /// Currently focused or hovered cell index (0 to 255)
  final int? activeCellIndex;

  /// Indices of cells classified as altered / spliced
  final List<int> alteredCellIndices;

  /// Indices of cells classified as overlapped layers
  final List<int> overlappedCellIndices;

  /// Indices of cells classified as hidden content
  final List<int> hiddenCellIndices;

  /// Layer filter mode: 0 = all, 1 = alterations, 2 = overlapped, 3 = hidden
  final int layerFilter;

  SteganographyHeatMapRenderer({
    required this.matrix,
    this.threshold = 0.55,
    this.activeCellIndex,
    this.alteredCellIndices = const [],
    this.overlappedCellIndices = const [],
    this.hiddenCellIndices = const [],
    this.layerFilter = 0,
  });

  /// Factory constructor to support 2D array input [16][16]
  factory SteganographyHeatMapRenderer.from2D({
    required List<List<double>> grid2D,
    double threshold = 0.55,
    int? activeCellIndex,
    List<int> alteredCellIndices = const [],
    List<int> overlappedCellIndices = const [],
    List<int> hiddenCellIndices = const [],
    int layerFilter = 0,
  }) {
    final flatList = <double>[];
    for (int r = 0; r < 16; r++) {
      for (int c = 0; c < 16; c++) {
        if (r < grid2D.length && c < grid2D[r].length) {
          flatList.add(grid2D[r][c]);
        } else {
          flatList.add(0.151);
        }
      }
    }
    return SteganographyHeatMapRenderer(
      matrix: flatList,
      threshold: threshold,
      activeCellIndex: activeCellIndex,
      alteredCellIndices: alteredCellIndices,
      overlappedCellIndices: overlappedCellIndices,
      hiddenCellIndices: hiddenCellIndices,
      layerFilter: layerFilter,
    );
  }

  @override
  void paint(Canvas canvas, Size size) {
    if (matrix.isEmpty) return;

    const int gridSize = 16;
    final cellWidth = size.width / gridSize;
    final cellHeight = size.height / gridSize;
    const double gap = 2.5;

    final cellPaint = Paint()..style = PaintingStyle.fill;
    final borderPaint = Paint()
      ..style = PaintingStyle.stroke
      ..strokeWidth = 1.0;

    for (int i = 0; i < 256; i++) {
      if (i >= matrix.length) break;

      final row = i ~/ gridSize;
      final col = i % gridSize;
      final x = col * cellWidth;
      final y = row * cellHeight;

      final rect = RRect.fromRectAndRadius(
        Rect.fromLTWH(
          x + gap / 2,
          y + gap / 2,
          cellWidth - gap,
          cellHeight - gap,
        ),
        const Radius.circular(3.0),
      );

      final val = matrix[i].clamp(0.0, 1.0);
      final isOverThreshold = val >= threshold;
      final isAltered = alteredCellIndices.contains(i);
      final isOverlapped = overlappedCellIndices.contains(i);
      final isHidden = hiddenCellIndices.contains(i);
      final isActive = activeCellIndex == i;

      // Layer filtering
      bool isDimmed = false;
      if (layerFilter == 1 && !isAltered) isDimmed = true;
      if (layerFilter == 2 && !isOverlapped) isDimmed = true;
      if (layerFilter == 3 && !isHidden) isDimmed = true;

      // Dynamic Color Mapping
      Color cellColor;
      if (isOverThreshold || isAltered) {
        // High-contrast neon red/orange for values exceeding threshold (> 55.0%)
        final t = ((val - threshold) / (1.0 - threshold)).clamp(0.0, 1.0);
        cellColor = Color.lerp(
          const Color(0xFFFF4757), // Neon orange-red
          const Color(0xFFFF0055), // Vivid neon crimson
          t,
        )!;
      } else {
        // Cool dark blues for baseline error values (< 55.0%)
        if (val < 0.20) {
          final t = (val / 0.20).clamp(0.0, 1.0);
          cellColor = Color.lerp(
            const Color(0xFF07162C), // Deep midnight blue
            const Color(0xFF0B2545), // Cool dark navy
            t,
          )!;
        } else if (val < 0.38) {
          final t = ((val - 0.20) / 0.18).clamp(0.0, 1.0);
          cellColor = Color.lerp(
            const Color(0xFF0B2545),
            const Color(0xFF0284C7), // Cool cyber blue
            t,
          )!;
        } else {
          final t = ((val - 0.38) / (threshold - 0.38)).clamp(0.0, 1.0);
          cellColor = Color.lerp(
            const Color(0xFF0284C7),
            const Color(0xFF0EA5E9), // Elevated cyan
            t,
          )!;
        }
      }

      if (isDimmed) {
        cellColor = cellColor.withValues(alpha: 0.18);
      }

      cellPaint.color = cellColor;
      canvas.drawRRect(rect, cellPaint);

      // Active / Focused Cell Selection Highlight
      if (isActive) {
        final activeBorder = Paint()
          ..color = Colors.white
          ..style = PaintingStyle.stroke
          ..strokeWidth = 2.0;
        canvas.drawRRect(rect, activeBorder);
      } else if (!isDimmed) {
        if (isOverThreshold || isAltered) {
          borderPaint.color = const Color(0xFFFF0055).withValues(alpha: 0.85);
          canvas.drawRRect(rect, borderPaint);
        } else if (isOverlapped) {
          borderPaint.color = const Color(0xFFF59E0B).withValues(alpha: 0.8);
          canvas.drawRRect(rect, borderPaint);
        } else if (isHidden) {
          borderPaint.color = const Color(0xFFC084FC).withValues(alpha: 0.8);
          canvas.drawRRect(rect, borderPaint);
        }
      }
    }

    // Scanline grid overlay simulating hardware-accelerated fragment shader
    final gridLinePaint = Paint()
      ..color = const Color(0x0EFFFFFF)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 0.8;

    for (int r = 0; r <= gridSize; r++) {
      canvas.drawLine(Offset(0, r * cellHeight), Offset(size.width, r * cellHeight), gridLinePaint);
      canvas.drawLine(Offset(r * cellWidth, 0), Offset(r * cellWidth, size.height), gridLinePaint);
    }
  }

  @override
  bool shouldRepaint(covariant SteganographyHeatMapRenderer oldDelegate) {
    return oldDelegate.matrix != matrix ||
        oldDelegate.activeCellIndex != activeCellIndex ||
        oldDelegate.threshold != threshold ||
        oldDelegate.layerFilter != layerFilter;
  }
}

/// Interactive 16x16 Steganography & ELA Matrix Widget backed by CustomPaint
class SteganographySpatialMatrixWidget extends ConsumerStatefulWidget {
  final List<double> matrix;
  final double threshold;
  final int? activeCellIndex;
  final ValueChanged<int?> onCellHovered;
  final ValueChanged<int>? onCellTapped;
  final List<int> alteredCellIndices;
  final List<int> overlappedCellIndices;
  final List<int> hiddenCellIndices;
  final int layerFilter;
  final double size;

  const SteganographySpatialMatrixWidget({
    super.key,
    required this.matrix,
    this.threshold = 0.55,
    this.activeCellIndex,
    required this.onCellHovered,
    this.onCellTapped,
    this.alteredCellIndices = const [],
    this.overlappedCellIndices = const [],
    this.hiddenCellIndices = const [],
    this.layerFilter = 0,
    this.size = 330,
  });

  @override
  ConsumerState<SteganographySpatialMatrixWidget> createState() => _SteganographySpatialMatrixWidgetState();
}

class _SteganographySpatialMatrixWidgetState extends ConsumerState<SteganographySpatialMatrixWidget> {
  int? _localHoveredIndex;

  void _handlePointer(Offset localPosition, Size canvasSize) {
    if (canvasSize.width <= 0 || canvasSize.height <= 0) return;
    final col = (localPosition.dx / (canvasSize.width / 16)).floor().clamp(0, 15);
    final row = (localPosition.dy / (canvasSize.height / 16)).floor().clamp(0, 15);
    final index = row * 16 + col;

    if (_localHoveredIndex != index) {
      setState(() => _localHoveredIndex = index);
      widget.onCellHovered(index);
    }
  }

  @override
  Widget build(BuildContext context) {
    final effectiveActiveIndex = widget.activeCellIndex ?? _localHoveredIndex;

    return Container(
      width: widget.size,
      height: widget.size,
      padding: const EdgeInsets.all(10),
      decoration: BoxDecoration(
        color: const Color(0xFF070D18),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: const Color(0x3338BDF8)),
        boxShadow: const [
          BoxShadow(
            color: Color(0x40000000),
            blurRadius: 16,
            offset: Offset(0, 4),
          ),
        ],
      ),
      child: LayoutBuilder(
        builder: (context, constraints) {
          final canvasSize = Size(constraints.maxWidth, constraints.maxHeight);

          return MouseRegion(
            onHover: (event) => _handlePointer(event.localPosition, canvasSize),
            onExit: (_) {
              setState(() => _localHoveredIndex = null);
              widget.onCellHovered(null);
            },
            child: GestureDetector(
              onTapUp: (details) {
                _handlePointer(details.localPosition, canvasSize);
                final col = (details.localPosition.dx / (canvasSize.width / 16)).floor().clamp(0, 15);
                final row = (details.localPosition.dy / (canvasSize.height / 16)).floor().clamp(0, 15);
                final index = row * 16 + col;
                widget.onCellTapped?.call(index);
              },
              child: CustomPaint(
                size: canvasSize,
                painter: SteganographyHeatMapRenderer(
                  matrix: widget.matrix,
                  threshold: widget.threshold,
                  activeCellIndex: effectiveActiveIndex,
                  alteredCellIndices: widget.alteredCellIndices,
                  overlappedCellIndices: widget.overlappedCellIndices,
                  hiddenCellIndices: widget.hiddenCellIndices,
                  layerFilter: widget.layerFilter,
                ),
              ),
            ),
          );
        },
      ),
    );
  }
}

/// The "Spatial Residual Inspector" panel synchronized dynamically with grid hover and clicks
class SpatialResidualInspectorPanel extends ConsumerWidget {
  final ProvenanceResult result;
  final int? activeCellIndex;

  const SpatialResidualInspectorPanel({
    super.key,
    required this.result,
    this.activeCellIndex,
  });

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final activeIdx = activeCellIndex ?? ref.watch(activeSpatialCellProvider);
    final activeVal = activeIdx != null && activeIdx < result.anomalyMatrix.length
        ? result.anomalyMatrix[activeIdx]
        : null;

    final isCellActive = activeIdx != null;
    final row = isCellActive ? (activeIdx ~/ 16) : null;
    final col = isCellActive ? (activeIdx % 16) : null;
    final cellXPercent = col != null ? (col * 6.25).toInt() : null;
    final cellYPercent = row != null ? (row * 6.25).toInt() : null;

    final isAltered = activeIdx != null && result.alteredCellIndices.contains(activeIdx);
    final isOverlapped = activeIdx != null && result.overlappedCellIndices.contains(activeIdx);
    final isHidden = activeIdx != null && result.hiddenCellIndices.contains(activeIdx);
    final isOverThreshold = activeVal != null && activeVal >= result.anomalyThreshold;

    String cellStatus;
    Color cellStatusColor;
    if (isAltered || isOverThreshold) {
      cellStatus = 'ALTERATION DETECTED (+${((activeVal ?? 0.95) * 100 - 15).toInt()}% Peak)';
      cellStatusColor = const Color(0xFFF43F5E);
    } else if (isOverlapped) {
      cellStatus = 'OVERLAPPED CONTENT (Whiteout / Annotation)';
      cellStatusColor = const Color(0xFFF59E0B);
    } else if (isHidden) {
      cellStatus = 'HIDDEN CONTENT (Stego / Invisible Mode)';
      cellStatusColor = const Color(0xFFC084FC);
    } else {
      cellStatus = 'AMBIENT BACKGROUND (Sensor Baseline)';
      cellStatusColor = const Color(0xFF38BDF8);
    }

    final displayPeakRate = isCellActive && activeVal != null
        ? '${(activeVal * 100).toStringAsFixed(1)}%'
        : '${(result.peakErrorRate * 100).toStringAsFixed(1)}%';

    final isDisplayAlert = isCellActive
        ? (activeVal != null && activeVal >= result.anomalyThreshold)
        : result.isTampered;

    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color: const Color(0xFF0C1322),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: const Color(0x2838BDF8)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header Row
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                'SPATIAL RESIDUAL INSPECTOR',
                style: GoogleFonts.jetBrainsMono(
                  fontSize: 11,
                  fontWeight: FontWeight.w800,
                  letterSpacing: 1.0,
                  color: const Color(0xFF38BDF8),
                ),
              ),
              Text(
                isCellActive ? 'CELL [R$row, C$col]' : 'PEAK RESIDUAL',
                style: GoogleFonts.jetBrainsMono(
                  fontSize: 10,
                  fontWeight: FontWeight.w700,
                  color: isDisplayAlert ? const Color(0xFFF43F5E) : CyberTheme.textMuted,
                  letterSpacing: 0.8,
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),

          // 3 Metric Cards
          Row(
            children: [
              _buildMiniMetric(
                label: isCellActive ? 'CELL ERROR RATE' : 'PEAK ERROR RATE',
                value: displayPeakRate,
                isAlert: isDisplayAlert,
              ),
              const SizedBox(width: 8),
              _buildMiniMetric(
                label: 'BACKGROUND BASELINE',
                value: '${(result.baselineErrorRate * 100).toStringAsFixed(1)}%',
                isAlert: false,
              ),
              const SizedBox(width: 8),
              _buildMiniMetric(
                label: 'ANOMALY THRESHOLD',
                value: '> ${(result.anomalyThreshold * 100).toStringAsFixed(1)}%',
                isAlert: false,
              ),
            ],
          ),
          const SizedBox(height: 14),

          // Focused / Peak Coordinates Box
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
            decoration: BoxDecoration(
              color: const Color(0x12FFFFFF),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(
                color: isCellActive ? cellStatusColor.withValues(alpha: 0.4) : const Color(0x1AFFFFFF),
              ),
            ),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(
                  Icons.location_searching_rounded,
                  size: 16,
                  color: isCellActive ? cellStatusColor : const Color(0xFF38BDF8),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        isCellActive ? 'Focused Cell Coordinates & Type:' : 'Detected Peak Coordinates:',
                        style: GoogleFonts.plusJakartaSans(
                          fontSize: 10,
                          fontWeight: FontWeight.w700,
                          color: CyberTheme.textMuted,
                        ),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        isCellActive
                            ? 'Cell [Row $row, Col $col] [X: $cellXPercent%..${cellXPercent! + 6}%, Y: $cellYPercent%..${cellYPercent! + 6}%] • $cellStatus'
                            : result.detectedPeakCoordinates,
                        style: GoogleFonts.jetBrainsMono(
                          fontSize: 11,
                          fontWeight: FontWeight.w700,
                          color: isCellActive ? cellStatusColor : Colors.white,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 16),

          // Color Gradient Bar (0% Clean -> 100% Tampered)
          Row(
            children: [
              Text(
                '0% Clean',
                style: GoogleFonts.jetBrainsMono(fontSize: 10, color: const Color(0xFF38BDF8)),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Stack(
                  alignment: Alignment.centerLeft,
                  children: [
                    Container(
                      height: 7,
                      decoration: BoxDecoration(
                        borderRadius: BorderRadius.circular(4),
                        gradient: const LinearGradient(
                          colors: [
                            Color(0xFF0B2545),
                            Color(0xFF0284C7),
                            Color(0xFF10B981),
                            Color(0xFFF59E0B),
                            Color(0xFFFF0055),
                          ],
                        ),
                      ),
                    ),
                    if (isCellActive && activeVal != null)
                      Positioned(
                        left: (activeVal.clamp(0.0, 1.0) * 160).clamp(0.0, 180),
                        child: Container(
                          width: 8,
                          height: 13,
                          decoration: BoxDecoration(
                            color: Colors.white,
                            borderRadius: BorderRadius.circular(2),
                            boxShadow: const [
                              BoxShadow(color: Colors.black, blurRadius: 4),
                            ],
                          ),
                        ),
                      ),
                  ],
                ),
              ),
              const SizedBox(width: 8),
              Text(
                '100% Tampered',
                style: GoogleFonts.jetBrainsMono(fontSize: 10, color: const Color(0xFFFF0055)),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildMiniMetric({
    required String label,
    required String value,
    required bool isAlert,
  }) {
    final color = isAlert ? const Color(0xFFF43F5E) : const Color(0xFF10B981);
    return Expanded(
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
        decoration: BoxDecoration(
          color: const Color(0x0AFFFFFF),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: const Color(0x18FFFFFF)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              label,
              style: GoogleFonts.jetBrainsMono(
                fontSize: 8.5,
                fontWeight: FontWeight.w700,
                color: CyberTheme.textMuted,
                letterSpacing: 0.5,
              ),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
            const SizedBox(height: 3),
            Text(
              value,
              style: GoogleFonts.jetBrainsMono(
                fontSize: 13,
                fontWeight: FontWeight.w800,
                color: color,
              ),
              maxLines: 1,
              overflow: TextOverflow.ellipsis,
            ),
          ],
        ),
      ),
    );
  }
}
