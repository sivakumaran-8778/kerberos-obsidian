import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import '../../provenance/presentation/upload_screen.dart';
import '../../network/presentation/transfer_screen.dart';
import '../../../shared/widgets/neomorphic_container.dart';
import '../../../shared/widgets/neomorphic_button.dart';
import '../../provenance/providers/provenance_providers.dart';

class DashboardScreen extends ConsumerWidget {
  const DashboardScreen({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    // Watch the active ingestion state to grab the perceptual hash if available
    final provenanceState = ref.watch(provenanceTaskNotifierProvider);

    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(32.0),
          child: Row(
            children: [
              // Premium Light Neomorphic Sidebar
              SizedBox(
                width: 280,
                child: NeomorphicContainer(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text('KERBEROS', style: Theme.of(context).textTheme.headlineSmall),
                      const SizedBox(height: 8),
                      Text('ZERO-TRUST LEDGER', style: Theme.of(context).textTheme.bodyMedium),
                      const Padding(
                        padding: EdgeInsets.symmetric(vertical: 24.0),
                        child: Divider(color: Colors.black12, thickness: 1.5),
                      ),
                      NeomorphicButton(
                        isExpanded: true,
                        onTap: () {
                          Navigator.push(context, MaterialPageRoute(builder: (_) => const UploadScreen()));
                        },
                        child: const Text('> INGEST & SEAL', style: TextStyle(color: kAccentColor, fontWeight: FontWeight.bold)),
                      ),
                      const SizedBox(height: 24),
                      NeomorphicButton(
                        isExpanded: true,
                        onTap: () {
                          Navigator.push(context, MaterialPageRoute(builder: (_) => const TransferScreen()));
                        },
                        child: const Text('> SECURE TRANSFER', style: TextStyle(color: kTextColor)),
                      ),
                    ],
                  ),
                ),
              ),
              
              const SizedBox(width: 32),
              
              // Main Content Area (Hardware Accelerated CustomPaint Heat-map)
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text('ASSET STEGANOGRAPHY HEAT-MAP', style: Theme.of(context).textTheme.bodyLarge),
                    const SizedBox(height: 24),
                    Expanded(
                      child: NeomorphicContainer(
                        depressed: true,
                        width: double.infinity,
                        padding: EdgeInsets.zero,
                        // If no hash is available, show standby text; otherwise paint the heat-map
                        child: provenanceState.maybeWhen(
                          data: (metadata) => metadata != null && metadata.perceptualHash != null
                              ? CustomPaint(
                                  painter: SteganographyHeatMapRenderer(metadata.perceptualHash!),
                                )
                              : const Center(child: Text('> STANDBY: NO ASSET VECTOR LOADED', style: TextStyle(color: Colors.black26))),
                          orElse: () => const Center(child: Text('> STANDBY: NO ASSET VECTOR LOADED', style: TextStyle(color: Colors.black26))),
                        ),
                      ),
                    ),
                  ],
                ),
              )
            ],
          ),
        ),
      ),
    );
  }
}

/// A highly-optimized CustomPaint widget simulating a hardware-accelerated WebGL fragment shader
/// which draws a forensic heat-map representing the perceptual hash vector of an image.
class SteganographyHeatMapRenderer extends CustomPainter {
  final List<double> vector;

  SteganographyHeatMapRenderer(this.vector);

  @override
  void paint(Canvas canvas, Size size) {
    if (vector.isEmpty) return;
    
    final paint = Paint()..style = PaintingStyle.fill;
    
    // We break the canvas into a 16x16 grid (256 dimensions)
    const int gridSize = 16;
    final cellWidth = size.width / gridSize;
    final cellHeight = size.height / gridSize;

    for (int i = 0; i < 256; i++) {
      if (i >= vector.length) break;
      
      final row = i ~/ gridSize;
      final col = i % gridSize;
      
      final rect = Rect.fromLTWH(col * cellWidth, row * cellHeight, cellWidth, cellHeight);
      
      // Map the double (0.0 to 1.0) to a heat-map color scale (Blue -> Green -> Red)
      // Since it's forensic light theme, we use subtle blues/reds
      final intensity = vector[i];
      if (intensity < 0.3) {
        paint.color = kNeomorphicBaseColor.withOpacity(0.8);
      } else if (intensity < 0.7) {
        paint.color = kAccentColor.withOpacity(intensity);
      } else {
        paint.color = kAlertColor.withOpacity(intensity); // Anomalies appear red
      }
      
      canvas.drawRect(rect, paint);
    }
    
    // Overlay a subtle scanline grid to enhance the forensic aesthetic
    final gridPaint = Paint()
      ..color = Colors.white.withOpacity(0.2)
      ..style = PaintingStyle.stroke
      ..strokeWidth = 1.0;
      
    for (int r = 0; r <= gridSize; r++) {
      canvas.drawLine(Offset(0, r * cellHeight), Offset(size.width, r * cellHeight), gridPaint);
      canvas.drawLine(Offset(r * cellWidth, 0), Offset(r * cellWidth, size.height), gridPaint);
    }
  }

  @override
  bool shouldRepaint(covariant SteganographyHeatMapRenderer oldDelegate) {
    return oldDelegate.vector != vector;
  }
}
