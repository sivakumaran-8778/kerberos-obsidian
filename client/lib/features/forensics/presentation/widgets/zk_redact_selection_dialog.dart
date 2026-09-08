import 'dart:ui' as ui;
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import '../../../../shared/theme/cyber_theme.dart';
import '../../../../shared/widgets/cyber_button.dart';

class ZkRedactSelectionDialog extends StatefulWidget {
  final Uint8List imageBytes;

  const ZkRedactSelectionDialog({super.key, required this.imageBytes});

  @override
  State<ZkRedactSelectionDialog> createState() => _ZkRedactSelectionDialogState();
}

class _ZkRedactSelectionDialogState extends State<ZkRedactSelectionDialog> {
  ui.Image? _decodedImage;
  Offset? _startPoint;
  Offset? _currentPoint;
  final GlobalKey _imageKey = GlobalKey();
  
  @override
  void initState() {
    super.initState();
    _decodeImage();
  }

  Future<void> _decodeImage() async {
    final codec = await ui.instantiateImageCodec(widget.imageBytes);
    final frameInfo = await codec.getNextFrame();
    if (mounted) {
      setState(() {
        _decodedImage = frameInfo.image;
      });
    }
  }

  void _onPanStart(DragDownDetails details) {
    setState(() {
      _startPoint = details.localPosition;
      _currentPoint = details.localPosition;
    });
  }

  void _onPanUpdate(DragUpdateDetails details) {
    setState(() {
      _currentPoint = details.localPosition;
    });
  }

  void _confirmRedaction() {
    if (_startPoint == null || _currentPoint == null || _decodedImage == null) return;
    
    final RenderBox renderBox = _imageKey.currentContext!.findRenderObject() as RenderBox;
    final size = renderBox.size;
    
    // Calculate the drawing bounds on screen
    final rect = Rect.fromPoints(_startPoint!, _currentPoint!);
    
    // We must scale the on-screen coordinates up to the true pixel resolution of the image
    // Find the scale factor. The image is rendered using BoxFit.contain.
    
    final imageRatio = _decodedImage!.width / _decodedImage!.height;
    final viewRatio = size.width / size.height;
    
    double renderWidth;
    double renderHeight;
    double offsetX = 0;
    double offsetY = 0;

    if (imageRatio > viewRatio) {
      // Image is wider than the view. It spans full width.
      renderWidth = size.width;
      renderHeight = renderWidth / imageRatio;
      offsetY = (size.height - renderHeight) / 2;
    } else {
      // Image is taller than the view. It spans full height.
      renderHeight = size.height;
      renderWidth = renderHeight * imageRatio;
      offsetX = (size.width - renderWidth) / 2;
    }

    final scaleX = _decodedImage!.width / renderWidth;
    final scaleY = _decodedImage!.height / renderHeight;

    // Adjust for centering offsets
    final trueX = (rect.left - offsetX) * scaleX;
    final trueY = (rect.top - offsetY) * scaleY;
    final trueWidth = rect.width * scaleX;
    final trueHeight = rect.height * scaleY;

    // Return the calculated coordinates back to DocumentForensicsScreen
    Navigator.of(context).pop({
      'x': trueX.toInt().clamp(0, _decodedImage!.width),
      'y': trueY.toInt().clamp(0, _decodedImage!.height),
      'width': trueWidth.toInt().clamp(0, _decodedImage!.width),
      'height': trueHeight.toInt().clamp(0, _decodedImage!.height),
    });
  }

  @override
  Widget build(BuildContext context) {
    return Dialog(
      backgroundColor: const Color(0xFF0F172A),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: const BorderSide(color: CyberTheme.accentColor, width: 1),
      ),
      child: Container(
        width: 800,
        height: 700,
        padding: const EdgeInsets.all(20),
        child: Column(
          children: [
            Text(
              'ZK-REDACT: SELECT SENSITIVE DATA',
              style: GoogleFonts.plusJakartaSans(
                fontSize: 16,
                fontWeight: FontWeight.w800,
                color: CyberTheme.accentColor,
                letterSpacing: 1.0,
              ),
            ),
            const SizedBox(height: 8),
            Text(
              'Draw a box over the pixels you wish to obliterate from the true bitstream. A cryptographic proof will be bound to the C2PA manifest.',
              textAlign: TextAlign.center,
              style: GoogleFonts.plusJakartaSans(
                fontSize: 12,
                color: CyberTheme.textMuted,
              ),
            ),
            const SizedBox(height: 20),
            
            Expanded(
              child: _decodedImage == null
                  ? const Center(child: CircularProgressIndicator(color: CyberTheme.accentColor))
                  : GestureDetector(
                      key: _imageKey,
                      onPanDown: _onPanStart,
                      onPanUpdate: _onPanUpdate,
                      child: Stack(
                        children: [
                          Center(
                            child: Image.memory(
                              widget.imageBytes,
                              fit: BoxFit.contain,
                              width: double.infinity,
                              height: double.infinity,
                            ),
                          ),
                          if (_startPoint != null && _currentPoint != null)
                            Positioned.fromRect(
                              rect: Rect.fromPoints(_startPoint!, _currentPoint!),
                              child: Container(
                                decoration: BoxDecoration(
                                  color: Colors.black.withValues(alpha: 0.85),
                                  border: Border.all(color: CyberTheme.emerald, width: 2),
                                ),
                                child: Center(
                                  child: Text(
                                    'REDACTED',
                                    style: GoogleFonts.jetBrainsMono(
                                      color: CyberTheme.emerald,
                                      fontWeight: FontWeight.bold,
                                      fontSize: 12,
                                    ),
                                  ),
                                ),
                              ),
                            ),
                        ],
                      ),
                    ),
            ),

            const SizedBox(height: 20),
            Row(
              mainAxisAlignment: MainAxisAlignment.end,
              children: [
                TextButton(
                  onPressed: () => Navigator.of(context).pop(),
                  child: Text(
                    'CANCEL',
                    style: GoogleFonts.plusJakartaSans(
                      color: CyberTheme.textMuted,
                      fontWeight: FontWeight.w700,
                    ),
                  ),
                ),
                const SizedBox(width: 16),
                CyberButton(
                  variant: CyberButtonVariant.emerald,
                  height: 40,
                  onTap: () {
                    if (_startPoint == null) {
                      ScaffoldMessenger.of(context).showSnackBar(
                        const SnackBar(content: Text('Please draw a redaction box first.')),
                      );
                      return;
                    }
                    _confirmRedaction();
                  },
                  child: const Text('CONFIRM REDACTION', style: TextStyle(fontWeight: FontWeight.bold, color: Colors.black)),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
