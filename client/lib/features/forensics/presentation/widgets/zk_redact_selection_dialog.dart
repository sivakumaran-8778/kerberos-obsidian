import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:image/image.dart' as img;
import '../../../../shared/theme/cyber_theme.dart';
import '../../../../shared/widgets/cyber_button.dart';
import '../../services/document_forensic_service.dart';

class ZkRedactSelectionDialog extends StatefulWidget {
  final Uint8List imageBytes;
  final Uint8List? previewBytes;
  final int pageIndex;
  final int totalPages;

  const ZkRedactSelectionDialog({
    super.key,
    required this.imageBytes,
    this.previewBytes,
    this.pageIndex = 0,
    this.totalPages = 1,
  });

  @override
  State<ZkRedactSelectionDialog> createState() => _ZkRedactSelectionDialogState();
}

class _ZkRedactSelectionDialogState extends State<ZkRedactSelectionDialog> {
  img.Image? _decodedImage;
  Uint8List? _encodedPngBytes;
  String? _error;
  Offset? _startPoint;
  Offset? _currentPoint;
  final GlobalKey _imageKey = GlobalKey();
  
  @override
  void initState() {
    super.initState();
    _decodeImage();
  }

  Future<void> _decodeImage() async {
    try {
      if (widget.imageBytes.isEmpty && (widget.previewBytes == null || widget.previewBytes!.isEmpty)) {
        throw Exception("File byte buffer is completely empty.");
      }
      
      img.Image? decoded;
      Uint8List? displayBytes;

      // 1. Direct raster preview provided by caller (e.g. from ELA analysis)
      if (widget.previewBytes != null && widget.previewBytes!.isNotEmpty) {
        decoded = img.decodeImage(widget.previewBytes!);
        if (decoded != null) {
          displayBytes = widget.previewBytes;
        }
      }

      // 2. If not decoded, check if PDF magic bytes (%PDF)
      if (decoded == null) {
        if (widget.imageBytes.length >= 4 &&
            widget.imageBytes[0] == 0x25 &&
            widget.imageBytes[1] == 0x50 &&
            widget.imageBytes[2] == 0x44 &&
            widget.imageBytes[3] == 0x46) {
          final preview = DocumentForensicService.computeQuickPreview(
            widget.imageBytes,
            targetPageIndex: widget.pageIndex,
            totalPageCount: widget.totalPages,
          );
          if (preview.previewImageBytes != null) {
            decoded = img.decodeImage(preview.previewImageBytes!);
            if (decoded != null) {
              displayBytes = preview.previewImageBytes;
            }
          }
        } else {
          decoded = img.decodeImage(widget.imageBytes);
          if (decoded != null) {
            displayBytes = widget.imageBytes;
          }
        }
      }
      
      // 3. Fallback: try quick preview rasterizer
      if (decoded == null) {
        final preview = DocumentForensicService.computeQuickPreview(
          widget.imageBytes,
          targetPageIndex: widget.pageIndex,
          totalPageCount: widget.totalPages,
        );
        if (preview.previewImageBytes != null) {
          decoded = img.decodeImage(preview.previewImageBytes!);
          if (decoded != null) {
            displayBytes = preview.previewImageBytes;
          }
        }
      }

      // 4. Final safety guarantee: blank document canvas
      if (decoded == null) {
        decoded = img.Image(width: 612, height: 792);
        img.fill(decoded, color: img.ColorRgb8(255, 255, 255));
        displayBytes = Uint8List.fromList(img.encodePng(decoded));
      }

      displayBytes ??= Uint8List.fromList(img.encodePng(decoded));

      if (mounted) {
        setState(() {
          _decodedImage = decoded;
          _encodedPngBytes = displayBytes;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = e.toString();
        });
      }
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
    
    // Scale on-screen coordinates up to true pixel resolution of the image
    final imageRatio = _decodedImage!.width / _decodedImage!.height;
    final viewRatio = size.width / size.height;
    
    double renderWidth;
    double renderHeight;
    double offsetX = 0;
    double offsetY = 0;

    if (imageRatio > viewRatio) {
      renderWidth = size.width;
      renderHeight = renderWidth / imageRatio;
      offsetY = (size.height - renderHeight) / 2;
    } else {
      renderHeight = size.height;
      renderWidth = renderHeight * imageRatio;
      offsetX = (size.width - renderWidth) / 2;
    }

    final scaleX = _decodedImage!.width / renderWidth;
    final scaleY = _decodedImage!.height / renderHeight;

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
      'canvasWidth': _decodedImage!.width.toDouble(),
      'canvasHeight': _decodedImage!.height.toDouble(),
      'pageIndex': widget.pageIndex,
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
              widget.totalPages > 1
                  ? 'ZK-REDACT: SELECT SENSITIVE DATA (PAGE ${widget.pageIndex + 1} OF ${widget.totalPages})'
                  : 'ZK-REDACT: SELECT SENSITIVE DATA',
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
              child: _error != null
                  ? Center(
                      child: Text(
                        'DOCUMENT RENDER ERROR: $_error\n\nPlease check file integrity and try again.',
                        textAlign: TextAlign.center,
                        style: const TextStyle(color: CyberTheme.coral, fontWeight: FontWeight.bold),
                      ),
                    )
                  : (_decodedImage == null || _encodedPngBytes == null)
                      ? const Center(child: CircularProgressIndicator(color: CyberTheme.accentColor))
                      : GestureDetector(
                      key: _imageKey,
                      onPanDown: _onPanStart,
                      onPanUpdate: _onPanUpdate,
                      child: Stack(
                        children: [
                          Center(
                            child: Image.memory(
                              _encodedPngBytes!,
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
