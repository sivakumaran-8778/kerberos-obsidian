import 'dart:math' as math;
import 'dart:typed_data';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:image/image.dart' as img;
import '../../../../shared/theme/cyber_theme.dart';
import '../../../../shared/widgets/cyber_button.dart';
import '../../services/document_forensic_service.dart';
import '../../services/pdf_rasterizer_helper.dart';

class ZkRedactSelectionDialog extends StatefulWidget {
  final Uint8List imageBytes;
  final Uint8List? previewBytes;
  final List<Uint8List>? allPagePreviews;
  final int pageIndex;
  final int totalPages;

  const ZkRedactSelectionDialog({
    super.key,
    required this.imageBytes,
    this.previewBytes,
    this.allPagePreviews,
    this.pageIndex = 0,
    this.totalPages = 1,
  });

  @override
  State<ZkRedactSelectionDialog> createState() => _ZkRedactSelectionDialogState();
}

class _ZkRedactSelectionDialogState extends State<ZkRedactSelectionDialog> {
  late int _currentPageIndex;
  late int _totalPages;
  List<Uint8List>? _pagePreviews;
  bool _isLoading = true;
  img.Image? _decodedImage;
  Uint8List? _encodedPngBytes;
  String? _error;
  Offset? _startPoint;
  Offset? _currentPoint;
  final GlobalKey _imageKey = GlobalKey();

  @override
  void initState() {
    super.initState();
    _currentPageIndex = widget.pageIndex;
    _totalPages = math.max(1, widget.totalPages);

    if (widget.allPagePreviews != null && widget.allPagePreviews!.isNotEmpty) {
      _pagePreviews = List<Uint8List>.from(widget.allPagePreviews!);
      _totalPages = math.max(_totalPages, _pagePreviews!.length);
    }

    _loadPageContent();
  }

  bool get _isPdf =>
      (widget.imageBytes.length >= 4 &&
          widget.imageBytes[0] == 0x25 &&
          widget.imageBytes[1] == 0x50 &&
          widget.imageBytes[2] == 0x44 &&
          widget.imageBytes[3] == 0x46);

  Future<void> _loadPageContent() async {
    setState(() {
      _isLoading = true;
      _error = null;
      _decodedImage = null;
      _encodedPngBytes = null;
    });

    try {
      // 1. If we don't have page previews yet and this is a PDF, rasterize all pages
      if ((_pagePreviews == null || _pagePreviews!.isEmpty) && _isPdf) {
        try {
          final rasters = await PdfRasterizerHelper.rasterizePdfPages(widget.imageBytes);
          if (rasters.isNotEmpty) {
            _pagePreviews = rasters;
            _totalPages = math.max(_totalPages, rasters.length);
          }
        } catch (e) {
          debugPrint('Notice: Native PDF rasterization in modal: $e');
        }
      }

      Uint8List? targetBytes;

      // 2. Try using the cached page preview
      if (_pagePreviews != null &&
          _currentPageIndex >= 0 &&
          _currentPageIndex < _pagePreviews!.length) {
        targetBytes = _pagePreviews![_currentPageIndex];
      }

      // 3. If target page matches widget.pageIndex and previewBytes was provided
      if (targetBytes == null &&
          _currentPageIndex == widget.pageIndex &&
          widget.previewBytes != null &&
          widget.previewBytes!.isNotEmpty) {
        targetBytes = widget.previewBytes;
      }

      // 4. Try rendering single page raster dynamically if still null
      if (targetBytes == null && _isPdf) {
        try {
          targetBytes = await PdfRasterizerHelper.rasterizePdfPage(
            widget.imageBytes,
            pageIndex: _currentPageIndex,
          );
        } catch (_) {}
      }

      // 5. Fallback to quick preview generator
      if (targetBytes == null) {
        final preview = DocumentForensicService.computeQuickPreview(
          widget.imageBytes,
          targetPageIndex: _currentPageIndex,
          totalPageCount: _totalPages,
        );
        targetBytes = preview.previewImageBytes ?? preview.elaImageBytes;
      }

      // 6. Final safety fallback: raw image bytes if it's an image
      if (targetBytes == null && !_isPdf && widget.imageBytes.isNotEmpty) {
        targetBytes = widget.imageBytes;
      }

      img.Image? decoded;
      if (targetBytes != null && targetBytes.isNotEmpty) {
        decoded = img.decodeImage(targetBytes);
      }

      // 7. Ultimate fallback: blank sheet
      if (decoded == null) {
        decoded = img.Image(width: 612, height: 792);
        img.fill(decoded, color: img.ColorRgb8(255, 255, 255));
        targetBytes = Uint8List.fromList(img.encodePng(decoded));
      }

      targetBytes ??= Uint8List.fromList(img.encodePng(decoded));

      if (mounted) {
        setState(() {
          _decodedImage = decoded;
          _encodedPngBytes = targetBytes;
          _isLoading = false;
        });
      }
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = e.toString();
          _isLoading = false;
        });
      }
    }
  }

  void _switchPage(int newIndex) {
    if (newIndex < 0 || newIndex >= _totalPages || newIndex == _currentPageIndex) return;
    setState(() {
      _currentPageIndex = newIndex;
      _startPoint = null;
      _currentPoint = null;
    });
    _loadPageContent();
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

    // Calculate drawing bounds on screen
    final rect = Rect.fromPoints(_startPoint!, _currentPoint!);

    // Scale on-screen coordinates to true pixel resolution of the image
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
      'pageIndex': _currentPageIndex,
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
        width: 860,
        height: 760,
        padding: const EdgeInsets.all(20),
        child: Column(
          children: [
            // Header Title
            Text(
              _totalPages > 1
                  ? 'ZK-REDACT: SELECT SENSITIVE DATA (PAGE ${_currentPageIndex + 1} OF $_totalPages)'
                  : 'ZK-REDACT: SELECT SENSITIVE DATA',
              style: GoogleFonts.plusJakartaSans(
                fontSize: 16,
                fontWeight: FontWeight.w800,
                color: CyberTheme.accentColor,
                letterSpacing: 1.0,
              ),
            ),
            const SizedBox(height: 6),
            Text(
              'Draw a box over the pixels you wish to obliterate from the true bitstream. A cryptographic proof will be bound to the C2PA manifest.',
              textAlign: TextAlign.center,
              style: GoogleFonts.plusJakartaSans(
                fontSize: 12,
                color: CyberTheme.textMuted,
              ),
            ),
            const SizedBox(height: 14),

            // Multi-page navigation bar inside modal
            if (_totalPages > 1)
              Container(
                margin: const EdgeInsets.only(bottom: 12),
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
                decoration: BoxDecoration(
                  color: CyberTheme.surfaceElevated.withValues(alpha: 0.6),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: CyberTheme.border),
                ),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        const Icon(Icons.menu_book_rounded, size: 16, color: CyberTheme.accentColor),
                        const SizedBox(width: 8),
                        Text(
                          'PAGE ${_currentPageIndex + 1} OF $_totalPages',
                          style: GoogleFonts.jetBrainsMono(
                            fontSize: 12,
                            fontWeight: FontWeight.bold,
                            color: Colors.white,
                            letterSpacing: 0.5,
                          ),
                        ),
                      ],
                    ),
                    Row(
                      mainAxisSize: MainAxisSize.min,
                      children: [
                        // Prev button
                        InkWell(
                          onTap: _currentPageIndex > 0
                              ? () => _switchPage(_currentPageIndex - 1)
                              : null,
                          borderRadius: BorderRadius.circular(6),
                          child: Container(
                            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                            decoration: BoxDecoration(
                              color: _currentPageIndex > 0 ? CyberTheme.surface : Colors.transparent,
                              borderRadius: BorderRadius.circular(6),
                              border: Border.all(
                                color: _currentPageIndex > 0 ? CyberTheme.border : Colors.transparent,
                              ),
                            ),
                            child: Row(
                              children: [
                                Icon(
                                  Icons.chevron_left_rounded,
                                  size: 16,
                                  color: _currentPageIndex > 0 ? Colors.white : Colors.white24,
                                ),
                                const SizedBox(width: 2),
                                Text(
                                  'Prev',
                                  style: TextStyle(
                                    fontSize: 11,
                                    fontWeight: FontWeight.w600,
                                    color: _currentPageIndex > 0 ? Colors.white : Colors.white24,
                                  ),
                                ),
                              ],
                            ),
                          ),
                        ),
                        const SizedBox(width: 6),
                        // Page chips
                        ...List.generate(math.min(_totalPages, 10), (i) {
                          final isSelected = i == _currentPageIndex;
                          return Padding(
                            padding: const EdgeInsets.symmetric(horizontal: 2),
                            child: InkWell(
                              onTap: () => _switchPage(i),
                              borderRadius: BorderRadius.circular(6),
                              child: Container(
                                width: 28,
                                height: 26,
                                alignment: Alignment.center,
                                decoration: BoxDecoration(
                                  color: isSelected ? CyberTheme.accentColor : CyberTheme.surface,
                                  borderRadius: BorderRadius.circular(6),
                                  border: Border.all(
                                    color: isSelected ? CyberTheme.accentColor : CyberTheme.border,
                                  ),
                                ),
                                child: Text(
                                  '${i + 1}',
                                  style: TextStyle(
                                    fontSize: 11,
                                    fontWeight: FontWeight.bold,
                                    color: isSelected ? Colors.white : CyberTheme.textMuted,
                                  ),
                                ),
                              ),
                            ),
                          );
                        }),
                        const SizedBox(width: 6),
                        // Next button
                        InkWell(
                          onTap: _currentPageIndex < _totalPages - 1
                              ? () => _switchPage(_currentPageIndex + 1)
                              : null,
                          borderRadius: BorderRadius.circular(6),
                          child: Container(
                            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                            decoration: BoxDecoration(
                              color: _currentPageIndex < _totalPages - 1 ? CyberTheme.surface : Colors.transparent,
                              borderRadius: BorderRadius.circular(6),
                              border: Border.all(
                                color: _currentPageIndex < _totalPages - 1 ? CyberTheme.border : Colors.transparent,
                              ),
                            ),
                            child: Row(
                              children: [
                                Text(
                                  'Next',
                                  style: TextStyle(
                                    fontSize: 11,
                                    fontWeight: FontWeight.w600,
                                    color: _currentPageIndex < _totalPages - 1 ? Colors.white : Colors.white24,
                                  ),
                                ),
                                const SizedBox(width: 2),
                                Icon(
                                  Icons.chevron_right_rounded,
                                  size: 16,
                                  color: _currentPageIndex < _totalPages - 1 ? Colors.white : Colors.white24,
                                ),
                              ],
                            ),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),

            // Document Viewport with Redaction Drag Layer
            Expanded(
              child: _error != null
                  ? Center(
                      child: Text(
                        'DOCUMENT RENDER ERROR: $_error\n\nPlease check file integrity and try again.',
                        textAlign: TextAlign.center,
                        style: const TextStyle(color: CyberTheme.coral, fontWeight: FontWeight.bold),
                      ),
                    )
                  : (_isLoading || _decodedImage == null || _encodedPngBytes == null)
                      ? const Center(
                          child: Column(
                            mainAxisSize: MainAxisSize.min,
                            children: [
                              CircularProgressIndicator(color: CyberTheme.accentColor),
                              SizedBox(height: 12),
                              Text(
                                'Rasterizing document page...',
                                style: TextStyle(color: CyberTheme.textMuted, fontSize: 12),
                              ),
                            ],
                          ),
                        )
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

            const SizedBox(height: 16),
            // Dialog Actions
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
                  child: const Text(
                    'CONFIRM REDACTION',
                    style: TextStyle(fontWeight: FontWeight.bold, color: Colors.black),
                  ),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
