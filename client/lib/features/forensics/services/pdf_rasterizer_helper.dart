import 'package:flutter/foundation.dart';
import 'package:printing/printing.dart';

/// Helper to rasterize PDF pages to high-resolution PNG images
/// using native OS hardware PDF engines (Windows.Data.Pdf, Android PdfRenderer, Web pdf.js).
class PdfRasterizerHelper {
  /// Rasterizes all pages of a PDF document into real high-fidelity PNG image byte buffers.
  static Future<List<Uint8List>> rasterizePdfPages(
    Uint8List pdfBytes, {
    double dpi = 144.0,
    int maxPages = 25,
  }) async {
    final pages = <Uint8List>[];
    try {
      int count = 0;
      await for (final page in Printing.raster(pdfBytes, dpi: dpi)) {
        final pngBytes = await page.toPng();
        pages.add(pngBytes);
        count++;
        if (count >= maxPages) break;
      }
    } catch (e) {
      debugPrint('PdfRasterizerHelper.rasterizePdfPages notice: $e');
    }
    return pages;
  }

  /// Rasterizes a single target page of a PDF document.
  static Future<Uint8List?> rasterizePdfPage(
    Uint8List pdfBytes, {
    int pageIndex = 0,
    double dpi = 144.0,
  }) async {
    try {
      await for (final page in Printing.raster(pdfBytes, pages: [pageIndex], dpi: dpi)) {
        return await page.toPng();
      }
    } catch (e) {
      debugPrint('PdfRasterizerHelper.rasterizePdfPage notice: $e');
    }
    return null;
  }
}
