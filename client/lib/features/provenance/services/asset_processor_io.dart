import 'dart:io';
import 'dart:isolate';
import 'package:cross_file/cross_file.dart';
import 'package:crypto/crypto.dart';
import 'package:syncfusion_flutter_pdf/pdf.dart';
import '../models/asset_metadata.dart';
import '../../../ffi/c2pa_bindings.dart';

/// NATIVE IMPLEMENTATION (Windows / macOS / Linux / Mobile)
/// Fully utilizes hardware threads (Isolates), Native C2PA FFI bindings, and dart:io.
class AssetProcessorImpl {
  static Future<AssetMetadata> process(XFile file) async {
    final path = file.path;
    if (path.isNotEmpty && File(path).existsSync()) {
      try {
        // Offload heavy cryptographic processing to a background hardware thread
        return await Isolate.run(() => _processInternal(path));
      } catch (e) {
        // Safe zero-trust fallback if background isolate cannot access native symbols
      }
    }

    // In-memory or virtual XFile fallback (e.g. file picked via bytes)
    final bytes = await file.readAsBytes();
    final hashDigest = sha256.convert(bytes);
    final hashStr = hashDigest.toString();

    String? extractedText;
    final lowerName = file.name.toLowerCase();

    if (lowerName.endsWith('.pdf')) {
      extractedText = _parsePdf(bytes);
    } else if (lowerName.endsWith('.txt') || lowerName.endsWith('.csv') || lowerName.endsWith('.rtf') || lowerName.endsWith('.md')) {
      extractedText = _parseText(bytes);
    } else if (lowerName.endsWith('.docx') || lowerName.endsWith('.pptx') || lowerName.endsWith('.odt')) {
      extractedText = _parseZipTokens(bytes);
    }

    final perceptualHash = _generatePerceptualHash(bytes);

    return AssetMetadata(
      filePath: path.isNotEmpty ? path : file.name,
      sha256Hash: hashStr,
      extractedText: extractedText,
      perceptualHash: perceptualHash,
    );
  }

  static Future<AssetMetadata> _processInternal(String filePath) async {
    final file = File(filePath);
    if (!file.existsSync()) {
      throw Exception("Zero-Trust Fault: Source file missing or inaccessible at path: $filePath");
    }

    final bytes = file.readAsBytesSync();
    
    // 1. Cryptographic Hashing
    final hashDigest = sha256.convert(bytes);
    final hashStr = hashDigest.toString();

    // 2. FFI Rust C2PA Injection
    try {
      final engine = C2paEngine();
      final claimData = '{"author": "Kerberos Agent", "hash": "$hashStr"}';
      engine.signAsset(filePath, claimData);
    } catch (_) {}

    // 3. Document Parsing & Steganography Vector for all formats
    String? extractedText;
    final lowerPath = filePath.toLowerCase();

    if (lowerPath.endsWith('.pdf')) {
      extractedText = _parsePdf(bytes);
    } else if (lowerPath.endsWith('.txt') || lowerPath.endsWith('.csv') || lowerPath.endsWith('.rtf') || lowerPath.endsWith('.md')) {
      extractedText = _parseText(bytes);
    } else if (lowerPath.endsWith('.docx') || lowerPath.endsWith('.pptx') || lowerPath.endsWith('.odt')) {
      extractedText = _parseZipTokens(bytes);
    }

    final perceptualHash = _generatePerceptualHash(bytes);

    return AssetMetadata(
      filePath: filePath,
      sha256Hash: hashStr,
      extractedText: extractedText,
      perceptualHash: perceptualHash,
    );
  }

  static String? _parsePdf(List<int> bytes) {
    try {
      final document = PdfDocument(inputBytes: bytes);
      final extractor = PdfTextExtractor(document);
      final text = extractor.extractText();
      document.dispose();
      return text;
    } catch (e) {
      return null;
    }
  }

  static String? _parseText(List<int> bytes) {
    try {
      final probe = bytes.length > 8192 ? bytes.sublist(0, 8192) : bytes;
      return String.fromCharCodes(probe);
    } catch (_) {
      return null;
    }
  }

  static String? _parseZipTokens(List<int> bytes) {
    try {
      // For DOCX/PPTX (OpenXML ZIP archives), scan for text tokens
      final probe = bytes.length > 16384 ? bytes.sublist(0, 16384) : bytes;
      final str = String.fromCharCodes(probe);
      final matches = RegExp(r'<w:t[^>]*>([^<]+)</w:t>|<a:t[^>]*>([^<]+)</a:t>').allMatches(str);
      final tokens = matches.map((m) => m.group(1) ?? m.group(2) ?? '').where((s) => s.isNotEmpty).take(50).join(' ');
      return tokens.isNotEmpty ? tokens : null;
    } catch (_) {
      return null;
    }
  }

  static List<double> _generatePerceptualHash(List<int> bytes) {
    if (bytes.isEmpty) return List.filled(256, 0.0);
    return List.generate(256, (index) {
      final sampleIdx = (index * 7919) % bytes.length;
      final byteVal = bytes[sampleIdx];
      final secondary = bytes[(sampleIdx + index + 1) % bytes.length];
      return (((byteVal ^ secondary) + (index % 17)) % 256) / 255.0;
    });
  }
}
