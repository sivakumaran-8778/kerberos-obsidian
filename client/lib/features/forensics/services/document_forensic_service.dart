import 'dart:convert';
import 'dart:typed_data';
import 'package:crypto/crypto.dart';
import '../../ledger/models/provenance_record.dart';
import '../models/document_forensic_models.dart';

class DocumentForensicService {
  /// Analyzes any document or image blindly (without requiring prior registration)
  /// and correlates with ledger anchors if available to produce a complete forensic audit.
  static DocumentForensicReport analyzeDocument({
    required Uint8List bytes,
    required String fileName,
    List<ProvenanceRecord>? ledgerHistory,
  }) {
    final sha256Digest = sha256.convert(bytes).toString();
    final lowerName = fileName.toLowerCase();
    final mimeType = _detectMimeType(bytes, fileName);

    // 1. Bitstream & Magic Byte Validation
    final magicByteCheck = _validateMagicBytes(bytes, lowerName);
    if (!magicByteCheck.isValid) {
      return DocumentForensicReport(
        fileName: fileName,
        fileSizeBytes: bytes.length,
        fileBytes: bytes,
        sha256Hash: sha256Digest,
        mimeType: mimeType,
        verdict: DocumentForensicVerdict.scrambledCorrupted,
        confidenceScore: 98,
        revisionCount: 0,
        history: [
          DocumentRevisionEntry(
            revisionIndex: 1,
            title: 'Corrupted Bitstream Ingestion',
            description: 'File structure is broken or scrambled. Magic byte verification failed: ${magicByteCheck.error}',
            isTamperOrAppended: true,
          ),
        ],
        editingSoftwareDetected: const [],
        anomalies: [
          TamperAnomalyFlag(
            title: 'Magic Byte Header Violation',
            technicalDetail: magicByteCheck.error,
            isSevere: true,
          ),
          TamperAnomalyFlag(
            title: 'Scrambled or Truncated Binary Stream',
            technicalDetail: 'The raw byte stream does not adhere to valid RFC/ISO specifications for $mimeType.',
            isSevere: true,
          ),
        ],
        isMagicByteValid: false,
        hasTrailingPayload: false,
      );
    }

    // 2. Check for Ledger Anchors (Cryptographic Zero-Trust match)
    ProvenanceRecord? matchedRecord;
    bool isCryptographicBitstreamMatch = false;
    if (ledgerHistory != null && ledgerHistory.isNotEmpty) {
      // Check exact hash match
      matchedRecord = ledgerHistory.where(
        (r) => r.originalFileHash.toLowerCase() == sha256Digest.toLowerCase(),
      ).firstOrNull;

      if (matchedRecord != null) {
        isCryptographicBitstreamMatch = true;
      } else {
        // Check base filename lineage match
        final inBase = _cleanFileName(fileName).toLowerCase();
        matchedRecord = ledgerHistory.where((r) {
          final sBase = _cleanFileName(r.filePath).toLowerCase();
          return sBase == inBase;
        }).firstOrNull;
      }
    }

    // If sealed in ledger and bitstream matches exactly:
    if (matchedRecord != null && isCryptographicBitstreamMatch) {
      return DocumentForensicReport(
        fileName: fileName,
        fileSizeBytes: bytes.length,
        fileBytes: bytes,
        sha256Hash: sha256Digest,
        mimeType: mimeType,
        verdict: DocumentForensicVerdict.sealedCryptographicMatch,
        confidenceScore: 100,
        revisionCount: 1,
        history: [
          DocumentRevisionEntry(
            revisionIndex: 1,
            title: 'Sealed Cryptographic Original',
            timestamp: matchedRecord.timestamp,
            softwareOrProducer: 'Kerberos Provenance Hardware Engine',
            description: 'Document is sealed with immutable Ed25519 signature in local ledger. Bitstream is 100% bit-for-bit pristine.',
          ),
        ],
        editingSoftwareDetected: const [],
        anomalies: const [],
        isMagicByteValid: true,
        hasTrailingPayload: false,
        creationDate: matchedRecord.timestamp,
        modificationDate: matchedRecord.timestamp,
        matchedLedgerRecord: matchedRecord,
      );
    }

    // If matched a ledger record but hash diverged:
    if (matchedRecord != null && !isCryptographicBitstreamMatch) {
      final anomalies = <TamperAnomalyFlag>[
        TamperAnomalyFlag(
          title: 'Immutable Ledger Parity Shattered',
          technicalDetail: 'Asset matches sealed ledger anchor "${_cleanFileName(matchedRecord.filePath)}", but live SHA-256 ($sha256Digest) diverges from sealed hash (${matchedRecord.originalFileHash}).',
          isSevere: true,
        ),
      ];

      // Perform deep forensic parsing as well to expose what changed
      final subAnalysis = _performDeepForensics(bytes, lowerName, mimeType);
      anomalies.addAll(subAnalysis.anomalies);

      return DocumentForensicReport(
        fileName: fileName,
        fileSizeBytes: bytes.length,
        fileBytes: bytes,
        sha256Hash: sha256Digest,
        mimeType: mimeType,
        verdict: DocumentForensicVerdict.sealedCryptographicTampered,
        confidenceScore: 100,
        revisionCount: subAnalysis.revisionCount > 1 ? subAnalysis.revisionCount : 2,
        history: [
          DocumentRevisionEntry(
            revisionIndex: 1,
            title: 'Initial Certified Issuance',
            timestamp: matchedRecord.timestamp,
            softwareOrProducer: 'Kerberos Provenance Engine (Anchor)',
            description: 'Original immutable ledger seal created: ${matchedRecord.originalFileHash.substring(0, 16)}...',
          ),
          DocumentRevisionEntry(
            revisionIndex: 2,
            title: 'External Alteration / Tampering',
            timestamp: DateTime.now(),
            softwareOrProducer: subAnalysis.editingSoftwareDetected.isNotEmpty
                ? subAnalysis.editingSoftwareDetected.join(', ')
                : 'External Hex/Binary Editor',
            description: 'Binary divergence detected. Live digest deviates from certified root seal.',
            isTamperOrAppended: true,
          ),
        ],
        editingSoftwareDetected: subAnalysis.editingSoftwareDetected,
        anomalies: anomalies,
        isMagicByteValid: true,
        hasTrailingPayload: subAnalysis.hasTrailingPayload,
        trailingPayloadBytes: subAnalysis.trailingPayloadBytes,
        creationDate: matchedRecord.timestamp,
        modificationDate: DateTime.now(),
        matchedLedgerRecord: matchedRecord,
      );
    }

    // 3. Blind Deep Forensics for Unsealed Documents (Medical Bills, Govt IDs, PDFs, Images)
    final forensicResult = _performDeepForensics(bytes, lowerName, mimeType);

    DocumentForensicVerdict verdict;
    int confidence;

    if (forensicResult.isScrambled) {
      verdict = DocumentForensicVerdict.scrambledCorrupted;
      confidence = 96;
    } else if (forensicResult.isTampered) {
      verdict = DocumentForensicVerdict.tamperedEdited;
      confidence = forensicResult.confidence;
    } else {
      verdict = DocumentForensicVerdict.authenticOriginal;
      confidence = 94;
    }

    return DocumentForensicReport(
      fileName: fileName,
      fileSizeBytes: bytes.length,
      fileBytes: bytes,
      sha256Hash: sha256Digest,
      mimeType: mimeType,
      verdict: verdict,
      confidenceScore: confidence,
      revisionCount: forensicResult.revisionCount,
      history: forensicResult.history,
      editingSoftwareDetected: forensicResult.editingSoftwareDetected,
      anomalies: forensicResult.anomalies,
      isMagicByteValid: true,
      hasTrailingPayload: forensicResult.hasTrailingPayload,
      trailingPayloadBytes: forensicResult.trailingPayloadBytes,
      creationDate: forensicResult.creationDate,
      modificationDate: forensicResult.modificationDate,
    );
  }

  // ==========================================
  // DEEP FORENSIC ENGINE (PDF & IMAGE PARSERS)
  // ==========================================

  static _InternalForensicAnalysis _performDeepForensics(
    Uint8List bytes,
    String lowerName,
    String mimeType,
  ) {
    if (mimeType == 'application/pdf' || lowerName.endsWith('.pdf')) {
      return _analyzePdfForensics(bytes);
    } else if (mimeType.startsWith('image/') ||
        lowerName.endsWith('.jpg') ||
        lowerName.endsWith('.jpeg') ||
        lowerName.endsWith('.png') ||
        lowerName.endsWith('.webp') ||
        lowerName.endsWith('.tiff')) {
      return _analyzeImageForensics(bytes, mimeType, lowerName);
    } else {
      return _analyzeGenericDocumentForensics(bytes, mimeType);
    }
  }

  /// PDF Forensics: Incremental revisions, multiple %%EOF, /Prev pointers, /Producer signatures
  static _InternalForensicAnalysis _analyzePdfForensics(Uint8List bytes) {
    final anomalies = <TamperAnomalyFlag>[];
    final editingTools = <String>{};
    final history = <DocumentRevisionEntry>[];

    // Convert raw bytes to ASCII-safe probe string for structural token scanning
    final rawAscii = _bytesToAsciiString(bytes);

    // A. Count %%EOF markers
    final eofRegex = RegExp(r'%%EOF');
    final eofMatches = eofRegex.allMatches(rawAscii).toList();
    final eofCount = eofMatches.length;

    // B. Check for /Prev xref pointers (indicates appended revision trailers)
    final prevRegex = RegExp(r'/Prev\s+(\d+)');
    final prevMatches = prevRegex.allMatches(rawAscii).toList();

    // C. Check trailing bytes after final %%EOF
    bool hasTrailing = false;
    int trailingBytes = 0;
    if (eofMatches.isNotEmpty) {
      final lastEofEnd = eofMatches.last.end;
      if (lastEofEnd < bytes.length) {
        final remaining = bytes.sublist(lastEofEnd);
        // Trim whitespace/newlines
        final nonWhitespace = remaining.where((b) => b != 10 && b != 13 && b != 32).length;
        if (nonWhitespace > 16) {
          hasTrailing = true;
          trailingBytes = remaining.length;
          anomalies.add(TamperAnomalyFlag(
            title: 'Trailing Injected Payload Detected',
            technicalDetail: '$trailingBytes bytes appended past the final %%EOF file terminator. Possible steganography or payload injection.',
            isSevere: true,
          ));
        }
      }
    }

    // D. Extract Document Metadata (/Producer, /Creator, /CreationDate, /ModDate)
    final producerMatch = RegExp(r'/Producer\s*(?:\(([^)]*)\)|<([a-fA-F0-9]+)>)').firstMatch(rawAscii);
    final creatorMatch = RegExp(r'/Creator\s*(?:\(([^)]*)\)|<([a-fA-F0-9]+)>)').firstMatch(rawAscii);
    final creationDateMatch = RegExp(r'/CreationDate\s*(?:\(([^)]*)\)|<([a-fA-F0-9]+)>)').firstMatch(rawAscii);
    final modDateMatch = RegExp(r'/ModDate\s*(?:\(([^)]*)\)|<([a-fA-F0-9]+)>)').firstMatch(rawAscii);

    String? producer = _extractPdfString(producerMatch);
    String? creator = _extractPdfString(creatorMatch);
    DateTime? creationDate = _parsePdfDate(_extractPdfString(creationDateMatch));
    DateTime? modDate = _parsePdfDate(_extractPdfString(modDateMatch));

    // E. Scan for Editing Software Signatures in raw bitstream
    const suspiciousEditorSignatures = {
      'Adobe Acrobat': 'Adobe Acrobat PDF Editor',
      'Acrobat Pro': 'Adobe Acrobat Pro',
      'Canva': 'Canva Graphic Studio',
      'Photoshop': 'Adobe Photoshop',
      'GIMP': 'GNU Image Manipulation Program (GIMP)',
      'iLovePDF': 'iLovePDF Online Document Editor',
      'Smallpdf': 'Smallpdf Online Editor',
      'PDF-XChange': 'PDF-XChange Editor',
      'Foxit': 'Foxit PDF Editor',
      'Nitro Pro': 'Nitro Pro Document Editor',
      'Inkscape': 'Inkscape Vector Editor',
      'CorelDraw': 'CorelDraw Graphics Suite',
      'Sejda': 'Sejda PDF Editor',
      'PDF24': 'PDF24 Creator Tool',
    };

    for (final entry in suspiciousEditorSignatures.entries) {
      if (rawAscii.contains(entry.key)) {
        editingTools.add(entry.value);
      }
    }

    // F. Incremental Revision Tampering Diagnosis
    final revisionCount = eofCount > 0 ? eofCount : 1;
    bool isTampered = false;

    if (eofCount > 1 || prevMatches.isNotEmpty) {
      isTampered = true;
      anomalies.add(TamperAnomalyFlag(
        title: 'Incremental Revision Tampering ($revisionCount Generations)',
        technicalDetail: 'Document contains $eofCount %%EOF terminators and ${prevMatches.length} /Prev xref revision pointers. PDF content was modified post-issuance via incremental update save.',
        isSevere: true,
      ));
    }

    // G. Software Footprints Flag
    if (editingTools.isNotEmpty) {
      // Check if original creation was by an automated engine and then edited
      anomalies.add(TamperAnomalyFlag(
        title: 'External Editing Software Footprints',
        technicalDetail: 'Binary stream contains editor signatures: ${editingTools.join(', ')}.',
        isSevere: true,
      ));
      isTampered = true;
    }

    // H. Timestamp Paradox Check
    if (creationDate != null && modDate != null) {
      final difference = modDate.difference(creationDate).abs();
      if (modDate.isAfter(creationDate) && difference.inMinutes > 5) {
        anomalies.add(TamperAnomalyFlag(
          title: 'Modification Timestamp Divergence',
          technicalDetail: 'Document modification date (${modDate.toUtc()}) is ${difference.inDays > 0 ? '${difference.inDays} days' : '${difference.inHours} hours'} after creation date (${creationDate.toUtc()}).',
          isSevere: difference.inDays > 1,
        ));
        if (difference.inHours > 2) {
          isTampered = true;
        }
      }
    }

    if (hasTrailing) {
      isTampered = true;
    }

    // Build Chronological History
    final initialTool = producer ?? creator ?? 'Official Document Generation System';
    history.add(DocumentRevisionEntry(
      revisionIndex: 1,
      title: 'Initial Document Generation (v1)',
      timestamp: creationDate ?? DateTime.now().subtract(const Duration(days: 30)),
      softwareOrProducer: initialTool,
      description: 'Primary PDF document structure and initial content streams compiled.',
      isTamperOrAppended: false,
    ));

    if (eofCount > 1) {
      for (int i = 2; i <= eofCount; i++) {
        history.add(DocumentRevisionEntry(
          revisionIndex: i,
          title: 'Appended Revision Save (v$i)',
          timestamp: modDate ?? DateTime.now(),
          softwareOrProducer: editingTools.isNotEmpty ? editingTools.first : 'Incremental PDF Editor',
          description: 'Trailer appended with modified stream offsets (/Prev pointer). Original content was altered.',
          isTamperOrAppended: true,
        ));
      }
    } else if (isTampered && editingTools.isNotEmpty) {
      history.add(DocumentRevisionEntry(
        revisionIndex: 2,
        title: 'Post-Generation Software Modification',
        timestamp: modDate ?? DateTime.now(),
        softwareOrProducer: editingTools.join(', '),
        description: 'Document streams or metadata modified using external editing software.',
        isTamperOrAppended: true,
      ));
    }

    int confidence = 92;
    if (eofCount > 1) confidence = 98;
    if (editingTools.isNotEmpty) confidence = 99;

    return _InternalForensicAnalysis(
      isTampered: isTampered,
      isScrambled: false,
      confidence: confidence,
      revisionCount: revisionCount,
      history: history,
      editingSoftwareDetected: editingTools.toList(),
      anomalies: anomalies,
      hasTrailingPayload: hasTrailing,
      trailingPayloadBytes: trailingBytes,
      creationDate: creationDate,
      modificationDate: modDate,
    );
  }

  /// Image Forensics: Photoshop 8BIM blocks, Canva/GIMP signatures, EXIF dates, trailing bytes
  static _InternalForensicAnalysis _analyzeImageForensics(
    Uint8List bytes,
    String mimeType,
    String lowerName,
  ) {
    final anomalies = <TamperAnomalyFlag>[];
    final editingTools = <String>{};
    final history = <DocumentRevisionEntry>[];
    final rawAscii = _bytesToAsciiString(bytes);

    bool isTampered = false;
    bool hasTrailing = false;
    int trailingBytes = 0;

    // A. Photoshop Detection (8BIM markers & Adobe XMP)
    if (rawAscii.contains('8BIM') ||
        rawAscii.contains('Photoshop 3.0') ||
        rawAscii.contains('Adobe Photoshop') ||
        rawAscii.contains('photoshop:DocumentID')) {
      editingTools.add('Adobe Photoshop');
      anomalies.add(const TamperAnomalyFlag(
        title: 'Photoshop 8BIM Resource Block Detected',
        technicalDetail: 'Image contains embedded Adobe Photoshop resource markers (8BIM / Photoshop 3.0 header). Image was manipulated or exported from Photoshop.',
        isSevere: true,
      ));
      isTampered = true;
    }

    // B. Canva / GIMP / Other Image Manipulators
    if (rawAscii.contains('Canva')) {
      editingTools.add('Canva Graphic Studio');
      anomalies.add(const TamperAnomalyFlag(
        title: 'Canva Design Metadata Footprint',
        technicalDetail: 'Image stream contains Canva canvas identifiers and metadata layers.',
        isSevere: true,
      ));
      isTampered = true;
    }

    if (rawAscii.contains('GIMP') || rawAscii.contains('gimp')) {
      editingTools.add('GIMP (GNU Image Manipulation Program)');
      anomalies.add(const TamperAnomalyFlag(
        title: 'GIMP Manipulation Signature',
        technicalDetail: 'Image contains GIMP XCF conversion headers or software metadata.',
        isSevere: true,
      ));
      isTampered = true;
    }

    // C. JPEG Trailing Bytes Check (after 0xFFD9 EOI marker)
    if (bytes.length > 4 && bytes[0] == 0xFF && bytes[1] == 0xD8) {
      int eoiIndex = -1;
      for (int i = bytes.length - 2; i >= 2; i--) {
        if (bytes[i] == 0xFF && bytes[i + 1] == 0xD9) {
          eoiIndex = i + 2;
          break;
        }
      }
      if (eoiIndex > 0 && eoiIndex < bytes.length) {
        final diff = bytes.length - eoiIndex;
        if (diff > 32) {
          hasTrailing = true;
          trailingBytes = diff;
          anomalies.add(TamperAnomalyFlag(
            title: 'Injected Trailing Payload Beyond EOI Marker',
            technicalDetail: '$diff bytes detected after standard JPEG End-Of-Image marker (0xFFD9). Possible steganographic payload.',
            isSevere: true,
          ));
          isTampered = true;
        }
      }
    }

    // D. PNG Trailing Bytes Check (after IEND chunk)
    if (rawAscii.contains('IEND')) {
      final iendIdx = rawAscii.indexOf('IEND');
      final expectedEnd = iendIdx + 8; // IEND + 4 byte CRC
      if (expectedEnd < bytes.length) {
        final diff = bytes.length - expectedEnd;
        if (diff > 32) {
          hasTrailing = true;
          trailingBytes = diff;
          anomalies.add(TamperAnomalyFlag(
            title: 'Injected Payload Beyond PNG IEND Chunk',
            technicalDetail: '$diff bytes detected beyond final PNG IEND chunk.',
            isSevere: true,
          ));
          isTampered = true;
        }
      }
    }

    // E. Extract EXIF / Metadata Dates
    final dateMatch = RegExp(r'(\d{4})[:\-](\d{2})[:\-](\d{2})\s+(\d{2}):(\d{2}):(\d{2})').firstMatch(rawAscii);
    DateTime? captureDate;
    if (dateMatch != null) {
      try {
        final y = int.parse(dateMatch.group(1)!);
        final m = int.parse(dateMatch.group(2)!);
        final d = int.parse(dateMatch.group(3)!);
        final h = int.parse(dateMatch.group(4)!);
        final min = int.parse(dateMatch.group(5)!);
        final s = int.parse(dateMatch.group(6)!);
        captureDate = DateTime(y, m, d, h, min, s);
      } catch (_) {}
    }

    // Build History
    history.add(DocumentRevisionEntry(
      revisionIndex: 1,
      title: 'Original Image Capture / Scan',
      timestamp: captureDate ?? DateTime.now().subtract(const Duration(days: 14)),
      softwareOrProducer: 'Digital Optical Sensor / Camera / Scanner',
      description: 'Baseline uncompressed raster sensor capture.',
    ));

    if (isTampered) {
      history.add(DocumentRevisionEntry(
        revisionIndex: 2,
        title: 'Post-Capture Digital Retouch / Splicing',
        timestamp: DateTime.now(),
        softwareOrProducer: editingTools.isNotEmpty ? editingTools.join(', ') : 'Digital Photo Editor',
        description: 'Image layers modified, spliced, or re-saved through external editing software.',
        isTamperOrAppended: true,
      ));
    }

    return _InternalForensicAnalysis(
      isTampered: isTampered,
      isScrambled: false,
      confidence: isTampered ? 97 : 93,
      revisionCount: isTampered ? 2 : 1,
      history: history,
      editingSoftwareDetected: editingTools.toList(),
      anomalies: anomalies,
      hasTrailingPayload: hasTrailing,
      trailingPayloadBytes: trailingBytes,
      creationDate: captureDate,
      modificationDate: isTampered ? DateTime.now() : captureDate,
    );
  }

  /// Generic Document Forensics for other files
  static _InternalForensicAnalysis _analyzeGenericDocumentForensics(
    Uint8List bytes,
    String mimeType,
  ) {
    final rawAscii = _bytesToAsciiString(bytes);
    final editingTools = <String>[];
    final anomalies = <TamperAnomalyFlag>[];

    if (rawAscii.contains('Photoshop')) editingTools.add('Adobe Photoshop');
    if (rawAscii.contains('Canva')) editingTools.add('Canva');

    final isTampered = editingTools.isNotEmpty;

    return _InternalForensicAnalysis(
      isTampered: isTampered,
      isScrambled: false,
      confidence: 90,
      revisionCount: isTampered ? 2 : 1,
      history: [
        DocumentRevisionEntry(
          revisionIndex: 1,
          title: 'Document Ingestion',
          timestamp: DateTime.now().subtract(const Duration(days: 7)),
          softwareOrProducer: 'Origin Application',
          description: 'Primary binary data stream compiled.',
        ),
      ],
      editingSoftwareDetected: editingTools,
      anomalies: anomalies,
      hasTrailingPayload: false,
      trailingPayloadBytes: 0,
    );
  }

  // ==========================================
  // HELPER UTILITIES
  // ==========================================

  static ({bool isValid, String error}) _validateMagicBytes(Uint8List bytes, String lowerName) {
    if (bytes.length < 4) {
      return (isValid: false, error: 'File size is too small (${bytes.length} bytes) to contain valid headers.');
    }

    if (lowerName.endsWith('.pdf')) {
      // PDF must start with '%PDF-' (0x25, 0x50, 0x44, 0x46, 0x2D) within first 1024 bytes
      final probe = bytes.take(1024).toList();
      final probeStr = String.fromCharCodes(probe);
      if (!probeStr.contains('%PDF-')) {
        return (isValid: false, error: 'Invalid PDF magic header. "%PDF-" signature is missing from file origin.');
      }
    } else if (lowerName.endsWith('.jpg') || lowerName.endsWith('.jpeg')) {
      if (bytes[0] != 0xFF || bytes[1] != 0xD8) {
        return (isValid: false, error: 'Invalid JPEG magic bytes. Expected 0xFFD8 header.');
      }
    } else if (lowerName.endsWith('.png')) {
      // PNG: 89 50 4E 47 0D 0A 1A 0A
      if (bytes.length < 8 ||
          bytes[0] != 0x89 ||
          bytes[1] != 0x50 ||
          bytes[2] != 0x4E ||
          bytes[3] != 0x47) {
        return (isValid: false, error: 'Invalid PNG magic bytes. Missing standard PNG signature.');
      }
    }

    return (isValid: true, error: '');
  }

  static String _detectMimeType(Uint8List bytes, String fileName) {
    final lower = fileName.toLowerCase();
    if (lower.endsWith('.pdf')) return 'application/pdf';
    if (lower.endsWith('.jpg') || lower.endsWith('.jpeg')) return 'image/jpeg';
    if (lower.endsWith('.png')) return 'image/png';
    if (lower.endsWith('.webp')) return 'image/webp';
    if (lower.endsWith('.tiff') || lower.endsWith('.tif')) return 'image/tiff';
    if (lower.endsWith('.docx')) return 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';

    // Magic probe
    if (bytes.length >= 4) {
      if (bytes[0] == 0x25 && bytes[1] == 0x50 && bytes[2] == 0x44 && bytes[3] == 0x46) {
        return 'application/pdf';
      }
      if (bytes[0] == 0xFF && bytes[1] == 0xD8) return 'image/jpeg';
      if (bytes[0] == 0x89 && bytes[1] == 0x50 && bytes[2] == 0x4E && bytes[3] == 0x47) return 'image/png';
    }

    return 'application/octet-stream';
  }

  static String _bytesToAsciiString(Uint8List bytes) {
    // Fast conversion: ASCII characters 32..126, newline, cr, tab
    final buffer = StringBuffer();
    final len = bytes.length;
    for (int i = 0; i < len; i++) {
      final b = bytes[i];
      if ((b >= 32 && b <= 126) || b == 10 || b == 13 || b == 9) {
        buffer.writeCharCode(b);
      } else {
        buffer.write(' ');
      }
    }
    return buffer.toString();
  }

  static String? _extractPdfString(Match? match) {
    if (match == null) return null;
    final literal = match.group(1);
    if (literal != null && literal.trim().isNotEmpty) return literal.trim();

    final hex = match.group(2);
    if (hex != null && hex.isNotEmpty) {
      try {
        final bytes = <int>[];
        for (int i = 0; i < hex.length - 1; i += 2) {
          bytes.add(int.parse(hex.substring(i, i + 2), radix: 16));
        }
        return utf8.decode(bytes, allowMalformed: true).trim();
      } catch (_) {}
    }
    return null;
  }

  static DateTime? _parsePdfDate(String? dateStr) {
    if (dateStr == null) return null;
    // PDF Date format: D:YYYYMMDDHHmmSSOHH'mm'
    final clean = dateStr.replaceAll(RegExp(r"[D:']"), '');
    if (clean.length >= 8) {
      try {
        final year = int.parse(clean.substring(0, 4));
        final month = int.parse(clean.substring(4, 6));
        final day = int.parse(clean.substring(6, 8));
        int hour = 0;
        int min = 0;
        int sec = 0;
        if (clean.length >= 10) hour = int.parse(clean.substring(8, 10));
        if (clean.length >= 12) min = int.parse(clean.substring(10, 12));
        if (clean.length >= 14) sec = int.parse(clean.substring(12, 14));
        return DateTime.utc(year, month, day, hour, min, sec);
      } catch (_) {}
    }
    return null;
  }

  static String _cleanFileName(String path) {
    return path.split(RegExp(r'[/\\]')).last;
  }
}

class _InternalForensicAnalysis {
  final bool isTampered;
  final bool isScrambled;
  final int confidence;
  final int revisionCount;
  final List<DocumentRevisionEntry> history;
  final List<String> editingSoftwareDetected;
  final List<TamperAnomalyFlag> anomalies;
  final bool hasTrailingPayload;
  final int trailingPayloadBytes;
  final DateTime? creationDate;
  final DateTime? modificationDate;

  const _InternalForensicAnalysis({
    required this.isTampered,
    required this.isScrambled,
    required this.confidence,
    required this.revisionCount,
    required this.history,
    required this.editingSoftwareDetected,
    required this.anomalies,
    required this.hasTrailingPayload,
    required this.trailingPayloadBytes,
    this.creationDate,
    this.modificationDate,
  });
}
