import 'dart:typed_data';
import 'package:flutter/material.dart';
import '../../ledger/models/provenance_record.dart';

/// Primary verdict reached by the Document Forensic Engine
enum DocumentForensicVerdict {
  /// Pristine single-generation file with matching internal creation metadata,
  /// no incremental revisions, no external editor signatures, and valid bitstream.
  authenticOriginal,

  /// Document was modified post-issuance (incremental PDF revisions,
  /// editing software signatures like Photoshop/Canva/Acrobat, virtual printer flattening,
  /// missing statutory UIDAI signature, timestamp paradox, or steganography).
  tamperedEdited,

  /// File bitstream is scrambled, truncated, missing magic bytes, or structurally corrupted.
  scrambledCorrupted,

  /// File matches a sealed Kerberos ledger anchor with 100% cryptographic SHA-256 parity.
  sealedCryptographicMatch,

  /// File matches a sealed Kerberos ledger anchor but has been altered.
  sealedCryptographicTampered,

  /// File was compressed or transcoded by a social media or messaging platform (e.g. WhatsApp, Telegram).
  /// Metadata was stripped by the platform pipeline without malicious binary tampering.
  socialMediaTranscoded,
}

extension DocumentForensicVerdictExtension on DocumentForensicVerdict {
  String get label {
    switch (this) {
      case DocumentForensicVerdict.authenticOriginal:
        return 'AUTHENTIC ORIGINAL';
      case DocumentForensicVerdict.tamperedEdited:
        return 'TAMPERED / EDITED';
      case DocumentForensicVerdict.scrambledCorrupted:
        return 'SCRAMBLED / CORRUPTED';
      case DocumentForensicVerdict.sealedCryptographicMatch:
        return 'IMMUTABLE CRYPTOGRAPHIC ORIGINAL';
      case DocumentForensicVerdict.sealedCryptographicTampered:
        return 'SEALED ASSET TAMPERED';
      case DocumentForensicVerdict.socialMediaTranscoded:
        return 'TRANSCODED / SOCIAL MEDIA COPY';
    }
  }

  String get summary {
    switch (this) {
      case DocumentForensicVerdict.authenticOriginal:
        return 'Pristine single-generation document. No incremental revisions, editor signatures, or structural anomalies detected.';
      case DocumentForensicVerdict.tamperedEdited:
        return 'Document was modified post-issuance. Appended incremental revisions, editing software footprints, virtual printer flattening, or metadata paradoxes detected.';
      case DocumentForensicVerdict.scrambledCorrupted:
        return 'Binary bitstream is scrambled, truncated, or structurally corrupted. File headers or object tables fail integrity checks.';
      case DocumentForensicVerdict.sealedCryptographicMatch:
        return 'Verified with 100% mathematical certainty against immutable Kerberos ledger seal. Bitstream is bit-for-bit pristine.';
      case DocumentForensicVerdict.sealedCryptographicTampered:
        return 'Original cryptographic seal exists in ledger, but file content was modified. Bitstream parity is shattered.';
      case DocumentForensicVerdict.socialMediaTranscoded:
        return 'Document was re-encoded by WhatsApp, Telegram, or a messaging platform. Metadata was stripped by the platform pipeline. For statutory or legal audit, upload the uncompressed original PDF or raw camera scan.';
    }
  }

  Color get color {
    switch (this) {
      case DocumentForensicVerdict.authenticOriginal:
      case DocumentForensicVerdict.sealedCryptographicMatch:
        return const Color(0xFF10B981); // Emerald
      case DocumentForensicVerdict.tamperedEdited:
      case DocumentForensicVerdict.sealedCryptographicTampered:
        return const Color(0xFFF43F5E); // Rose / Crimson
      case DocumentForensicVerdict.scrambledCorrupted:
        return const Color(0xFFF59E0B); // Amber
      case DocumentForensicVerdict.socialMediaTranscoded:
        return const Color(0xFF38BDF8); // Sky Blue
    }
  }

  IconData get icon {
    switch (this) {
      case DocumentForensicVerdict.authenticOriginal:
      case DocumentForensicVerdict.sealedCryptographicMatch:
        return Icons.verified_rounded;
      case DocumentForensicVerdict.tamperedEdited:
      case DocumentForensicVerdict.sealedCryptographicTampered:
        return Icons.gpp_bad_rounded;
      case DocumentForensicVerdict.scrambledCorrupted:
        return Icons.warning_amber_rounded;
      case DocumentForensicVerdict.socialMediaTranscoded:
        return Icons.phonelink_ring_rounded;
    }
  }
}

/// A specific anomaly flag discovered during binary inspection
class TamperAnomalyFlag {
  final String title;
  final String technicalDetail;
  final bool isSevere;

  const TamperAnomalyFlag({
    required this.title,
    required this.technicalDetail,
    this.isSevere = true,
  });
}

/// A chronological revision entry extracted from the document structure
class DocumentRevisionEntry {
  final int revisionIndex;
  final String title;
  final DateTime? timestamp;
  final String? softwareOrProducer;
  final String description;
  final bool isTamperOrAppended;

  const DocumentRevisionEntry({
    required this.revisionIndex,
    required this.title,
    this.timestamp,
    this.softwareOrProducer,
    required this.description,
    this.isTamperOrAppended = false,
  });
}

/// Error Level Analysis (ELA) spatial quantization matrix and pixel-level heatmap
class DocumentElaAnalysis {
  final List<double> heatmapTensor; // 256 normalized floats (16x16 grid)
  final double peakErrorRate; // 0.0 to 1.0
  final double baselineErrorRate; // 0.0 to 1.0 (mean background residual)
  final String anomalyCoordinates;
  final bool hasSplicingAnomaly;
  final Uint8List? elaImageBytes; // Real encoded PNG of amplified ELA residual difference
  final Uint8List? thermalImageBytes; // Real false-color thermal heatmap PNG
  final Uint8List? previewImageBytes; // Base raster image PNG that was analyzed
  final int imageWidth;
  final int imageHeight;

  const DocumentElaAnalysis({
    required this.heatmapTensor,
    required this.peakErrorRate,
    this.baselineErrorRate = 0.124,
    required this.anomalyCoordinates,
    required this.hasSplicingAnomaly,
    this.elaImageBytes,
    this.thermalImageBytes,
    this.previewImageBytes,
    this.imageWidth = 0,
    this.imageHeight = 0,
  });
}

/// UIDAI Secure QR Code validation result
class DocumentQrValidation {
  final bool hasQrCode;
  final bool isUidaiSigned;
  final bool isTextMatchingQr;
  final String? extractedDemographics;
  final String? qrDiscrepancyDetail;

  const DocumentQrValidation({
    required this.hasQrCode,
    required this.isUidaiSigned,
    required this.isTextMatchingQr,
    this.extractedDemographics,
    this.qrDiscrepancyDetail,
  });
}

/// Incremental PDF text stream diff (extracted between revision 1 and revision 2)
class PdfRevisionDiff {
  final List<String> removedTokens;
  final List<String> addedTokens;
  final String summary;

  const PdfRevisionDiff({
    required this.removedTokens,
    required this.addedTokens,
    required this.summary,
  });

  bool get hasChanges => removedTokens.isNotEmpty || addedTokens.isNotEmpty;
}

/// Category of file being inspected by the forensic engine
enum ForensicFileCategory {
  document,
  image,
  audio,
  video,
  textData,
}

extension ForensicFileCategoryExtension on ForensicFileCategory {
  String get label {
    switch (this) {
      case ForensicFileCategory.document:
        return 'Document (PDF / Office)';
      case ForensicFileCategory.image:
        return 'Image (Visual Media)';
      case ForensicFileCategory.audio:
        return 'Acoustic Audio';
      case ForensicFileCategory.video:
        return 'Motion Video';
      case ForensicFileCategory.textData:
        return 'Text & Structured Data';
    }
  }

  IconData get icon {
    switch (this) {
      case ForensicFileCategory.document:
        return Icons.description_rounded;
      case ForensicFileCategory.image:
        return Icons.image_rounded;
      case ForensicFileCategory.audio:
        return Icons.audiotrack_rounded;
      case ForensicFileCategory.video:
        return Icons.videocam_rounded;
      case ForensicFileCategory.textData:
        return Icons.data_object_rounded;
    }
  }

  Color get themeColor {
    switch (this) {
      case ForensicFileCategory.document:
        return const Color(0xFF38BDF8);
      case ForensicFileCategory.image:
        return const Color(0xFFC084FC);
      case ForensicFileCategory.audio:
        return const Color(0xFF10B981);
      case ForensicFileCategory.video:
        return const Color(0xFFF59E0B);
      case ForensicFileCategory.textData:
        return const Color(0xFF06B6D4);
    }
  }
}

/// Audio-specific forensic inspection details
class AudioForensicsDetails {
  final String audioFormat;
  final String? audioDurationEstimate;
  final List<String> dawFootprints;
  final bool hasSilenceSplicing;
  final bool hasContainerSizeDivergence;
  final bool hasTrailingAudioPayload;
  final int trailingBytes;
  final String? audioIntegritySummary;

  const AudioForensicsDetails({
    required this.audioFormat,
    this.audioDurationEstimate,
    required this.dawFootprints,
    this.hasSilenceSplicing = false,
    this.hasContainerSizeDivergence = false,
    this.hasTrailingAudioPayload = false,
    this.trailingBytes = 0,
    this.audioIntegritySummary,
  });
}

/// Video-specific forensic inspection details
class VideoForensicsDetails {
  final String videoContainer;
  final String? videoCodec;
  final List<String> editorFootprints;
  final List<String> atomHierarchy;
  final bool hasAudioVideoDesync;
  final int desyncDeltaMs;
  final bool hasTrailingPayload;
  final int trailingBytes;
  final bool isMoovAtomValid;
  final String? videoIntegritySummary;

  const VideoForensicsDetails({
    required this.videoContainer,
    this.videoCodec,
    required this.editorFootprints,
    required this.atomHierarchy,
    this.hasAudioVideoDesync = false,
    this.desyncDeltaMs = 0,
    this.hasTrailingPayload = false,
    this.trailingBytes = 0,
    this.isMoovAtomValid = true,
    this.videoIntegritySummary,
  });
}

/// Text, code, and structured data forensic inspection details
class TextForensicsDetails {
  final String encoding;
  final String lineEndingProfile;
  final int crlfCount;
  final int lfCount;
  final bool hasMixedLineEndings;
  final bool hasInvisibleOrZeroWidthChars;
  final int invisibleCharCount;
  final bool hasHomoglyphSpoofing;
  final List<String> homoglyphFlags;
  final bool isCsvOrTable;
  final bool hasCsvColumnDrift;
  final int? expectedColumns;
  final List<int> anomalousRows;
  final bool isLogFile;
  final bool hasTimestampReversal;
  final String? logIntegritySummary;

  const TextForensicsDetails({
    required this.encoding,
    required this.lineEndingProfile,
    required this.crlfCount,
    required this.lfCount,
    required this.hasMixedLineEndings,
    this.hasInvisibleOrZeroWidthChars = false,
    this.invisibleCharCount = 0,
    this.hasHomoglyphSpoofing = false,
    this.homoglyphFlags = const [],
    this.isCsvOrTable = false,
    this.hasCsvColumnDrift = false,
    this.expectedColumns,
    this.anomalousRows = const [],
    this.isLogFile = false,
    this.hasTimestampReversal = false,
    this.logIntegritySummary,
  });
}

/// Complete forensic evaluation report for an uploaded document or media file
class DocumentForensicReport {
  final String fileName;
  final int fileSizeBytes;
  final Uint8List fileBytes;
  final String sha256Hash;
  final String mimeType;
  final ForensicFileCategory fileCategory;
  final DocumentForensicVerdict verdict;
  final int confidenceScore; // 0 to 100%
  final int revisionCount;
  final List<DocumentRevisionEntry> history;
  final List<String> editingSoftwareDetected;
  final List<TamperAnomalyFlag> anomalies;
  final bool isMagicByteValid;
  final bool hasTrailingPayload;
  final int trailingPayloadBytes;
  final DateTime? creationDate;
  final DateTime? modificationDate;
  final ProvenanceRecord? matchedLedgerRecord;

  // Advanced Forensic Hardening Indicators
  final bool isDigitalSignaturePresent;
  final bool isGovernmentOrAadhaarDoc;
  final bool isVirtualPrinterFlattened;
  final bool isScreenshotOrScreenCapture;
  final bool isSocialMediaCompressed;
  final String? digitalSignatureAlgorithm;

  // Multi-Media Specialized Analysis
  final DocumentElaAnalysis? elaAnalysis;
  final DocumentQrValidation? qrValidation;
  final PdfRevisionDiff? revisionDiff;
  final AudioForensicsDetails? audioForensics;
  final VideoForensicsDetails? videoForensics;
  final TextForensicsDetails? textForensics;

  const DocumentForensicReport({
    required this.fileName,
    required this.fileSizeBytes,
    required this.fileBytes,
    required this.sha256Hash,
    required this.mimeType,
    this.fileCategory = ForensicFileCategory.document,
    required this.verdict,
    required this.confidenceScore,
    required this.revisionCount,
    required this.history,
    required this.editingSoftwareDetected,
    required this.anomalies,
    required this.isMagicByteValid,
    required this.hasTrailingPayload,
    this.trailingPayloadBytes = 0,
    this.creationDate,
    this.modificationDate,
    this.matchedLedgerRecord,
    this.isDigitalSignaturePresent = false,
    this.isGovernmentOrAadhaarDoc = false,
    this.isVirtualPrinterFlattened = false,
    this.isScreenshotOrScreenCapture = false,
    this.isSocialMediaCompressed = false,
    this.digitalSignatureAlgorithm,
    this.elaAnalysis,
    this.qrValidation,
    this.revisionDiff,
    this.audioForensics,
    this.videoForensics,
    this.textForensics,
  });

  bool get isTampered =>
      verdict == DocumentForensicVerdict.tamperedEdited ||
      verdict == DocumentForensicVerdict.sealedCryptographicTampered;

  bool get isScrambled =>
      verdict == DocumentForensicVerdict.scrambledCorrupted;

  bool get isOriginal =>
      verdict == DocumentForensicVerdict.authenticOriginal ||
      verdict == DocumentForensicVerdict.sealedCryptographicMatch;

  bool get isTranscoded =>
      verdict == DocumentForensicVerdict.socialMediaTranscoded;

  bool get isPdf =>
      mimeType == 'application/pdf' || fileName.toLowerCase().endsWith('.pdf');

  bool get isImage =>
      fileCategory == ForensicFileCategory.image || mimeType.startsWith('image/');

  Map<String, String> get metadata {
    final map = <String, String>{};
    if (creationDate != null) map['created'] = creationDate!.toIso8601String();
    if (modificationDate != null) map['modified'] = modificationDate!.toIso8601String();
    if (editingSoftwareDetected.isNotEmpty) map['software'] = editingSoftwareDetected.first;
    for (final h in history) {
      if (h.softwareOrProducer != null && h.softwareOrProducer!.isNotEmpty) {
        map['producer'] = h.softwareOrProducer!;
        break;
      }
    }
    return map;
  }
}
