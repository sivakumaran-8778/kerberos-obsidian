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

/// Complete forensic evaluation report for an uploaded document
class DocumentForensicReport {
  final String fileName;
  final int fileSizeBytes;
  final Uint8List fileBytes;
  final String sha256Hash;
  final String mimeType;
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

  const DocumentForensicReport({
    required this.fileName,
    required this.fileSizeBytes,
    required this.fileBytes,
    required this.sha256Hash,
    required this.mimeType,
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
}
