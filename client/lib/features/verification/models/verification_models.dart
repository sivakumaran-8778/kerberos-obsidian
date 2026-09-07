import 'dart:typed_data';
import '../../ledger/models/provenance_record.dart';

/// Overall verification status of an asset under the Zero-Trust Protocol
enum VerificationVerdict {
  /// File is cryptographically pristine: SHA-256 bitstream valid, C2PA JUMBF envelope intact, perceptual delta 0.00%.
  pristineSealed,

  /// Microscopic 1-byte or multi-byte alteration detected against the signed C2PA manifest.
  bitstreamShattered,

  /// File structure and container intact, but visual steganographic tampering / hue drift detected by edge inference.
  steganographyAltered,

  /// Third-party platform (e.g. WhatsApp, Discord, email proxy) stripped C2PA JUMBF metadata.
  metadataScrubbed,

  /// File has never been sealed under the Obsidian Protocol.
  unsealed,
}

/// Result of Test 1: The Hex Editor Attack (Bitstream Shatter)
class BitstreamCheck {
  final String computedHash;
  final String manifestHash;
  final bool isMatch;
  final int flippedBytesCount;
  final int? byteOffset;
  final int? originalByteValue;
  final int? tamperedByteValue;
  final bool stealthAlertTriggered;

  const BitstreamCheck({
    required this.computedHash,
    required this.manifestHash,
    required this.isMatch,
    this.flippedBytesCount = 0,
    this.byteOffset,
    this.originalByteValue,
    this.tamperedByteValue,
    this.stealthAlertTriggered = false,
  });

  BitstreamCheck copyWith({
    String? computedHash,
    String? manifestHash,
    bool? isMatch,
    int? flippedBytesCount,
    int? byteOffset,
    int? originalByteValue,
    int? tamperedByteValue,
    bool? stealthAlertTriggered,
  }) {
    return BitstreamCheck(
      computedHash: computedHash ?? this.computedHash,
      manifestHash: manifestHash ?? this.manifestHash,
      isMatch: isMatch ?? this.isMatch,
      flippedBytesCount: flippedBytesCount ?? this.flippedBytesCount,
      byteOffset: byteOffset ?? this.byteOffset,
      originalByteValue: originalByteValue ?? this.originalByteValue,
      tamperedByteValue: tamperedByteValue ?? this.tamperedByteValue,
      stealthAlertTriggered: stealthAlertTriggered ?? this.stealthAlertTriggered,
    );
  }
}

/// Result of Test 2: The Steganography Attack (Edge-Native Inference & Heat-Map)
class SteganographyCheck {
  final double perceptualDrift; // Percentage drift, e.g. 0.00% to 100.00%
  final bool isAltered;
  final String? anomalyCoordinates;
  final List<double> heatmapVector; // 256-cell tensor (16x16 grid)
  final bool rtxAccelerationActive;
  final String inferenceModel;

  const SteganographyCheck({
    required this.perceptualDrift,
    required this.isAltered,
    this.anomalyCoordinates,
    required this.heatmapVector,
    this.rtxAccelerationActive = true,
    this.inferenceModel = 'Edge-Native Anomaly Embedding (RTX Tensor Core)',
  });

  SteganographyCheck copyWith({
    double? perceptualDrift,
    bool? isAltered,
    String? anomalyCoordinates,
    List<double>? heatmapVector,
    bool? rtxAccelerationActive,
    String? inferenceModel,
  }) {
    return SteganographyCheck(
      perceptualDrift: perceptualDrift ?? this.perceptualDrift,
      isAltered: isAltered ?? this.isAltered,
      anomalyCoordinates: anomalyCoordinates ?? this.anomalyCoordinates,
      heatmapVector: heatmapVector ?? this.heatmapVector,
      rtxAccelerationActive: rtxAccelerationActive ?? this.rtxAccelerationActive,
      inferenceModel: inferenceModel ?? this.inferenceModel,
    );
  }
}

/// Result of Test 3: The Metadata Scrub (Social Media Interception)
class MetadataScrubCheck {
  final bool hasJumbfPayload;
  final String? c2paVersion;
  final String? boxType;
  final String? signerDevice;
  final bool originCertificateValid;
  final bool isScrubbed;
  final String? interceptorDiagnosis;

  const MetadataScrubCheck({
    required this.hasJumbfPayload,
    this.c2paVersion,
    this.boxType,
    this.signerDevice,
    required this.originCertificateValid,
    required this.isScrubbed,
    this.interceptorDiagnosis,
  });

  MetadataScrubCheck copyWith({
    bool? hasJumbfPayload,
    String? c2paVersion,
    String? boxType,
    String? signerDevice,
    bool? originCertificateValid,
    bool? isScrubbed,
    String? interceptorDiagnosis,
  }) {
    return MetadataScrubCheck(
      hasJumbfPayload: hasJumbfPayload ?? this.hasJumbfPayload,
      c2paVersion: c2paVersion ?? this.c2paVersion,
      boxType: boxType ?? this.boxType,
      signerDevice: signerDevice ?? this.signerDevice,
      originCertificateValid: originCertificateValid ?? this.originCertificateValid,
      isScrubbed: isScrubbed ?? this.isScrubbed,
      interceptorDiagnosis: interceptorDiagnosis ?? this.interceptorDiagnosis,
    );
  }
}

/// Result of Test 4: The Injection Attack (Sanitization Check)
class SanitizationCheck {
  final String rawInput;
  final String sanitizedOutput;
  final List<String> threatsNeutralized;
  final bool inputLaneSecured;
  final String sanitizationPolicy;

  const SanitizationCheck({
    required this.rawInput,
    required this.sanitizedOutput,
    required this.threatsNeutralized,
    required this.inputLaneSecured,
    this.sanitizationPolicy = 'Strict Text-Lane Only (RFC 3986 / C2PA Spec)',
  });

  SanitizationCheck copyWith({
    String? rawInput,
    String? sanitizedOutput,
    List<String>? threatsNeutralized,
    bool? inputLaneSecured,
    String? sanitizationPolicy,
  }) {
    return SanitizationCheck(
      rawInput: rawInput ?? this.rawInput,
      sanitizedOutput: sanitizedOutput ?? this.sanitizedOutput,
      threatsNeutralized: threatsNeutralized ?? this.threatsNeutralized,
      inputLaneSecured: inputLaneSecured ?? this.inputLaneSecured,
      sanitizationPolicy: sanitizationPolicy ?? this.sanitizationPolicy,
    );
  }
}

/// Complete Zero-Trust Verification Report encompassing all 4 QA vectors
class CompleteVerificationReport {
  final String fileName;
  final int fileSizeBytes;
  final Uint8List? fileBytes;
  final DateTime timestamp;
  final VerificationVerdict verdict;
  final BitstreamCheck bitstream;
  final SteganographyCheck steganography;
  final MetadataScrubCheck metadataScrub;
  final SanitizationCheck sanitization;

  /// The cryptographic ledger anchor matched via content-addressable SHA-256 or C2PA manifest
  final ProvenanceRecord? matchedRecord;

  /// The original filename sealed when the asset was first ingested into the air-gapped ledger
  final String? originalSealedName;

  /// True if the current file was renamed, but its cryptographic bitstream seal remains intact
  final bool isRenamed;

  /// Human-readable explanation of how the zero-trust correlation was established
  final String? matchReason;

  const CompleteVerificationReport({
    required this.fileName,
    required this.fileSizeBytes,
    this.fileBytes,
    required this.timestamp,
    required this.verdict,
    required this.bitstream,
    required this.steganography,
    required this.metadataScrub,
    required this.sanitization,
    this.matchedRecord,
    this.originalSealedName,
    this.isRenamed = false,
    this.matchReason,
  });

  CompleteVerificationReport copyWith({
    String? fileName,
    int? fileSizeBytes,
    Uint8List? fileBytes,
    DateTime? timestamp,
    VerificationVerdict? verdict,
    BitstreamCheck? bitstream,
    SteganographyCheck? steganography,
    MetadataScrubCheck? metadataScrub,
    SanitizationCheck? sanitization,
    ProvenanceRecord? matchedRecord,
    String? originalSealedName,
    bool? isRenamed,
    String? matchReason,
  }) {
    return CompleteVerificationReport(
      fileName: fileName ?? this.fileName,
      fileSizeBytes: fileSizeBytes ?? this.fileSizeBytes,
      fileBytes: fileBytes ?? this.fileBytes,
      timestamp: timestamp ?? this.timestamp,
      verdict: verdict ?? this.verdict,
      bitstream: bitstream ?? this.bitstream,
      steganography: steganography ?? this.steganography,
      metadataScrub: metadataScrub ?? this.metadataScrub,
      sanitization: sanitization ?? this.sanitization,
      matchedRecord: matchedRecord ?? this.matchedRecord,
      originalSealedName: originalSealedName ?? this.originalSealedName,
      isRenamed: isRenamed ?? this.isRenamed,
      matchReason: matchReason ?? this.matchReason,
    );
  }
}
