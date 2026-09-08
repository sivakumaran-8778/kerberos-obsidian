import 'dart:convert';

/// Media modality inspected by the AI detection engine.
enum AiDetectionModality {
  document,
  image,
  video,
}

/// Final forensic classification verdict.
enum AiDetectionVerdict {
  humanAuthored,
  aiGenerated,
  aiAssisted,
  deepfakeManipulated,
  inconclusive,
}

/// Enterprise risk severity level.
enum AiRiskLevel {
  negligible,
  low,
  moderate,
  elevated,
  critical,
}

/// Status of individual enterprise compliance checkpoints.
enum AiCheckpointStatus {
  passed,
  flagged,
  warning,
  info,
}

/// Quantitative breakdown across independent forensic vectors.
class AiVectorBreakdown {
  final double provenanceScore; // 0.0 (Clean/Human) to 1.0 (AI Tagged)
  final double stylometricScore; // 0.0 (High Burstiness) to 1.0 (Uniform LLM)
  final double spectralArtifactScore; // 0.0 (Natural Sensor) to 1.0 (Diffusion Grid)
  final double neuralConfidenceScore; // 0.0 (Human) to 1.0 (Gemini 2.5 Flash Synthetic)

  const AiVectorBreakdown({
    this.provenanceScore = 0.0,
    this.stylometricScore = 0.0,
    this.spectralArtifactScore = 0.0,
    this.neuralConfidenceScore = 0.0,
  });

  Map<String, dynamic> toJson() => {
        'provenanceScore': provenanceScore,
        'stylometricScore': stylometricScore,
        'spectralArtifactScore': spectralArtifactScore,
        'neuralConfidenceScore': neuralConfidenceScore,
      };

  factory AiVectorBreakdown.fromJson(Map<String, dynamic> json) =>
      AiVectorBreakdown(
        provenanceScore: (json['provenanceScore'] as num?)?.toDouble() ?? 0.0,
        stylometricScore: (json['stylometricScore'] as num?)?.toDouble() ?? 0.0,
        spectralArtifactScore:
            (json['spectralArtifactScore'] as num?)?.toDouble() ?? 0.0,
        neuralConfidenceScore:
            (json['neuralConfidenceScore'] as num?)?.toDouble() ?? 0.0,
      );
}

/// Segment-level text forensic unit for highlighting AI spans in documents.
class AiTextSpanSegment {
  final int sentenceIndex;
  final String text;
  final double aiProbability; // 0.0 to 1.0
  final String reason;
  final bool isFlagged;

  const AiTextSpanSegment({
    required this.sentenceIndex,
    required this.text,
    required this.aiProbability,
    required this.reason,
    required this.isFlagged,
  });

  Map<String, dynamic> toJson() => {
        'sentenceIndex': sentenceIndex,
        'text': text,
        'aiProbability': aiProbability,
        'reason': reason,
        'isFlagged': isFlagged,
      };

  factory AiTextSpanSegment.fromJson(Map<String, dynamic> json) =>
      AiTextSpanSegment(
        sentenceIndex: json['sentenceIndex'] as int? ?? 0,
        text: json['text'] as String? ?? '',
        aiProbability: (json['aiProbability'] as num?)?.toDouble() ?? 0.0,
        reason: json['reason'] as String? ?? '',
        isFlagged: json['isFlagged'] as bool? ?? false,
      );
}

/// Enterprise verification checkpoint.
class AiCheckPoint {
  final String id;
  final String title;
  final String subtitle;
  final AiCheckpointStatus status;
  final String details;
  final double confidence; // 0.0 to 1.0

  const AiCheckPoint({
    required this.id,
    required this.title,
    required this.subtitle,
    required this.status,
    required this.details,
    this.confidence = 1.0,
  });

  Map<String, dynamic> toJson() => {
        'id': id,
        'title': title,
        'subtitle': subtitle,
        'status': status.name,
        'details': details,
        'confidence': confidence,
      };

  factory AiCheckPoint.fromJson(Map<String, dynamic> json) => AiCheckPoint(
        id: json['id'] as String? ?? '',
        title: json['title'] as String? ?? '',
        subtitle: json['subtitle'] as String? ?? '',
        status: AiCheckpointStatus.values.firstWhere(
          (e) => e.name == json['status'],
          orElse: () => AiCheckpointStatus.info,
        ),
        details: json['details'] as String? ?? '',
        confidence: (json['confidence'] as num?)?.toDouble() ?? 1.0,
      );
}

/// Master Forensic Report for AI Content & Deepfake Scanner.
class AiDetectionReport {
  final String fileName;
  final int fileSize;
  final String mimeType;
  final String sha256Hash;
  final DateTime analyzedAt;
  final AiDetectionModality modality;
  final double overallAiProbability; // 0.0 to 100.0%
  final AiDetectionVerdict verdict;
  final AiRiskLevel riskLevel;
  final String detectedModelFamily;
  final String executiveSummary;
  final AiVectorBreakdown vectorBreakdown;
  final List<AiCheckPoint> checkpoints;
  final bool isNeuralVerified;
  final String neuralEngineModel; // e.g. "gemini-2.5-flash"

  // Document specifics
  final List<AiTextSpanSegment> textSegments;
  final double burstinessVariance;
  final double perplexityEstimate;
  final double lexicalDiversityTtr;
  final List<String> detectedBoilerplatePhrases;

  // Image specifics
  final List<double> spectralFftGrid; // 16x16 = 256 values
  final double highFrequencyAnomalyScore;
  final Map<String, String> extractedGenerativeMetadata;
  final bool hasC2paManifest;

  // Video specifics
  final double temporalFlickerVariance;
  final int analyzedFrameCount;
  final List<double> frameDeltaTimeline;

  const AiDetectionReport({
    required this.fileName,
    required this.fileSize,
    required this.mimeType,
    required this.sha256Hash,
    required this.analyzedAt,
    required this.modality,
    required this.overallAiProbability,
    required this.verdict,
    required this.riskLevel,
    required this.detectedModelFamily,
    required this.executiveSummary,
    required this.vectorBreakdown,
    required this.checkpoints,
    this.isNeuralVerified = false,
    this.neuralEngineModel = 'gemini-2.5-flash',
    this.textSegments = const [],
    this.burstinessVariance = 0.0,
    this.perplexityEstimate = 0.0,
    this.lexicalDiversityTtr = 0.0,
    this.detectedBoilerplatePhrases = const [],
    this.spectralFftGrid = const [],
    this.highFrequencyAnomalyScore = 0.0,
    this.extractedGenerativeMetadata = const {},
    this.hasC2paManifest = false,
    this.temporalFlickerVariance = 0.0,
    this.analyzedFrameCount = 0,
    this.frameDeltaTimeline = const [],
  });

  String get verdictLabel {
    switch (verdict) {
      case AiDetectionVerdict.humanAuthored:
        return 'HUMAN AUTHORED';
      case AiDetectionVerdict.aiGenerated:
        return 'AI GENERATED (SYNTHETIC)';
      case AiDetectionVerdict.aiAssisted:
        return 'AI ASSISTED / HYBRID';
      case AiDetectionVerdict.deepfakeManipulated:
        return 'DEEPFAKE MANIPULATED';
      case AiDetectionVerdict.inconclusive:
        return 'INCONCLUSIVE TELEMETRY';
    }
  }

  String get riskLabel {
    switch (riskLevel) {
      case AiRiskLevel.negligible:
        return 'NEGLIGIBLE RISK';
      case AiRiskLevel.low:
        return 'LOW RISK';
      case AiRiskLevel.moderate:
        return 'MODERATE RISK';
      case AiRiskLevel.elevated:
        return 'ELEVATED RISK';
      case AiRiskLevel.critical:
        return 'CRITICAL THREAT';
    }
  }

  Map<String, dynamic> toJson() => {
        'fileName': fileName,
        'fileSize': fileSize,
        'mimeType': mimeType,
        'sha256Hash': sha256Hash,
        'analyzedAt': analyzedAt.toIso8601String(),
        'modality': modality.name,
        'overallAiProbability': overallAiProbability,
        'verdict': verdict.name,
        'riskLevel': riskLevel.name,
        'detectedModelFamily': detectedModelFamily,
        'executiveSummary': executiveSummary,
        'vectorBreakdown': vectorBreakdown.toJson(),
        'checkpoints': checkpoints.map((c) => c.toJson()).toList(),
        'isNeuralVerified': isNeuralVerified,
        'neuralEngineModel': neuralEngineModel,
        'textSegments': textSegments.map((s) => s.toJson()).toList(),
        'burstinessVariance': burstinessVariance,
        'perplexityEstimate': perplexityEstimate,
        'lexicalDiversityTtr': lexicalDiversityTtr,
        'detectedBoilerplatePhrases': detectedBoilerplatePhrases,
        'spectralFftGrid': spectralFftGrid,
        'highFrequencyAnomalyScore': highFrequencyAnomalyScore,
        'extractedGenerativeMetadata': extractedGenerativeMetadata,
        'hasC2paManifest': hasC2paManifest,
        'temporalFlickerVariance': temporalFlickerVariance,
        'analyzedFrameCount': analyzedFrameCount,
        'frameDeltaTimeline': frameDeltaTimeline,
      };

  String toPrettyJson() => const JsonEncoder.withIndent('  ').convert(toJson());
}
