class AssetMetadata {
  final String filePath;
  final String sha256Hash;
  final String? extractedText;
  final List<double>? perceptualHash; // For Vector Storage
  final bool isTampered;
  final String? originalSealedHash;
  final String? c2paManifestUri;

  AssetMetadata({
    required this.filePath,
    required this.sha256Hash,
    this.extractedText,
    this.perceptualHash,
    this.isTampered = false,
    this.originalSealedHash,
    this.c2paManifestUri,
  });

  AssetMetadata copyWith({
    String? filePath,
    String? sha256Hash,
    String? extractedText,
    List<double>? perceptualHash,
    bool? isTampered,
    String? originalSealedHash,
    String? c2paManifestUri,
  }) {
    return AssetMetadata(
      filePath: filePath ?? this.filePath,
      sha256Hash: sha256Hash ?? this.sha256Hash,
      extractedText: extractedText ?? this.extractedText,
      perceptualHash: perceptualHash ?? this.perceptualHash,
      isTampered: isTampered ?? this.isTampered,
      originalSealedHash: originalSealedHash ?? this.originalSealedHash,
      c2paManifestUri: c2paManifestUri ?? this.c2paManifestUri,
    );
  }

  @override
  String toString() {
    return 'AssetMetadata(filePath: $filePath, sha256Hash: $sha256Hash, isTampered: $isTampered, originalSealedHash: $originalSealedHash, hasText: ${extractedText != null}, hasVector: ${perceptualHash != null})';
  }
}
