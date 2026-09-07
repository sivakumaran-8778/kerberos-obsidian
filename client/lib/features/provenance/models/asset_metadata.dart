class AssetMetadata {
  final String filePath;
  final String sha256Hash;
  final String? extractedText;
  final List<double>? perceptualHash; // For Vector Storage

  AssetMetadata({
    required this.filePath,
    required this.sha256Hash,
    this.extractedText,
    this.perceptualHash,
  });

  @override
  String toString() {
    return 'AssetMetadata(filePath: $filePath, sha256Hash: $sha256Hash, hasText: ${extractedText != null}, hasVector: ${perceptualHash != null})';
  }
}
