import 'dart:typed_data';

/// Stub wrapper for the Zero-Trust Cryptographic Web Engines
class CryptoEngineWeb {
  
  static Future<Map<String, dynamic>> generateRedactionProof(Uint8List fileBytes, Map<String, dynamic> coords) async {
    throw UnsupportedError('zk-Redact Protocol is currently only supported on Web edge nodes.');
  }

  static Future<Map<String, dynamic>> verifyRedactionProof(
      Uint8List redactedBytes, 
      Map<String, dynamic> zkProof, 
      List<String> publicSignals, 
      Map<String, dynamic> verificationKey, 
      String expectedManifestHash) async {
    throw UnsupportedError('zk-Redact Protocol is currently only supported on Web edge nodes.');
  }

  static Future<Map<String, dynamic>> evaluateProvenance(Uint8List fileBytes, Map<String, dynamic> parsedC2paManifest) async {
    throw UnsupportedError('Provenance Evaluation is currently only supported on Web edge nodes.');
  }
}
