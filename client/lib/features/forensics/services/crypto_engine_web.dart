import 'dart:js_interop';
import 'dart:js_interop_unsafe';
import 'dart:typed_data';
import 'dart:convert';
import 'dart:js_util' as js_util;

/// Binds to window.generateRedactionProof
@JS('generateRedactionProof')
external JSPromise _generateRedactionProof(JSArrayBuffer originalFileBuffer, JSObject redactionCoordinates);

/// Binds to window.verifyRedactionProof
@JS('verifyRedactionProof')
external JSPromise _verifyRedactionProof(JSArrayBuffer redactedFileBuffer, JSObject zkProof, JSArray publicSignals, JSObject verificationKey, JSString expectedManifestHash);

/// Binds to window.evaluateProvenance
@JS('evaluateProvenance')
external JSPromise _evaluateProvenance(JSArrayBuffer fileBuffer, JSObject parsedC2paManifest);

/// Dart wrapper for the Zero-Trust Cryptographic Web Engines
class CryptoEngineWeb {
  
  /// Generates a Zero-Knowledge Proof for the redacted file buffer.
  static Future<Map<String, dynamic>> generateRedactionProof(Uint8List fileBytes, Map<String, dynamic> coords) async {
    final jsBuffer = fileBytes.buffer.toJS;
    final jsCoords = js_util.jsify(coords) as JSObject;

    final jsPromise = _generateRedactionProof(jsBuffer, jsCoords);
    final jsResult = await js_util.promiseToFuture<dynamic>(jsPromise);
    
    // Parse the resulting JS object back into a Dart map
    final dartMap = js_util.dartify(jsResult) as Map<dynamic, dynamic>;
    return dartMap.cast<String, dynamic>();
  }

  /// Verifies a zk-SNARK proof against a redacted file buffer and the trusted C2PA manifest.
  static Future<Map<String, dynamic>> verifyRedactionProof(
      Uint8List redactedBytes, 
      Map<String, dynamic> zkProof, 
      List<String> publicSignals, 
      Map<String, dynamic> verificationKey, 
      String expectedManifestHash) async {
    
    final jsBuffer = redactedBytes.buffer.toJS;
    final jsProof = js_util.jsify(zkProof) as JSObject;
    final jsSignals = js_util.jsify(publicSignals) as JSArray;
    final jsKey = js_util.jsify(verificationKey) as JSObject;
    final jsHash = expectedManifestHash.toJS;

    final jsPromise = _verifyRedactionProof(jsBuffer, jsProof, jsSignals, jsKey, jsHash);
    final jsResult = await js_util.promiseToFuture<dynamic>(jsPromise);
    
    final dartMap = js_util.dartify(jsResult) as Map<dynamic, dynamic>;
    return dartMap.cast<String, dynamic>();
  }

  /// Evaluates the provenance pipeline (Trust Anchor, Hash Binding, Blind Forensics Backstop)
  static Future<Map<String, dynamic>> evaluateProvenance(Uint8List fileBytes, Map<String, dynamic> parsedC2paManifest) async {
    final jsBuffer = fileBytes.buffer.toJS;
    final jsManifest = js_util.jsify(parsedC2paManifest) as JSObject;

    final jsPromise = _evaluateProvenance(jsBuffer, jsManifest);
    final jsResult = await js_util.promiseToFuture<dynamic>(jsPromise);
    
    final dartMap = js_util.dartify(jsResult) as Map<dynamic, dynamic>;
    return dartMap.cast<String, dynamic>();
  }
}
