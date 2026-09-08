import 'dart:js_interop';
import 'dart:typed_data';
import 'package:image/image.dart' as img;

/// Binds to window.generateRedactionProof
@JS('generateRedactionProof')
external JSPromise<JSAny?> _generateRedactionProof(JSArrayBuffer originalFileBuffer, JSObject redactionCoordinates);

/// Binds to window.verifyRedactionProof
@JS('verifyRedactionProof')
external JSPromise<JSAny?> _verifyRedactionProof(JSArrayBuffer redactedFileBuffer, JSObject zkProof, JSArray publicSignals, JSObject verificationKey, JSString expectedManifestHash);

/// Binds to window.evaluateProvenance
@JS('evaluateProvenance')
external JSPromise<JSAny?> _evaluateProvenance(JSArrayBuffer fileBuffer, JSObject parsedC2paManifest);

/// Dart wrapper for the Zero-Trust Cryptographic Web Engines
class CryptoEngineWeb {
  /// Destructively blackouts pixels in the selected rectangle and returns new PNG bytes
  static Uint8List applyPixelBlackout(Uint8List originalBytes, Map<String, dynamic> coords) {
    final decoded = img.decodeImage(originalBytes);
    if (decoded == null) return originalBytes;

    final int rx = (coords['x'] as num).toInt();
    final int ry = (coords['y'] as num).toInt();
    final int rw = (coords['width'] as num).toInt();
    final int rh = (coords['height'] as num).toInt();

    for (int y = ry; y < ry + rh; y++) {
      for (int x = rx; x < rx + rw; x++) {
        if (x >= 0 && x < decoded.width && y >= 0 && y < decoded.height) {
          decoded.setPixelRgb(x, y, 0, 0, 0);
        }
      }
    }

    return Uint8List.fromList(img.encodePng(decoded));
  }
  
  /// Generates a Zero-Knowledge Proof for the redacted file buffer.
  static Future<Map<String, dynamic>> generateRedactionProof(Uint8List fileBytes, Map<String, dynamic> coords) async {
    final jsBuffer = fileBytes.buffer.toJS;
    // Basic conversion for coordinates map to JSObject
    final jsCoords = coords.jsify() as JSObject;

    final jsPromise = _generateRedactionProof(jsBuffer, jsCoords);
    final jsResult = await jsPromise.toDart;
    
    final dartMap = (jsResult as JSObject).dartify() as Map<dynamic, dynamic>;
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
    final jsProof = zkProof.jsify() as JSObject;
    final jsSignals = publicSignals.jsify() as JSArray;
    final jsKey = verificationKey.jsify() as JSObject;
    final jsHash = expectedManifestHash.toJS;

    final jsPromise = _verifyRedactionProof(jsBuffer, jsProof, jsSignals, jsKey, jsHash);
    final jsResult = await jsPromise.toDart;
    
    final dartMap = (jsResult as JSObject).dartify() as Map<dynamic, dynamic>;
    return dartMap.cast<String, dynamic>();
  }

  /// Evaluates the provenance pipeline (Trust Anchor, Hash Binding, Blind Forensics Backstop)
  static Future<Map<String, dynamic>> evaluateProvenance(Uint8List fileBytes, Map<String, dynamic> parsedC2paManifest) async {
    final jsBuffer = fileBytes.buffer.toJS;
    final jsManifest = parsedC2paManifest.jsify() as JSObject;

    final jsPromise = _evaluateProvenance(jsBuffer, jsManifest);
    final jsResult = await jsPromise.toDart;
    
    final dartMap = (jsResult as JSObject).dartify() as Map<dynamic, dynamic>;
    return dartMap.cast<String, dynamic>();
  }
}
