import 'dart:ffi';
import 'package:ffi/ffi.dart';
import 'dart:io';

/// Defines the C struct mapped to Dart
final class C2paResult extends Struct {
  @Bool()
  external bool success;

  external Pointer<Utf8> manifestJson;
  external Pointer<Utf8> errorMsg;
}

// Function typedefs bridging Dart and C
typedef SignAssetC = Pointer<C2paResult> Function(Pointer<Utf8> filePath, Pointer<Utf8> claimData);
typedef SignAssetDart = Pointer<C2paResult> Function(Pointer<Utf8> filePath, Pointer<Utf8> claimData);

typedef FreeC2paResultC = Void Function(Pointer<C2paResult> ptr);
typedef FreeC2paResultDart = void Function(Pointer<C2paResult> ptr);

/// The C2PA Engine manages the FFI boundary, ensuring absolutely leak-proof execution.
class C2paEngine {
  late final DynamicLibrary _lib;
  late final SignAssetDart _signAsset;
  late final FreeC2paResultDart _freeC2paResult;

  C2paEngine() {
    // Dynamic loading configuration for edge environments (Mobile/Desktop)
    _lib = Platform.isAndroid 
        ? DynamicLibrary.open('libcore.so') 
        : DynamicLibrary.process(); 

    _signAsset = _lib.lookupFunction<SignAssetC, SignAssetDart>('sign_asset');
    _freeC2paResult = _lib.lookupFunction<FreeC2paResultC, FreeC2paResultDart>('free_c2pa_result');
  }

  /// Injects C2PA JUMBF payload into the asset.
  /// Strictly guarantees memory cleanup via try/finally blocks to prevent C-pointer leaks.
  String signAsset(String filePath, String claimData) {
    // Allocate memory on the native heap for strings passing to Rust
    final filePathPtr = filePath.toNativeUtf8();
    final claimDataPtr = claimData.toNativeUtf8();
    
    Pointer<C2paResult>? resultPtr;

    try {
      // Execute the heavy Rust function
      resultPtr = _signAsset(filePathPtr, claimDataPtr);

      if (resultPtr == nullptr) {
        throw Exception("Zero-Trust Fault: FFI returned a fatal null pointer from Rust");
      }

      final result = resultPtr.ref;

      if (!result.success) {
        final errorMsg = result.errorMsg != nullptr ? result.errorMsg.toDartString() : "Unknown FFI Native Error";
        throw Exception("C2PA Injection Failed: $errorMsg");
      }

      // Extract the successful manifest JSON
      final manifestJson = result.manifestJson != nullptr ? result.manifestJson.toDartString() : "";
      return manifestJson;
      
    } finally {
      // 1. Free Dart allocated memory (malloc/calloc)
      calloc.free(filePathPtr);
      calloc.free(claimDataPtr);
      
      // 2. CRITICAL MEMORY SAFETY: Instruct Rust to free its own allocations
      if (resultPtr != null && resultPtr != nullptr) {
        _freeC2paResult(resultPtr);
      }
    }
  }
}
