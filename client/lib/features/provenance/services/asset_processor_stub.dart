import 'package:cross_file/cross_file.dart';
import '../models/asset_metadata.dart';

/// Stub implementation to satisfy the compiler
class AssetProcessorImpl {
  static Future<AssetMetadata> process(XFile file) {
    throw UnsupportedError('Asset processing is not supported on this platform.');
  }
}
