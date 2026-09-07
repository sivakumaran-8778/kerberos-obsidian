import 'package:cross_file/cross_file.dart';
import '../models/asset_metadata.dart';
import 'asset_processor_stub.dart'
    if (dart.library.io) 'asset_processor_io.dart'
    if (dart.library.html) 'asset_processor_web.dart';

class AssetProcessor {
  static Future<AssetMetadata> processFile(XFile file, {bool signWithC2pa = true}) async {
    return AssetProcessorImpl.process(file, signWithC2pa: signWithC2pa);
  }
}
