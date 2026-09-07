import 'package:riverpod_annotation/riverpod_annotation.dart';
import 'package:uuid/uuid.dart';
import '../models/asset_metadata.dart';
import '../services/asset_processor.dart';
import '../../ledger/models/provenance_record.dart';
import '../../../main.dart'; // Importer for ledgerProvider
import 'package:cross_file/cross_file.dart';

part 'provenance_providers.g.dart';

@riverpod
class ProvenanceTaskNotifier extends _$ProvenanceTaskNotifier {
  
  @override
  FutureOr<AssetMetadata?> build() {
    return null;
  }

  Future<void> ingestFile(XFile file) async {
    state = const AsyncValue.loading();
    
    try {
      // 1. Offload to Dart Isolate (Hashes & FFI Sealing)
      final metadata = await AssetProcessor.processFile(file);
      
      // 2. Fetch the globally initialized LedgerService
      final secureLedger = ref.read(ledgerProvider);
      
      // 3. Construct the immutable Providence Record
      final record = ProvenanceRecord(
        id: const Uuid().v4(), // Generate secure UUID
        originalFileHash: metadata.sha256Hash,
        c2paManifestUri: 'urn:kerberos:sealed:${metadata.sha256Hash.substring(0, 12)}',
        timestamp: DateTime.now(),
        signature: 'ed25519-placeholder-signature', // Provisioned from .env in full prod
        filePath: metadata.filePath,
      );
      
      // 4. Seal into the AES-256 Air-Gapped Hive DB
      await secureLedger.addRecord(record);
      
      state = AsyncValue.data(metadata);
    } catch (e, stackTrace) {
      // Zero-Trust Silent Exception Routing
      state = AsyncValue.error(e, stackTrace);
    }
  }
}
