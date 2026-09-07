import 'package:riverpod_annotation/riverpod_annotation.dart';
import 'package:uuid/uuid.dart';
import '../models/asset_metadata.dart';
import '../services/asset_processor.dart';
import '../../ledger/models/provenance_record.dart';
import '../../auth/providers/auth_providers.dart';
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
      final secureLedger = ref.read(ledgerProvider);
      final currentEmail = ref.read(currentUserProvider)?.email;
      final inBaseName = file.name.split(RegExp(r'[\\/]')).last;

      // 1. Check if an asset with this base filename was already sealed in the ledger
      final existingRecordByName = secureLedger.getRecordByFileName(inBaseName, filterEmail: currentEmail);

      // 2. Offload to Dart Isolate (Hashes & Vector extraction)
      // Skip C2PA injection if this file was already sealed to avoid re-writing manifests over tampered or sealed files
      final metadata = await AssetProcessor.processFile(
        file,
        signWithC2pa: existingRecordByName == null,
      );

      // 3. Check for tampering: If filename matches an existing record but SHA-256 diverges
      if (existingRecordByName != null) {
        final sealedHash = existingRecordByName.originalFileHash.trim().toLowerCase();
        final currentHash = metadata.sha256Hash.trim().toLowerCase();

        if (sealedHash != currentHash) {
          // ZERO-TRUST TAMPER DETECTED!
          // Keep the original SHA-256 and original C2PA manifest intact.
          // DO NOT write a new manifest. DO NOT update the ledger.
          final tamperedMeta = metadata.copyWith(
            isTampered: true,
            originalSealedHash: existingRecordByName.originalFileHash,
            c2paManifestUri: existingRecordByName.c2paManifestUri,
          );
          state = AsyncValue.data(tamperedMeta);
          return;
        }
      }
      
      // 4. Construct the immutable Provenance Record (reuse existing ID if file was previously sealed)
      final existingRecord = existingRecordByName ?? secureLedger.getRecordByHash(metadata.sha256Hash, filterEmail: currentEmail);
      final manifestUri = existingRecord?.c2paManifestUri ?? 'urn:kerberos:sealed:${metadata.sha256Hash.substring(0, 12)}';

      final record = ProvenanceRecord(
        id: existingRecord?.id ?? const Uuid().v4(),
        originalFileHash: metadata.sha256Hash,
        c2paManifestUri: manifestUri,
        timestamp: DateTime.now(),
        signature: 'ed25519-placeholder-signature', // Provisioned from .env in full prod
        filePath: metadata.filePath,
        ownerEmail: currentEmail,
      );
      
      // 5. Seal into the AES-256 Air-Gapped Hive DB (deduplicates in-place)
      await secureLedger.addRecord(record);
      
      state = AsyncValue.data(metadata.copyWith(
        c2paManifestUri: manifestUri,
      ));
    } catch (e, stackTrace) {
      // Zero-Trust Silent Exception Routing
      state = AsyncValue.error(e, stackTrace);
    }
  }
}
