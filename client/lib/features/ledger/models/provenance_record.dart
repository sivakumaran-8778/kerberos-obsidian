import 'package:hive/hive.dart';

part 'provenance_record.g.dart';

/// The core data structure representing a securely sealed provenance event.
/// To be stored exclusively within the encrypted local ledger.
@HiveType(typeId: 0)
class ProvenanceRecord extends HiveObject {
  @HiveField(0)
  final String id; // Secure UUID

  @HiveField(1)
  final String originalFileHash; // Immutable SHA-256 verification

  @HiveField(2)
  final String c2paManifestUri; // JUMBF Payload identifier

  @HiveField(3)
  final DateTime timestamp;

  @HiveField(4)
  final String signature; // Ed25519 Cryptographic Signature proving device-origin

  @HiveField(5)
  final String filePath; // Explicit physical path required for P2P transfer

  ProvenanceRecord({
    required this.id,
    required this.originalFileHash,
    required this.c2paManifestUri,
    required this.timestamp,
    required this.signature,
    required this.filePath,
  });
}
