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

  @HiveField(6)
  final String? ownerEmail;

  ProvenanceRecord({
    required this.id,
    required this.originalFileHash,
    required this.c2paManifestUri,
    required this.timestamp,
    required this.signature,
    required this.filePath,
    this.ownerEmail,
  });

  Map<String, dynamic> toJson() => {
    'id': id,
    'originalFileHash': originalFileHash,
    'c2paManifestUri': c2paManifestUri,
    'timestamp': timestamp.toIso8601String(),
    'signature': signature,
    'filePath': filePath,
    if (ownerEmail != null) 'ownerEmail': ownerEmail,
  };

  factory ProvenanceRecord.fromJson(Map<String, dynamic> json) => ProvenanceRecord(
    id: json['id']?.toString() ?? '',
    originalFileHash: json['originalFileHash']?.toString() ?? '',
    c2paManifestUri: json['c2paManifestUri']?.toString() ?? '',
    timestamp: json['timestamp'] != null
        ? DateTime.tryParse(json['timestamp'].toString()) ?? DateTime.now()
        : DateTime.now(),
    signature: json['signature']?.toString() ?? '',
    filePath: json['filePath']?.toString() ?? '',
    ownerEmail: json['ownerEmail']?.toString(),
  );

  ProvenanceRecord copyWith({
    String? id,
    String? originalFileHash,
    String? c2paManifestUri,
    DateTime? timestamp,
    String? signature,
    String? filePath,
    String? ownerEmail,
  }) => ProvenanceRecord(
    id: id ?? this.id,
    originalFileHash: originalFileHash ?? this.originalFileHash,
    c2paManifestUri: c2paManifestUri ?? this.c2paManifestUri,
    timestamp: timestamp ?? this.timestamp,
    signature: signature ?? this.signature,
    filePath: filePath ?? this.filePath,
    ownerEmail: ownerEmail ?? this.ownerEmail,
  );
}

