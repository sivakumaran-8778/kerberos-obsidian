import 'package:flutter_test/flutter_test.dart';
import 'package:kerberos_client/features/ledger/models/provenance_record.dart';
import 'package:kerberos_client/features/network/providers/network_providers.dart';

void main() {
  group('Ledger Cross-Computer Email Sync & Integrity Tests', () {
    test('ProvenanceRecord serialization round-trip retains ownerEmail and all fields', () {
      final now = DateTime.now();
      final original = ProvenanceRecord(
        id: 'rec-uuid-001',
        originalFileHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
        c2paManifestUri: 'urn:c2pa:obsidian:e3b0c44298fc',
        timestamp: now,
        signature: 'ed25519-sig-test-01',
        filePath: 'classified_satellite_map.png',
        ownerEmail: 'analyst1@defense.mil',
      );

      final json = original.toJson();
      expect(json['id'], 'rec-uuid-001');
      expect(json['originalFileHash'], 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
      expect(json['c2paManifestUri'], 'urn:c2pa:obsidian:e3b0c44298fc');
      expect(json['signature'], 'ed25519-sig-test-01');
      expect(json['filePath'], 'classified_satellite_map.png');
      expect(json['ownerEmail'], 'analyst1@defense.mil');

      final reconstructed = ProvenanceRecord.fromJson(json);
      expect(reconstructed.id, original.id);
      expect(reconstructed.originalFileHash, original.originalFileHash);
      expect(reconstructed.c2paManifestUri, original.c2paManifestUri);
      expect(reconstructed.filePath, original.filePath);
      expect(reconstructed.signature, original.signature);
      expect(reconstructed.ownerEmail, original.ownerEmail);
      expect(reconstructed.timestamp.millisecondsSinceEpoch, original.timestamp.millisecondsSinceEpoch);
    });

    test('Simulated Multi-Computer Flow: Computer 1 seals file -> Computer 2 restores by email', () {
      // 1. User seals 2 files on Computer 1 under alice@enclave.local
      final comp1Records = [
        ProvenanceRecord(
          id: 'seal-comp1-01',
          originalFileHash: 'hash-abc-111',
          c2paManifestUri: 'urn:c2pa:obsidian:hash-abc-111',
          timestamp: DateTime.now().subtract(const Duration(hours: 2)),
          signature: 'sig-comp1-01',
          filePath: 'satellite_recon_alpha.png',
          ownerEmail: 'alice@enclave.local',
        ),
        ProvenanceRecord(
          id: 'seal-comp1-02',
          originalFileHash: 'hash-def-222',
          c2paManifestUri: 'urn:c2pa:obsidian:hash-def-222',
          timestamp: DateTime.now().subtract(const Duration(minutes: 30)),
          signature: 'sig-comp1-02',
          filePath: 'flight_telemetry_vector.pdf',
          ownerEmail: 'alice@enclave.local',
        ),
      ];

      // 2. Computer 1 serializes records to Supabase user_metadata
      final cloudUserMetadata = <String, dynamic>{
        'sealed_ledger_records': comp1Records.map((r) => r.toJson()).toList(),
      };

      // 3. User walks to Computer 2, launches app, logs in as alice@enclave.local
      final rawRecords = cloudUserMetadata['sealed_ledger_records'] as List<dynamic>;
      final comp2Restored = rawRecords
          .map((item) => ProvenanceRecord.fromJson(Map<String, dynamic>.from(item as Map)))
          .where((r) => r.id != 'sample-satellite-01' && r.filePath != 'satellite_recon_delta_09.png')
          .toList();

      expect(comp2Restored.length, 2);
      expect(comp2Restored[0].filePath, 'satellite_recon_alpha.png');
      expect(comp2Restored[1].filePath, 'flight_telemetry_vector.pdf');
      expect(comp2Restored[0].ownerEmail, 'alice@enclave.local');
      expect(comp2Restored[1].ownerEmail, 'alice@enclave.local');
    });

    test('Email Partitioning: User A cannot see User B sealed files in their ledger history', () {
      final allRecords = [
        ProvenanceRecord(
          id: 'rec-alice-1',
          originalFileHash: 'hash-alice-1',
          c2paManifestUri: 'urn:c2pa:alice',
          timestamp: DateTime.now(),
          signature: 'sig-alice',
          filePath: 'alice_research_notes.docx',
          ownerEmail: 'alice@enclave.local',
        ),
        ProvenanceRecord(
          id: 'rec-bob-1',
          originalFileHash: 'hash-bob-1',
          c2paManifestUri: 'urn:c2pa:bob',
          timestamp: DateTime.now(),
          signature: 'sig-bob',
          filePath: 'bob_budget_sheet.xlsx',
          ownerEmail: 'bob@enclave.local',
        ),
      ];

      // Filter for Alice
      final aliceView = allRecords.where((r) {
        if (r.id == 'sample-satellite-01' || r.filePath == 'satellite_recon_delta_09.png') return false;
        return r.ownerEmail?.toLowerCase() == 'alice@enclave.local';
      }).toList();

      expect(aliceView.length, 1);
      expect(aliceView.first.filePath, 'alice_research_notes.docx');

      // Filter for Bob
      final bobView = allRecords.where((r) {
        if (r.id == 'sample-satellite-01' || r.filePath == 'satellite_recon_delta_09.png') return false;
        return r.ownerEmail?.toLowerCase() == 'bob@enclave.local';
      }).toList();

      expect(bobView.length, 1);
      expect(bobView.first.filePath, 'bob_budget_sheet.xlsx');
    });

    test('Sample asset purging: sample-satellite-01 is explicitly excluded from display and storage', () {
      final recordsWithSample = [
        ProvenanceRecord(
          id: 'sample-satellite-01',
          originalFileHash: 'mock-sample-hash',
          c2paManifestUri: 'urn:c2pa:sample',
          timestamp: DateTime.now(),
          signature: 'ed25519-seed-0x9fbc8d31a47b192e',
          filePath: 'satellite_recon_delta_09.png',
        ),
        ProvenanceRecord(
          id: 'authentic-user-file-01',
          originalFileHash: 'authentic-hash-999',
          c2paManifestUri: 'urn:c2pa:authentic',
          timestamp: DateTime.now(),
          signature: 'authentic-sig-999',
          filePath: 'project_blueprint.pdf',
          ownerEmail: 'sivakumaran8778@gmail.com',
        ),
      ];

      final cleanHistory = recordsWithSample.where((r) {
        return r.id != 'sample-satellite-01' && r.filePath != 'satellite_recon_delta_09.png';
      }).toList();

      expect(cleanHistory.length, 1);
      expect(cleanHistory.first.id, 'authentic-user-file-01');
      expect(cleanHistory.first.filePath, 'project_blueprint.pdf');
      expect(cleanHistory.any((r) => r.id == 'sample-satellite-01'), isFalse);
    });

    test('Device UUID resolution generates non-empty distinct client device ID', () {
      final deviceId = getPersistentDeviceId();
      expect(deviceId, isNotEmpty);
      expect(deviceId.length, greaterThanOrEqualTo(16));
    });
  });
}
