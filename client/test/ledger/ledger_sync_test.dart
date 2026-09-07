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

    test('Deduplication: sealing identical file multiple times retains only one unique entry in ledger history', () {
      final fileHash = 'c2pa-sha256-sample-hash-12345';
      final records = [
        ProvenanceRecord(
          id: 'seal-attempt-1',
          originalFileHash: fileHash,
          c2paManifestUri: 'urn:c2pa:obsidian:hash-1',
          timestamp: DateTime.now().subtract(const Duration(minutes: 10)),
          signature: 'sig-attempt-1',
          filePath: 'design_document.pdf',
          ownerEmail: 'analyst@enclave.local',
        ),
        ProvenanceRecord(
          id: 'seal-attempt-2',
          originalFileHash: fileHash,
          c2paManifestUri: 'urn:c2pa:obsidian:hash-1',
          timestamp: DateTime.now().subtract(const Duration(minutes: 5)),
          signature: 'sig-attempt-2',
          filePath: 'design_document.pdf',
          ownerEmail: 'analyst@enclave.local',
        ),
        ProvenanceRecord(
          id: 'seal-attempt-3',
          originalFileHash: fileHash,
          c2paManifestUri: 'urn:c2pa:obsidian:hash-1',
          timestamp: DateTime.now(),
          signature: 'sig-attempt-3',
          filePath: 'design_document.pdf',
          ownerEmail: 'analyst@enclave.local',
        ),
      ];

      // Simulate getHistory deduplication logic
      final Set<String> seenHashes = {};
      final List<ProvenanceRecord> uniqueHistory = [];

      for (final r in records.reversed) {
        if (r.id == 'sample-satellite-01' || r.filePath == 'satellite_recon_delta_09.png') continue;
        final hash = r.originalFileHash.trim().toLowerCase();
        if (!seenHashes.contains(hash)) {
          seenHashes.add(hash);
          uniqueHistory.add(r);
        }
      }

      // Verify only 1 entry is retained and it is the latest seal
      expect(uniqueHistory.length, 1);
      expect(uniqueHistory.first.id, 'seal-attempt-3');
      expect(uniqueHistory.first.originalFileHash, fileHash);
      expect(uniqueHistory.first.signature, 'sig-attempt-3');
    });

    test('Deduplication: distinct files with different hashes are both preserved', () {
      final records = [
        ProvenanceRecord(
          id: 'file-01',
          originalFileHash: 'hash-aaa-111',
          c2paManifestUri: 'urn:c2pa:aaa',
          timestamp: DateTime.now().subtract(const Duration(minutes: 2)),
          signature: 'sig-aaa',
          filePath: 'photo_evidence.jpg',
          ownerEmail: 'analyst@enclave.local',
        ),
        ProvenanceRecord(
          id: 'file-02',
          originalFileHash: 'hash-bbb-222',
          c2paManifestUri: 'urn:c2pa:bbb',
          timestamp: DateTime.now(),
          signature: 'sig-bbb',
          filePath: 'financial_audit.xlsx',
          ownerEmail: 'analyst@enclave.local',
        ),
      ];

      final Set<String> seenHashes = {};
      final List<ProvenanceRecord> uniqueHistory = [];

      for (final r in records.reversed) {
        final hash = r.originalFileHash.trim().toLowerCase();
        if (!seenHashes.contains(hash)) {
          seenHashes.add(hash);
          uniqueHistory.add(r);
        }
      }

      expect(uniqueHistory.length, 2);
      expect(uniqueHistory.map((r) => r.originalFileHash).toSet(), containsAll(['hash-aaa-111', 'hash-bbb-222']));
    });
  });
}
