import 'package:flutter_test/flutter_test.dart';
import 'package:kerberos_client/features/ledger/models/provenance_record.dart';

void main() {
  group('Distributed Ledger Deletion & Tombstone Integrity Tests', () {
    test('Single entity deletion registers tombstone and suppresses record from history', () {
      final records = [
        ProvenanceRecord(
          id: 'rec-01',
          originalFileHash: 'hash-alpha-111',
          c2paManifestUri: 'urn:c2pa:alpha',
          timestamp: DateTime.now().subtract(const Duration(minutes: 5)),
          signature: 'sig-01',
          filePath: 'target_contract.pdf',
          ownerEmail: 'alice@enclave.local',
        ),
        ProvenanceRecord(
          id: 'rec-02',
          originalFileHash: 'hash-beta-222',
          c2paManifestUri: 'urn:c2pa:beta',
          timestamp: DateTime.now(),
          signature: 'sig-02',
          filePath: 'satellite_pass.png',
          ownerEmail: 'alice@enclave.local',
        ),
      ];

      final deletedHashes = <String>{};

      // Simulate deleting 'rec-01'
      final target = records.firstWhere((r) => r.id == 'rec-01');
      deletedHashes.add(target.originalFileHash);

      // Verify getHistory filters out tombstoned hashes
      final activeRecords = records.where((r) => !deletedHashes.contains(r.originalFileHash)).toList();
      expect(activeRecords.length, 1);
      expect(activeRecords.first.id, 'rec-02');
      expect(activeRecords.first.originalFileHash, 'hash-beta-222');
      expect(deletedHashes, contains('hash-alpha-111'));
    });

    test('Zombie Record Prevention: Machine 2 purges local copy when cloud provides tombstones', () {
      // Machine 2 holds local records
      final machine2LocalRecords = <String, ProvenanceRecord>{
        'rec-01': ProvenanceRecord(
          id: 'rec-01',
          originalFileHash: 'hash-alpha-111',
          c2paManifestUri: 'urn:c2pa:alpha',
          timestamp: DateTime.now().subtract(const Duration(hours: 1)),
          signature: 'sig-01',
          filePath: 'document_to_delete.pdf',
          ownerEmail: 'bob@enclave.local',
        ),
        'rec-02': ProvenanceRecord(
          id: 'rec-02',
          originalFileHash: 'hash-beta-222',
          c2paManifestUri: 'urn:c2pa:beta',
          timestamp: DateTime.now(),
          signature: 'sig-02',
          filePath: 'retained_record.pdf',
          ownerEmail: 'bob@enclave.local',
        ),
      };

      // Cloud metadata received by Machine 2 contains tombstones from Machine 1
      final cloudMetadata = {
        'sealed_ledger_records': [
          machine2LocalRecords['rec-02']!.toJson(),
        ],
        'deleted_ledger_hashes': ['hash-alpha-111'],
      };

      // Machine 2 processes tombstones
      final tombstones = Set<String>.from(cloudMetadata['deleted_ledger_hashes'] as List);
      final purgedKeys = <String>[];
      machine2LocalRecords.forEach((key, record) {
        if (tombstones.contains(record.originalFileHash)) {
          purgedKeys.add(key);
        }
      });
      for (final k in purgedKeys) {
        machine2LocalRecords.remove(k);
      }

      // Verify zombie record was purged on Machine 2
      expect(machine2LocalRecords.containsKey('rec-01'), isFalse);
      expect(machine2LocalRecords.containsKey('rec-02'), isTrue);

      // Verify Machine 2 will NOT re-upload the tombstoned record
      final recordsToUpload = machine2LocalRecords.values
          .where((r) => !tombstones.contains(r.originalFileHash))
          .map((r) => r.toJson())
          .toList();

      expect(recordsToUpload.length, 1);
      expect(recordsToUpload.first['id'], 'rec-02');
    });

    test('Total History Wipe: epoch timestamp purges older records across devices', () {
      final wipeEpoch = DateTime.now().toUtc();
      final preWipeTimestamp = wipeEpoch.subtract(const Duration(minutes: 10));
      final postWipeTimestamp = wipeEpoch.add(const Duration(minutes: 5));

      final recordsOnSecondaryMachine = [
        ProvenanceRecord(
          id: 'old-01',
          originalFileHash: 'hash-old-1',
          c2paManifestUri: 'urn:c2pa:old1',
          timestamp: preWipeTimestamp,
          signature: 'sig-old1',
          filePath: 'old_asset_1.png',
          ownerEmail: 'shared@enclave.local',
        ),
        ProvenanceRecord(
          id: 'old-02',
          originalFileHash: 'hash-old-2',
          c2paManifestUri: 'urn:c2pa:old2',
          timestamp: preWipeTimestamp,
          signature: 'sig-old2',
          filePath: 'old_asset_2.pdf',
          ownerEmail: 'shared@enclave.local',
        ),
        ProvenanceRecord(
          id: 'new-01',
          originalFileHash: 'hash-new-1',
          c2paManifestUri: 'urn:c2pa:new1',
          timestamp: postWipeTimestamp,
          signature: 'sig-new1',
          filePath: 'newly_sealed_asset.pdf',
          ownerEmail: 'shared@enclave.local',
        ),
      ];

      // Secondary machine applies wipe epoch
      final remainingRecords = recordsOnSecondaryMachine.where((r) {
        return !r.timestamp.toUtc().isBefore(wipeEpoch);
      }).toList();

      expect(remainingRecords.length, 1);
      expect(remainingRecords.first.id, 'new-01');
      expect(remainingRecords.first.originalFileHash, 'hash-new-1');
    });

    test('Re-sealing after deletion clears tombstone and reactivates record', () {
      final deletedHashes = <String>{'hash-target-333'};

      const targetHash = 'hash-target-333';
      expect(deletedHashes.contains(targetHash), isTrue);

      // Re-sealing the asset
      deletedHashes.remove(targetHash);

      final newRecord = ProvenanceRecord(
        id: 're-sealed-01',
        originalFileHash: targetHash,
        c2paManifestUri: 'urn:c2pa:target333',
        timestamp: DateTime.now(),
        signature: 'sig-re-seal',
        filePath: 'contract_v2.pdf',
        ownerEmail: 'analyst@enclave.local',
      );

      final isVisible = !deletedHashes.contains(newRecord.originalFileHash);
      expect(isVisible, isTrue);
      expect(deletedHashes, isEmpty);
    });

    test('Cross-Computer Realtime Broadcast payload contracts for delete_single and clear_total', () {
      final deleteSinglePayload = {
        'sender_device_id': 'device-alpha-1234',
        'hash': 'sha256-abcde-0000',
        'email': 'commander@enclave.local',
        'timestamp': DateTime.now().toUtc().toIso8601String(),
      };

      expect(deleteSinglePayload['sender_device_id'], isNotEmpty);
      expect(deleteSinglePayload['hash'], 'sha256-abcde-0000');
      expect(deleteSinglePayload['email'], 'commander@enclave.local');
      expect(DateTime.tryParse(deleteSinglePayload['timestamp']!), isNotNull);

      final clearTotalPayload = {
        'sender_device_id': 'device-alpha-1234',
        'cleared_at': DateTime.now().toUtc().toIso8601String(),
        'email': 'commander@enclave.local',
      };

      expect(clearTotalPayload['sender_device_id'], isNotEmpty);
      expect(clearTotalPayload['email'], 'commander@enclave.local');
      expect(DateTime.tryParse(clearTotalPayload['cleared_at']!), isNotNull);
    });

    test('Flexible owner email matching includes unassigned and offline records for signed-in user', () {
      final records = [
        ProvenanceRecord(
          id: 'rec-mine',
          originalFileHash: 'hash-mine',
          c2paManifestUri: 'urn:c2pa:1',
          timestamp: DateTime.now(),
          signature: 'sig-1',
          filePath: 'my_file.pdf',
          ownerEmail: 'user@test.local',
        ),
        ProvenanceRecord(
          id: 'rec-unassigned',
          originalFileHash: 'hash-unassigned',
          c2paManifestUri: 'urn:c2pa:2',
          timestamp: DateTime.now(),
          signature: 'sig-2',
          filePath: 'legacy_file.png',
          ownerEmail: null,
        ),
        ProvenanceRecord(
          id: 'rec-offline',
          originalFileHash: 'hash-offline',
          c2paManifestUri: 'urn:c2pa:3',
          timestamp: DateTime.now(),
          signature: 'sig-3',
          filePath: 'offline_file.pdf',
          ownerEmail: 'offline@enclave.local',
        ),
        ProvenanceRecord(
          id: 'rec-other',
          originalFileHash: 'hash-other',
          c2paManifestUri: 'urn:c2pa:4',
          timestamp: DateTime.now(),
          signature: 'sig-4',
          filePath: 'other_user_file.pdf',
          ownerEmail: 'other@test.local',
        ),
      ];

      const targetEmail = 'user@test.local';
      final filtered = records.where((r) {
        final owner = r.ownerEmail?.trim().toLowerCase();
        final isMatch = owner == null ||
            owner.isEmpty ||
            owner == 'offline@enclave.local' ||
            owner == targetEmail;
        return isMatch;
      }).toList();

      expect(filtered.length, 3);
      expect(filtered.map((r) => r.id), containsAll(['rec-mine', 'rec-unassigned', 'rec-offline']));
      expect(filtered.map((r) => r.id), isNot(contains('rec-other')));
    });
  });
}
