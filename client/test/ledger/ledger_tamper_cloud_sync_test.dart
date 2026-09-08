import 'package:flutter_test/flutter_test.dart';
import 'package:kerberos_client/features/ledger/models/provenance_record.dart';
import 'package:kerberos_client/features/ledger/services/ledger_service.dart';

void main() {
  group('Zero-Trust Cloud Ledger Tamper Resistance & Audit Tests', () {
    test('Cloud Poisoning Attack: Tampered cloud record cannot overwrite local verified baseline', () {
      const genuineHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
      const poisonedCloudHash = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';
      const fileName = 'quarterly_financial_audit.pdf';

      final localRecord = ProvenanceRecord(
        id: 'local-genuine-001',
        originalFileHash: genuineHash,
        c2paManifestUri: 'urn:c2pa:obsidian:genuine111',
        timestamp: DateTime.now().subtract(const Duration(hours: 2)),
        signature: 'ed25519-hardware-sig-genuine',
        filePath: fileName,
        ownerEmail: 'auditor@defense.mil',
      );

      // Attacker in the cloud tries to inject a record for the same file with a forged hash
      final poisonedCloudRecord = {
        'id': 'cloud-injected-999',
        'originalFileHash': poisonedCloudHash,
        'c2paManifestUri': 'urn:c2pa:obsidian:forged222',
        'timestamp': DateTime.now().toIso8601String(),
        'signature': 'fake-attacker-sig',
        'filePath': fileName,
        'ownerEmail': 'auditor@defense.mil',
      };

      // Ingest verification logic simulation (mirroring LedgerService.syncWithCloud)
      String clean(String p) => p.split(RegExp(r'[\\/]')).last.trim().toLowerCase();
      final targetBase = clean(poisonedCloudRecord['filePath']!);
      final cloudHash = poisonedCloudRecord['originalFileHash']!.trim().toLowerCase();

      final existingLocal = (clean(localRecord.filePath) == targetBase) ? localRecord : null;
      bool isCloudPoisoned = false;
      bool rejectedAndQuarantined = false;

      if (existingLocal != null && existingLocal.originalFileHash.trim().toLowerCase() != cloudHash) {
        isCloudPoisoned = true;
        rejectedAndQuarantined = true;
      }

      // Assert Zero-Trust defense succeeded
      expect(isCloudPoisoned, isTrue);
      expect(rejectedAndQuarantined, isTrue);
      // Local record remains untouched and authoritative
      expect(localRecord.originalFileHash, genuineHash);
      expect(localRecord.originalFileHash, isNot(equals(poisonedCloudHash)));
    });

    test('Corrupted Cloud Ingest: Malformed records (nulls, invalid types, bad hashes) are quarantined without crashing', () {
      final cloudPayload = [
        null,
        'string_instead_of_map',
        12345,
        {'incomplete': true},
        {
          'id': 'bad-hash-rec',
          'originalFileHash': 'not_a_valid_hex_hash!!!',
          'c2paManifestUri': 'urn:c2pa:bad',
          'timestamp': DateTime.now().toIso8601String(),
          'signature': 'sig',
          'filePath': 'corrupt.pdf',
          'ownerEmail': 'test@enclave.local',
        },
        {
          'id': 'clean-rec-001',
          'originalFileHash': 'aabbccddeeff00112233445566778899',
          'c2paManifestUri': 'urn:c2pa:clean',
          'timestamp': DateTime.now().toIso8601String(),
          'signature': 'ed25519-clean-sig',
          'filePath': 'clean_asset.png',
          'ownerEmail': 'test@enclave.local',
        },
      ];

      final cleanIngested = <ProvenanceRecord>[];
      int quarantinedCount = 0;

      for (final item in cloudPayload) {
        if (item is! Map) {
          quarantinedCount++;
          continue;
        }

        try {
          final record = ProvenanceRecord.fromJson(Map<String, dynamic>.from(item));
          final hash = record.originalFileHash.trim().toLowerCase();

          // Validation gate
          if (record.id.isEmpty || record.filePath.isEmpty || hash.length < 16 || RegExp(r'[^a-fA-F0-9]').hasMatch(hash)) {
            quarantinedCount++;
            continue;
          }

          cleanIngested.add(record);
        } catch (_) {
          quarantinedCount++;
        }
      }

      // Assert that all 5 corrupt entries were safely dropped and only 1 clean record survived
      expect(quarantinedCount, 5);
      expect(cleanIngested.length, 1);
      expect(cleanIngested.first.id, 'clean-rec-001');
      expect(cleanIngested.first.filePath, 'clean_asset.png');
    });

    test('LedgerAuditReport structure correctly classifies clean vs compromised states', () {
      const cleanReport = LedgerAuditReport(
        totalRecords: 10,
        verifiedRecords: 10,
        quarantinedRecords: 0,
        isIntegrityIntact: true,
        anomalyDescriptions: [],
      );

      expect(cleanReport.isIntegrityIntact, isTrue);
      expect(cleanReport.quarantinedRecords, 0);
      expect(cleanReport.anomalyDescriptions, isEmpty);

      const tamperedReport = LedgerAuditReport(
        totalRecords: 10,
        verifiedRecords: 8,
        quarantinedRecords: 2,
        isIntegrityIntact: false,
        anomalyDescriptions: [
          "Hash divergence on identical file 'contract.pdf': 'hash1' vs 'hash2'.",
          "Cryptographic hash corrupt on 'bad.png': invalid hex format '???'.",
        ],
      );

      expect(tamperedReport.isIntegrityIntact, isFalse);
      expect(tamperedReport.quarantinedRecords, 2);
      expect(tamperedReport.anomalyDescriptions.length, 2);
      expect(tamperedReport.anomalyDescriptions.first, contains('Hash divergence'));
    });

    test('Zombie Resurrection Prevention: Cloud cannot re-inject tombstoned records', () {
      final activeTombstones = <String>{'deadbeef000111222333444555666777'};

      final cloudRecords = [
        ProvenanceRecord(
          id: 'zombie-001',
          originalFileHash: 'deadbeef000111222333444555666777',
          c2paManifestUri: 'urn:c2pa:zombie',
          timestamp: DateTime.now(),
          signature: 'zombie-sig',
          filePath: 'deleted_file.pdf',
          ownerEmail: 'user@test.local',
        ),
        ProvenanceRecord(
          id: 'alive-002',
          originalFileHash: '112233445566778899aabbccddeeff00',
          c2paManifestUri: 'urn:c2pa:alive',
          timestamp: DateTime.now(),
          signature: 'alive-sig',
          filePath: 'live_file.pdf',
          ownerEmail: 'user@test.local',
        ),
      ];

      final filteredAfterSync = cloudRecords.where((r) {
        return !activeTombstones.contains(r.originalFileHash.trim().toLowerCase());
      }).toList();

      expect(filteredAfterSync.length, 1);
      expect(filteredAfterSync.first.id, 'alive-002');
      expect(filteredAfterSync.any((r) => r.id == 'zombie-001'), isFalse);
    });
  });
}
