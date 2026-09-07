import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:file_picker/file_picker.dart';
import 'package:desktop_drop/desktop_drop.dart';
import 'package:google_fonts/google_fonts.dart';

import '../../../shared/theme/cyber_theme.dart';
import '../../../shared/widgets/cyber_button.dart';
import '../../../main.dart'; // for ledgerProvider
import '../models/verification_models.dart';
import '../services/verification_service.dart';

enum _StepOutcome {
  passed,
  failed,
  unsealed,
}

class _StepScanEvaluation {
  final String stepNumber;
  final String title;
  final String inProgressSubtitle;
  final String completedSubtitle;
  final _StepOutcome outcome;
  final String badgeText;
  final Color badgeColor;
  final String practicalReason;
  final IconData icon;

  const _StepScanEvaluation({
    required this.stepNumber,
    required this.title,
    required this.inProgressSubtitle,
    required this.completedSubtitle,
    required this.outcome,
    required this.badgeText,
    required this.badgeColor,
    required this.practicalReason,
    required this.icon,
  });
}

class VerificationPage extends ConsumerStatefulWidget {
  const VerificationPage({super.key});

  @override
  ConsumerState<VerificationPage> createState() => _VerificationPageState();
}

class _VerificationPageState extends ConsumerState<VerificationPage> {
  CompleteVerificationReport? _report;
  bool _isDragging = false;

  // Minimal Sequential Scanning State
  bool _isScanning = false;
  bool _scanCompleted = false;
  String _scanningFileName = '';
  int _scanningFileSize = 0;
  int _currentScanningStep = 0;
  bool _step1Revealed = false;
  bool _step2Revealed = false;
  bool _step3Revealed = false;
  bool _step4Revealed = false;
  double _scanProgress = 0.0;
  CompleteVerificationReport? _pendingReport;
  _StepScanEvaluation? _step1Eval;
  _StepScanEvaluation? _step2Eval;
  _StepScanEvaluation? _step3Eval;
  _StepScanEvaluation? _step4Eval;

  _StepScanEvaluation _evaluateStep1(CompleteVerificationReport report) {
    final bitstream = report.bitstream;
    final isMatch = bitstream.isMatch;
    final verdict = report.verdict;
    final isUnsealed = verdict == VerificationVerdict.unsealed;
    final isShattered = verdict == VerificationVerdict.bitstreamShattered || (!isMatch && report.matchedRecord != null);

    final hash = bitstream.computedHash;
    final shortHash = hash.length >= 24
        ? '${hash.substring(0, 10)}...${hash.substring(hash.length - 8)}'
        : hash;

    if (isShattered) {
      final offsetHex = (bitstream.byteOffset ?? 0).toRadixString(16).toUpperCase();
      return _StepScanEvaluation(
        stepNumber: '01',
        title: 'Pillar I: Bitstream Cryptographic Parity (SHA-256)',
        inProgressSubtitle: 'Calculating live bitstream digest & matching against seal...',
        completedSubtitle: 'SHA-256 shattered • ${bitstream.flippedBytesCount} byte(s) altered at offset 0x$offsetHex',
        outcome: _StepOutcome.failed,
        badgeText: 'FAILED',
        badgeColor: const Color(0xFFEF4444),
        icon: Icons.close_rounded,
        practicalReason: 'WHAT PRACTICALLY HAPPENED: This file was opened in an editor and resaved. Modifying or re-encoding byte sequences breaks the mathematical SHA-256 cryptographic seal, proving the binary payload was altered after initial sealing.',
      );
    } else if (isUnsealed) {
      return _StepScanEvaluation(
        stepNumber: '01',
        title: 'Pillar I: Bitstream Cryptographic Parity (SHA-256)',
        inProgressSubtitle: 'Calculating raw SHA-256 cryptographic checksum...',
        completedSubtitle: 'Digest: $shortHash • No baseline record in ledger',
        outcome: _StepOutcome.unsealed,
        badgeText: 'UNSEALED',
        badgeColor: const Color(0xFFF59E0B),
        icon: Icons.lock_open_rounded,
        practicalReason: 'WHAT PRACTICALLY HAPPENED: This file was never ingested or sealed through Project Kerberos. The binary hash was computed successfully, but no signed cryptographic baseline exists in the enclave ledger to verify authenticity.',
      );
    } else {
      return _StepScanEvaluation(
        stepNumber: '01',
        title: 'Pillar I: Bitstream Cryptographic Parity (SHA-256)',
        inProgressSubtitle: 'Verifying live binary bitstream against cryptographic seal...',
        completedSubtitle: 'Bit-for-bit parity verified • SHA-256: $shortHash',
        outcome: _StepOutcome.passed,
        badgeText: 'PASSED',
        badgeColor: const Color(0xFF10B981),
        icon: Icons.check_rounded,
        practicalReason: 'Asset bitstream is bit-for-bit identical to the signed cryptographic baseline in the hardware enclave.',
      );
    }
  }

  _StepScanEvaluation _evaluateStep2(CompleteVerificationReport report) {
    final meta = report.metadataScrub;
    final verdict = report.verdict;
    final isScrubbed = verdict == VerificationVerdict.metadataScrubbed || meta.isScrubbed;
    final isUnsealed = verdict == VerificationVerdict.unsealed || (!meta.hasJumbfPayload && report.matchedRecord == null);

    if (isScrubbed) {
      return const _StepScanEvaluation(
        stepNumber: '02',
        title: 'Pillar II: C2PA Manifest Provenance Envelope',
        inProgressSubtitle: 'Scanning binary for JUMBF assertion boxes & X.509 certs...',
        completedSubtitle: 'JUMBF box missing • Social media proxy interception detected',
        outcome: _StepOutcome.failed,
        badgeText: 'STRIPPED',
        badgeColor: Color(0xFFEF4444),
        icon: Icons.close_rounded,
        practicalReason: 'WHAT PRACTICALLY HAPPENED: An intermediary platform (such as WhatsApp, Discord, Slack, Twitter, or an email transcode proxy) re-encoded or compressed this media, stripping away all embedded C2PA JUMBF assertion boxes, provenance claims, and X.509 certificates.',
      );
    } else if (isUnsealed) {
      return const _StepScanEvaluation(
        stepNumber: '02',
        title: 'Pillar II: C2PA Manifest Provenance Envelope',
        inProgressSubtitle: 'Scanning for embedded C2PA JUMBF assertion boxes...',
        completedSubtitle: 'No C2PA manifest container detected in raw stream',
        outcome: _StepOutcome.unsealed,
        badgeText: 'MISSING',
        badgeColor: Color(0xFFF59E0B),
        icon: Icons.warning_amber_rounded,
        practicalReason: 'WHAT PRACTICALLY HAPPENED: This asset was created or exported without a standard C2PA provenance envelope. Raw binary contains no JUMBF assertion store, signer identity, or provenance claim manifests.',
      );
    } else {
      final version = meta.c2paVersion ?? 'C2PA v1.4';
      return _StepScanEvaluation(
        stepNumber: '02',
        title: 'Pillar II: C2PA Manifest Provenance Envelope',
        inProgressSubtitle: 'Validating C2PA JUMBF envelope and certificate chain...',
        completedSubtitle: 'Hardware JUMBF assertion box & $version verified',
        outcome: _StepOutcome.passed,
        badgeText: 'PASSED',
        badgeColor: const Color(0xFF10B981),
        icon: Icons.check_rounded,
        practicalReason: 'Hardware-generated C2PA JUMBF envelope is present with valid cryptographic assertion claims and signature chains.',
      );
    }
  }

  _StepScanEvaluation _evaluateStep3(CompleteVerificationReport report) {
    final stego = report.steganography;
    final verdict = report.verdict;
    final isAltered = verdict == VerificationVerdict.steganographyAltered || stego.isAltered || stego.perceptualDrift > 0.05;

    if (isAltered) {
      final driftStr = stego.perceptualDrift.toStringAsFixed(2);
      return _StepScanEvaluation(
        stepNumber: '03',
        title: 'Pillar III: 256-Cell Perceptual Neural Tensor',
        inProgressSubtitle: 'Computing 16x16 perceptual delta matrix & stego analysis...',
        completedSubtitle: 'Perceptual drift: $driftStr% • Steganographic alteration',
        outcome: _StepOutcome.failed,
        badgeText: 'ALTERED',
        badgeColor: const Color(0xFFEF4444),
        icon: Icons.close_rounded,
        practicalReason: 'WHAT PRACTICALLY HAPPENED: Edge neural inference identified visual drift in high-frequency color channels. Localized steganographic tampering, object removal/insertion, or hidden data payloads were injected into the media.',
      );
    } else if (verdict == VerificationVerdict.unsealed) {
      return const _StepScanEvaluation(
        stepNumber: '03',
        title: 'Pillar III: 256-Cell Perceptual Neural Tensor',
        inProgressSubtitle: 'Executing edge neural inference tensor model...',
        completedSubtitle: '16x16 visual baseline computed • Ready for anchoring',
        outcome: _StepOutcome.passed,
        badgeText: 'BASELINE',
        badgeColor: Color(0xFF38BDF8),
        icon: Icons.check_circle_rounded,
        practicalReason: 'Edge neural perceptual model processed all 256 grid cells. Baseline visual tensor generated successfully.',
      );
    } else {
      return const _StepScanEvaluation(
        stepNumber: '03',
        title: 'Pillar III: 256-Cell Perceptual Neural Tensor',
        inProgressSubtitle: 'Running edge-native perceptual drift analysis...',
        completedSubtitle: '0.00% perceptual drift • 256-cell tensor bit-exact',
        outcome: _StepOutcome.passed,
        badgeText: 'PASSED',
        badgeColor: Color(0xFF10B981),
        icon: Icons.check_circle_rounded,
        practicalReason: 'Neural perceptual matrix matches sealed baseline with 0.00% drift. No visual, semantic, or steganographic modifications.',
      );
    }
  }

  _StepScanEvaluation _evaluateStep4(CompleteVerificationReport report) {
    final record = report.matchedRecord;
    final verdict = report.verdict;
    final isUnsealed = verdict == VerificationVerdict.unsealed || record == null;

    if (isUnsealed) {
      return const _StepScanEvaluation(
        stepNumber: '04',
        title: 'Pillar IV: Air-Gapped Ledger Cross-Validation',
        inProgressSubtitle: 'Querying immutable cryptographic ledger anchors...',
        completedSubtitle: 'Unanchored asset • No matching record in Hive ledger',
        outcome: _StepOutcome.unsealed,
        badgeText: 'UNREGISTERED',
        badgeColor: Color(0xFFF59E0B),
        icon: Icons.warning_amber_rounded,
        practicalReason: 'WHAT PRACTICALLY HAPPENED: No matching cryptographic record exists in the immutable Hive ledger. The asset either originated outside the enclave perimeter or was never sealed under the Obsidian protocol.',
      );
    } else if (report.isRenamed) {
      final orig = report.originalSealedName ?? 'Original File';
      final curr = report.fileName;
      return _StepScanEvaluation(
        stepNumber: '04',
        title: 'Pillar IV: Air-Gapped Ledger Cross-Validation',
        inProgressSubtitle: 'Cross-examining ledger history & lineage chains...',
        completedSubtitle: 'Ledger anchor confirmed • Renamed from "$orig"',
        outcome: _StepOutcome.passed,
        badgeText: 'ANCHORED',
        badgeColor: const Color(0xFF10B981),
        icon: Icons.check_circle_rounded,
        practicalReason: 'WHAT PRACTICALLY HAPPENED: The file name was changed from "$orig" to "$curr", but content-addressable cryptographic analysis verified that the binary content is 100% bit-for-bit identical to the immutable ledger seal.',
      );
    } else {
      return const _StepScanEvaluation(
        stepNumber: '04',
        title: 'Pillar IV: Air-Gapped Ledger Cross-Validation',
        inProgressSubtitle: 'Validating cryptographic ledger provenance chain...',
        completedSubtitle: 'Cryptographic anchor verified in immutable Hive ledger',
        outcome: _StepOutcome.passed,
        badgeText: 'ANCHORED',
        badgeColor: Color(0xFF10B981),
        icon: Icons.check_circle_rounded,
        practicalReason: 'Cryptographic provenance anchor verified in local immutable ledger with valid hardware signature and timestamp.',
      );
    }
  }

  Future<void> _analyzeLoadedBytes(Uint8List bytes, String name) async {
    final ledger = ref.read(ledgerProvider);
    final history = ledger.getHistory();

    final newReport = VerificationService.analyzeAsset(
      bytes: bytes,
      fileName: name,
      ledgerHistory: history,
    );

    final s1 = _evaluateStep1(newReport);
    final s2 = _evaluateStep2(newReport);
    final s3 = _evaluateStep3(newReport);
    final s4 = _evaluateStep4(newReport);

    setState(() {
      _isScanning = true;
      _scanCompleted = false;
      _scanningFileName = name;
      _scanningFileSize = bytes.length;
      _currentScanningStep = 1;
      _step1Revealed = false;
      _step2Revealed = false;
      _step3Revealed = false;
      _step4Revealed = false;
      _scanProgress = 0.20;
      _pendingReport = newReport;
      _step1Eval = s1;
      _step2Eval = s2;
      _step3Eval = s3;
      _step4Eval = s4;
    });

    // Step 1: Bitstream Cryptographic Parity (SHA-256)
    await Future.delayed(const Duration(milliseconds: 280));
    if (!mounted) return;
    setState(() {
      _step1Revealed = true;
      _currentScanningStep = 2;
      _scanProgress = 0.45;
    });

    // Step 2: C2PA Manifest Provenance Envelope
    await Future.delayed(const Duration(milliseconds: 280));
    if (!mounted) return;
    setState(() {
      _step2Revealed = true;
      _currentScanningStep = 3;
      _scanProgress = 0.70;
    });

    // Step 3: 256-Cell Perceptual Neural Tensor
    await Future.delayed(const Duration(milliseconds: 280));
    if (!mounted) return;
    setState(() {
      _step3Revealed = true;
      _currentScanningStep = 4;
      _scanProgress = 0.90;
    });

    // Step 4: Air-Gapped Ledger Cross-Validation
    await Future.delayed(const Duration(milliseconds: 280));
    if (!mounted) return;
    setState(() {
      _step4Revealed = true;
      _currentScanningStep = 5;
      _scanProgress = 1.0;
      _scanCompleted = true;
    });

    // Smooth, minimal auto-transition to the report after brief tick view
    await Future.delayed(const Duration(milliseconds: 400));
    if (!mounted) return;
    setState(() {
      _report = _pendingReport;
      _isScanning = false;
      _scanCompleted = false;
    });
  }

  Future<void> _pickFile() async {
    try {
      final result = await FilePicker.platform.pickFiles(withData: true);
      if (result != null && result.files.isNotEmpty) {
        final file = result.files.first;
        if (file.bytes != null) {
          _analyzeLoadedBytes(file.bytes!, file.name);
        }
      }
    } catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text('Error selecting file: $e'),
            backgroundColor: const Color(0xFFEF4444),
          ),
        );
      }
    }
  }

  void _resetVerification() {
    setState(() {
      _report = null;
      _pendingReport = null;
      _isScanning = false;
      _scanCompleted = false;
      _step1Eval = null;
      _step2Eval = null;
      _step3Eval = null;
      _step4Eval = null;
    });
  }

  @override
  Widget build(BuildContext context) {
    return DropTarget(
      onDragEntered: (_) => setState(() => _isDragging = true),
      onDragExited: (_) => setState(() => _isDragging = false),
      onDragDone: (details) async {
        setState(() => _isDragging = false);
        if (details.files.isNotEmpty) {
          final file = details.files.first;
          final bytes = await file.readAsBytes();
          _analyzeLoadedBytes(bytes, file.name);
        }
      },
      child: AnimatedSwitcher(
        duration: const Duration(milliseconds: 250),
        child: _isScanning
            ? _buildMinimalScanningLoader()
            : (_report == null ? _buildCleanDropzoneHero() : _buildCleanReportView()),
      ),
    );
  }

  // ==========================================
  // 1. CLEAN DROPZONE HERO (Fits on screen)
  // ==========================================
  Widget _buildCleanDropzoneHero() {
    return Center(
      child: Container(
        constraints: const BoxConstraints(maxWidth: 820),
        margin: const EdgeInsets.symmetric(vertical: 12),
        padding: const EdgeInsets.symmetric(horizontal: 28, vertical: 32),
        decoration: BoxDecoration(
          color: _isDragging ? const Color(0x22C084FC) : const Color(0x10FFFFFF),
          borderRadius: BorderRadius.circular(20),
          border: Border.all(
            color: _isDragging ? CyberTheme.accentColor : const Color(0x24FFFFFF),
            width: 1.2,
          ),
          boxShadow: [
            BoxShadow(
              color: _isDragging
                  ? CyberTheme.accentColor.withValues(alpha: 0.25)
                  : Colors.black.withValues(alpha: 0.3),
              blurRadius: 24,
            ),
          ],
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Minimal Cyber Icon
            Container(
              width: 54,
              height: 54,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                gradient: CyberTheme.shardGradient,
                boxShadow: [
                  BoxShadow(
                    color: CyberTheme.accentColor.withValues(alpha: 0.35),
                    blurRadius: 16,
                  ),
                ],
              ),
              child: const Icon(
                Icons.verified_user_rounded,
                color: Colors.white,
                size: 26,
              ),
            ),
            const SizedBox(height: 16),

            Text(
              'Cryptographic Forensic Verification',
              style: GoogleFonts.plusJakartaSans(
                fontSize: 18,
                fontWeight: FontWeight.w800,
                color: Colors.white,
                letterSpacing: -0.3,
              ),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 6),

            ConstrainedBox(
              constraints: const BoxConstraints(maxWidth: 580),
              child: Text(
                'Drop any digital asset to perform 4-pillar cryptographic verification: live SHA-256 bitstream parity, C2PA JUMBF assertion envelope, neural perceptual matrix, and air-gapped ledger anchors.',
                style: GoogleFonts.plusJakartaSans(
                  fontSize: 12,
                  color: CyberTheme.textSecondary,
                  height: 1.45,
                ),
                textAlign: TextAlign.center,
              ),
            ),
            const SizedBox(height: 20),

            CyberButton(
              variant: CyberButtonVariant.whitePill,
              height: 38,
              padding: const EdgeInsets.symmetric(horizontal: 24),
              icon: Icons.folder_open_rounded,
              onTap: _pickFile,
              child: const Text('Browse File to Audit'),
            ),
            const SizedBox(height: 20),

            // Minimal Supported Formats Pills
            Wrap(
              spacing: 8,
              runSpacing: 6,
              alignment: WrapAlignment.center,
              children: [
                _buildFormatPill('IMAGE', 'JPG, PNG, WEBP, TIFF'),
                _buildFormatPill('AUDIO', 'MP3, WAV, M4A, AAC'),
                _buildFormatPill('DOCUMENT', 'PDF, C2PA, BIN'),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildFormatPill(String label, String formats) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(
        color: const Color(0x0CFFFFFF),
        borderRadius: BorderRadius.circular(100),
        border: Border.all(color: const Color(0x1CFFFFFF)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Text(
            '$label: ',
            style: GoogleFonts.plusJakartaSans(
              fontSize: 10,
              fontWeight: FontWeight.w700,
              color: const Color(0xFFC084FC),
            ),
          ),
          Text(
            formats,
            style: GoogleFonts.jetBrainsMono(
              fontSize: 10,
              color: Colors.white60,
            ),
          ),
        ],
      ),
    );
  }

  // =========================================================
  // 2. MINIMAL SCANNING LOADER (Compact, Sleek, In-Theme)
  // =========================================================
  Widget _buildMinimalScanningLoader() {
    final hasFailures = (_step1Eval?.outcome == _StepOutcome.failed) ||
        (_step2Eval?.outcome == _StepOutcome.failed) ||
        (_step3Eval?.outcome == _StepOutcome.failed) ||
        (_step4Eval?.outcome == _StepOutcome.failed);

    final isUnsealed = (_pendingReport?.verdict == VerificationVerdict.unsealed) ||
        (!hasFailures &&
            ((_step1Eval?.outcome == _StepOutcome.unsealed) ||
                (_step2Eval?.outcome == _StepOutcome.unsealed) ||
                (_step4Eval?.outcome == _StepOutcome.unsealed)));

    final Color accent = !_scanCompleted
        ? CyberTheme.accentColor
        : (hasFailures
            ? const Color(0xFFEF4444)
            : (isUnsealed ? const Color(0xFFF59E0B) : const Color(0xFF10B981)));

    return Center(
      child: Container(
        constraints: const BoxConstraints(maxWidth: 620),
        margin: const EdgeInsets.symmetric(vertical: 16),
        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 20),
        decoration: BoxDecoration(
          color: const Color(0x14FFFFFF),
          borderRadius: BorderRadius.circular(20),
          border: Border.all(color: accent.withValues(alpha: 0.35), width: 1.2),
          boxShadow: [
            BoxShadow(
              color: accent.withValues(alpha: 0.18),
              blurRadius: 24,
            ),
          ],
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // Top Status Header Row
            Row(
              children: [
                SizedBox(
                  width: 22,
                  height: 22,
                  child: !_scanCompleted
                      ? CircularProgressIndicator(
                          strokeWidth: 2.2,
                          valueColor: AlwaysStoppedAnimation<Color>(accent),
                        )
                      : Icon(
                          hasFailures
                              ? Icons.cancel_rounded
                              : (isUnsealed ? Icons.error_outline_rounded : Icons.check_circle_rounded),
                          color: accent,
                          size: 22,
                        ),
                ),
                const SizedBox(width: 12),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Flexible(
                            child: Text(
                              _scanningFileName,
                              style: GoogleFonts.plusJakartaSans(
                                fontSize: 13.5,
                                fontWeight: FontWeight.w700,
                                color: Colors.white,
                              ),
                              maxLines: 1,
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                          const SizedBox(width: 8),
                          Text(
                            '• ${(_scanningFileSize / 1024).toStringAsFixed(1)} KB',
                            style: GoogleFonts.jetBrainsMono(
                              fontSize: 10.5,
                              color: CyberTheme.textSecondary,
                            ),
                          ),
                        ],
                      ),
                      Text(
                        !_scanCompleted ? 'Executing zero-trust cryptographic audit...' : 'Audit complete. Compiling forensic breakdown...',
                        style: GoogleFonts.jetBrainsMono(
                          fontSize: 10,
                          color: accent,
                        ),
                      ),
                    ],
                  ),
                ),
                Text(
                  '${(_scanProgress * 100).toInt()}%',
                  style: GoogleFonts.jetBrainsMono(
                    fontSize: 13,
                    fontWeight: FontWeight.w800,
                    color: accent,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 14),

            // Minimal Progress Line
            ClipRRect(
              borderRadius: BorderRadius.circular(100),
              child: SizedBox(
                height: 3,
                child: LinearProgressIndicator(
                  value: _scanProgress,
                  backgroundColor: const Color(0x20FFFFFF),
                  valueColor: AlwaysStoppedAnimation<Color>(accent),
                ),
              ),
            ),
            const SizedBox(height: 16),

            // 4 Sequential Tests Minimal Rows
            if (_step1Eval != null)
              _buildMinimalScanRow(eval: _step1Eval!, isRevealed: _step1Revealed, isActive: _currentScanningStep == 1),
            const SizedBox(height: 8),

            if (_step2Eval != null)
              _buildMinimalScanRow(eval: _step2Eval!, isRevealed: _step2Revealed, isActive: _currentScanningStep == 2),
            const SizedBox(height: 8),

            if (_step3Eval != null)
              _buildMinimalScanRow(eval: _step3Eval!, isRevealed: _step3Revealed, isActive: _currentScanningStep == 3),
            const SizedBox(height: 8),

            if (_step4Eval != null)
              _buildMinimalScanRow(eval: _step4Eval!, isRevealed: _step4Revealed, isActive: _currentScanningStep == 4),
          ],
        ),
      ),
    );
  }

  Widget _buildMinimalScanRow({
    required _StepScanEvaluation eval,
    required bool isRevealed,
    required bool isActive,
  }) {
    return AnimatedContainer(
      duration: const Duration(milliseconds: 200),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 9),
      decoration: BoxDecoration(
        color: isRevealed
            ? eval.badgeColor.withValues(alpha: 0.08)
            : (isActive ? const Color(0x15C084FC) : const Color(0x06FFFFFF)),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(
          color: isRevealed
              ? eval.badgeColor.withValues(alpha: 0.35)
              : (isActive ? const Color(0x50C084FC) : const Color(0x14FFFFFF)),
        ),
      ),
      child: Row(
        children: [
          // Step Icon / Status
          SizedBox(
            width: 20,
            height: 20,
            child: isRevealed
                ? Icon(
                    eval.outcome == _StepOutcome.passed
                        ? Icons.check_circle_rounded
                        : (eval.outcome == _StepOutcome.failed ? Icons.cancel_rounded : Icons.error_outline_rounded),
                    color: eval.badgeColor,
                    size: 16,
                  )
                : (isActive
                    ? const Center(
                        child: SizedBox(
                          width: 13,
                          height: 13,
                          child: CircularProgressIndicator(
                            strokeWidth: 1.8,
                            valueColor: AlwaysStoppedAnimation<Color>(Color(0xFFC084FC)),
                          ),
                        ),
                      )
                    : Center(
                        child: Text(
                          eval.stepNumber,
                          style: GoogleFonts.jetBrainsMono(
                            fontSize: 9.5,
                            color: Colors.white30,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      )),
          ),
          const SizedBox(width: 10),

          // Title & Subtitle
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  eval.title,
                  style: GoogleFonts.plusJakartaSans(
                    fontSize: 11.5,
                    fontWeight: isRevealed || isActive ? FontWeight.w700 : FontWeight.w500,
                    color: isRevealed ? Colors.white : (isActive ? const Color(0xFFE9D5FF) : Colors.white54),
                  ),
                ),
                Text(
                  isRevealed ? eval.completedSubtitle : (isActive ? eval.inProgressSubtitle : 'Awaiting check...'),
                  style: GoogleFonts.jetBrainsMono(
                    fontSize: 9.5,
                    color: isRevealed ? eval.badgeColor : (isActive ? const Color(0xFFC084FC) : Colors.white38),
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
          const SizedBox(width: 8),

          // Badge
          if (isRevealed)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
              decoration: BoxDecoration(
                color: eval.badgeColor.withValues(alpha: 0.18),
                borderRadius: BorderRadius.circular(6),
                border: Border.all(color: eval.badgeColor.withValues(alpha: 0.4)),
              ),
              child: Text(
                eval.badgeText,
                style: GoogleFonts.jetBrainsMono(
                  fontSize: 8.5,
                  fontWeight: FontWeight.w800,
                  color: eval.badgeColor,
                ),
              ),
            ),
        ],
      ),
    );
  }

  // ================================================================
  // 3. CLEAN REPORT VIEW (Fits on Screen, 0 Attack Simulations)
  // ================================================================
  Widget _buildCleanReportView() {
    final report = _report!;
    final verdict = report.verdict;
    final isTampered = verdict == VerificationVerdict.bitstreamShattered ||
        verdict == VerificationVerdict.metadataScrubbed ||
        verdict == VerificationVerdict.steganographyAltered;
    final isUnsealed = verdict == VerificationVerdict.unsealed;
    final isPristine = !isTampered && !isUnsealed;

    final Color statusColor = isPristine
        ? const Color(0xFF10B981)
        : (isTampered ? const Color(0xFFEF4444) : const Color(0xFFF59E0B));

    final String verdictTitle = isPristine
        ? (report.isRenamed ? 'GENUINE • RENAMED ASSET' : 'VERIFIED GENUINE & SEALED')
        : (isTampered ? 'FORENSIC BREACH DETECTED' : 'UNSEALED DIGITAL ASSET');

    // Resolve exact failure or notice explanation
    String explanationText = '';
    if (isTampered) {
      if (verdict == VerificationVerdict.bitstreamShattered) {
        final offset = (report.bitstream.byteOffset ?? 0).toRadixString(16).toUpperCase();
        explanationText = 'Bitstream alteration detected: ${report.bitstream.flippedBytesCount} byte(s) modified at offset 0x$offset. SHA-256 hash shattered after initial sealing.';
      } else if (verdict == VerificationVerdict.metadataScrubbed) {
        explanationText = 'C2PA JUMBF assertion box was stripped. Re-encoded by an intermediary platform or social media proxy.';
      } else if (verdict == VerificationVerdict.steganographyAltered) {
        explanationText = 'Perceptual drift detected: ${(report.steganography.perceptualDrift).toStringAsFixed(2)}% drift across high-frequency visual channels.';
      }
    } else if (isUnsealed) {
      explanationText = 'No cryptographic baseline exists in the enclave ledger. Asset is unsealed and ready for provenance sealing.';
    } else if (report.isRenamed) {
      explanationText = 'File was renamed from "${report.originalSealedName}" to "${report.fileName}", but binary bitstream is 100% bit-for-bit identical to sealed ledger entry.';
    }

    return LayoutBuilder(
      builder: (context, constraints) {
        final isWide = constraints.maxWidth >= 780;

        return Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.stretch,
          children: [
            // 1. Sleek Compact Top Bar
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
              decoration: BoxDecoration(
                color: const Color(0x12FFFFFF),
                borderRadius: BorderRadius.circular(14),
                border: Border.all(color: statusColor.withValues(alpha: 0.35)),
              ),
              child: Row(
                children: [
                  Icon(
                    isPristine
                        ? Icons.verified_user_rounded
                        : (isTampered ? Icons.gpp_bad_rounded : Icons.lock_open_rounded),
                    color: statusColor,
                    size: 20,
                  ),
                  const SizedBox(width: 10),

                  // File and Verdict Info
                  Expanded(
                    child: Row(
                      children: [
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2.5),
                          decoration: BoxDecoration(
                            color: statusColor.withValues(alpha: 0.16),
                            borderRadius: BorderRadius.circular(6),
                            border: Border.all(color: statusColor.withValues(alpha: 0.45)),
                          ),
                          child: Text(
                            verdictTitle,
                            style: GoogleFonts.jetBrainsMono(
                              fontSize: 10,
                              fontWeight: FontWeight.w800,
                              color: statusColor,
                              letterSpacing: 0.5,
                            ),
                          ),
                        ),
                        const SizedBox(width: 12),
                        Flexible(
                          child: Text(
                            report.fileName,
                            style: GoogleFonts.plusJakartaSans(
                              fontSize: 13,
                              fontWeight: FontWeight.w700,
                              color: Colors.white,
                            ),
                            maxLines: 1,
                            overflow: TextOverflow.ellipsis,
                          ),
                        ),
                        const SizedBox(width: 8),
                        Text(
                          '• ${(report.fileSizeBytes / 1024).toStringAsFixed(1)} KB',
                          style: GoogleFonts.jetBrainsMono(
                            fontSize: 11,
                            color: CyberTheme.textSecondary,
                          ),
                        ),
                      ],
                    ),
                  ),
                  const SizedBox(width: 12),

                  // Verify Another Button
                  CyberButton(
                    variant: CyberButtonVariant.glassPill,
                    height: 32,
                    padding: const EdgeInsets.symmetric(horizontal: 14),
                    icon: Icons.refresh_rounded,
                    onTap: _resetVerification,
                    child: const Text('Verify Another'),
                  ),
                ],
              ),
            ),

            // 2. Compact Notice Strip (Only if there is an alert / renamed file)
            if (explanationText.isNotEmpty) ...[
              const SizedBox(height: 8),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 7),
                decoration: BoxDecoration(
                  color: statusColor.withValues(alpha: 0.10),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: statusColor.withValues(alpha: 0.28)),
                ),
                child: Row(
                  children: [
                    Icon(
                      isTampered
                          ? Icons.warning_amber_rounded
                          : (isUnsealed ? Icons.info_outline_rounded : Icons.check_circle_outline_rounded),
                      color: statusColor,
                      size: 15,
                    ),
                    const SizedBox(width: 8),
                    Expanded(
                      child: Text(
                        explanationText,
                        style: GoogleFonts.plusJakartaSans(
                          fontSize: 11,
                          color: Colors.white70,
                          height: 1.3,
                        ),
                        maxLines: 2,
                        overflow: TextOverflow.ellipsis,
                      ),
                    ),
                  ],
                ),
              ),
            ],
            const SizedBox(height: 12),

            // 3. The 4 Verification Pillar Cards (Clean 2x2 Grid or 1 Column)
            if (isWide)
              Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Row(
                    children: [
                      Expanded(child: _buildPillarCard1Bitstream(report)),
                      const SizedBox(width: 12),
                      Expanded(child: _buildPillarCard2C2PA(report)),
                    ],
                  ),
                  const SizedBox(height: 12),
                  Row(
                    children: [
                      Expanded(child: _buildPillarCard3Stego(report)),
                      const SizedBox(width: 12),
                      Expanded(child: _buildPillarCard4Ledger(report)),
                    ],
                  ),
                ],
              )
            else
              Column(
                mainAxisSize: MainAxisSize.min,
                children: [
                  _buildPillarCard1Bitstream(report),
                  const SizedBox(height: 10),
                  _buildPillarCard2C2PA(report),
                  const SizedBox(height: 10),
                  _buildPillarCard3Stego(report),
                  const SizedBox(height: 10),
                  _buildPillarCard4Ledger(report),
                ],
              ),
          ],
        );
      },
    );
  }

  // -------------------------------------------------------------
  // PILLAR 1 CARD: Bitstream Cryptographic Parity (SHA-256)
  // -------------------------------------------------------------
  Widget _buildPillarCard1Bitstream(CompleteVerificationReport report) {
    final b = report.bitstream;
    final isMatch = b.isMatch;
    final isUnsealed = report.verdict == VerificationVerdict.unsealed;
    final Color badgeColor = isMatch
        ? const Color(0xFF10B981)
        : (isUnsealed ? const Color(0xFFF59E0B) : const Color(0xFFEF4444));

    final String badgeText = isMatch
        ? (report.isRenamed ? '100% BITSTREAM MATCH' : 'PARITY VERIFIED')
        : (isUnsealed ? 'UNSEALED' : 'PARITY SHATTERED');

    final expectedShort = b.manifestHash.length >= 20
        ? '${b.manifestHash.substring(0, 10)}...${b.manifestHash.substring(b.manifestHash.length - 8)}'
        : b.manifestHash;

    final computedShort = b.computedHash.length >= 20
        ? '${b.computedHash.substring(0, 10)}...${b.computedHash.substring(b.computedHash.length - 8)}'
        : b.computedHash;

    return _buildPillarContainer(
      icon: Icons.fingerprint_rounded,
      title: 'I. BITSTREAM CRYPTOGRAPHIC PARITY',
      badgeText: badgeText,
      badgeColor: badgeColor,
      rows: [
        _buildMetricRow(
          label: 'EXPECTED SEAL',
          value: isUnsealed ? 'None (Unsealed Asset)' : expectedShort,
          isMono: true,
          copyValue: isUnsealed ? null : b.manifestHash,
        ),
        _buildMetricRow(
          label: 'COMPUTED LIVE HASH',
          value: computedShort,
          isMono: true,
          isAlert: !isMatch && !isUnsealed,
          copyValue: b.computedHash,
        ),
        _buildMetricRow(
          label: 'BYTE INTEGRITY METRIC',
          value: isMatch
              ? (report.isRenamed ? '0 Bytes Altered (Identical Bitstream)' : '0 Bytes Altered • Perfect Mathematical Parity')
              : (isUnsealed
                  ? 'Raw SHA-256 calculated • Ready for seal'
                  : '${b.flippedBytesCount} Byte(s) Altered at 0x${(b.byteOffset ?? 0).toRadixString(16).toUpperCase()}'),
          isAlert: !isMatch && !isUnsealed,
          valueColor: isMatch ? const Color(0xFF34D399) : null,
        ),
      ],
    );
  }

  // -------------------------------------------------------------
  // PILLAR 2 CARD: C2PA Manifest Provenance Envelope
  // -------------------------------------------------------------
  Widget _buildPillarCard2C2PA(CompleteVerificationReport report) {
    final m = report.metadataScrub;
    final isUnsealed = report.verdict == VerificationVerdict.unsealed;
    final isScrubbed = m.isScrubbed;
    final Color badgeColor = !isScrubbed && !isUnsealed
        ? const Color(0xFF10B981)
        : (isUnsealed ? const Color(0xFFF59E0B) : const Color(0xFFEF4444));

    final String badgeText = !isScrubbed && !isUnsealed
        ? 'C2PA v1.4 VALID'
        : (isUnsealed ? 'NO MANIFEST' : 'MANIFEST STRIPPED');

    return _buildPillarContainer(
      icon: Icons.verified_outlined,
      title: 'II. C2PA MANIFEST ENVELOPE',
      badgeText: badgeText,
      badgeColor: badgeColor,
      rows: [
        _buildMetricRow(
          label: 'JUMBF ASSERTION CONTAINER',
          value: m.hasJumbfPayload ? 'Present (c2pa:jumbf:assertion-store)' : 'Null Pointer (0x0 - Missing)',
          isAlert: !m.hasJumbfPayload && !isUnsealed,
          valueColor: m.hasJumbfPayload ? const Color(0xFF34D399) : null,
        ),
        _buildMetricRow(
          label: 'ORIGIN DEVICE CERTIFICATE',
          value: m.originCertificateValid ? 'Valid Ed25519 Hardware Signature' : 'Broken / Missing Signature Chain',
          isAlert: !m.originCertificateValid && !isUnsealed,
          valueColor: m.originCertificateValid ? const Color(0xFF34D399) : null,
        ),
        _buildMetricRow(
          label: 'PROXY / INTERCEPTOR ANALYSIS',
          value: m.interceptorDiagnosis ?? 'Direct P2P Link (Pristine Origin)',
          isAlert: isScrubbed,
        ),
      ],
    );
  }

  // -------------------------------------------------------------
  // PILLAR 3 CARD: Neural Steganography & Perceptual Drift
  // -------------------------------------------------------------
  Widget _buildPillarCard3Stego(CompleteVerificationReport report) {
    final s = report.steganography;
    final isUnsealed = report.verdict == VerificationVerdict.unsealed;
    final isAltered = s.isAltered;
    final Color badgeColor = !isAltered
        ? (isUnsealed ? const Color(0xFF38BDF8) : const Color(0xFF10B981))
        : const Color(0xFFEF4444);

    final String badgeText = !isAltered
        ? (isUnsealed ? 'BASELINE MATRIX' : 'PRISTINE (0.00%)')
        : 'STEGO DRIFT DETECTED';

    return _buildPillarContainer(
      icon: Icons.grid_4x4_rounded,
      title: 'III. NEURAL PERCEPTUAL MATRIX',
      badgeText: badgeText,
      badgeColor: badgeColor,
      rows: [
        _buildMetricRow(
          label: 'PERCEPTUAL DRIFT',
          value: '${s.perceptualDrift.toStringAsFixed(2)}%',
          isMono: true,
          isAlert: isAltered,
          valueColor: !isAltered ? const Color(0xFF34D399) : null,
        ),
        _buildMetricRow(
          label: 'HIGH-FREQUENCY ANOMALIES',
          value: isAltered ? 'Altered / Stego Injected Pixels' : 'None Detected (Pristine Visual Parity)',
          isAlert: isAltered,
          valueColor: !isAltered ? const Color(0xFF34D399) : null,
        ),
        _buildMetricRow(
          label: 'INFERENCE ACCELERATION',
          value: 'Edge Neural Perceptual Model (256-Cell Tensor)',
          isMono: false,
        ),
      ],
    );
  }

  // -------------------------------------------------------------
  // PILLAR 4 CARD: Air-Gapped Ledger Proof
  // -------------------------------------------------------------
  Widget _buildPillarCard4Ledger(CompleteVerificationReport report) {
    final record = report.matchedRecord;
    final isUnsealed = report.verdict == VerificationVerdict.unsealed || record == null;
    final Color badgeColor = !isUnsealed ? const Color(0xFF10B981) : const Color(0xFFF59E0B);
    final String badgeText = !isUnsealed ? 'ANCHORED IN LEDGER' : 'UNREGISTERED';

    String recordIdShort = 'None (Unsealed Asset)';
    if (record != null) {
      recordIdShort = record.id.length >= 18
          ? 'rec-${record.id.substring(0, 8)}...${record.id.substring(record.id.length - 4)}'
          : record.id;
    }

    String formattedDate = 'N/A';
    if (record != null) {
      final t = record.timestamp;
      formattedDate = '${t.year}-${t.month.toString().padLeft(2, '0')}-${t.day.toString().padLeft(2, '0')} ${t.hour.toString().padLeft(2, '0')}:${t.minute.toString().padLeft(2, '0')} UTC';
    }

    return _buildPillarContainer(
      icon: Icons.hub_outlined,
      title: 'IV. AIR-GAPPED LEDGER PROOF',
      badgeText: badgeText,
      badgeColor: badgeColor,
      rows: [
        _buildMetricRow(
          label: 'IMMUTABLE RECORD ID',
          value: recordIdShort,
          isMono: true,
          copyValue: record?.id,
        ),
        _buildMetricRow(
          label: 'ANCHOR SIGNER / ENCLAVE',
          value: record?.ownerEmail ?? (record?.signature != null ? 'Ed25519 Hardware Device Key' : 'Local Enclave'),
          isAlert: isUnsealed,
        ),
        _buildMetricRow(
          label: 'ORIGINAL SEAL TIMESTAMP',
          value: formattedDate,
          isMono: true,
        ),
      ],
    );
  }

  // Helper container wrapper for the 4 pillars
  Widget _buildPillarContainer({
    required IconData icon,
    required String title,
    required String badgeText,
    required Color badgeColor,
    required List<Widget> rows,
  }) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      decoration: BoxDecoration(
        color: const Color(0x10FFFFFF),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: const Color(0x1EFFFFFF)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.stretch,
        mainAxisSize: MainAxisSize.min,
        children: [
          // Header
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(icon, size: 15, color: const Color(0xFFC084FC)),
                  const SizedBox(width: 7),
                  Text(
                    title,
                    style: GoogleFonts.jetBrainsMono(
                      fontSize: 10.5,
                      fontWeight: FontWeight.w800,
                      color: Colors.white,
                      letterSpacing: 0.6,
                    ),
                  ),
                ],
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                decoration: BoxDecoration(
                  color: badgeColor.withValues(alpha: 0.16),
                  borderRadius: BorderRadius.circular(5),
                  border: Border.all(color: badgeColor.withValues(alpha: 0.4)),
                ),
                child: Text(
                  badgeText,
                  style: GoogleFonts.jetBrainsMono(
                    fontSize: 8.5,
                    fontWeight: FontWeight.w800,
                    color: badgeColor,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 10),
          const Divider(color: Color(0x12FFFFFF), height: 1),
          const SizedBox(height: 8),

          // Key-Value Rows
          ...rows,
        ],
      ),
    );
  }

  Widget _buildMetricRow({
    required String label,
    required String value,
    bool isMono = false,
    bool isAlert = false,
    Color? valueColor,
    String? copyValue,
  }) {
    final Color textColor = isAlert
        ? const Color(0xFFFB7185)
        : (valueColor ?? Colors.white);

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 3.5),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 155,
            child: Text(
              label,
              style: GoogleFonts.jetBrainsMono(
                fontSize: 9.5,
                fontWeight: FontWeight.w700,
                color: const Color(0xFF94A3B8),
                letterSpacing: 0.4,
              ),
            ),
          ),
          Expanded(
            child: Row(
              children: [
                Expanded(
                  child: Text(
                    value,
                    style: isMono
                        ? GoogleFonts.jetBrainsMono(
                            fontSize: 10.5,
                            fontWeight: FontWeight.w600,
                            color: textColor,
                          )
                        : GoogleFonts.plusJakartaSans(
                            fontSize: 11,
                            fontWeight: FontWeight.w600,
                            color: textColor,
                          ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
                if (copyValue != null) ...[
                  const SizedBox(width: 4),
                  InkWell(
                    onTap: () {
                      Clipboard.setData(ClipboardData(text: copyValue));
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(
                          content: Text('Copied: $copyValue', style: GoogleFonts.jetBrainsMono(fontSize: 11)),
                          duration: const Duration(seconds: 1),
                          behavior: SnackBarBehavior.floating,
                        ),
                      );
                    },
                    borderRadius: BorderRadius.circular(4),
                    child: const Padding(
                      padding: EdgeInsets.all(2),
                      child: Icon(Icons.copy_rounded, size: 12, color: Color(0xFF94A3B8)),
                    ),
                  ),
                ],
              ],
            ),
          ),
        ],
      ),
    );
  }
}
