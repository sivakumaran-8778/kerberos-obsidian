import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:file_picker/file_picker.dart';
import 'package:desktop_drop/desktop_drop.dart';
import 'package:google_fonts/google_fonts.dart';

import 'package:flutter/foundation.dart';
import 'package:cross_file/cross_file.dart';
import '../../../shared/theme/cyber_theme.dart';
import '../../../shared/widgets/cyber_button.dart';
import '../../../shared/widgets/glass_container.dart';
import '../../../main.dart'; // for ledgerProvider
import '../../ledger/models/provenance_record.dart';
import '../models/document_forensic_models.dart';
import '../services/document_forensic_service.dart';
import '../services/crypto_engine.dart';
import '../../verification/presentation/widgets/steganography_spatial_matrix.dart';
import './widgets/zk_redact_selection_dialog.dart';

class DocumentForensicsScreen extends ConsumerStatefulWidget {
  const DocumentForensicsScreen({super.key});

  @override
  ConsumerState<DocumentForensicsScreen> createState() => _DocumentForensicsScreenState();
}

class _DocumentForensicsScreenState extends ConsumerState<DocumentForensicsScreen>
    with SingleTickerProviderStateMixin {
  bool _isDragging = false;
  bool _isAnalyzing = false;
  DocumentForensicReport? _report;
  late AnimationController _pulseController;
  int? _hoveredElaIndex;
  int _elaViewMode = 0; // 0: 16x16 Matrix, 1: Document Overlay, 2: Layer & Overlap X-Ray, 3: Raw ELA Residuals, 4: Original Asset
  int _elaLayerFilter = 0; // 0: All, 1: Changes, 2: Overlapped, 3: Hidden
  double _elaOverlayOpacity = 0.65;

  @override
  void initState() {
    super.initState();
    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 2000),
    )..repeat(reverse: true);
  }

  @override
  void dispose() {
    _pulseController.dispose();
    super.dispose();
  }

  Future<void> _pickAndAnalyzeFile() async {
    try {
      final result = await FilePicker.platform.pickFiles(
        type: FileType.custom,
        allowedExtensions: [
          'pdf', 'png', 'jpg', 'jpeg', 'webp', 'tiff', 'docx',
          'wav', 'mp3', 'm4a', 'flac', 'ogg', 'aac',
          'mp4', 'mov', 'mkv', 'avi', 'webm',
          'txt', 'csv', 'json', 'log', 'xml', 'md',
        ],
        withData: true,
      );

      if (result != null && result.files.isNotEmpty) {
        final file = result.files.first;
        Uint8List? bytes = file.bytes;
        if (bytes == null && file.path != null) {
          try {
            bytes = await XFile(file.path!).readAsBytes();
          } catch (e) {
            debugPrint('Error reading file from path: $e');
          }
        }
        if (bytes != null && bytes.isNotEmpty) {
          await _processBytes(bytes, file.name);
        }
      }
    } catch (e) {
      debugPrint('Error picking document: $e');
    }
  }

  Future<void> _processBytes(Uint8List bytes, String fileName) async {
    setState(() {
      _isAnalyzing = true;
    });

    try {
      // Yield to let UI update and show the scan animation
      await Future.delayed(const Duration(milliseconds: 100));

      final ledger = ref.read(ledgerProvider);
      final history = ledger.getHistory();

      // Run heavy forensic computation in background isolate to prevent UI thread lock
      final report = await compute(
        _runForensicAnalysisCompute,
        _ForensicAnalysisJob(
          bytes: bytes,
          fileName: fileName,
          ledgerHistory: history,
        ),
      );

      if (mounted) {
        setState(() {
          _report = report;
          _isAnalyzing = false;
          _hoveredElaIndex = null;
        });
      }
    } catch (e, stack) {
      debugPrint('Background forensic compute error: $e\n$stack');
      // Direct fallback in case background isolate has serialization issues
      try {
        final ledger = ref.read(ledgerProvider);
        final report = DocumentForensicService.analyzeDocument(
          bytes: bytes,
          fileName: fileName,
          ledgerHistory: ledger.getHistory(),
        );
        if (mounted) {
          setState(() {
            _report = report;
            _isAnalyzing = false;
            _hoveredElaIndex = null;
          });
        }
      } catch (fatalError) {
        if (mounted) {
          setState(() {
            _isAnalyzing = false;
          });
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(
              backgroundColor: CyberTheme.surfaceElevated,
              content: Text(
                'Notice: Could not parse file "$fileName": $fatalError',
                style: const TextStyle(color: CyberTheme.coral, fontSize: 12),
              ),
            ),
          );
        }
      }
    }
  }

  void _resetAudit() {
    setState(() {
      _report = null;
      _isAnalyzing = false;
      _hoveredElaIndex = null;
    });
  }

  @override
  Widget build(BuildContext context) {
    return LayoutBuilder(
      builder: (context, screenConstraints) {
        final isMobile = screenConstraints.maxWidth < 600;

        return Center(
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 1100),
            child: SingleChildScrollView(
              padding: EdgeInsets.symmetric(horizontal: isMobile ? 12 : 24, vertical: 20),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  if (_report == null) ...[
                    _buildIntroHeader(),
                    const SizedBox(height: 24),
                    _buildUploadDropZone(isMobile: isMobile),
                    const SizedBox(height: 28),
                    _buildForensicCapabilitiesGrid(),
                  ] else ...[
                _buildAuditHeader(),
                const SizedBox(height: 20),
                _buildVerdictBanner(),
                if (_report!.isTranscoded) ...[
                  const SizedBox(height: 16),
                  _buildTranscodeGuidanceBanner(),
                ],
                if (_report!.qrValidation != null) ...[
                  const SizedBox(height: 20),
                  _buildQrValidationSection(_report!.qrValidation!),
                ],
                if (_report!.audioForensics != null) ...[
                  const SizedBox(height: 24),
                  _buildAudioForensicsSection(_report!.audioForensics!),
                ],
                if (_report!.videoForensics != null) ...[
                  const SizedBox(height: 24),
                  _buildVideoForensicsSection(_report!.videoForensics!),
                ],
                if (_report!.textForensics != null) ...[
                  const SizedBox(height: 24),
                  _buildTextForensicsSection(_report!.textForensics!),
                ],
                const SizedBox(height: 24),
                _buildDocumentHistoryTimeline(),
                if (_report!.elaAnalysis != null) ...[
                  const SizedBox(height: 24),
                  _buildElaHeatmapSection(_report!.elaAnalysis!),
                ],
                const SizedBox(height: 24),
                if (_report!.anomalies.isNotEmpty) ...[
                  _buildAnomaliesCard(),
                  const SizedBox(height: 24),
                ],
                _buildTechnicalMetricsGrid(),
                const SizedBox(height: 32),
              ],
            ],
          ),
        ),
      ),
    );
  },
);
}

  // ==========================================
  // INTRO HEADER (BEFORE UPLOAD)
  // ==========================================
  Widget _buildIntroHeader() {
    return Column(
      children: [
        Center(
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 4),
            decoration: BoxDecoration(
              color: const Color(0x2238BDF8),
              borderRadius: BorderRadius.circular(100),
              border: Border.all(color: const Color(0x6638BDF8)),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(Icons.shield_outlined, size: 13, color: Color(0xFF38BDF8)),
                const SizedBox(width: 6),
                Flexible(
                  child: Text(
                    'ZERO-TRUST UNSEALED DOCUMENT FORENSICS',
                    style: GoogleFonts.jetBrainsMono(
                      fontSize: 10,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 0.8,
                      color: const Color(0xFF38BDF8),
                    ),
                    maxLines: 1,
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
              ],
            ),
          ),
        ),
        const SizedBox(height: 14),
        Text(
          'Document Integrity & Forensics',
          textAlign: TextAlign.center,
          style: GoogleFonts.plusJakartaSans(
            fontSize: 28,
            fontWeight: FontWeight.w800,
            letterSpacing: -0.5,
            color: Colors.white,
          ),
        ),
        const SizedBox(height: 8),
        Text(
          'Upload any government-issued ID, medical bill, tax invoice, or digital file.\nInstantly uncover if it is an Authentic Original or Tampered, Scrambled, or Edited.',
          textAlign: TextAlign.center,
          style: GoogleFonts.plusJakartaSans(
            fontSize: 14,
            height: 1.5,
            color: CyberTheme.textSecondary,
          ),
        ),
      ],
    );
  }

  // ==========================================
  // SINGLE UPLOAD DROP-ZONE (EXACT USER REQUIREMENT)
  // ==========================================
  Widget _buildUploadDropZone({bool isMobile = false}) {
    return DropTarget(
      onDragEntered: (_) => setState(() => _isDragging = true),
      onDragExited: (_) => setState(() => _isDragging = false),
      onDragDone: (details) async {
        setState(() => _isDragging = false);
        if (details.files.isNotEmpty) {
          final file = details.files.first;
          final bytes = await file.readAsBytes();
          await _processBytes(bytes, file.name);
        }
      },
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 240),
        decoration: BoxDecoration(
          color: _isDragging
              ? const Color(0x1F38BDF8)
              : const Color(0x0CFFFFFF),
          borderRadius: BorderRadius.circular(20),
          border: Border.all(
            color: _isDragging
                ? const Color(0xFF38BDF8)
                : const Color(0x33FFFFFF),
            width: _isDragging ? 2.0 : 1.2,
          ),
          boxShadow: [
            BoxShadow(
              color: _isDragging
                  ? const Color(0x3338BDF8)
                  : Colors.black.withValues(alpha: 0.35),
              blurRadius: 28,
              offset: const Offset(0, 8),
            ),
          ],
        ),
        child: Padding(
          padding: EdgeInsets.symmetric(horizontal: isMobile ? 16 : 32, vertical: isMobile ? 28 : 48),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              if (_isAnalyzing) ...[
                const SizedBox(
                  width: 54,
                  height: 54,
                  child: CircularProgressIndicator(
                    color: Color(0xFF38BDF8),
                    strokeWidth: 3.5,
                  ),
                ),
                const SizedBox(height: 20),
                Text(
                  'RUNNING FORENSIC BITSTREAM INSPECTION...',
                  style: GoogleFonts.jetBrainsMono(
                    fontSize: 13,
                    fontWeight: FontWeight.w700,
                    letterSpacing: 1.2,
                    color: const Color(0xFF38BDF8),
                  ),
                ),
                const SizedBox(height: 6),
                Text(
                  'Deconstructing incremental PDF revisions, software markers, and magic bytes',
                  style: GoogleFonts.plusJakartaSans(
                    fontSize: 12,
                    color: CyberTheme.textMuted,
                  ),
                ),
              ] else ...[
                Container(
                  width: 72,
                  height: 72,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    color: const Color(0x1A38BDF8),
                    border: Border.all(color: const Color(0x4438BDF8), width: 1.5),
                  ),
                  child: const Icon(
                    Icons.fingerprint_rounded,
                    size: 38,
                    color: Color(0xFF38BDF8),
                  ),
                ),
                const SizedBox(height: 18),
                Text(
                  _isDragging ? 'RELEASE TO COMMENCE ZERO-TRUST FORENSIC SCAN' : 'DRAG & DROP DOCUMENT OR TAP TO AUDIT',
                  textAlign: TextAlign.center,
                  style: GoogleFonts.plusJakartaSans(
                    fontSize: 15,
                    fontWeight: FontWeight.w800,
                    letterSpacing: 0.4,
                    color: _isDragging ? const Color(0xFF38BDF8) : Colors.white,
                  ),
                ),
                const SizedBox(height: 6),
                Text(
                  'Supports statutory Aadhaar/UIDAI PDFs, medical bills, bank statements, JPG/PNG scans, Audio (WAV/MP3), and Video (MP4/MKV)',
                  textAlign: TextAlign.center,
                  style: GoogleFonts.plusJakartaSans(
                    fontSize: 12,
                    color: CyberTheme.textMuted,
                  ),
                ),
                const SizedBox(height: 22),
                CyberButton(
                  variant: CyberButtonVariant.primary,
                  height: 44,
                  padding: const EdgeInsets.symmetric(horizontal: 26),
                  onTap: _pickAndAnalyzeFile,
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(Icons.upload_file_rounded, size: 18),
                      const SizedBox(width: 8),
                      Flexible(
                        child: Text(
                          'SELECT ANY DOCUMENT / MULTIMEDIA',
                          style: GoogleFonts.plusJakartaSans(
                            fontSize: 12,
                            fontWeight: FontWeight.w800,
                            letterSpacing: 0.8,
                          ),
                          maxLines: 1,
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                    ],
                  ),
                ),
                const SizedBox(height: 18),
                Wrap(
                  spacing: 12,
                  runSpacing: 8,
                  alignment: WrapAlignment.center,
                  children: [
                    _buildPillTag('PDF / SCAN'),
                    _buildPillTag('IMAGE (PNG/JPG)'),
                    _buildPillTag('AUDIO (WAV/MP3/M4A)'),
                    _buildPillTag('VIDEO (MP4/MKV)'),
                    _buildPillTag('TEXT / CSV / LOG'),
                  ],
                ),
              ],
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildPillTag(String label) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 3),
      decoration: BoxDecoration(
        color: const Color(0x14FFFFFF),
        borderRadius: BorderRadius.circular(6),
        border: Border.all(color: const Color(0x22FFFFFF)),
      ),
      child: Text(
        label,
        style: GoogleFonts.jetBrainsMono(
          fontSize: 10,
          fontWeight: FontWeight.w600,
          color: CyberTheme.textMuted,
        ),
      ),
    );
  }

  // ==========================================
  // CAPABILITIES SUMMARY (BELOW UPLOAD)
  // ==========================================
  Widget _buildForensicCapabilitiesGrid() {
    final cards = [
      _buildFeatureSummaryCard(
        icon: Icons.difference_rounded,
        title: 'PDF Revisions & Inline Diff',
        description:
            'Deconstructs BT...ET text streams between original v1 and appended v2 revisions to pinpoint altered numbers.',
      ),
      _buildFeatureSummaryCard(
        icon: Icons.grid_goldenratio_rounded,
        title: 'Error Level Analysis (ELA)',
        description:
            'Visualizes spatial 16x16 quantization residuals to expose spliced text and copy-pasted images even without EXIF.',
      ),
      _buildFeatureSummaryCard(
        icon: Icons.qr_code_scanner_rounded,
        title: 'UIDAI QR Cross-Validation',
        description:
            'Validates RSA-signed 2D QR payloads on Aadhaar cards to detect surface text tampering and identity forgeries.',
      ),
      _buildFeatureSummaryCard(
        icon: Icons.fingerprint_rounded,
        title: 'Editor Software Signatures',
        description:
            'Identifies hidden footprints from Photoshop (8BIM), GIMP, Canva, iLovePDF, and unauthorized tools.',
      ),
      _buildFeatureSummaryCard(
        icon: Icons.print_disabled_rounded,
        title: 'Virtual Printer Laundering',
        description:
            'Detects re-distilled documents processed via virtual printer drivers (e.g. Print to PDF) to erase edit history.',
      ),
      _buildFeatureSummaryCard(
        icon: Icons.alt_route_rounded,
        title: 'Scramble & Header Parity',
        description:
            'Validates magic bytes, cross-reference tables, and detects scrambled bitstreams or truncated files.',
      ),
    ];

    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth >= 820) {
          // 3 columns
          return Column(
            children: [
              Row(
                children: [
                  Expanded(child: cards[0]),
                  const SizedBox(width: 14),
                  Expanded(child: cards[1]),
                  const SizedBox(width: 14),
                  Expanded(child: cards[2]),
                ],
              ),
              const SizedBox(height: 14),
              Row(
                children: [
                  Expanded(child: cards[3]),
                  const SizedBox(width: 14),
                  Expanded(child: cards[4]),
                  const SizedBox(width: 14),
                  Expanded(child: cards[5]),
                ],
              ),
            ],
          );
        } else if (constraints.maxWidth >= 550) {
          // 2 columns
          return Column(
            children: [
              Row(
                children: [
                  Expanded(child: cards[0]),
                  const SizedBox(width: 12),
                  Expanded(child: cards[1]),
                ],
              ),
              const SizedBox(height: 12),
              Row(
                children: [
                  Expanded(child: cards[2]),
                  const SizedBox(width: 12),
                  Expanded(child: cards[3]),
                ],
              ),
              const SizedBox(height: 12),
              Row(
                children: [
                  Expanded(child: cards[4]),
                  const SizedBox(width: 12),
                  Expanded(child: cards[5]),
                ],
              ),
            ],
          );
        } else {
          // 1 column for mobile
          return Column(
            children: [
              for (int i = 0; i < cards.length; i++) ...[
                if (i > 0) const SizedBox(height: 10),
                cards[i],
              ],
            ],
          );
        }
      },
    );
  }

  Widget _buildFeatureSummaryCard({
    required IconData icon,
    required String title,
    required String description,
  }) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0x0CFFFFFF),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: const Color(0x1AFFFFFF)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Icon(icon, size: 22, color: const Color(0xFFC084FC)),
          const SizedBox(height: 10),
          Text(
            title,
            style: GoogleFonts.plusJakartaSans(
              fontSize: 13,
              fontWeight: FontWeight.w700,
              color: Colors.white,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            description,
            style: GoogleFonts.plusJakartaSans(
              fontSize: 11,
              height: 1.4,
              color: CyberTheme.textMuted,
            ),
          ),
        ],
      ),
    );
  }

  // ==========================================
  // AUDIT REPORT: TOP HEADER
  // ==========================================
  Widget _buildAuditHeader() {
    final report = _report!;
    final sizeKb = (report.fileSizeBytes / 1024).toStringAsFixed(1);
    final shortHash = report.sha256Hash.length >= 24
        ? '${report.sha256Hash.substring(0, 10)}...${report.sha256Hash.substring(report.sha256Hash.length - 8)}'
        : report.sha256Hash;

    return LayoutBuilder(
      builder: (context, constraints) {
        final isNarrow = constraints.maxWidth < 620;
        final infoColumn = Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                  margin: const EdgeInsets.only(right: 8),
                  decoration: BoxDecoration(
                    color: report.fileCategory.themeColor.withValues(alpha: 0.15),
                    borderRadius: BorderRadius.circular(6),
                    border: Border.all(color: report.fileCategory.themeColor.withValues(alpha: 0.5)),
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Icon(report.fileCategory.icon, size: 12, color: report.fileCategory.themeColor),
                      const SizedBox(width: 4),
                      Text(
                        report.fileCategory.label.toUpperCase(),
                        style: GoogleFonts.jetBrainsMono(
                          fontSize: 10,
                          fontWeight: FontWeight.w800,
                          color: report.fileCategory.themeColor,
                          letterSpacing: 0.5,
                        ),
                      ),
                    ],
                  ),
                ),
                Flexible(
                  child: Text(
                    report.fileName,
                    style: GoogleFonts.plusJakartaSans(
                      fontSize: 17,
                      fontWeight: FontWeight.w800,
                      color: Colors.white,
                    ),
                    overflow: TextOverflow.ellipsis,
                  ),
                ),
              ],
            ),
            const SizedBox(height: 4),
            Wrap(
              spacing: 6,
              runSpacing: 4,
              crossAxisAlignment: WrapCrossAlignment.center,
              children: [
                Text(
                  '$sizeKb KB • ${report.mimeType.toUpperCase()} • ',
                  style: GoogleFonts.jetBrainsMono(
                    fontSize: 11,
                    color: CyberTheme.textMuted,
                  ),
                ),
                InkWell(
                  onTap: () {
                    Clipboard.setData(ClipboardData(text: report.sha256Hash));
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(
                        content: Text('SHA-256 Digest copied to clipboard'),
                        duration: Duration(seconds: 2),
                      ),
                    );
                  },
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Text(
                        'SHA: $shortHash',
                        style: GoogleFonts.jetBrainsMono(
                          fontSize: 11,
                          color: const Color(0xFF38BDF8),
                          decoration: TextDecoration.underline,
                        ),
                      ),
                      const SizedBox(width: 4),
                      const Icon(Icons.copy_rounded, size: 11, color: Color(0xFF38BDF8)),
                    ],
                  ),
                ),
              ],
            ),
          ],
        );

        final auditAnotherButton = CyberButton(
          variant: CyberButtonVariant.glass,
          height: 36,
          padding: const EdgeInsets.symmetric(horizontal: 16),
          onTap: _resetAudit,
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.refresh_rounded, size: 14),
              const SizedBox(width: 6),
              Text(
                'AUDIT ANOTHER',
                style: GoogleFonts.plusJakartaSans(
                  fontSize: 11,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 0.6,
                ),
              ),
            ],
          ),
        );

        final zkRedactButton = CyberButton(
          variant: CyberButtonVariant.primary,
          height: 36,
          padding: const EdgeInsets.symmetric(horizontal: 16),
          onTap: () async {
            if (report.fileBytes == null) return;
            
            // 1. Open the interactive overlay to let the user draw the exact blackout coordinates
            final coords = await showDialog<Map<String, dynamic>>(
              context: context,
              builder: (context) => ZkRedactSelectionDialog(imageBytes: report.fileBytes!),
            );

            if (coords == null) return; // User cancelled

            try {
              // 2. Feed the true mathematical coordinates to the zero-knowledge edge engine
              final result = await CryptoEngineWeb.generateRedactionProof(
                  report.fileBytes!, coords);
              
              if (context.mounted) {
                ScaffoldMessenger.of(context).showSnackBar(
                  const SnackBar(
                    backgroundColor: CyberTheme.emerald,
                    content: Text(
                      'ZK-REDACT PROOF GENERATED. Authenticity Preserved.',
                      style: TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.bold),
                    ),
                  ),
                );
              }
            } catch (e) {
               if (context.mounted) {
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    backgroundColor: CyberTheme.coral,
                    content: Text('ZK-REDACT FAILED: $e', style: const TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.bold)),
                  ),
                );
              }
            }
          },
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.draw_rounded, size: 14, color: Colors.black),
              const SizedBox(width: 6),
              Text('ZK-REDACT',
                style: GoogleFonts.plusJakartaSans(fontSize: 11, fontWeight: FontWeight.w700, letterSpacing: 0.6, color: Colors.black),
              ),
            ],
          ),
        );

        final evaluateProvenanceButton = CyberButton(
          variant: CyberButtonVariant.primary,
          height: 36,
          padding: const EdgeInsets.symmetric(horizontal: 16),
          onTap: () async {
            try {
              final result = await CryptoEngineWeb.evaluateProvenance(
                  report.fileBytes ?? Uint8List(0), 
                  {'issuer': 'Content Authenticity Initiative', 'manifestHash': report.sha256Hash});
              
              if (context.mounted) {
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    backgroundColor: result['verdict'] == true ? CyberTheme.emerald : CyberTheme.coral,
                    content: Text(
                      result['verdict'] == true ? 'PROVENANCE VERIFIED. Chain of Custody intact.' : 'PROVENANCE PARADOX. Forged ledger detected.',
                      style: const TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.bold),
                    ),
                  ),
                );
              }
            } catch (e) {
               if (context.mounted) {
                ScaffoldMessenger.of(context).showSnackBar(
                  SnackBar(
                    backgroundColor: CyberTheme.coral,
                    content: Text('PROVENANCE EVALUATION FAILED: $e', style: const TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.bold)),
                  ),
                );
              }
            }
          },
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              const Icon(Icons.security_rounded, size: 14, color: Colors.black),
              const SizedBox(width: 6),
              Text('EVALUATE PROVENANCE',
                style: GoogleFonts.plusJakartaSans(fontSize: 11, fontWeight: FontWeight.w700, letterSpacing: 0.6, color: Colors.black),
              ),
            ],
          ),
        );

        final actionButtons = Wrap(
          spacing: 10,
          runSpacing: 10,
          children: [
            zkRedactButton,
            evaluateProvenanceButton,
            auditAnotherButton,
          ],
        );

        if (isNarrow) {
          return Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              infoColumn,
              const SizedBox(height: 12),
              actionButtons,
            ],
          );
        }

        return Row(
          children: [
            Expanded(child: infoColumn),
            const SizedBox(width: 14),
            actionButtons,
          ],
        );
      },
    );
  }

  // ==========================================
  // AUDIT REPORT: PROMINENT VERDICT BANNER
  // ==========================================
  Widget _buildVerdictBanner() {
    final report = _report!;
    final verdict = report.verdict;
    final color = verdict.color;
    final icon = verdict.icon;

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 22),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.12),
        borderRadius: BorderRadius.circular(18),
        border: Border.all(color: color.withValues(alpha: 0.6), width: 1.6),
        boxShadow: [
          BoxShadow(
            color: color.withValues(alpha: 0.25),
            blurRadius: 28,
            offset: const Offset(0, 4),
          ),
        ],
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: color.withValues(alpha: 0.2),
              border: Border.all(color: color.withValues(alpha: 0.5), width: 1.5),
            ),
            child: Icon(icon, size: 30, color: color),
          ),
          const SizedBox(width: 20),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Wrap(
                  spacing: 12,
                  runSpacing: 6,
                  crossAxisAlignment: WrapCrossAlignment.center,
                  children: [
                    Text(
                      verdict.label,
                      style: GoogleFonts.plusJakartaSans(
                        fontSize: 18,
                        fontWeight: FontWeight.w900,
                        letterSpacing: 0.8,
                        color: color,
                      ),
                    ),
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                      decoration: BoxDecoration(
                        color: color.withValues(alpha: 0.2),
                        borderRadius: BorderRadius.circular(6),
                        border: Border.all(color: color.withValues(alpha: 0.4)),
                      ),
                      child: Text(
                        '${report.confidenceScore}% CONFIDENCE',
                        style: GoogleFonts.jetBrainsMono(
                          fontSize: 10,
                          fontWeight: FontWeight.w800,
                          color: color,
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 6),
                Text(
                  verdict.summary,
                  style: GoogleFonts.plusJakartaSans(
                    fontSize: 13,
                    height: 1.5,
                    color: Colors.white.withValues(alpha: 0.9),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  // ==========================================
  // TOTAL DOCUMENT HISTORY & TIMELINE
  // ==========================================
  Widget _buildDocumentHistoryTimeline() {
    final report = _report!;
    final history = report.history;

    return GlassContainer(
      padding: const EdgeInsets.all(22),
      borderRadius: 18.0,
      borderColor: const Color(0x28FFFFFF),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.history_edu_rounded, size: 18, color: Color(0xFFC084FC)),
              const SizedBox(width: 8),
              Text(
                'TOTAL DOCUMENT HISTORY & PROVENANCE TIMELINE',
                style: GoogleFonts.plusJakartaSans(
                  fontSize: 13,
                  fontWeight: FontWeight.w800,
                  letterSpacing: 0.8,
                  color: Colors.white,
                ),
              ),
              const Spacer(),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: const Color(0x18FFFFFF),
                  borderRadius: BorderRadius.circular(6),
                ),
                child: Text(
                  '${history.length} LIFECYCLE GENERATION${history.length > 1 ? 'S' : ''}',
                  style: GoogleFonts.jetBrainsMono(
                    fontSize: 10,
                    fontWeight: FontWeight.w700,
                    color: CyberTheme.textSecondary,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 18),
          ListView.separated(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            itemCount: history.length,
            separatorBuilder: (_, __) => Padding(
              padding: const EdgeInsets.only(left: 17),
              child: Container(
                width: 2,
                height: 18,
                color: const Color(0x33FFFFFF),
              ),
            ),
            itemBuilder: (context, index) {
              final entry = history[index];
              final isTamper = entry.isTamperOrAppended;
              final accentColor = isTamper ? const Color(0xFFF43F5E) : const Color(0xFF10B981);

              return Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Container(
                    margin: const EdgeInsets.only(top: 2),
                    width: 36,
                    height: 36,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: accentColor.withValues(alpha: 0.18),
                      border: Border.all(color: accentColor, width: 1.5),
                    ),
                    child: Center(
                      child: Text(
                        'v${entry.revisionIndex}',
                        style: GoogleFonts.jetBrainsMono(
                          fontSize: 11,
                          fontWeight: FontWeight.w800,
                          color: accentColor,
                        ),
                      ),
                    ),
                  ),
                  const SizedBox(width: 14),
                  Expanded(
                    child: Container(
                      padding: const EdgeInsets.all(14),
                      decoration: BoxDecoration(
                        color: isTamper
                            ? const Color(0x1FF43F5E)
                            : const Color(0x0EFFFFFF),
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(
                          color: isTamper
                              ? const Color(0x55F43F5E)
                              : const Color(0x1AFFFFFF),
                        ),
                      ),
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              Text(
                                entry.title,
                                style: GoogleFonts.plusJakartaSans(
                                  fontSize: 13,
                                  fontWeight: FontWeight.w800,
                                  color: isTamper ? const Color(0xFFFDA4AF) : Colors.white,
                                ),
                              ),
                              const Spacer(),
                              if (entry.timestamp != null)
                                Text(
                                  _formatDate(entry.timestamp!),
                                  style: GoogleFonts.jetBrainsMono(
                                    fontSize: 10,
                                    color: CyberTheme.textMuted,
                                  ),
                                ),
                            ],
                          ),
                          if (entry.softwareOrProducer != null) ...[
                            const SizedBox(height: 4),
                            Row(
                              children: [
                                Icon(
                                  isTamper ? Icons.warning_rounded : Icons.terminal_rounded,
                                  size: 12,
                                  color: isTamper ? const Color(0xFFF43F5E) : CyberTheme.textSecondary,
                                ),
                                const SizedBox(width: 4),
                                Text(
                                  entry.softwareOrProducer!,
                                  style: GoogleFonts.jetBrainsMono(
                                    fontSize: 11,
                                    fontWeight: FontWeight.w600,
                                    color: isTamper ? const Color(0xFFF43F5E) : CyberTheme.textSecondary,
                                  ),
                                ),
                              ],
                            ),
                          ],
                          const SizedBox(height: 6),
                          Text(
                            entry.description,
                            style: GoogleFonts.plusJakartaSans(
                              fontSize: 12,
                              height: 1.4,
                              color: isTamper ? Colors.white : CyberTheme.textSecondary,
                            ),
                          ),
                          if (isTamper && report.revisionDiff != null && report.revisionDiff!.hasChanges) ...[
                            const SizedBox(height: 10),
                            _buildRevisionDiffBox(report.revisionDiff!),
                          ],
                        ],
                      ),
                    ),
                  ),
                ],
              );
            },
          ),
        ],
      ),
    );
  }

  // ==========================================
  // PDF INCREMENTAL REVISION TEXT DIFF BOX
  // ==========================================
  Widget _buildRevisionDiffBox(PdfRevisionDiff diff) {
    return Container(
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: const Color(0xFF090D16),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: const Color(0x33F43F5E)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.difference_rounded, size: 14, color: Color(0xFFF43F5E)),
              const SizedBox(width: 6),
              Text(
                'PDF INCREMENTAL CONTENT MODIFICATION DIFF',
                style: GoogleFonts.jetBrainsMono(
                  fontSize: 10,
                  fontWeight: FontWeight.w800,
                  letterSpacing: 0.6,
                  color: const Color(0xFFFDA4AF),
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          if (diff.removedTokens.isNotEmpty) ...[
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'REMOVED (v1): ',
                  style: GoogleFonts.jetBrainsMono(
                    fontSize: 10,
                    fontWeight: FontWeight.w800,
                    color: const Color(0xFFF43F5E),
                  ),
                ),
                const SizedBox(width: 6),
                Expanded(
                  child: Wrap(
                    spacing: 6,
                    runSpacing: 4,
                    children: diff.removedTokens
                        .map(
                          (t) => Container(
                            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                            decoration: BoxDecoration(
                              color: const Color(0x2EF43F5E),
                              borderRadius: BorderRadius.circular(4),
                              border: Border.all(color: const Color(0x55F43F5E)),
                            ),
                            child: Text(
                              '- $t',
                              maxLines: 2,
                              overflow: TextOverflow.ellipsis,
                              style: GoogleFonts.jetBrainsMono(
                                fontSize: 10,
                                fontWeight: FontWeight.w700,
                                color: const Color(0xFFFDA4AF),
                              ),
                            ),
                          ),
                        )
                        .toList(),
                  ),
                ),
              ],
            ),
            const SizedBox(height: 6),
          ],
          if (diff.addedTokens.isNotEmpty) ...[
            Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'ADDED (v2):   ',
                  style: GoogleFonts.jetBrainsMono(
                    fontSize: 10,
                    fontWeight: FontWeight.w800,
                    color: const Color(0xFF10B981),
                  ),
                ),
                const SizedBox(width: 6),
                Expanded(
                  child: Wrap(
                    spacing: 6,
                    runSpacing: 4,
                    children: diff.addedTokens
                        .map(
                          (t) => Container(
                            padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                            decoration: BoxDecoration(
                              color: const Color(0x2E10B981),
                              borderRadius: BorderRadius.circular(4),
                              border: Border.all(color: const Color(0x5510B981)),
                            ),
                            child: Text(
                              '+ $t',
                              maxLines: 2,
                              overflow: TextOverflow.ellipsis,
                              style: GoogleFonts.jetBrainsMono(
                                fontSize: 10,
                                fontWeight: FontWeight.w700,
                                color: const Color(0xFFA7F3D0),
                              ),
                            ),
                          ),
                        )
                        .toList(),
                  ),
                ),
              ],
            ),
          ],
        ],
      ),
    );
  }

  // ==========================================
  // UIDAI SECURE QR CODE CROSS-VALIDATION
  // ==========================================
  Widget _buildQrValidationSection(DocumentQrValidation qr) {
    final isGood = qr.hasQrCode && qr.isUidaiSigned && qr.isTextMatchingQr;
    final isMismatch = qr.hasQrCode && (!qr.isTextMatchingQr || qr.qrDiscrepancyDetail != null);
    final accentColor = isGood
        ? const Color(0xFF10B981)
        : (isMismatch ? const Color(0xFFF43F5E) : const Color(0xFFF59E0B));

    String statusText = 'CRYPTOGRAPHICALLY AUTHENTIC QR';
    if (!qr.hasQrCode) {
      statusText = 'MISSING STATUTORY QR CODE';
    } else if (isMismatch) {
      statusText = 'CRITICAL VISUAL-TO-QR MISMATCH (FORGERY)';
    } else if (!qr.isUidaiSigned) {
      statusText = 'UNVERIFIED QR SIGNATURE';
    }

    return GlassContainer(
      padding: const EdgeInsets.all(22),
      borderRadius: 18.0,
      borderColor: accentColor.withValues(alpha: 0.5),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Wrap(
            alignment: WrapAlignment.spaceBetween,
            crossAxisAlignment: WrapCrossAlignment.center,
            spacing: 10,
            runSpacing: 8,
            children: [
              Row(
                mainAxisSize: MainAxisSize.min,
                children: [
                  Icon(Icons.qr_code_scanner_rounded, size: 20, color: accentColor),
                  const SizedBox(width: 10),
                  Text(
                    'UIDAI SECURE QR CODE CROSS-VALIDATION',
                    style: GoogleFonts.plusJakartaSans(
                      fontSize: 13,
                      fontWeight: FontWeight.w800,
                      letterSpacing: 0.8,
                      color: Colors.white,
                    ),
                  ),
                ],
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                decoration: BoxDecoration(
                  color: accentColor.withValues(alpha: 0.18),
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(color: accentColor.withValues(alpha: 0.5)),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Container(
                      width: 6,
                      height: 6,
                      decoration: BoxDecoration(shape: BoxShape.circle, color: accentColor),
                    ),
                    const SizedBox(width: 6),
                    Text(
                      statusText,
                      style: GoogleFonts.jetBrainsMono(
                        fontSize: 10,
                        fontWeight: FontWeight.w800,
                        color: accentColor,
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            'High-density 2D QR codes on Aadhaar cards contain UIDAI RSA-signed demographic payloads. Cross-validation decodes the tamper-proof QR and checks if visual text or photos were altered independently.',
            style: GoogleFonts.plusJakartaSans(
              fontSize: 12,
              height: 1.45,
              color: CyberTheme.textSecondary,
            ),
          ),
          if (qr.qrDiscrepancyDetail != null) ...[
            const SizedBox(height: 14),
            Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: const Color(0x22F43F5E),
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: const Color(0x66F43F5E), width: 1.2),
              ),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Icon(Icons.warning_amber_rounded, size: 20, color: Color(0xFFF43F5E)),
                  const SizedBox(width: 12),
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Text(
                          'CRITICAL DEMOGRAPHIC DIVERGENCE DETECTED',
                          style: GoogleFonts.plusJakartaSans(
                            fontSize: 12,
                            fontWeight: FontWeight.w800,
                            letterSpacing: 0.6,
                            color: const Color(0xFFFDA4AF),
                          ),
                        ),
                        const SizedBox(height: 4),
                        Text(
                          qr.qrDiscrepancyDetail!,
                          style: GoogleFonts.plusJakartaSans(
                            fontSize: 12,
                            height: 1.4,
                            color: Colors.white,
                          ),
                        ),
                      ],
                    ),
                  ),
                ],
              ),
            ),
          ],
          if (qr.extractedDemographics != null) ...[
            const SizedBox(height: 14),
            Container(
              padding: const EdgeInsets.all(14),
              decoration: BoxDecoration(
                color: const Color(0x0EFFFFFF),
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: const Color(0x18FFFFFF)),
              ),
              child: Row(
                children: [
                  const Icon(Icons.verified_user_rounded, size: 18, color: Color(0xFF10B981)),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      qr.extractedDemographics!,
                      style: GoogleFonts.jetBrainsMono(
                        fontSize: 11,
                        fontWeight: FontWeight.w600,
                        color: Colors.white,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ],
        ],
      ),
    );
  }

  // ==========================================
  // ERROR LEVEL ANALYSIS (ELA) HEATMAP SECTION
  // ==========================================
  Widget _buildElaHeatmapSection(DocumentElaAnalysis ela) {
    final hasAnomaly = ela.hasSplicingAnomaly;
    final badgeColor = hasAnomaly ? const Color(0xFFF43F5E) : const Color(0xFF10B981);
    final hoveredIndex = _hoveredElaIndex;
    final hoveredVal = hoveredIndex != null && hoveredIndex < ela.heatmapTensor.length
        ? ela.heatmapTensor[hoveredIndex]
        : null;
    final hasRealImage = ela.previewImageBytes != null;

    return GlassContainer(
      padding: const EdgeInsets.all(22),
      borderRadius: 18.0,
      borderColor: hasAnomaly ? const Color(0x44F43F5E) : const Color(0x3338BDF8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          LayoutBuilder(
            builder: (context, headerConstraints) {
              final isNarrow = headerConstraints.maxWidth < 620;
              final badgeWidget = Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                decoration: BoxDecoration(
                  color: badgeColor.withValues(alpha: 0.18),
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(color: badgeColor.withValues(alpha: 0.5)),
                ),
                child: Row(
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Container(
                      width: 6,
                      height: 6,
                      decoration: BoxDecoration(shape: BoxShape.circle, color: badgeColor),
                    ),
                    const SizedBox(width: 6),
                    Text(
                      hasAnomaly ? 'SPLICING ANOMALY DETECTED' : 'UNIFORM SENSOR BASELINE',
                      style: GoogleFonts.jetBrainsMono(
                        fontSize: 10,
                        fontWeight: FontWeight.w800,
                        color: badgeColor,
                      ),
                    ),
                  ],
                ),
              );

              final titleWidget = Row(
                children: [
                  Icon(
                    Icons.grid_goldenratio_rounded,
                    size: 20,
                    color: hasAnomaly ? const Color(0xFFF43F5E) : const Color(0xFF38BDF8),
                  ),
                  const SizedBox(width: 10),
                  Flexible(
                    child: Text(
                      'ERROR LEVEL ANALYSIS (ELA) SPATIAL RESIDUAL MATRIX',
                      style: GoogleFonts.plusJakartaSans(
                        fontSize: isNarrow ? 11.5 : 13,
                        fontWeight: FontWeight.w800,
                        letterSpacing: 0.8,
                        color: Colors.white,
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                ],
              );

              if (isNarrow) {
                return Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    titleWidget,
                    const SizedBox(height: 8),
                    badgeWidget,
                  ],
                );
              }

              return Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Expanded(child: titleWidget),
                  const SizedBox(width: 12),
                  badgeWidget,
                ],
              );
            },
          ),
          const SizedBox(height: 8),
          Text(
            'Re-compression quantization residuals across a 16×16 spatial matrix. Spliced objects, altered numbers, or pasted signatures exhibit distinct compression artifacts diverging from ambient background noise.',
            style: GoogleFonts.plusJakartaSans(
              fontSize: 12,
              height: 1.45,
              color: CyberTheme.textSecondary,
            ),
          ),
          const SizedBox(height: 16),

          // Multi-View Forensic Mode Bar
          LayoutBuilder(
            builder: (context, barConstraints) {
              final isCompact = barConstraints.maxWidth < 680;
              final modes = [
                (index: 0, label: '16×16 MATRIX', icon: Icons.grid_4x4_rounded),
                if (hasRealImage) ...[
                  (index: 1, label: 'DOCUMENT OVERLAY', icon: Icons.layers_rounded),
                  (index: 2, label: 'LAYER X-RAY', icon: Icons.view_in_ar_rounded),
                  (index: 3, label: 'RAW ELA MAP', icon: Icons.grain_rounded),
                  (index: 4, label: 'ORIGINAL ASSET', icon: Icons.image_outlined),
                ],
              ];

              return Container(
                padding: const EdgeInsets.all(4),
                decoration: BoxDecoration(
                  color: const Color(0x18FFFFFF),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: const Color(0x28FFFFFF)),
                ),
                child: isCompact
                    ? Wrap(
                        spacing: 4,
                        runSpacing: 4,
                        children: modes.map((m) => _buildModeTab(m.index, m.label, m.icon)).toList(),
                      )
                    : Row(
                        children: modes
                            .map((m) => Expanded(child: _buildModeTab(m.index, m.label, m.icon)))
                            .toList(),
                      ),
              );
            },
          ),
          if (_elaViewMode == 1 && hasRealImage) ...[
            const SizedBox(height: 12),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
              decoration: BoxDecoration(
                color: const Color(0x0EFFFFFF),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: const Color(0x18FFFFFF)),
              ),
              child: Row(
                children: [
                  const Icon(Icons.tune_rounded, size: 16, color: Color(0xFF38BDF8)),
                  const SizedBox(width: 8),
                  Text(
                    'OVERLAY INTENSITY:',
                    style: GoogleFonts.jetBrainsMono(
                      fontSize: 10,
                      fontWeight: FontWeight.w700,
                      color: CyberTheme.textMuted,
                    ),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: SliderTheme(
                      data: SliderThemeData(
                        trackHeight: 3,
                        activeTrackColor: const Color(0xFF38BDF8),
                        inactiveTrackColor: const Color(0x33FFFFFF),
                        thumbColor: Colors.white,
                        thumbShape: const RoundSliderThumbShape(enabledThumbRadius: 6),
                        overlayShape: const RoundSliderOverlayShape(overlayRadius: 12),
                      ),
                      child: Slider(
                        value: _elaOverlayOpacity,
                        min: 0.1,
                        max: 1.0,
                        onChanged: (v) => setState(() => _elaOverlayOpacity = v),
                      ),
                    ),
                  ),
                  const SizedBox(width: 8),
                  Text(
                    '${(_elaOverlayOpacity * 100).toInt()}%',
                    style: GoogleFonts.jetBrainsMono(
                      fontSize: 11,
                      fontWeight: FontWeight.w800,
                      color: const Color(0xFF38BDF8),
                    ),
                  ),
                ],
              ),
            ),
          ],
          const SizedBox(height: 16),

          LayoutBuilder(
            builder: (context, constraints) {
              final isWide = constraints.maxWidth > 780;
              final canvasWidget = _buildElaVisualCanvas(ela, constraints.maxWidth);
              final inspectorWidget = _buildElaInspector(ela, hoveredVal, hoveredIndex);

              if (isWide) {
                return Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Expanded(
                      flex: 6,
                      child: canvasWidget,
                    ),
                    const SizedBox(width: 20),
                    Expanded(
                      flex: 5,
                      child: inspectorWidget,
                    ),
                  ],
                );
              } else {
                return Column(
                  children: [
                    canvasWidget,
                    const SizedBox(height: 18),
                    inspectorWidget,
                  ],
                );
              }
            },
          ),
        ],
      ),
    );
  }

  Widget _buildModeTab(int index, String label, IconData icon) {
    final isSelected = _elaViewMode == index;
    return GestureDetector(
      onTap: () => setState(() => _elaViewMode = index),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 160),
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
        decoration: BoxDecoration(
          color: isSelected ? CyberTheme.accentColor.withValues(alpha: 0.35) : Colors.transparent,
          borderRadius: BorderRadius.circular(7),
          border: Border.all(
            color: isSelected ? CyberTheme.accentColor : Colors.transparent,
            width: 1.0,
          ),
        ),
        child: Row(
          mainAxisAlignment: MainAxisAlignment.center,
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              icon,
              size: 13,
              color: isSelected ? Colors.white : CyberTheme.textMuted,
            ),
            const SizedBox(width: 6),
            Flexible(
              child: Text(
                label,
                style: GoogleFonts.jetBrainsMono(
                  fontSize: 10,
                  fontWeight: isSelected ? FontWeight.w800 : FontWeight.w600,
                  color: isSelected ? Colors.white : CyberTheme.textMuted,
                ),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildElaVisualCanvas(DocumentElaAnalysis ela, double availableWidth) {
    // Mode 0 is the 16x16 Spatial Residual Matrix from user reference image
    if (_elaViewMode == 0 || ela.previewImageBytes == null) {
      return Center(
        child: _buildElaGrid(ela),
      );
    }

    final double aspect = (ela.imageWidth > 0 && ela.imageHeight > 0)
        ? (ela.imageWidth / ela.imageHeight).clamp(0.55, 2.2)
        : 1.0;

    final hoveredIdx = _hoveredElaIndex;
    final hoveredRow = hoveredIdx != null ? (hoveredIdx ~/ 16) : null;
    final hoveredCol = hoveredIdx != null ? (hoveredIdx % 16) : null;

    Widget imageStack;
    if (_elaViewMode == 1) {
      // 1. Composite Thermal Document Overlay
      imageStack = Stack(
        fit: StackFit.expand,
        children: [
          Image.memory(
            ela.previewImageBytes!,
            fit: BoxFit.contain,
          ),
          if (ela.thermalImageBytes != null)
            Opacity(
              opacity: _elaOverlayOpacity,
              child: Image.memory(
                ela.thermalImageBytes!,
                fit: BoxFit.contain,
              ),
            ),
          if (hoveredRow != null && hoveredCol != null)
            FractionallySizedBox(
              alignment: FractionalOffset(
                (hoveredCol + 0.5) / 16.0,
                (hoveredRow + 0.5) / 16.0,
              ),
              widthFactor: 1.0 / 16.0,
              heightFactor: 1.0 / 16.0,
              child: Container(
                decoration: BoxDecoration(
                  border: Border.all(color: Colors.white, width: 2.0),
                  color: Colors.white.withValues(alpha: 0.25),
                  boxShadow: const [
                    BoxShadow(color: Color(0x99FFFFFF), blurRadius: 8),
                  ],
                ),
              ),
            ),
        ],
      );
    } else if (_elaViewMode == 2) {
      // 2. Layer & Overlap X-Ray (Bounding boxes for altered text, whiteouts, and hidden elements)
      imageStack = Stack(
        fit: StackFit.expand,
        children: [
          Image.memory(
            ela.previewImageBytes!,
            fit: BoxFit.contain,
          ),
          // Draw bounding overlays for changed cells
          for (final idx in ela.changedCellIndices)
            FractionallySizedBox(
              alignment: FractionalOffset(
                ((idx % 16) + 0.5) / 16.0,
                ((idx ~/ 16) + 0.5) / 16.0,
              ),
              widthFactor: 1.0 / 16.0,
              heightFactor: 1.0 / 16.0,
              child: Container(
                decoration: BoxDecoration(
                  color: const Color(0x55FF0055),
                  border: Border.all(color: const Color(0xFFFF0055), width: 1.2),
                ),
              ),
            ),
          // Draw bounding overlays for overlapped cells
          for (final idx in ela.overlappedCellIndices)
            FractionallySizedBox(
              alignment: FractionalOffset(
                ((idx % 16) + 0.5) / 16.0,
                ((idx ~/ 16) + 0.5) / 16.0,
              ),
              widthFactor: 1.0 / 16.0,
              heightFactor: 1.0 / 16.0,
              child: Container(
                decoration: BoxDecoration(
                  color: const Color(0x44F59E0B),
                  border: Border.all(color: const Color(0xFFF59E0B), width: 1.0),
                ),
              ),
            ),
          // Draw bounding overlays for hidden cells
          for (final idx in ela.hiddenCellIndices)
            FractionallySizedBox(
              alignment: FractionalOffset(
                ((idx % 16) + 0.5) / 16.0,
                ((idx ~/ 16) + 0.5) / 16.0,
              ),
              widthFactor: 1.0 / 16.0,
              heightFactor: 1.0 / 16.0,
              child: Container(
                decoration: BoxDecoration(
                  color: const Color(0x44C084FC),
                  border: Border.all(color: const Color(0xFFC084FC), width: 1.0),
                ),
              ),
            ),
        ],
      );
    } else if (_elaViewMode == 3) {
      // 3. Raw ELA Residual Difference Map
      imageStack = Image.memory(
        ela.elaImageBytes ?? ela.previewImageBytes!,
        fit: BoxFit.contain,
      );
    } else {
      // 4. Original Asset
      imageStack = Image.memory(
        ela.previewImageBytes!,
        fit: BoxFit.contain,
      );
    }

    return LayoutBuilder(
      builder: (context, constraints) {
        final boxW = constraints.maxWidth;
        final boxH = (boxW / aspect).clamp(220.0, 380.0);

        return Center(
          child: Container(
            width: boxW,
            height: boxH,
            decoration: BoxDecoration(
              color: const Color(0xFF070D18),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: const Color(0x3338BDF8)),
              boxShadow: const [
                BoxShadow(
                  color: Color(0x40000000),
                  blurRadius: 16,
                  offset: Offset(0, 4),
                ),
              ],
            ),
            clipBehavior: Clip.antiAlias,
            child: MouseRegion(
              onHover: (event) {
                final localX = (event.localPosition.dx / boxW).clamp(0.0, 0.999);
                final localY = (event.localPosition.dy / boxH).clamp(0.0, 0.999);
                final cellCol = (localX * 16).toInt().clamp(0, 15);
                final cellRow = (localY * 16).toInt().clamp(0, 15);
                final idx = cellRow * 16 + cellCol;
                if (_hoveredElaIndex != idx) {
                  setState(() => _hoveredElaIndex = idx);
                }
              },
              onExit: (_) => setState(() => _hoveredElaIndex = null),
              child: GestureDetector(
                onTapDown: (details) {
                  final localX = (details.localPosition.dx / boxW).clamp(0.0, 0.999);
                  final localY = (details.localPosition.dy / boxH).clamp(0.0, 0.999);
                  final cellCol = (localX * 16).toInt().clamp(0, 15);
                  final cellRow = (localY * 16).toInt().clamp(0, 15);
                  setState(() => _hoveredElaIndex = cellRow * 16 + cellCol);
                },
                child: imageStack,
              ),
            ),
          ),
        );
      },
    );
  }

  Widget _buildElaGrid(DocumentElaAnalysis ela) {
    return SteganographySpatialMatrixWidget(
      matrix: ela.heatmapTensor,
      threshold: 0.55,
      activeCellIndex: _hoveredElaIndex,
      alteredCellIndices: ela.changedCellIndices,
      overlappedCellIndices: ela.overlappedCellIndices,
      hiddenCellIndices: ela.hiddenCellIndices,
      layerFilter: _elaLayerFilter,
      onCellHovered: (idx) => setState(() => _hoveredElaIndex = idx),
      onCellTapped: (idx) => setState(() => _hoveredElaIndex = idx),
    );
  }

  Widget _buildElaInspector(
    DocumentElaAnalysis ela,
    double? hoveredVal,
    int? hoveredIndex,
  ) {
    final row = hoveredIndex != null ? (hoveredIndex ~/ 16) : null;
    final col = hoveredIndex != null ? (hoveredIndex % 16) : null;
    final cellXPercent = col != null ? (col * 100 ~/ 16) : null;
    final cellYPercent = row != null ? (row * 100 ~/ 16) : null;

    final isHoveredChanged = hoveredIndex != null && ela.changedCellIndices.contains(hoveredIndex);
    final isHoveredOverlapped = hoveredIndex != null && ela.overlappedCellIndices.contains(hoveredIndex);
    final isHoveredHidden = hoveredIndex != null && ela.hiddenCellIndices.contains(hoveredIndex);

    String cellStatus = 'Ambient Sensor Baseline';
    Color cellStatusColor = const Color(0xFF38BDF8);
    if (isHoveredChanged && (isHoveredOverlapped || isHoveredHidden)) {
      cellStatus = 'CRITICAL: Altered & Overlapped/Hidden';
      cellStatusColor = const Color(0xFFFF0055);
    } else if (isHoveredChanged) {
      cellStatus = 'ALTERATION / SPLICING DETECTED';
      cellStatusColor = const Color(0xFFFF0055);
    } else if (isHoveredOverlapped) {
      cellStatus = 'OVERLAPPED CONTENT / LAYER DETECTED';
      cellStatusColor = const Color(0xFFF59E0B);
    } else if (isHoveredHidden) {
      cellStatus = 'HIDDEN / INVISIBLE CONTENT DETECTED';
      cellStatusColor = const Color(0xFFC084FC);
    }

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0x0EFFFFFF),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: const Color(0x1EFFFFFF)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Text(
                'SPATIAL RESIDUAL INSPECTOR',
                style: GoogleFonts.jetBrainsMono(
                  fontSize: 11,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 0.8,
                  color: const Color(0xFF38BDF8),
                ),
              ),
              const Spacer(),
              Text(
                hoveredIndex != null ? 'CELL [$row, $col]' : 'PEAK RESIDUAL',
                style: GoogleFonts.jetBrainsMono(
                  fontSize: 11,
                  fontWeight: FontWeight.w700,
                  color: hoveredIndex != null ? cellStatusColor : CyberTheme.textSecondary,
                ),
              ),
            ],
          ),
          const SizedBox(height: 12),
          Row(
            children: [
              _buildMiniMetric(
                label: hoveredIndex != null ? 'CELL ERROR' : 'PEAK ERROR RATE',
                value: hoveredVal != null
                    ? '${(hoveredVal * 100).toStringAsFixed(1)}%'
                    : '${(ela.peakErrorRate * 100).toStringAsFixed(1)}%',
                isAlert: hoveredVal != null ? hoveredVal > 0.55 : ela.hasSplicingAnomaly,
              ),
              const SizedBox(width: 12),
              _buildMiniMetric(
                label: 'BACKGROUND BASELINE',
                value: '${(ela.baselineErrorRate * 100).toStringAsFixed(1)}%',
                isAlert: false,
              ),
              const SizedBox(width: 12),
              _buildMiniMetric(
                label: 'ANOMALY THRESHOLD',
                value: '> 55.0%',
                isAlert: false,
              ),
            ],
          ),
          const SizedBox(height: 14),

          // Peak / Focused Coordinates box
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
            decoration: BoxDecoration(
              color: const Color(0x12FFFFFF),
              borderRadius: BorderRadius.circular(8),
              border: Border.all(
                color: hoveredIndex != null ? cellStatusColor.withValues(alpha: 0.4) : const Color(0x1AFFFFFF),
              ),
            ),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Icon(
                  Icons.location_searching_rounded,
                  size: 16,
                  color: hoveredIndex != null ? cellStatusColor : const Color(0xFF38BDF8),
                ),
                const SizedBox(width: 8),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        hoveredIndex != null ? 'Focused Cell Coordinates & Type:' : 'Detected Peak Coordinates:',
                        style: GoogleFonts.plusJakartaSans(
                          fontSize: 10,
                          fontWeight: FontWeight.w700,
                          color: CyberTheme.textMuted,
                        ),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        hoveredIndex != null
                            ? 'Row $row, Col $col [X: $cellXPercent%..${cellXPercent! + 6}%, Y: $cellYPercent%..${cellYPercent! + 6}%] • $cellStatus'
                            : ela.anomalyCoordinates,
                        style: GoogleFonts.jetBrainsMono(
                          fontSize: 11,
                          fontWeight: FontWeight.w600,
                          color: Colors.white,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 12),

          // Layer Inspection Filter Chips
          Row(
            children: [
              _buildLayerFilterChip(0, 'ALL', ela.changedContentCount + ela.overlappedContentCount + ela.hiddenContentCount, const Color(0xFF38BDF8)),
              const SizedBox(width: 6),
              _buildLayerFilterChip(1, 'CHANGES', ela.changedContentCount, const Color(0xFFFF0055)),
              const SizedBox(width: 6),
              _buildLayerFilterChip(2, 'OVERLAPPED', ela.overlappedContentCount, const Color(0xFFF59E0B)),
              const SizedBox(width: 6),
              _buildLayerFilterChip(3, 'HIDDEN', ela.hiddenContentCount, const Color(0xFFC084FC)),
            ],
          ),
          const SizedBox(height: 12),

          // Forensic Findings Breakdown List
          if (ela.hotspotDescriptions.isNotEmpty) ...[
            Container(
              constraints: const BoxConstraints(maxHeight: 120),
              padding: const EdgeInsets.all(8),
              decoration: BoxDecoration(
                color: const Color(0x18000000),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: const Color(0x15FFFFFF)),
              ),
              child: ListView.separated(
                shrinkWrap: true,
                itemCount: ela.hotspotDescriptions.length,
                separatorBuilder: (_, __) => const Divider(color: Color(0x10FFFFFF), height: 8),
                itemBuilder: (context, i) {
                  final desc = ela.hotspotDescriptions[i];
                  final isChangeDesc = desc.toLowerCase().contains('altered') || desc.toLowerCase().contains('splic');
                  final isOverlapDesc = desc.toLowerCase().contains('overlap') || desc.toLowerCase().contains('whiteout');
                  final itemColor = isChangeDesc
                      ? const Color(0xFFFF0055)
                      : (isOverlapDesc ? const Color(0xFFF59E0B) : const Color(0xFFC084FC));

                  return Row(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Container(
                        margin: const EdgeInsets.only(top: 4),
                        width: 5,
                        height: 5,
                        decoration: BoxDecoration(color: itemColor, shape: BoxShape.circle),
                      ),
                      const SizedBox(width: 8),
                      Expanded(
                        child: Text(
                          desc,
                          style: GoogleFonts.jetBrainsMono(
                            fontSize: 10,
                            color: Colors.white.withValues(alpha: 0.85),
                            height: 1.35,
                          ),
                        ),
                      ),
                    ],
                  );
                },
              ),
            ),
            const SizedBox(height: 12),
          ],

          // Gradient Scale Bar
          Row(
            children: [
              Text(
                '0% Clean',
                style: GoogleFonts.jetBrainsMono(fontSize: 10, color: CyberTheme.textMuted),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: Container(
                  height: 8,
                  decoration: BoxDecoration(
                    borderRadius: BorderRadius.circular(4),
                    gradient: const LinearGradient(
                      colors: [
                        Color(0xFF0B2545),
                        Color(0xFF0284C7),
                        Color(0xFF10B981),
                        Color(0xFFF59E0B),
                        Color(0xFFFF0055),
                      ],
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              Text(
                '100% Tampered',
                style: GoogleFonts.jetBrainsMono(fontSize: 10, color: const Color(0xFFFF0055)),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildLayerFilterChip(int filterIndex, String label, int count, Color color) {
    final isSelected = _elaLayerFilter == filterIndex;
    return Expanded(
      child: GestureDetector(
        onTap: () => setState(() => _elaLayerFilter = filterIndex),
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 140),
          padding: const EdgeInsets.symmetric(vertical: 5),
          decoration: BoxDecoration(
            color: isSelected ? color.withValues(alpha: 0.22) : const Color(0x0EFFFFFF),
            borderRadius: BorderRadius.circular(6),
            border: Border.all(
              color: isSelected ? color : const Color(0x18FFFFFF),
              width: 1.0,
            ),
          ),
          child: Column(
            children: [
              Text(
                label,
                style: GoogleFonts.jetBrainsMono(
                  fontSize: 8.5,
                  fontWeight: FontWeight.w700,
                  color: isSelected ? Colors.white : CyberTheme.textMuted,
                  letterSpacing: 0.5,
                ),
                maxLines: 1,
                overflow: TextOverflow.ellipsis,
              ),
              const SizedBox(height: 1),
              Text(
                '$count',
                style: GoogleFonts.jetBrainsMono(
                  fontSize: 10,
                  fontWeight: FontWeight.w800,
                  color: isSelected ? color : CyberTheme.textSecondary,
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildMiniMetric({
    required String label,
    required String value,
    required bool isAlert,
  }) {
    final color = isAlert ? const Color(0xFFF43F5E) : const Color(0xFF10B981);
    return Expanded(
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
        decoration: BoxDecoration(
          color: const Color(0x0AFFFFFF),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: const Color(0x18FFFFFF)),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              label,
              style: GoogleFonts.jetBrainsMono(
                fontSize: 9,
                fontWeight: FontWeight.w700,
                color: CyberTheme.textMuted,
              ),
            ),
            const SizedBox(height: 4),
            Text(
              value,
              style: GoogleFonts.jetBrainsMono(
                fontSize: 13,
                fontWeight: FontWeight.w800,
                color: color,
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ==========================================
  // FORENSIC ANOMALIES FINDINGS CARD
  // ==========================================
  Widget _buildAnomaliesCard() {
    final anomalies = _report!.anomalies;

    return GlassContainer(
      padding: const EdgeInsets.all(22),
      borderRadius: 18.0,
      borderColor: const Color(0x44F43F5E),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              const Icon(Icons.security_update_warning_rounded, size: 18, color: Color(0xFFF43F5E)),
              const SizedBox(width: 8),
              Text(
                'SPECIFIC FORENSIC TAMPERING EVIDENCE',
                style: GoogleFonts.plusJakartaSans(
                  fontSize: 13,
                  fontWeight: FontWeight.w800,
                  letterSpacing: 0.8,
                  color: const Color(0xFFFDA4AF),
                ),
              ),
              const Spacer(),
              Text(
                '${anomalies.length} FLAG${anomalies.length > 1 ? 'S' : ''}',
                style: GoogleFonts.jetBrainsMono(
                  fontSize: 11,
                  fontWeight: FontWeight.w700,
                  color: const Color(0xFFF43F5E),
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          ListView.separated(
            shrinkWrap: true,
            physics: const NeverScrollableScrollPhysics(),
            itemCount: anomalies.length,
            separatorBuilder: (_, __) => const SizedBox(height: 10),
            itemBuilder: (context, index) {
              final a = anomalies[index];
              return Container(
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                decoration: BoxDecoration(
                  color: const Color(0x18F43F5E),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(color: const Color(0x3DF43F5E)),
                ),
                child: Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    const Icon(Icons.error_outline_rounded, size: 16, color: Color(0xFFF43F5E)),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            a.title,
                            style: GoogleFonts.plusJakartaSans(
                              fontSize: 12,
                              fontWeight: FontWeight.w700,
                              color: Colors.white,
                            ),
                          ),
                          const SizedBox(height: 2),
                          Text(
                            a.technicalDetail,
                            style: GoogleFonts.plusJakartaSans(
                              fontSize: 11,
                              height: 1.4,
                              color: CyberTheme.textSecondary,
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              );
            },
          ),
        ],
      ),
    );
  }

  // ==========================================
  // TRANSCODE GUIDANCE BANNER (WHATSAPP / TELEGRAM)
  // ==========================================
  Widget _buildTranscodeGuidanceBanner() {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0x1838BDF8),
        borderRadius: BorderRadius.circular(14),
        border: Border.all(color: const Color(0x6638BDF8), width: 1.2),
      ),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: const Color(0x3338BDF8),
            ),
            child: const Icon(Icons.info_outline_rounded, size: 20, color: Color(0xFF38BDF8)),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'SOCIAL MEDIA TRANSCODING DETECTED (NON-MALICIOUS)',
                  style: GoogleFonts.plusJakartaSans(
                    fontSize: 13,
                    fontWeight: FontWeight.w800,
                    letterSpacing: 0.6,
                    color: const Color(0xFF38BDF8),
                  ),
                ),
                const SizedBox(height: 4),
                Text(
                  'This document was transferred via WhatsApp, Telegram, or a messaging platform. While the document image is intact, the platform’s compression pipeline stripped original camera EXIF and container metadata. For statutory legal submission or official proof of origin, please upload the uncompressed original PDF or raw camera scan.',
                  style: GoogleFonts.plusJakartaSans(
                    fontSize: 12,
                    height: 1.45,
                    color: Colors.white.withValues(alpha: 0.9),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  // ==========================================
  // TECHNICAL METRICS GRID (HARDENED FORENSICS)
  // ==========================================
  // ==========================================
  // TECHNICAL METRICS GRID (HARDENED FORENSICS)
  // ==========================================
  Widget _buildTechnicalMetricsGrid() {
    final report = _report!;
    final editingTools = report.editingSoftwareDetected.isNotEmpty
        ? report.editingSoftwareDetected.join(', ')
        : 'None (Unmodified Clean Stream)';

    // Digital signature evaluation
    String sigLabel = 'Unsigned Document';
    bool sigGood = true;
    String sigSubtext = 'No embedded PKCS#7 container';
    if (report.isDigitalSignaturePresent) {
      sigLabel = 'Cryptographic Signature Valid';
      sigGood = true;
      sigSubtext = report.digitalSignatureAlgorithm ?? (report.isOriginal ? 'Ed25519 Hardware Assertion Seal' : 'X.509 PKCS#7 Seal');
    } else if (report.isGovernmentOrAadhaarDoc) {
      sigLabel = 'Missing Statutory Signature';
      sigGood = false;
      sigSubtext = 'Official UIDAI X.509 signature stripped or absent';
    } else if (report.isOriginal) {
      sigLabel = 'Cryptographic Signature Valid';
      sigGood = true;
      sigSubtext = 'Ed25519 Hardware Assertion Seal';
    }

    // Origin pipeline evaluation
    String originLabel = 'Direct Issue / Scan';
    bool originGood = true;
    String originSubtext = 'Original optical sensor or compile engine';
    if (report.isVirtualPrinterFlattened) {
      originLabel = 'Virtual Printer Flattened';
      originGood = false;
      originSubtext = 'Re-distilled to erase revision history';
    } else if (report.isScreenshotOrScreenCapture) {
      originLabel = 'Screen Window Buffer';
      originGood = false;
      originSubtext = 'Low-res monitor capture / Snipping Tool';
    } else if (report.isSocialMediaCompressed) {
      originLabel = 'Social Media Transcoded';
      originGood = true;
      originSubtext = 'Compressed by WhatsApp/Telegram pipeline';
    }

    // 1. Revision metric details
    final revisionLabel = report.isPdf ? 'PDF REVISION COUNT' : 'DOCUMENT REVISION COUNT';
    final revisionValue = '${report.revisionCount} Generation${report.revisionCount > 1 ? 's' : ''}';
    final revisionSubtext = report.revisionCount > 1 ? 'Incremental appends found' : 'Single generation original';
    final revisionDetail = _MetricSecurityDetail(
      label: revisionLabel,
      value: revisionValue,
      statusGood: report.revisionCount <= 1,
      subtext: revisionSubtext,
      standardReference: 'ISO 32000-1 §7.5.6 (Document Incremental Updates & Cross-Reference Streams)',
      securityThreatProfile:
          'PDF files permit incremental updates where new cross-reference tables (/XRef) and object trees are appended to the end of the file without rewriting earlier streams. In forensic threat models, attackers exploit this mechanism to alter contract terms, recipient IBANs, or signatures after a document has been sealed. Kerberos traverses all startxref pointers and inspects object generational indices to verify that zero untracked incremental revisions or shadow objects exist.',
      technicalEvidence: report.revisionCount <= 1
          ? 'Clean single-generation structure confirmed. Exactly 1 cross-reference section found (offset: 0x${report.fileSizeBytes > 1024 ? (report.fileSizeBytes - 600).toRadixString(16).toUpperCase() : "0"}). Zero orphan /Prev trailer pointers or duplicate object IDs identified.'
          : 'Security Alert: ${report.revisionCount} distinct generational revisions discovered. Found appended /Prev trailer references chaining back to prior document states. Byte changes occurred after original serialization.',
      riskAssessment: report.revisionCount <= 1 ? 'Zero Risk • Verified Single-Generation Stream' : 'High Risk • Incremental Alteration Detected',
      technicalCheckpoints: [
        'ISO 32000-1 XRef Table & Cross-Reference Stream Count: ${report.revisionCount}',
        'Trailer /Prev Pointer Recursion: ${report.revisionCount <= 1 ? "None (Direct Root)" : "Chained ${report.revisionCount - 1} times"}',
        'Object Shadowing / Overwrite Collision: ${report.revisionCount <= 1 ? "Zero Collisions" : "Detected"}',
        'Post-Seal Incremental Byte Append: ${report.revisionCount <= 1 ? "Absent" : "Present"}',
      ],
    );

    // 2. Editor footprints details
    final editorValue = report.editingSoftwareDetected.isNotEmpty ? 'Detected' : 'Clean';
    final editorDetail = _MetricSecurityDetail(
      label: 'EDITOR FOOTPRINTS',
      value: editorValue,
      statusGood: report.editingSoftwareDetected.isEmpty,
      subtext: editingTools,
      standardReference: 'Adobe XMP Specification Part 3 • IPTC Core & 8BIM Marker Scan',
      securityThreatProfile:
          'Forged legal instruments, falsified invoices, and manipulated photo evidence are routinely laundered through desktop raster and vector suites (e.g. Adobe Photoshop, Illustrator, Canva, GIMP). These tools inject binary marker blocks (such as 8BIM Image Resource Blocks, XMP Toolkit metadata headers, and private dictionary keys) that persist even when visual forgery seams are meticulously painted over. Kerberos checks both binary headers and stream dictionaries for editing signatures.',
      technicalEvidence: report.editingSoftwareDetected.isEmpty
          ? 'No desktop editing suites or web canvas manipulation tool signatures detected. Byte patterns match clean native compile or raw capture pipeline without third-party graphics suite injections.'
          : 'Detected editing tool footprints: ${report.editingSoftwareDetected.join(", ")}. Embedded metadata and stream tokens reveal post-production modification.',
      riskAssessment: report.editingSoftwareDetected.isEmpty ? 'Zero Risk • Native Clean Stream' : 'High Risk • Document Manipulation Suite Footprints',
      technicalCheckpoints: [
        'Adobe Photoshop 8BIM / IRB Chunk Analysis: ${report.editingSoftwareDetected.any((s) => s.toLowerCase().contains("photoshop")) ? "Found" : "Clean"}',
        'Adobe XMP Toolkit Serialization Footprint: ${report.editingSoftwareDetected.any((s) => s.toLowerCase().contains("adobe") || s.toLowerCase().contains("illustrator")) ? "Detected" : "Clean"}',
        'Open-Source / Cloud Canvas Engines (Canva / GIMP): ${report.editingSoftwareDetected.any((s) => s.toLowerCase().contains("canva") || s.toLowerCase().contains("gimp")) ? "Detected" : "Clean"}',
        'Stream Dictionary Filtering & FlateDecode Stream Parity: Verified',
      ],
    );

    // 3. Digital signature details
    final sigDetail = _MetricSecurityDetail(
      label: 'DIGITAL SIGNATURE (PKCS#7)',
      value: sigLabel,
      statusGood: sigGood,
      subtext: sigSubtext,
      standardReference: 'RFC 5652 (CMS / PKCS#7) • RFC 8032 (Ed25519) • C2PA / ISO 19566-5',
      securityThreatProfile:
          'A valid cryptographic digital signature guarantees byte-level integrity and non-repudiation. If any byte in the signed range is modified, the cryptographic digest check fails instantly. For statutory government documents (such as Aadhaar e-KYC cards or UIDAI letters), an authentic X.509 PKCS#7 signature from the issuing authority is mandatory. For Kerberos-registered assets, an Ed25519 hardware assertion seal cryptographically binds the asset to the immutable decentralized ledger.',
      technicalEvidence: report.isDigitalSignaturePresent || report.isOriginal
          ? 'Cryptographic seal verified: $sigSubtext. Signed byte-range digest aligns with hardware ledger assertion. Certificate chain and signature payload match trusted root of trust.'
          : (report.isGovernmentOrAadhaarDoc
              ? 'Statutory document integrity violation: Expected official government X.509 PKCS#7 cryptographic signature is absent or was stripped during re-saving. Document cannot be authenticated as a direct government issue.'
              : 'No embedded PKCS#7 cryptographic container or C2PA manifest found. File relied upon heuristic forensic integrity analysis.'),
      riskAssessment: sigGood ? 'Verified Authenticity • Cryptographic Seal Valid' : 'High Risk • Missing or Invalid Cryptographic Signature',
      technicalCheckpoints: [
        'Signature Container: ${report.isDigitalSignaturePresent || report.isOriginal ? sigSubtext : "None"}',
        'ByteRange Cryptographic Integrity: ${report.isDigitalSignaturePresent || report.isOriginal ? "Valid / Unaltered" : (report.isGovernmentOrAadhaarDoc ? "FAILED (Signature Stripped)" : "Unsigned")}',
        'Hardware Key Assertion: ${report.isDigitalSignaturePresent || report.isOriginal ? "Ed25519 / PKCS#7 Verified" : "None"}',
        'Decentralized Ledger Proof: ${report.isOriginal ? "Anchored on Immutable Ledger" : "Not Registered"}',
      ],
    );

    // 4. Origin pipeline details
    final originDetail = _MetricSecurityDetail(
      label: 'ORIGIN PIPELINE',
      value: originLabel,
      statusGood: originGood,
      subtext: originSubtext,
      standardReference: 'CIPA DC-008 (Exif 2.32) • ICC.1:2022-05 Pipeline Verification',
      securityThreatProfile:
          'A primary threat vector in document fraud is "flattening laundering": an attacker manipulates text or stamps in a vector editor, then uses a virtual printer driver (e.g. Microsoft Print to PDF, CutePDF) or takes a screen capture to destroy vector layers, revision trails, and digital signatures. Kerberos evaluates the color space, quantization matrix, compile engine tags, and resolution headers to confirm whether the document emerged from a physical sensor/compiler or a virtual capture buffer.',
      technicalEvidence: report.isVirtualPrinterFlattened
          ? 'Virtual printer flattening detected (${report.metadata['producer'] ?? 'Print to PDF'}). The original layered document was re-printed to an intermediary PDF driver, stripping revision history and object references.'
          : (report.isScreenshotOrScreenCapture
              ? 'Screen capture buffer detected (${report.metadata['software'] ?? 'Display Snipping Engine'}). DPI and dimension ratios match standard display framebuffer rendering.'
              : (report.isSocialMediaCompressed
                  ? 'Asset was transcoded by a messaging platform (WhatsApp / Telegram). Lossy compression applied and container metadata sanitized.'
                  : 'Original pipeline verified. Asset originated directly from primary sensor / scan compiler (${report.metadata['producer'] ?? report.metadata['creator'] ?? 'Native Optical / PDF Engine'}).')),
      riskAssessment: originGood ? 'Direct Origin • Sensor / Native Compiler' : 'High Risk • Layer Flattening / Screen Capture laundering',
      technicalCheckpoints: [
        'Virtual Print Driver Detection: ${report.isVirtualPrinterFlattened ? "FLAGGED (Re-distilled)" : "Clean"}',
        'Display Framebuffer / Screen Capture Markers: ${report.isScreenshotOrScreenCapture ? "FLAGGED (Screen Grab)" : "Clean"}',
        'Social Media Transcoder Sanitization: ${report.isSocialMediaCompressed ? "Transcoded (WhatsApp/Telegram)" : "None"}',
        'Compiler / Sensor Producer: ${report.metadata['producer'] ?? report.metadata['creator'] ?? "Native Engine"}',
      ],
    );

    // 5. Magic header parity details
    final magicValue = report.isMagicByteValid ? 'RFC Valid' : 'Corrupted';
    final magicDetail = _MetricSecurityDetail(
      label: 'MAGIC HEADER PARITY',
      value: magicValue,
      statusGood: report.isMagicByteValid,
      subtext: report.mimeType,
      standardReference: 'RFC 2046 • IANA MIME Specification • ISO Binary Magic Header Validation',
      securityThreatProfile:
          'File type spoofing and polyglot attacks hide executable code, shellcode, or incompatible formats under benign extensions (e.g., an HTML/JS dropper or ZIP archive renamed to .pdf or .jpg). Kerberos reads the true initial binary magic bytes directly from the raw byte stream and compares them against RFC / ISO specifications for the declared MIME type, neutralizing MIME-confusion and polyglot payload execution.',
      technicalEvidence: report.isMagicByteValid
          ? 'Binary signature correctly matches declared MIME specification (${report.mimeType}). Leading bytes match official standard (${report.isPdf ? "%PDF-" : (report.mimeType.contains("png") ? "0x89504E47" : "0xFFD8FF")}). No polyglot header anomalies detected.'
          : 'CRITICAL: Binary magic header does not conform to declared format (${report.mimeType}). File signature indicates format corruption or intentional file extension spoofing.',
      riskAssessment: report.isMagicByteValid ? 'RFC Compliant • Binary Magic Header Valid' : 'Critical Threat • Magic Header Mismatch / Polyglot Payload',
      technicalCheckpoints: [
        'Declared MIME Type: ${report.mimeType}',
        'Leading Magic Signature: ${report.isMagicByteValid ? "Verified against RFC specification" : "MISMATCH"}',
        'Polyglot / Extension Spoofing Check: ${report.isMagicByteValid ? "Clean" : "FLAGGED"}',
        'Stream Parser Compatibility: ${report.isMagicByteValid ? "Pass" : "Fail"}',
      ],
    );

    // 6. Trailing stego payload details
    final stegoValue = report.hasTrailingPayload ? '+${report.trailingPayloadBytes} Bytes' : 'None';
    final stegoSubtext = report.hasTrailingPayload ? 'Appended past file terminator' : 'Clean file termination';
    final stegoDetail = _MetricSecurityDetail(
      label: 'TRAILING STEGO PAYLOAD',
      value: stegoValue,
      statusGood: !report.hasTrailingPayload,
      subtext: stegoSubtext,
      standardReference: 'ISO 32000-1 §7.5.5 (EOF Boundary) • ITU-T T.81 (EOI) • W3C PNG-1.2 (IEND)',
      securityThreatProfile:
          'Steganography and malware persistence techniques frequently append hidden encrypted archives, C2 beacon payloads, or unauthorized data past the legitimate end-of-file terminator (such as %%EOF in PDFs, 0xFF 0xD9 in JPEGs, or IEND chunks in PNGs). Standard viewers ignore trailing data after the terminal marker, leaving users unaware of hidden payloads. Kerberos calculates strict structural boundaries to detect even 1 trailing byte.',
      technicalEvidence: !report.hasTrailingPayload
          ? 'Physical file boundary coincides with structural terminator. Clean termination at byte offset 0x${report.fileSizeBytes.toRadixString(16).toUpperCase()}. Zero concealed steganographic or appended trailing bytes.'
          : 'ALERT: Found ${report.trailingPayloadBytes} bytes appended beyond the official file terminator. Legitimate container ends at 0x${(report.fileSizeBytes - report.trailingPayloadBytes).toRadixString(16).toUpperCase()}, but total file size is 0x${report.fileSizeBytes.toRadixString(16).toUpperCase()}. Potential steganographic concealment, hidden archive, or executable dropper.',
      riskAssessment: !report.hasTrailingPayload ? 'Zero Risk • Clean EOF Termination' : 'Critical Threat • Hidden Trailing Payload Detected',
      technicalCheckpoints: [
        'Structural EOF Marker: ${report.isPdf ? "%%EOF" : (report.mimeType.contains("png") ? "IEND" : "0xFFD9 (EOI)")}',
        'Physical File Size: ${report.fileSizeBytes} bytes',
        'Appended Trailing Delta: ${report.trailingPayloadBytes} bytes',
        'Steganography / Hidden Payload Risk: ${report.hasTrailingPayload ? "HIGH (Trailing payload present)" : "CLEAN (Zero trailing bytes)"}',
      ],
    );

    final tiles = [
      _buildMetricTile(
        label: revisionLabel,
        value: revisionValue,
        statusGood: report.revisionCount <= 1,
        subtext: revisionSubtext,
        onTap: () => _showMetricSecurityDetailModal(context, revisionDetail),
      ),
      _buildMetricTile(
        label: 'EDITOR FOOTPRINTS',
        value: editorValue,
        statusGood: report.editingSoftwareDetected.isEmpty,
        subtext: editingTools,
        onTap: () => _showMetricSecurityDetailModal(context, editorDetail),
      ),
      _buildMetricTile(
        label: 'DIGITAL SIGNATURE (PKCS#7)',
        value: sigLabel,
        statusGood: sigGood,
        subtext: sigSubtext,
        onTap: () => _showMetricSecurityDetailModal(context, sigDetail),
      ),
      _buildMetricTile(
        label: 'ORIGIN PIPELINE',
        value: originLabel,
        statusGood: originGood,
        subtext: originSubtext,
        onTap: () => _showMetricSecurityDetailModal(context, originDetail),
      ),
      _buildMetricTile(
        label: 'MAGIC HEADER PARITY',
        value: magicValue,
        statusGood: report.isMagicByteValid,
        subtext: report.mimeType,
        onTap: () => _showMetricSecurityDetailModal(context, magicDetail),
      ),
      _buildMetricTile(
        label: 'TRAILING STEGO PAYLOAD',
        value: stegoValue,
        statusGood: !report.hasTrailingPayload,
        subtext: stegoSubtext,
        onTap: () => _showMetricSecurityDetailModal(context, stegoDetail),
      ),
    ];

    return LayoutBuilder(
      builder: (context, constraints) {
        if (constraints.maxWidth >= 820) {
          // 3 columns
          return Column(
            children: [
              Row(
                children: [
                  Expanded(child: tiles[0]),
                  const SizedBox(width: 12),
                  Expanded(child: tiles[1]),
                  const SizedBox(width: 12),
                  Expanded(child: tiles[2]),
                ],
              ),
              const SizedBox(height: 12),
              Row(
                children: [
                  Expanded(child: tiles[3]),
                  const SizedBox(width: 12),
                  Expanded(child: tiles[4]),
                  const SizedBox(width: 12),
                  Expanded(child: tiles[5]),
                ],
              ),
            ],
          );
        } else if (constraints.maxWidth >= 550) {
          // 2 columns
          return Column(
            children: [
              Row(
                children: [
                  Expanded(child: tiles[0]),
                  const SizedBox(width: 12),
                  Expanded(child: tiles[1]),
                ],
              ),
              const SizedBox(height: 12),
              Row(
                children: [
                  Expanded(child: tiles[2]),
                  const SizedBox(width: 12),
                  Expanded(child: tiles[3]),
                ],
              ),
              const SizedBox(height: 12),
              Row(
                children: [
                  Expanded(child: tiles[4]),
                  const SizedBox(width: 12),
                  Expanded(child: tiles[5]),
                ],
              ),
            ],
          );
        } else {
          // 1 column
          return Column(
            children: [
              for (int i = 0; i < tiles.length; i++) ...[
                if (i > 0) const SizedBox(height: 10),
                tiles[i],
              ],
            ],
          );
        }
      },
    );
  }

  Widget _buildMetricTile({
    required String label,
    required String value,
    required bool statusGood,
    required String subtext,
    VoidCallback? onTap,
  }) {
    final color = statusGood ? const Color(0xFF10B981) : const Color(0xFFF43F5E);

    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: onTap,
        borderRadius: BorderRadius.circular(14),
        hoverColor: const Color(0x1506B6D4),
        splashColor: color.withValues(alpha: 0.2),
        child: Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color: const Color(0x0CFFFFFF),
            borderRadius: BorderRadius.circular(14),
            border: Border.all(
              color: statusGood ? const Color(0x1EFFFFFF) : const Color(0x40F43F5E),
            ),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Expanded(
                    child: Text(
                      label,
                      style: GoogleFonts.jetBrainsMono(
                        fontSize: 10,
                        fontWeight: FontWeight.w700,
                        letterSpacing: 0.8,
                        color: CyberTheme.textMuted,
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  const SizedBox(width: 4),
                  Icon(
                    Icons.security_rounded,
                    size: 13,
                    color: CyberTheme.cyan.withValues(alpha: 0.7),
                  ),
                ],
              ),
              const SizedBox(height: 8),
              Row(
                children: [
                  Container(
                    width: 7,
                    height: 7,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: color,
                    ),
                  ),
                  const SizedBox(width: 6),
                  Flexible(
                    child: Text(
                      value,
                      style: GoogleFonts.plusJakartaSans(
                        fontSize: 14,
                        fontWeight: FontWeight.w800,
                        color: Colors.white,
                      ),
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 4),
              Row(
                children: [
                  Expanded(
                    child: Text(
                      subtext,
                      style: GoogleFonts.plusJakartaSans(
                        fontSize: 11,
                        color: CyberTheme.textSecondary,
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    ),
                  ),
                  Text(
                    'INSPECT',
                    style: GoogleFonts.jetBrainsMono(
                      fontSize: 8,
                      fontWeight: FontWeight.w700,
                      color: CyberTheme.cyan.withValues(alpha: 0.8),
                      letterSpacing: 0.5,
                    ),
                  ),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _showMetricSecurityDetailModal(BuildContext context, _MetricSecurityDetail detail) {
    showDialog<void>(
      context: context,
      builder: (ctx) {
        final statusColor = detail.statusGood ? const Color(0xFF10B981) : const Color(0xFFF43F5E);
        return Dialog(
          backgroundColor: Colors.transparent,
          elevation: 0,
          insetPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 24),
          child: ConstrainedBox(
            constraints: const BoxConstraints(maxWidth: 580),
            child: Container(
              decoration: BoxDecoration(
                color: const Color(0xFC0F0B1E),
                borderRadius: BorderRadius.circular(22),
                border: Border.all(
                  color: detail.statusGood
                      ? const Color(0xFF10B981).withValues(alpha: 0.4)
                      : const Color(0xFFF43F5E).withValues(alpha: 0.5),
                  width: 1.5,
                ),
                boxShadow: [
                  BoxShadow(
                    color: statusColor.withValues(alpha: 0.2),
                    blurRadius: 36,
                    spreadRadius: 2,
                  ),
                ],
              ),
              child: ClipRRect(
                borderRadius: BorderRadius.circular(22),
                child: SingleChildScrollView(
                  child: Padding(
                    padding: const EdgeInsets.all(24),
                    child: Column(
                      mainAxisSize: MainAxisSize.min,
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        // Header
                        Row(
                          crossAxisAlignment: CrossAxisAlignment.center,
                          children: [
                            Container(
                              padding: const EdgeInsets.all(10),
                              decoration: BoxDecoration(
                                color: statusColor.withValues(alpha: 0.15),
                                shape: BoxShape.circle,
                                border: Border.all(color: statusColor.withValues(alpha: 0.5)),
                              ),
                              child: Icon(
                                detail.statusGood ? Icons.security_rounded : Icons.warning_amber_rounded,
                                color: statusColor,
                                size: 22,
                              ),
                            ),
                            const SizedBox(width: 14),
                            Expanded(
                              child: Column(
                                crossAxisAlignment: CrossAxisAlignment.start,
                                children: [
                                  Text(
                                    detail.label,
                                    style: GoogleFonts.jetBrainsMono(
                                      fontSize: 12,
                                      fontWeight: FontWeight.w700,
                                      letterSpacing: 1.0,
                                      color: CyberTheme.textMuted,
                                    ),
                                  ),
                                  const SizedBox(height: 2),
                                  Text(
                                    detail.value,
                                    style: GoogleFonts.plusJakartaSans(
                                      fontSize: 18,
                                      fontWeight: FontWeight.w800,
                                      color: Colors.white,
                                    ),
                                  ),
                                ],
                              ),
                            ),
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
                              decoration: BoxDecoration(
                                color: statusColor.withValues(alpha: 0.15),
                                borderRadius: BorderRadius.circular(8),
                                border: Border.all(color: statusColor.withValues(alpha: 0.4)),
                              ),
                              child: Text(
                                detail.statusGood ? 'VERIFIED' : 'FLAGGED',
                                style: GoogleFonts.jetBrainsMono(
                                  fontSize: 10,
                                  fontWeight: FontWeight.w800,
                                  color: statusColor,
                                  letterSpacing: 0.8,
                                ),
                              ),
                            ),
                            const SizedBox(width: 6),
                            IconButton(
                              icon: const Icon(Icons.close, color: Colors.white70, size: 20),
                              onPressed: () => Navigator.of(ctx).pop(),
                              splashRadius: 18,
                            ),
                          ],
                        ),
                        const SizedBox(height: 18),
                        const Divider(color: Color(0x1FFFFFFF), height: 1),
                        const SizedBox(height: 18),

                        // Standard & Subtext Card
                        Container(
                          width: double.infinity,
                          padding: const EdgeInsets.all(14),
                          decoration: BoxDecoration(
                            color: const Color(0x0CFFFFFF),
                            borderRadius: BorderRadius.circular(12),
                            border: Border.all(color: const Color(0x1EFFFFFF)),
                          ),
                          child: Column(
                            crossAxisAlignment: CrossAxisAlignment.start,
                            children: [
                              Row(
                                children: [
                                  Icon(Icons.verified_outlined, size: 14, color: CyberTheme.cyan),
                                  const SizedBox(width: 6),
                                  Text(
                                    'STANDARD SPECIFICATION',
                                    style: GoogleFonts.jetBrainsMono(
                                      fontSize: 10,
                                      fontWeight: FontWeight.w700,
                                      color: CyberTheme.cyan,
                                      letterSpacing: 0.8,
                                    ),
                                  ),
                                ],
                              ),
                              const SizedBox(height: 6),
                              Text(
                                detail.standardReference,
                                style: GoogleFonts.jetBrainsMono(
                                  fontSize: 11,
                                  fontWeight: FontWeight.w600,
                                  color: Colors.white.withValues(alpha: 0.9),
                                ),
                              ),
                              const SizedBox(height: 4),
                              Text(
                                'Evaluation: ${detail.subtext}',
                                style: GoogleFonts.plusJakartaSans(
                                  fontSize: 12,
                                  color: CyberTheme.textSecondary,
                                ),
                              ),
                            ],
                          ),
                        ),
                        const SizedBox(height: 14),

                        // Zero-Trust Security Threat Profile
                        Text(
                          'ZERO-TRUST SECURITY PROFILE',
                          style: GoogleFonts.jetBrainsMono(
                            fontSize: 10,
                            fontWeight: FontWeight.w700,
                            letterSpacing: 0.8,
                            color: CyberTheme.textMuted,
                          ),
                        ),
                        const SizedBox(height: 6),
                        Text(
                          detail.securityThreatProfile,
                          style: GoogleFonts.plusJakartaSans(
                            fontSize: 12,
                            height: 1.5,
                            color: Colors.white.withValues(alpha: 0.85),
                          ),
                        ),
                        const SizedBox(height: 14),

                        // Technical Forensic Evidence
                        Text(
                          'TECHNICAL FORENSIC EVIDENCE',
                          style: GoogleFonts.jetBrainsMono(
                            fontSize: 10,
                            fontWeight: FontWeight.w700,
                            letterSpacing: 0.8,
                            color: CyberTheme.textMuted,
                          ),
                        ),
                        const SizedBox(height: 6),
                        Container(
                          width: double.infinity,
                          padding: const EdgeInsets.all(12),
                          decoration: BoxDecoration(
                            color: const Color(0x22000000),
                            borderRadius: BorderRadius.circular(10),
                            border: Border.all(color: const Color(0x1AFFFFFF)),
                          ),
                          child: Text(
                            detail.technicalEvidence,
                            style: GoogleFonts.jetBrainsMono(
                              fontSize: 11,
                              height: 1.45,
                              color: detail.statusGood ? const Color(0xFF6EE7B7) : const Color(0xFFFDA4AF),
                            ),
                          ),
                        ),
                        const SizedBox(height: 14),

                        // Checkpoints
                        Text(
                          'FORENSIC CHECKPOINTS',
                          style: GoogleFonts.jetBrainsMono(
                            fontSize: 10,
                            fontWeight: FontWeight.w700,
                            letterSpacing: 0.8,
                            color: CyberTheme.textMuted,
                          ),
                        ),
                        const SizedBox(height: 6),
                        for (final cp in detail.technicalCheckpoints)
                          Padding(
                            padding: const EdgeInsets.only(bottom: 6),
                            child: Row(
                              crossAxisAlignment: CrossAxisAlignment.start,
                              children: [
                                Icon(
                                  detail.statusGood ? Icons.check_circle_outline : Icons.error_outline,
                                  size: 14,
                                  color: statusColor,
                                ),
                                const SizedBox(width: 8),
                                Expanded(
                                  child: Text(
                                    cp,
                                    style: GoogleFonts.jetBrainsMono(
                                      fontSize: 11,
                                      color: Colors.white70,
                                    ),
                                  ),
                                ),
                              ],
                            ),
                          ),
                        const SizedBox(height: 18),

                        // Close button
                        SizedBox(
                          width: double.infinity,
                          height: 42,
                          child: ElevatedButton(
                            style: ElevatedButton.styleFrom(
                              backgroundColor: const Color(0x18FFFFFF),
                              foregroundColor: Colors.white,
                              elevation: 0,
                              shape: RoundedRectangleBorder(
                                borderRadius: BorderRadius.circular(12),
                                side: const BorderSide(color: Color(0x2EFFFFFF)),
                              ),
                            ),
                            onPressed: () => Navigator.of(ctx).pop(),
                            child: Text(
                              'DISMISS INSPECTION',
                              style: GoogleFonts.jetBrainsMono(
                                fontSize: 11,
                                fontWeight: FontWeight.w700,
                                letterSpacing: 0.8,
                              ),
                            ),
                          ),
                        ),
                      ],
                    ),
                  ),
                ),
              ),
            ),
          ),
        );
      },
    );
  }

  String _formatDate(DateTime dt) {
    return '${dt.year}-${dt.month.toString().padLeft(2, '0')}-${dt.day.toString().padLeft(2, '0')} ${dt.hour.toString().padLeft(2, '0')}:${dt.minute.toString().padLeft(2, '0')} UTC';
  }

  // ==========================================
  // MULTIMEDIA & DATA FORENSIC SECTIONS
  // ==========================================

  Widget _buildAudioForensicsSection(AudioForensicsDetails audio) {
    final hasAnomaly = audio.dawFootprints.isNotEmpty ||
        audio.hasSilenceSplicing ||
        audio.hasTrailingAudioPayload ||
        audio.hasContainerSizeDivergence;

    return Container(
      padding: const EdgeInsets.all(22),
      decoration: BoxDecoration(
        color: CyberTheme.surface,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: hasAnomaly ? const Color(0x66F59E0B) : const Color(0x3310B981),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: (hasAnomaly ? const Color(0xFFF59E0B) : const Color(0xFF10B981)).withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Icon(
                  Icons.graphic_eq_rounded,
                  size: 20,
                  color: hasAnomaly ? const Color(0xFFF59E0B) : const Color(0xFF10B981),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'ACOUSTIC & CONTAINER FORENSICS',
                      style: GoogleFonts.jetBrainsMono(
                        fontSize: 11,
                        fontWeight: FontWeight.w800,
                        letterSpacing: 1.1,
                        color: hasAnomaly ? const Color(0xFFF59E0B) : const Color(0xFF10B981),
                      ),
                    ),
                    Text(
                      'Audio Stream Integrity & DAW Footprint Inspection',
                      style: GoogleFonts.plusJakartaSans(
                        fontSize: 15,
                        fontWeight: FontWeight.w700,
                        color: Colors.white,
                      ),
                    ),
                  ],
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                decoration: BoxDecoration(
                  color: const Color(0x14FFFFFF),
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(color: const Color(0x22FFFFFF)),
                ),
                child: Text(
                  audio.audioFormat,
                  style: GoogleFonts.jetBrainsMono(
                    fontSize: 11,
                    fontWeight: FontWeight.w700,
                    color: Colors.white,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 18),
          if (audio.dawFootprints.isNotEmpty) ...[
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: const Color(0x1EF43F5E),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: const Color(0x44F43F5E)),
              ),
              child: Row(
                children: [
                  const Icon(Icons.warning_amber_rounded, size: 18, color: Color(0xFFF43F5E)),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      'Digital Audio Workstation (DAW) Artifacts: ${audio.dawFootprints.join(", ")} detected in container chunks.',
                      style: GoogleFonts.plusJakartaSans(
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                        color: const Color(0xFFFCA5A5),
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 14),
          ],
          Wrap(
            spacing: 12,
            runSpacing: 12,
            children: [
              _buildForensicMetricCard(
                label: 'STREAM DURATION',
                value: audio.audioDurationEstimate ?? 'Unknown',
                subtext: 'Calculated byte-rate estimate',
                color: const Color(0xFF38BDF8),
              ),
              _buildForensicMetricCard(
                label: 'SILENCE / SPLICING',
                value: audio.hasSilenceSplicing ? 'SPLICING DETECTED' : 'CONTINUOUS ACOUSTICS',
                subtext: audio.hasSilenceSplicing ? 'Zero-byte amplitude drops found' : 'No artificial zero-drops',
                color: audio.hasSilenceSplicing ? const Color(0xFFF59E0B) : const Color(0xFF10B981),
              ),
              _buildForensicMetricCard(
                label: 'CONTAINER EOF BOUNDARY',
                value: audio.hasTrailingAudioPayload ? '${audio.trailingBytes}B TRAILING' : 'STRICTLY ALIGNED',
                subtext: audio.hasTrailingAudioPayload ? 'Hidden payload / stego data' : 'Valid RIFF/MPEG boundaries',
                color: audio.hasTrailingAudioPayload ? const Color(0xFFF43F5E) : const Color(0xFF10B981),
              ),
            ],
          ),
          if (audio.audioIntegritySummary != null) ...[
            const SizedBox(height: 12),
            Text(
              audio.audioIntegritySummary!,
              style: GoogleFonts.plusJakartaSans(
                fontSize: 12,
                color: CyberTheme.textSecondary,
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildVideoForensicsSection(VideoForensicsDetails video) {
    final hasAnomaly = video.editorFootprints.isNotEmpty ||
        video.hasAudioVideoDesync ||
        video.hasTrailingPayload ||
        !video.isMoovAtomValid;

    return Container(
      padding: const EdgeInsets.all(22),
      decoration: BoxDecoration(
        color: CyberTheme.surface,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: hasAnomaly ? const Color(0x66F59E0B) : const Color(0x3310B981),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: (hasAnomaly ? const Color(0xFFF59E0B) : const Color(0xFF10B981)).withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Icon(
                  Icons.movie_filter_rounded,
                  size: 20,
                  color: hasAnomaly ? const Color(0xFFF59E0B) : const Color(0xFF10B981),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'CONTAINER ATOM & NLE STREAM FORENSICS',
                      style: GoogleFonts.jetBrainsMono(
                        fontSize: 11,
                        fontWeight: FontWeight.w800,
                        letterSpacing: 1.1,
                        color: hasAnomaly ? const Color(0xFFF59E0B) : const Color(0xFF10B981),
                      ),
                    ),
                    Text(
                      'Video Track Continuity & Re-Encoding Analysis',
                      style: GoogleFonts.plusJakartaSans(
                        fontSize: 15,
                        fontWeight: FontWeight.w700,
                        color: Colors.white,
                      ),
                    ),
                  ],
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                decoration: BoxDecoration(
                  color: const Color(0x14FFFFFF),
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(color: const Color(0x22FFFFFF)),
                ),
                child: Text(
                  video.videoContainer,
                  style: GoogleFonts.jetBrainsMono(
                    fontSize: 11,
                    fontWeight: FontWeight.w700,
                    color: Colors.white,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 18),
          if (video.editorFootprints.isNotEmpty) ...[
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: const Color(0x1EF43F5E),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: const Color(0x44F43F5E)),
              ),
              child: Row(
                children: [
                  const Icon(Icons.warning_amber_rounded, size: 18, color: Color(0xFFF43F5E)),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      'Non-Linear Video Editor (NLE) Footprints: ${video.editorFootprints.join(", ")} detected in container metadata.',
                      style: GoogleFonts.plusJakartaSans(
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                        color: const Color(0xFFFCA5A5),
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 14),
          ],
          Wrap(
            spacing: 12,
            runSpacing: 12,
            children: [
              _buildForensicMetricCard(
                label: 'ATOM HIERARCHY',
                value: video.atomHierarchy.isNotEmpty ? video.atomHierarchy.take(4).join(' > ') : 'STANDARD',
                subtext: video.isMoovAtomValid ? 'Valid moov/mdat sequence' : 'Corrupted or re-ordered atoms',
                color: video.isMoovAtomValid ? const Color(0xFF10B981) : const Color(0xFFF43F5E),
              ),
              _buildForensicMetricCard(
                label: 'A/V TRACK SYNC',
                value: video.hasAudioVideoDesync ? '${video.desyncDeltaMs}ms DESYNC' : 'SYNCHRONIZED',
                subtext: video.hasAudioVideoDesync ? 'Track splicing length divergence' : 'Coincident audio/video streams',
                color: video.hasAudioVideoDesync ? const Color(0xFFF59E0B) : const Color(0xFF10B981),
              ),
              _buildForensicMetricCard(
                label: 'EOF PAYLOAD INTEGRITY',
                value: video.hasTrailingPayload ? '${video.trailingBytes}B TRAILING' : 'STRICTLY BOUNDED',
                subtext: video.hasTrailingPayload ? 'Stego injection past container' : 'No trailing bytes past atoms',
                color: video.hasTrailingPayload ? const Color(0xFFF43F5E) : const Color(0xFF10B981),
              ),
            ],
          ),
          if (video.videoIntegritySummary != null) ...[
            const SizedBox(height: 12),
            Text(
              video.videoIntegritySummary!,
              style: GoogleFonts.plusJakartaSans(
                fontSize: 12,
                color: CyberTheme.textSecondary,
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildTextForensicsSection(TextForensicsDetails text) {
    final hasAnomaly = text.hasMixedLineEndings ||
        text.hasInvisibleOrZeroWidthChars ||
        text.hasHomoglyphSpoofing ||
        text.hasCsvColumnDrift ||
        text.hasTimestampReversal;

    return Container(
      padding: const EdgeInsets.all(22),
      decoration: BoxDecoration(
        color: CyberTheme.surface,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: hasAnomaly ? const Color(0x66F59E0B) : const Color(0x3310B981),
        ),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Container(
                padding: const EdgeInsets.all(8),
                decoration: BoxDecoration(
                  color: (hasAnomaly ? const Color(0xFFF59E0B) : const Color(0xFF10B981)).withValues(alpha: 0.12),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Icon(
                  Icons.data_object_rounded,
                  size: 20,
                  color: hasAnomaly ? const Color(0xFFF59E0B) : const Color(0xFF10B981),
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'TEXT & STRUCTURED DATA FORENSICS',
                      style: GoogleFonts.jetBrainsMono(
                        fontSize: 11,
                        fontWeight: FontWeight.w800,
                        letterSpacing: 1.1,
                        color: hasAnomaly ? const Color(0xFFF59E0B) : const Color(0xFF10B981),
                      ),
                    ),
                    Text(
                      'Encoding, Steganography, & Structural Consistency',
                      style: GoogleFonts.plusJakartaSans(
                        fontSize: 15,
                        fontWeight: FontWeight.w700,
                        color: Colors.white,
                      ),
                    ),
                  ],
                ),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                decoration: BoxDecoration(
                  color: const Color(0x14FFFFFF),
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(color: const Color(0x22FFFFFF)),
                ),
                child: Text(
                  text.encoding,
                  style: GoogleFonts.jetBrainsMono(
                    fontSize: 11,
                    fontWeight: FontWeight.w700,
                    color: Colors.white,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 18),
          if (text.hasInvisibleOrZeroWidthChars) ...[
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: const Color(0x1EF43F5E),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: const Color(0x44F43F5E)),
              ),
              child: Row(
                children: [
                  const Icon(Icons.security_rounded, size: 18, color: Color(0xFFF43F5E)),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      'Invisible Unicode / Steganography: ${text.invisibleCharCount} zero-width or Trojan Source control characters detected.',
                      style: GoogleFonts.plusJakartaSans(
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                        color: const Color(0xFFFCA5A5),
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 14),
          ],
          if (text.hasHomoglyphSpoofing) ...[
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: const Color(0x1EF59E0B),
                borderRadius: BorderRadius.circular(8),
                border: Border.all(color: const Color(0x44F59E0B)),
              ),
              child: Row(
                children: [
                  const Icon(Icons.spellcheck_rounded, size: 18, color: Color(0xFFF59E0B)),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      'Homoglyph Confusable Attack: Mixed script characters detected (${text.homoglyphFlags.join(", ")}).',
                      style: GoogleFonts.plusJakartaSans(
                        fontSize: 12,
                        fontWeight: FontWeight.w600,
                        color: const Color(0xFFFCD34D),
                      ),
                    ),
                  ),
                ],
              ),
            ),
            const SizedBox(height: 14),
          ],
          Wrap(
            spacing: 12,
            runSpacing: 12,
            children: [
              _buildForensicMetricCard(
                label: 'LINE ENDINGS',
                value: text.hasMixedLineEndings ? 'MIXED CRLF & LF' : text.lineEndingProfile,
                subtext: text.hasMixedLineEndings ? 'Potential multi-source paste injection' : 'Consistent across entire payload',
                color: text.hasMixedLineEndings ? const Color(0xFFF59E0B) : const Color(0xFF10B981),
              ),
              if (text.isCsvOrTable)
                _buildForensicMetricCard(
                  label: 'CSV COLUMN INTEGRITY',
                  value: text.hasCsvColumnDrift ? 'DRIFT IN ROW ${text.anomalousRows.take(2).join(",")}' : 'UNIFORM (${text.expectedColumns ?? 0} COLS)',
                  subtext: text.hasCsvColumnDrift ? 'Injected/missing column fields' : 'All rows match schema regularity',
                  color: text.hasCsvColumnDrift ? const Color(0xFFF43F5E) : const Color(0xFF10B981),
                ),
              if (text.isLogFile)
                _buildForensicMetricCard(
                  label: 'LOG CHRONOLOGY',
                  value: text.hasTimestampReversal ? 'REVERSAL DETECTED' : 'STRICT MONOTONIC',
                  subtext: text.hasTimestampReversal ? 'Out-of-order log splicing' : 'Timestamps advance chronologically',
                  color: text.hasTimestampReversal ? const Color(0xFFF43F5E) : const Color(0xFF10B981),
                ),
              if (!text.isCsvOrTable && !text.isLogFile)
                _buildForensicMetricCard(
                  label: 'UNICODE SANITIZATION',
                  value: text.hasInvisibleOrZeroWidthChars ? 'DIRTY (${text.invisibleCharCount} HIDDEN)' : 'CLEAN (0 HIDDEN)',
                  subtext: text.hasInvisibleOrZeroWidthChars ? 'Hidden stego payload' : 'Pure printable glyphs',
                  color: text.hasInvisibleOrZeroWidthChars ? const Color(0xFFF43F5E) : const Color(0xFF10B981),
                ),
            ],
          ),
          if (text.logIntegritySummary != null) ...[
            const SizedBox(height: 12),
            Text(
              text.logIntegritySummary!,
              style: GoogleFonts.plusJakartaSans(
                fontSize: 12,
                color: CyberTheme.textSecondary,
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildForensicMetricCard({
    required String label,
    required String value,
    required String subtext,
    required Color color,
  }) {
    return Container(
      width: 200,
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: const Color(0x0CFFFFFF),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0x1EFFFFFF)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            style: GoogleFonts.jetBrainsMono(
              fontSize: 10,
              fontWeight: FontWeight.w700,
              letterSpacing: 0.8,
              color: CyberTheme.textMuted,
            ),
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              Container(
                width: 7,
                height: 7,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: color,
                ),
              ),
              const SizedBox(width: 6),
              Flexible(
                child: Text(
                  value,
                  style: GoogleFonts.plusJakartaSans(
                    fontSize: 13,
                    fontWeight: FontWeight.w800,
                    color: Colors.white,
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
            ],
          ),
          const SizedBox(height: 4),
          Text(
            subtext,
            style: GoogleFonts.plusJakartaSans(
              fontSize: 11,
              color: CyberTheme.textSecondary,
            ),
            maxLines: 1,
            overflow: TextOverflow.ellipsis,
          ),
        ],
      ),
    );
  }
}

class _ForensicAnalysisJob {
  final Uint8List bytes;
  final String fileName;
  final List<ProvenanceRecord>? ledgerHistory;

  const _ForensicAnalysisJob({
    required this.bytes,
    required this.fileName,
    required this.ledgerHistory,
  });
}

DocumentForensicReport _runForensicAnalysisCompute(_ForensicAnalysisJob job) {
  return DocumentForensicService.analyzeDocument(
    bytes: job.bytes,
    fileName: job.fileName,
    ledgerHistory: job.ledgerHistory,
  );
}

class _MetricSecurityDetail {
  final String label;
  final String value;
  final bool statusGood;
  final String subtext;
  final String standardReference;
  final String securityThreatProfile;
  final String technicalEvidence;
  final String riskAssessment;
  final List<String> technicalCheckpoints;

  const _MetricSecurityDetail({
    required this.label,
    required this.value,
    required this.statusGood,
    required this.subtext,
    required this.standardReference,
    required this.securityThreatProfile,
    required this.technicalEvidence,
    required this.riskAssessment,
    required this.technicalCheckpoints,
  });
}
