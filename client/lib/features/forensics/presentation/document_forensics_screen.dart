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
    return Center(
      child: ConstrainedBox(
        constraints: const BoxConstraints(maxWidth: 1100),
        child: SingleChildScrollView(
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 20),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              if (_report == null) ...[
                _buildIntroHeader(),
                const SizedBox(height: 24),
                _buildUploadDropZone(),
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
  }

  // ==========================================
  // INTRO HEADER (BEFORE UPLOAD)
  // ==========================================
  Widget _buildIntroHeader() {
    return Column(
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Container(
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
                  Text(
                    'ZERO-TRUST UNSEALED DOCUMENT FORENSICS',
                    style: GoogleFonts.jetBrainsMono(
                      fontSize: 10,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 1.1,
                      color: const Color(0xFF38BDF8),
                    ),
                  ),
                ],
              ),
            ),
          ],
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
  Widget _buildUploadDropZone() {
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
          padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 48),
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
                    Icons.file_upload_outlined,
                    size: 34,
                    color: Color(0xFF38BDF8),
                  ),
                ),
                const SizedBox(height: 20),
                Text(
                  'DRAG & DROP DOCUMENT HERE',
                  style: GoogleFonts.plusJakartaSans(
                    fontSize: 16,
                    fontWeight: FontWeight.w800,
                    letterSpacing: 0.8,
                    color: Colors.white,
                  ),
                ),
                const SizedBox(height: 6),
                Text(
                  'Supports Medical Bills, IDs, Invoices, Audio (WAV/MP3), Video (MP4/MKV), CSV, Logs, & Text Data',
                  textAlign: TextAlign.center,
                  style: GoogleFonts.plusJakartaSans(
                    fontSize: 12,
                    color: CyberTheme.textSecondary,
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
                      Text(
                        'SELECT ANY DOCUMENT / MULTIMEDIA',
                        style: GoogleFonts.plusJakartaSans(
                          fontSize: 12,
                          fontWeight: FontWeight.w800,
                          letterSpacing: 0.8,
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
    return Column(
      children: [
        Row(
          children: [
            Expanded(
              child: _buildFeatureSummaryCard(
                icon: Icons.difference_rounded,
                title: 'PDF Revisions & Inline Diff',
                description:
                    'Deconstructs BT...ET text streams between original v1 and appended v2 revisions to pinpoint altered numbers.',
              ),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: _buildFeatureSummaryCard(
                icon: Icons.grid_goldenratio_rounded,
                title: 'Error Level Analysis (ELA)',
                description:
                    'Visualizes spatial 16x16 quantization residuals to expose spliced text and copy-pasted images even without EXIF.',
              ),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: _buildFeatureSummaryCard(
                icon: Icons.qr_code_scanner_rounded,
                title: 'UIDAI QR Cross-Validation',
                description:
                    'Validates RSA-signed 2D QR payloads on Aadhaar cards to detect surface text tampering and identity forgeries.',
              ),
            ),
          ],
        ),
        const SizedBox(height: 14),
        Row(
          children: [
            Expanded(
              child: _buildFeatureSummaryCard(
                icon: Icons.fingerprint_rounded,
                title: 'Editor Software Signatures',
                description:
                    'Identifies hidden footprints from Photoshop (8BIM), GIMP, Canva, iLovePDF, and unauthorized tools.',
              ),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: _buildFeatureSummaryCard(
                icon: Icons.print_disabled_rounded,
                title: 'Virtual Printer Laundering',
                description:
                    'Detects re-distilled documents processed via virtual printer drivers (e.g. Print to PDF) to erase edit history.',
              ),
            ),
            const SizedBox(width: 14),
            Expanded(
              child: _buildFeatureSummaryCard(
                icon: Icons.alt_route_rounded,
                title: 'Scramble & Header Parity',
                description:
                    'Validates magic bytes, cross-reference tables, and detects scrambled bitstreams or truncated files.',
              ),
            ),
          ],
        ),
      ],
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

    return Row(
      children: [
        Expanded(
          child: Column(
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
              Row(
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
          ),
        ),
        CyberButton(
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
                'AUDIT ANOTHER FILE',
                style: GoogleFonts.plusJakartaSans(
                  fontSize: 11,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 0.6,
                ),
              ),
            ],
          ),
        ),
      ],
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
                Row(
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
                    const SizedBox(width: 12),
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
          Row(
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
              const Spacer(),
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

    return GlassContainer(
      padding: const EdgeInsets.all(22),
      borderRadius: 18.0,
      borderColor: hasAnomaly ? const Color(0x44F43F5E) : const Color(0x3338BDF8),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(
                Icons.grid_goldenratio_rounded,
                size: 20,
                color: hasAnomaly ? const Color(0xFFF43F5E) : const Color(0xFF38BDF8),
              ),
              const SizedBox(width: 10),
              Text(
                'ERROR LEVEL ANALYSIS (ELA) SPATIAL QUANTIZATION MATRIX',
                style: GoogleFonts.plusJakartaSans(
                  fontSize: 13,
                  fontWeight: FontWeight.w800,
                  letterSpacing: 0.8,
                  color: Colors.white,
                ),
              ),
              const Spacer(),
              Container(
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
              ),
            ],
          ),
          const SizedBox(height: 6),
          Text(
            'Re-compression quantization residuals across a 16×16 spatial matrix. Spliced objects, altered numbers, or pasted signatures exhibit distinct compression artifacts diverging from ambient background noise.',
            style: GoogleFonts.plusJakartaSans(
              fontSize: 12,
              height: 1.45,
              color: CyberTheme.textSecondary,
            ),
          ),
          const SizedBox(height: 18),
          LayoutBuilder(
            builder: (context, constraints) {
              final isWide = constraints.maxWidth > 700;
              final gridWidget = _buildElaGrid(ela);
              final inspectorWidget = _buildElaInspector(ela, hoveredVal, hoveredIndex);

              if (isWide) {
                return Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    SizedBox(
                      width: 280,
                      height: 280,
                      child: gridWidget,
                    ),
                    const SizedBox(width: 24),
                    Expanded(child: inspectorWidget),
                  ],
                );
              } else {
                return Column(
                  children: [
                    Center(
                      child: SizedBox(
                        width: 280,
                        height: 280,
                        child: gridWidget,
                      ),
                    ),
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

  Widget _buildElaGrid(DocumentElaAnalysis ela) {
    return Container(
      padding: const EdgeInsets.all(8),
      decoration: BoxDecoration(
        color: const Color(0xFF070D18),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: const Color(0x3338BDF8)),
      ),
      child: GridView.builder(
        physics: const NeverScrollableScrollPhysics(),
        itemCount: 256,
        gridDelegate: const SliverGridDelegateWithFixedCrossAxisCount(
          crossAxisCount: 16,
          mainAxisSpacing: 2,
          crossAxisSpacing: 2,
        ),
        itemBuilder: (context, idx) {
          final val = ela.heatmapTensor[idx];
          final isHovered = _hoveredElaIndex == idx;
          final cellColor = _getElaColor(val);

          return MouseRegion(
            onEnter: (_) => setState(() => _hoveredElaIndex = idx),
            onExit: (_) => setState(() => _hoveredElaIndex = null),
            child: GestureDetector(
              onTap: () => setState(() => _hoveredElaIndex = idx),
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 150),
                decoration: BoxDecoration(
                  color: cellColor,
                  borderRadius: BorderRadius.circular(2),
                  border: isHovered
                      ? Border.all(color: Colors.white, width: 1.5)
                      : (val > 0.65
                          ? Border.all(
                              color: const Color(0xFFFF0055).withValues(alpha: 0.6),
                              width: 0.8,
                            )
                          : null),
                ),
              ),
            ),
          );
        },
      ),
    );
  }

  Color _getElaColor(double val) {
    if (val <= 0.25) {
      return Color.lerp(
        const Color(0xFF0B192C),
        const Color(0xFF0284C7),
        val / 0.25,
      )!;
    } else if (val <= 0.55) {
      return Color.lerp(
        const Color(0xFF0284C7),
        const Color(0xFFF59E0B),
        (val - 0.25) / 0.30,
      )!;
    } else {
      return Color.lerp(
        const Color(0xFFF59E0B),
        const Color(0xFFFF0055),
        ((val - 0.55) / 0.45).clamp(0.0, 1.0),
      )!;
    }
  }

  Widget _buildElaInspector(
    DocumentElaAnalysis ela,
    double? hoveredVal,
    int? hoveredIndex,
  ) {
    final row = hoveredIndex != null ? (hoveredIndex ~/ 16) : null;
    final col = hoveredIndex != null ? (hoveredIndex % 16) : null;

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0x0EFFFFFF),
        borderRadius: BorderRadius.circular(12),
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
                  color: CyberTheme.textSecondary,
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
                isAlert: hoveredVal != null
                    ? hoveredVal > 0.55
                    : ela.hasSplicingAnomaly,
              ),
              const SizedBox(width: 14),
              _buildMiniMetric(
                label: 'BACKGROUND BASELINE',
                value: '${(ela.baselineErrorRate * 100).toStringAsFixed(1)}%',
                isAlert: false,
              ),
              const SizedBox(width: 14),
              _buildMiniMetric(
                label: 'ANOMALY THRESHOLD',
                value: '> 55.0%',
                isAlert: false,
              ),
            ],
          ),
          const SizedBox(height: 14),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
            decoration: BoxDecoration(
              color: const Color(0x12FFFFFF),
              borderRadius: BorderRadius.circular(8),
            ),
            child: Row(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                const Icon(Icons.location_searching_rounded, size: 16, color: Color(0xFF38BDF8)),
                const SizedBox(width: 8),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'Detected Coordinates:',
                        style: GoogleFonts.plusJakartaSans(
                          fontSize: 10,
                          fontWeight: FontWeight.w700,
                          color: CyberTheme.textMuted,
                        ),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        ela.anomalyCoordinates,
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
          const SizedBox(height: 14),
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
                        Color(0xFF0B192C),
                        Color(0xFF0284C7),
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
      sigSubtext = report.digitalSignatureAlgorithm ?? 'X.509 PKCS#7 Seal';
    } else if (report.isGovernmentOrAadhaarDoc) {
      sigLabel = 'Missing Statutory Signature';
      sigGood = false;
      sigSubtext = 'Official UIDAI X.509 signature stripped or absent';
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

    return Column(
      children: [
        Row(
          children: [
            Expanded(
              child: _buildMetricTile(
                label: 'PDF REVISION COUNT',
                value: '${report.revisionCount} Generation${report.revisionCount > 1 ? 's' : ''}',
                statusGood: report.revisionCount <= 1,
                subtext: report.revisionCount > 1 ? 'Incremental appends found' : 'Single generation original',
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _buildMetricTile(
                label: 'EDITOR FOOTPRINTS',
                value: report.editingSoftwareDetected.isNotEmpty ? 'Detected' : 'Clean',
                statusGood: report.editingSoftwareDetected.isEmpty,
                subtext: editingTools,
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _buildMetricTile(
                label: 'DIGITAL SIGNATURE (PKCS#7)',
                value: sigLabel,
                statusGood: sigGood,
                subtext: sigSubtext,
              ),
            ),
          ],
        ),
        const SizedBox(height: 12),
        Row(
          children: [
            Expanded(
              child: _buildMetricTile(
                label: 'ORIGIN PIPELINE',
                value: originLabel,
                statusGood: originGood,
                subtext: originSubtext,
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _buildMetricTile(
                label: 'MAGIC HEADER PARITY',
                value: report.isMagicByteValid ? 'RFC Valid' : 'Corrupted',
                statusGood: report.isMagicByteValid,
                subtext: report.mimeType,
              ),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: _buildMetricTile(
                label: 'TRAILING STEGO PAYLOAD',
                value: report.hasTrailingPayload ? '+${report.trailingPayloadBytes} Bytes' : 'None',
                statusGood: !report.hasTrailingPayload,
                subtext: report.hasTrailingPayload ? 'Appended past file terminator' : 'Clean file termination',
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _buildMetricTile({
    required String label,
    required String value,
    required bool statusGood,
    required String subtext,
  }) {
    final color = statusGood ? const Color(0xFF10B981) : const Color(0xFFF43F5E);

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0x0CFFFFFF),
        borderRadius: BorderRadius.circular(14),
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
