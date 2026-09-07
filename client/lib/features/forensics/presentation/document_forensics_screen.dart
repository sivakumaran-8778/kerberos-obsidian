import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:file_picker/file_picker.dart';
import 'package:desktop_drop/desktop_drop.dart';
import 'package:google_fonts/google_fonts.dart';

import '../../../shared/theme/cyber_theme.dart';
import '../../../shared/widgets/cyber_button.dart';
import '../../../shared/widgets/glass_container.dart';
import '../../../main.dart'; // for ledgerProvider
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
        allowedExtensions: ['pdf', 'png', 'jpg', 'jpeg', 'webp', 'tiff', 'docx'],
        withData: true,
      );

      if (result != null && result.files.isNotEmpty) {
        final file = result.files.first;
        final bytes = file.bytes;
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

    // Provide smooth perceptual scan latency
    await Future.delayed(const Duration(milliseconds: 600));

    final ledger = ref.read(ledgerProvider);
    final history = ledger.getHistory();

    final report = DocumentForensicService.analyzeDocument(
      bytes: bytes,
      fileName: fileName,
      ledgerHistory: history,
    );

    if (mounted) {
      setState(() {
        _report = report;
        _isAnalyzing = false;
      });
    }
  }

  void _resetAudit() {
    setState(() {
      _report = null;
      _isAnalyzing = false;
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
                const SizedBox(height: 24),
                _buildDocumentHistoryTimeline(),
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
                  'Supports Medical Bills, Government IDs, Certificates, Invoices, PDFs, Scans, & Images',
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
                        'SELECT DOCUMENT OR SCAN',
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
                    _buildPillTag('PDF'),
                    _buildPillTag('PNG'),
                    _buildPillTag('JPEG'),
                    _buildPillTag('TIFF'),
                    _buildPillTag('WEBP'),
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
    return Row(
      children: [
        Expanded(
          child: _buildFeatureSummaryCard(
            icon: Icons.layers_outlined,
            title: 'PDF Incremental Revisions',
            description:
                'Detects appended updates and trailers (/Prev pointers, multiple %%EOF) made in Adobe Acrobat, Canva, or Foxit.',
          ),
        ),
        const SizedBox(width: 14),
        Expanded(
          child: _buildFeatureSummaryCard(
            icon: Icons.fingerprint_rounded,
            title: 'Editor Software Signatures',
            description:
                'Identifies hidden footprints from Photoshop (8BIM), GIMP, Canva, iLovePDF, or unauthorized post-processing tools.',
          ),
        ),
        const SizedBox(width: 14),
        Expanded(
          child: _buildFeatureSummaryCard(
            icon: Icons.alt_route_rounded,
            title: 'Scramble & Header Parity',
            description:
                'Validates magic bytes, cross-reference structures, and detects byte tampering, scrambled bitstreams, or truncated files.',
          ),
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
                  const Icon(Icons.description_outlined, size: 18, color: CyberTheme.shardColor),
                  const SizedBox(width: 8),
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
}
