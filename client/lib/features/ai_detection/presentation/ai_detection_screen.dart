import 'dart:convert';
import 'package:desktop_drop/desktop_drop.dart';
import 'package:file_picker/file_picker.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:cross_file/cross_file.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:printing/printing.dart';
import 'package:syncfusion_flutter_pdf/pdf.dart';
import 'package:uuid/uuid.dart';

import '../../../main.dart'; // for ledgerProvider
import '../../../shared/theme/cyber_theme.dart';
import '../../../shared/widgets/cyber_button.dart';
import '../../../shared/widgets/glass_container.dart';
import '../../auth/providers/auth_providers.dart';
import '../../ledger/models/provenance_record.dart';
import '../models/ai_detection_models.dart';
import '../services/ai_detection_service.dart';
import '../services/gemini_ai_client.dart';
import 'widgets/ai_confidence_gauge.dart';
import 'widgets/ai_spectral_grid_view.dart';
import 'widgets/ai_text_heatmap_view.dart';

/// Flagship Enterprise AI Content & Deepfake Scanner Screen.
class AiDetectionScreen extends ConsumerStatefulWidget {
  const AiDetectionScreen({super.key});

  @override
  ConsumerState<AiDetectionScreen> createState() => _AiDetectionScreenState();
}

class _AiDetectionScreenState extends ConsumerState<AiDetectionScreen>
    with SingleTickerProviderStateMixin {
  bool _isDragging = false;
  bool _isAnalyzing = false;
  String _analysisStatusStep = '';
  AiDetectionReport? _report;
  late AnimationController _pulseController;
  int _activeInspectorTab = 0; // 0: Modality Inspector, 1: Checkpoints, 2: Raw Telemetry
  String? _customApiKey;
  bool _isLedgerAnchored = false;

  @override
  void initState() {
    super.initState();
    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 1800),
    )..repeat(reverse: true);
  }

  @override
  void dispose() {
    _pulseController.dispose();
    super.dispose();
  }

  // ==========================================
  // INGESTION METHODS
  // ==========================================
  Future<void> _pickFile() async {
    try {
      final result = await FilePicker.platform.pickFiles(
        type: FileType.custom,
        allowedExtensions: [
          'pdf', 'docx', 'txt', 'csv', 'json', 'log', 'md',
          'png', 'jpg', 'jpeg', 'webp', 'tiff', 'bmp',
          'mp4', 'mov', 'mkv', 'avi', 'webm',
        ],
        withData: true,
      );

      if (result != null && result.files.isNotEmpty) {
        final file = result.files.first;
        Uint8List? bytes = file.bytes;
        String? filePath;
        // On Flutter Web, accessing file.path throws an UnsupportedError.
        if (!kIsWeb) {
          filePath = file.path;
          if (bytes == null && filePath != null) {
            bytes = await XFile(filePath).readAsBytes();
          }
        }
        if (bytes != null && bytes.isNotEmpty) {
          await _runAnalysis(bytes, file.name, path: filePath);
        } else {
          _showSnackbar('Could not load file data. Please try again.', isError: true);
        }
      }
    } catch (e) {
      _showSnackbar('File selection error: $e', isError: true);
    }
  }

  Future<void> _runAnalysis(Uint8List bytes, String fileName, {String? path}) async {
    setState(() {
      _isAnalyzing = true;
      _report = null;
      _isLedgerAnchored = false;
      _analysisStatusStep = 'Extracting cryptographic metadata & SHA-256...';
    });

    try {
      await Future.delayed(const Duration(milliseconds: 300));
      setState(() => _analysisStatusStep =
          'Running 2D FFT spectral harmonics & sentence burstiness...');

      await Future.delayed(const Duration(milliseconds: 350));
      setState(() => _analysisStatusStep =
          'Querying Gemini 2.5 Flash multimodal neural validator...');

      final report = await AiDetectionService.analyzeFile(
        bytes: bytes,
        fileName: fileName,
        path: path,
        overrideApiKey: _customApiKey,
        enableGeminiNeural: true,
      );

      setState(() => _analysisStatusStep = 'Fusing Bayesian forensic verdict...');
      await Future.delayed(const Duration(milliseconds: 200));

      setState(() {
        _report = report;
        _isAnalyzing = false;
      });
    } catch (e) {
      setState(() => _isAnalyzing = false);
      _showSnackbar('Forensic analysis failed: $e', isError: true);
    }
  }

  // Quick Demo Samples
  void _loadSample(int sampleType) {
    // 0: Synthetic Document (GPT-4)
    // 1: Synthetic Image (Midjourney/SDXL)
    // 2: Human Document
    if (sampleType == 0) {
      const syntheticDoc = '''
In conclusion, it is important to note that the tapestry of modern technological transformation fosters a pivotal role across organizational workflows. Furthermore, delving into the nuances of artificial intelligence serves as a reminder of the ever-evolving landscape we navigate today. Moreover, this crucial aspect underscores the multifaceted nature of digital adoption. At its core, the seamless integration of distributed ledgers represents a profound impact on provenance verification. In summary, harnessing the power of cryptographic algorithms provides a beacon of transparency and an indispensable tool for forward-looking enterprises.
''';
      final bytes = Uint8List.fromList(utf8.encode(syntheticDoc));
      _runAnalysis(bytes, 'executive_ai_briefing.txt');
    } else if (sampleType == 1) {
      // Simulate synthetic PNG with prompt parameters
      final mockPngHeader = Uint8List.fromList([
        0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A,
        ...utf8.encode(
            'tEXtparameters\x00photorealistic cinematic portrait of cyber auditor, ultra-detailed, 8k Steps: 35, Sampler: DPM++ 2M Karras, CFG scale: 7, Seed: 8392193821, Model: SDXL-v1.0-refiner, Clip skip: 2\x00'),
        0x00, 0x00, 0x00, 0x00, 0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82,
      ]);
      _runAnalysis(mockPngHeader, 'cyber_recon_portrait_sdxl.png');
    } else {
      const humanDoc = '''
Yesterday we completed the preliminary audit for the firmware upgrade. We ran into three unexpected segmentation faults in the ring buffer allocator around 3:00 AM.
After checking the stack trace, Dave realized the pointer offset was off by eight bytes on 64-bit architectures.
We patched the assembly stub. The tests finally passed on the test bench.
We then had coffee, reviewed the git diff, and signed off on the release build.
''';
      final bytes = Uint8List.fromList(utf8.encode(humanDoc));
      _runAnalysis(bytes, 'hardware_audit_log_human.txt');
    }
  }

  // ==========================================
  // LEDGER & PDF EXPORTS
  // ==========================================
  Future<void> _anchorToLedger() async {
    if (_report == null) return;
    try {
      final user = ref.read(currentUserProvider);
      final ledger = ref.read(ledgerProvider);

      final record = ProvenanceRecord(
        id: const Uuid().v4(),
        originalFileHash: _report!.sha256Hash,
        c2paManifestUri:
            'kerberos:ai-audit:${_report!.verdict.name}:${_report!.overallAiProbability.toStringAsFixed(1)}',
        timestamp: DateTime.now(),
        signature: 'AI-AUDIT-${_report!.sha256Hash.substring(0, 16)}',
        filePath: _report!.fileName,
        ownerEmail: user?.email,
      );

      await ledger.addRecord(record);
      setState(() => _isLedgerAnchored = true);
      _showSnackbar('Finding anchored to Zero-Trust Ledger successfully!');
    } catch (e) {
      _showSnackbar('Failed to anchor to ledger: $e', isError: true);
    }
  }

  Future<void> _exportPdfReport() async {
    if (_report == null) return;

    try {
      final pdf = PdfDocument();
      final page = pdf.pages.add();
      final graphics = page.graphics;
      final fontTitle = PdfStandardFont(PdfFontFamily.helvetica, 18,
          style: PdfFontStyle.bold);
      final fontBody = PdfStandardFont(PdfFontFamily.helvetica, 10);
      final fontBold = PdfStandardFont(PdfFontFamily.helvetica, 10,
          style: PdfFontStyle.bold);

      graphics.drawString('PROJECT KERBEROS // ZERO-TRUST AUDIT', fontTitle,
          bounds: const Rect.fromLTWH(0, 0, 500, 30));

      graphics.drawString(
          'ENTERPRISE AI CONTENT & DEEPFAKE FORENSIC CERTIFICATE', fontBold,
          bounds: const Rect.fromLTWH(0, 35, 500, 20));

      graphics.drawString(
          'Generated: ${_report!.analyzedAt.toUtc().toIso8601String()}', fontBody,
          bounds: const Rect.fromLTWH(0, 55, 500, 15));

      graphics.drawString('File Name: ${_report!.fileName}', fontBody,
          bounds: const Rect.fromLTWH(0, 75, 500, 15));

      graphics.drawString('SHA-256 Hash: ${_report!.sha256Hash}', fontBody,
          bounds: const Rect.fromLTWH(0, 90, 500, 15));

      graphics.drawString(
          'Verdict: ${_report!.verdictLabel} (${_report!.overallAiProbability.toStringAsFixed(1)}% Synthetic)',
          fontBold,
          bounds: const Rect.fromLTWH(0, 115, 500, 20));

      graphics.drawString('Identified Model: ${_report!.detectedModelFamily}',
          fontBody,
          bounds: const Rect.fromLTWH(0, 135, 500, 15));

      graphics.drawString('Risk Level: ${_report!.riskLabel}', fontBody,
          bounds: const Rect.fromLTWH(0, 150, 500, 15));

      graphics.drawString('Executive Forensic Summary:', fontBold,
          bounds: const Rect.fromLTWH(0, 175, 500, 15));

      graphics.drawString(_report!.executiveSummary, fontBody,
          bounds: const Rect.fromLTWH(0, 195, 500, 50));

      // Checkpoints summary
      graphics.drawString('Enterprise Checkpoint Statuses:', fontBold,
          bounds: const Rect.fromLTWH(0, 255, 500, 15));

      double y = 275;
      for (final cp in _report!.checkpoints) {
        graphics.drawString(
            '• [${cp.status.name.toUpperCase()}] ${cp.title}: ${cp.details}',
            fontBody,
            bounds: Rect.fromLTWH(0, y, 500, 24));
        y += 24;
      }

      final pdfBytes = await pdf.save();
      pdf.dispose();

      await Printing.sharePdf(
        bytes: Uint8List.fromList(pdfBytes),
        filename: 'kerberos_ai_audit_${_report!.fileName}.pdf',
      );
    } catch (e) {
      _showSnackbar('PDF Export error: $e', isError: true);
    }
  }

  void _showApiKeyDialog() {
    final controller = TextEditingController(
        text: _customApiKey ?? GeminiAiClient.getApiKey() ?? '');

    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: CyberTheme.surfaceElevated,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: const BorderSide(color: CyberTheme.borderAccent),
        ),
        title: Row(
          children: [
            const Icon(Icons.vpn_key_rounded,
                color: CyberTheme.accentColor, size: 20),
            const SizedBox(width: 8),
            Text(
              'Gemini 2.5 Flash API Key',
              style: GoogleFonts.spaceGrotesk(
                color: Colors.white,
                fontWeight: FontWeight.w800,
                fontSize: 16,
              ),
            ),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Paste your Google Gemini API key below to unlock 95%+ verifiable neural detection accuracy.\n\nOption 1: Save it right here for this session.\nOption 2: Add GEMINI_API_KEY=your_key in client/.env for permanent loading.',
              style: GoogleFonts.plusJakartaSans(
                fontSize: 12,
                color: CyberTheme.textMuted,
                height: 1.4,
              ),
            ),
            const SizedBox(height: 14),
            TextField(
              controller: controller,
              style: GoogleFonts.spaceGrotesk(color: Colors.white, fontSize: 13),
              decoration: InputDecoration(
                hintText: 'AIzaSy...',
                hintStyle: GoogleFonts.spaceGrotesk(color: Colors.white24),
                filled: true,
                fillColor: const Color(0x22000000),
                border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(10),
                  borderSide: const BorderSide(color: CyberTheme.border),
                ),
                focusedBorder: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(10),
                  borderSide: const BorderSide(color: CyberTheme.accentColor),
                ),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: Text(
              'Cancel',
              style: GoogleFonts.plusJakartaSans(color: CyberTheme.textMuted),
            ),
          ),
          CyberButton(
            icon: Icons.check,
            onTap: () {
              final key = controller.text.trim();
              setState(() {
                _customApiKey = key;
              });
              GeminiAiClient.setApiKey(key);
              Navigator.pop(ctx);
              _showSnackbar(key.isNotEmpty
                  ? 'Gemini 2.5 Flash API key saved! Hybrid engine active.'
                  : 'Gemini API key cleared.');
            },
            child: const Text('Save Key'),
          ),
        ],
      ),
    );
  }

  void _showSnackbar(String message, {bool isError = false}) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        backgroundColor:
            isError ? const Color(0xFFEF4444) : CyberTheme.surfaceElevated,
        content: Text(
          message,
          style: GoogleFonts.plusJakartaSans(
            color: Colors.white,
            fontWeight: FontWeight.w600,
          ),
        ),
      ),
    );
  }

  // ==========================================
  // BUILD METHOD
  // ==========================================
  @override
  Widget build(BuildContext context) {
    final hasGeminiKey = GeminiAiClient.getApiKey(overrideKey: _customApiKey) != null;

    return SingleChildScrollView(
      padding: const EdgeInsets.only(bottom: 80),
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 1300),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // 1. Top Sub-Header & Gemini Neural Status Bar
              _buildTopBar(hasGeminiKey),

              const SizedBox(height: 16),

              // 2. Ingestion Zone (if no report or currently analyzing)
              if (_report == null || _isAnalyzing) ...[
                _buildIngestionDropZone(),
              ] else ...[
                // 3. Hero Verdict & Score Dashboard
                _buildHeroVerdictCard(),

                const SizedBox(height: 16),

                // 4. Tabbed Deep-Dive Inspector
                _buildTabbedInspector(),

                const SizedBox(height: 16),

                // 5. Action Bar
                _buildActionBar(),
              ],
            ],
          ),
        ),
      ),
    );
  }

  // ==========================================
  // HEADER & STATUS BAR
  // ==========================================
  Widget _buildTopBar(bool hasGeminiKey) {
    return GlassContainer(
      borderRadius: 14,
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
      child: Row(
        children: [
          // Engine badge
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
            decoration: BoxDecoration(
              color: hasGeminiKey
                  ? const Color(0x2210B981)
                  : const Color(0x22F59E0B),
              borderRadius: BorderRadius.circular(100),
              border: Border.all(
                color: hasGeminiKey
                    ? const Color(0xFF10B981)
                    : const Color(0xFFF59E0B),
                width: 1.0,
              ),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                AnimatedBuilder(
                  animation: _pulseController,
                  builder: (context, child) => Container(
                    width: 7,
                    height: 7,
                    decoration: BoxDecoration(
                      shape: BoxShape.circle,
                      color: hasGeminiKey
                          ? const Color(0xFF10B981)
                          : const Color(0xFFF59E0B),
                      boxShadow: [
                        BoxShadow(
                          color: (hasGeminiKey
                                  ? const Color(0xFF10B981)
                                  : const Color(0xFFF59E0B))
                              .withValues(
                                  alpha: 0.3 + 0.7 * _pulseController.value),
                          blurRadius: 6,
                          spreadRadius: 2,
                        ),
                      ],
                    ),
                  ),
                ),
                const SizedBox(width: 8),
                Text(
                  hasGeminiKey
                      ? 'HYBRID ENGINE: GEMINI 2.5 FLASH ACTIVE (95%+ ACCURACY)'
                      : 'EDGE-ONLY ENGINE (ADD GEMINI KEY FOR 95%+ ACCURACY)',
                  style: GoogleFonts.spaceGrotesk(
                    fontSize: 11,
                    fontWeight: FontWeight.w800,
                    color: hasGeminiKey
                        ? const Color(0xFF10B981)
                        : const Color(0xFFF59E0B),
                    letterSpacing: 0.6,
                  ),
                ),
              ],
            ),
          ),

          const Spacer(),

          // Configure API Key action
          TextButton.icon(
            onPressed: _showApiKeyDialog,
            icon: const Icon(Icons.key_rounded,
                size: 15, color: CyberTheme.accentColor),
            label: Text(
              hasGeminiKey ? 'Change API Key' : 'Configure Gemini Key',
              style: GoogleFonts.spaceGrotesk(
                fontSize: 11.5,
                fontWeight: FontWeight.w700,
                color: CyberTheme.accentColor,
              ),
            ),
            style: TextButton.styleFrom(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
              backgroundColor: CyberTheme.accentColor.withValues(alpha: 0.1),
              shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(8),
                side: const BorderSide(color: CyberTheme.borderAccent),
              ),
            ),
          ),
        ],
      ),
    );
  }

  // ==========================================
  // INGESTION DROP ZONE
  // ==========================================
  Widget _buildIngestionDropZone() {
    if (_isAnalyzing) {
      return GlassContainer(
        borderRadius: 18,
        padding: const EdgeInsets.all(48),
        child: Center(
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              SizedBox(
                width: 64,
                height: 64,
                child: CircularProgressIndicator(
                  strokeWidth: 3.5,
                  valueColor:
                      const AlwaysStoppedAnimation<Color>(CyberTheme.accentColor),
                ),
              ),
              const SizedBox(height: 24),
              Text(
                'EXECUTING ZERO-TRUST AI CONTENT AUDIT',
                style: GoogleFonts.spaceGrotesk(
                  fontSize: 16,
                  fontWeight: FontWeight.w900,
                  letterSpacing: 1.2,
                  color: Colors.white,
                ),
              ),
              const SizedBox(height: 8),
              AnimatedBuilder(
                animation: _pulseController,
                builder: (context, child) => Text(
                  _analysisStatusStep,
                  style: GoogleFonts.plusJakartaSans(
                    fontSize: 13,
                    color: CyberTheme.accentColor.withValues(
                        alpha: 0.6 + 0.4 * _pulseController.value),
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
            ],
          ),
        ),
      );
    }

    return DropTarget(
      onDragEntered: (_) => setState(() => _isDragging = true),
      onDragExited: (_) => setState(() => _isDragging = false),
      onDragDone: (detail) async {
        setState(() => _isDragging = false);
        if (detail.files.isNotEmpty) {
          final file = detail.files.first;
          final bytes = await file.readAsBytes();
          String? filePath;
          if (!kIsWeb) {
            try {
              filePath = file.path;
            } catch (_) {}
          }
          await _runAnalysis(bytes, file.name, path: filePath);
        }
      },
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 200),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(18),
          border: Border.all(
            color: _isDragging
                ? CyberTheme.accentColor
                : const Color(0x38FFFFFF),
            width: _isDragging ? 2.0 : 1.2,
          ),
          color: _isDragging
              ? CyberTheme.accentColor.withValues(alpha: 0.12)
              : const Color(0x10FFFFFF),
        ),
        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 36),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            // Icon
            Container(
              width: 72,
              height: 72,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                gradient: CyberTheme.shardGradient,
                boxShadow: [
                  BoxShadow(
                    color: CyberTheme.accentColor.withValues(alpha: 0.4),
                    blurRadius: 20,
                    spreadRadius: 2,
                  ),
                ],
              ),
              child: const Icon(
                Icons.document_scanner_rounded,
                color: Colors.white,
                size: 36,
              ),
            ),

            const SizedBox(height: 18),

            Text(
              'DRAG & DROP ASSETS TO DETECT AI GENERATION',
              style: GoogleFonts.spaceGrotesk(
                fontSize: 17,
                fontWeight: FontWeight.w900,
                color: Colors.white,
                letterSpacing: 0.8,
              ),
            ),

            const SizedBox(height: 8),

            Text(
              'Supports Images (PNG, JPG, WEBP), Videos (MP4, MOV, MKV), and Documents (PDF, DOCX, TXT, CSV, JSON)',
              style: GoogleFonts.plusJakartaSans(
                fontSize: 13,
                color: CyberTheme.textMuted,
              ),
              textAlign: TextAlign.center,
            ),

            const SizedBox(height: 20),

            // Browse button
            CyberButton(
              icon: Icons.upload_file_rounded,
              onTap: _pickFile,
              child: const Text('Browse Local Storage'),
            ),

            const SizedBox(height: 28),

            const Divider(color: Color(0x1FFFFFFF)),

            const SizedBox(height: 16),

            // Demo Chips
            Text(
              'OR RUN QUICK BENCHMARK SAMPLES:',
              style: GoogleFonts.spaceGrotesk(
                fontSize: 11,
                fontWeight: FontWeight.w800,
                letterSpacing: 0.8,
                color: CyberTheme.textMuted,
              ),
            ),

            const SizedBox(height: 10),

            Wrap(
              spacing: 10,
              runSpacing: 8,
              alignment: WrapAlignment.center,
              children: [
                _buildSampleChip(
                  label: 'Synthetic Doc (GPT-4)',
                  icon: Icons.auto_awesome_rounded,
                  color: const Color(0xFFF43F5E),
                  onTap: () => _loadSample(0),
                ),
                _buildSampleChip(
                  label: 'Diffusion Image (SDXL / Midjourney)',
                  icon: Icons.image_rounded,
                  color: const Color(0xFFF59E0B),
                  onTap: () => _loadSample(1),
                ),
                _buildSampleChip(
                  label: 'Human Document (Authentic)',
                  icon: Icons.person_rounded,
                  color: const Color(0xFF10B981),
                  onTap: () => _loadSample(2),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildSampleChip({
    required String label,
    required IconData icon,
    required Color color,
    required VoidCallback onTap,
  }) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(8),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
        decoration: BoxDecoration(
          color: color.withValues(alpha: 0.12),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: color.withValues(alpha: 0.5), width: 1.0),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(icon, size: 14, color: color),
            const SizedBox(width: 6),
            Text(
              label,
              style: GoogleFonts.spaceGrotesk(
                fontSize: 11.5,
                fontWeight: FontWeight.w700,
                color: Colors.white,
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ==========================================
  // HERO VERDICT DASHBOARD
  // ==========================================
  Widget _buildHeroVerdictCard() {
    final rep = _report!;
    final isSynthetic = rep.overallAiProbability >= 60.0;
    final verdictColor = isSynthetic
        ? const Color(0xFFF43F5E)
        : rep.overallAiProbability >= 35.0
            ? const Color(0xFFF59E0B)
            : const Color(0xFF10B981);

    return LayoutBuilder(
      builder: (context, constraints) {
        final isWide = constraints.maxWidth > 780;

        return GlassContainer(
          borderRadius: 18,
          padding: const EdgeInsets.all(22),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Header tag
              Row(
                children: [
                  Container(
                    padding:
                        const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                    decoration: BoxDecoration(
                      color: verdictColor.withValues(alpha: 0.15),
                      borderRadius: BorderRadius.circular(6),
                      border: Border.all(color: verdictColor, width: 1.0),
                    ),
                    child: Text(
                      rep.verdictLabel,
                      style: GoogleFonts.spaceGrotesk(
                        fontSize: 12,
                        fontWeight: FontWeight.w900,
                        color: verdictColor,
                        letterSpacing: 0.8,
                      ),
                    ),
                  ),
                  const SizedBox(width: 10),
                  Text(
                    rep.fileName,
                    style: GoogleFonts.spaceGrotesk(
                      fontSize: 14,
                      fontWeight: FontWeight.w700,
                      color: Colors.white,
                    ),
                  ),
                  const Spacer(),
                  if (rep.isNeuralVerified)
                    Container(
                      padding: const EdgeInsets.symmetric(
                          horizontal: 8, vertical: 3),
                      decoration: BoxDecoration(
                        color: const Color(0x3310B981),
                        borderRadius: BorderRadius.circular(4),
                        border: Border.all(
                            color: const Color(0xFF10B981), width: 0.8),
                      ),
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          const Icon(Icons.psychology_rounded,
                              size: 13, color: Color(0xFF10B981)),
                          const SizedBox(width: 4),
                          Text(
                            'GEMINI 2.5 FLASH VERIFIED',
                            style: GoogleFonts.spaceGrotesk(
                              fontSize: 9.5,
                              fontWeight: FontWeight.w800,
                              color: const Color(0xFF10B981),
                            ),
                          ),
                        ],
                      ),
                    ),
                ],
              ),

              const SizedBox(height: 20),

              // Split View
              if (isWide)
                Row(
                  crossAxisAlignment: CrossAxisAlignment.center,
                  children: [
                    // Gauge
                    AiConfidenceGauge(
                      probability: rep.overallAiProbability,
                      verdict: rep.verdict,
                      riskLevel: rep.riskLevel,
                      size: 210,
                    ),

                    const SizedBox(width: 28),

                    // Right column: Model Family, Summary & Vector Bars
                    Expanded(child: _buildVerdictDetails(rep)),
                  ],
                )
              else
                Column(
                  children: [
                    Center(
                      child: AiConfidenceGauge(
                        probability: rep.overallAiProbability,
                        verdict: rep.verdict,
                        riskLevel: rep.riskLevel,
                        size: 200,
                      ),
                    ),
                    const SizedBox(height: 18),
                    _buildVerdictDetails(rep),
                  ],
                ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildVerdictDetails(AiDetectionReport rep) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        // Model Lineage
        Row(
          children: [
            Text(
              'DETECTED MODEL LINEAGE: ',
              style: GoogleFonts.spaceGrotesk(
                fontSize: 11,
                fontWeight: FontWeight.w800,
                color: CyberTheme.textMuted,
                letterSpacing: 0.6,
              ),
            ),
            Expanded(
              child: Text(
                rep.detectedModelFamily,
                style: GoogleFonts.spaceGrotesk(
                  fontSize: 12,
                  fontWeight: FontWeight.w800,
                  color: Colors.white,
                ),
                overflow: TextOverflow.ellipsis,
              ),
            ),
          ],
        ),

        const SizedBox(height: 10),

        // Executive Summary
        Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            color: const Color(0x18FFFFFF),
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: const Color(0x24FFFFFF), width: 1.0),
          ),
          child: Text(
            rep.executiveSummary,
            style: GoogleFonts.plusJakartaSans(
              fontSize: 12.5,
              height: 1.45,
              color: Colors.white.withValues(alpha: 0.95),
            ),
          ),
        ),

        const SizedBox(height: 14),

        // 4 Vector Bars
        _buildVectorMeter(
          label: 'Provenance & Watermark Vector',
          score: rep.vectorBreakdown.provenanceScore,
        ),
        _buildVectorMeter(
          label: 'Stylometric & Perplexity Vector',
          score: rep.vectorBreakdown.stylometricScore,
        ),
        _buildVectorMeter(
          label: 'Spectral FFT Artifact Vector',
          score: rep.vectorBreakdown.spectralArtifactScore,
        ),
        _buildVectorMeter(
          label: 'Gemini 2.5 Flash Neural Vector',
          score: rep.vectorBreakdown.neuralConfidenceScore,
        ),
      ],
    );
  }

  Widget _buildVectorMeter({required String label, required double score}) {
    final pct = (score * 100).clamp(0.0, 100.0);
    final color = pct > 65.0
        ? const Color(0xFFF43F5E)
        : pct > 35.0
            ? const Color(0xFFF59E0B)
            : const Color(0xFF10B981);

    return Padding(
      padding: const EdgeInsets.symmetric(vertical: 3.0),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text(
                label,
                style: GoogleFonts.plusJakartaSans(
                  fontSize: 11,
                  fontWeight: FontWeight.w600,
                  color: CyberTheme.textMuted,
                ),
              ),
              Text(
                '${pct.toStringAsFixed(1)}%',
                style: GoogleFonts.spaceGrotesk(
                  fontSize: 11,
                  fontWeight: FontWeight.w800,
                  color: color,
                ),
              ),
            ],
          ),
          const SizedBox(height: 3),
          ClipRRect(
            borderRadius: BorderRadius.circular(100),
            child: LinearProgressIndicator(
              value: score.clamp(0.0, 1.0),
              minHeight: 5,
              backgroundColor: const Color(0x22FFFFFF),
              valueColor: AlwaysStoppedAnimation<Color>(color),
            ),
          ),
        ],
      ),
    );
  }

  // ==========================================
  // TABBED DEEP DIVE INSPECTOR
  // ==========================================
  Widget _buildTabbedInspector() {
    final rep = _report!;

    return GlassContainer(
      borderRadius: 18,
      padding: const EdgeInsets.all(20),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Tab bar
          Row(
            children: [
              _buildInspectorTabButton(
                title: rep.modality == AiDetectionModality.document
                    ? 'Sentence Heatmap'
                    : 'Spectral Frequency Matrix',
                icon: rep.modality == AiDetectionModality.document
                    ? Icons.format_color_text_rounded
                    : Icons.blur_linear_rounded,
                index: 0,
              ),
              const SizedBox(width: 8),
              _buildInspectorTabButton(
                title: 'Enterprise Checkpoints',
                icon: Icons.checklist_rounded,
                index: 1,
              ),
              const SizedBox(width: 8),
              _buildInspectorTabButton(
                title: 'Raw Forensic Telemetry',
                icon: Icons.data_object_rounded,
                index: 2,
              ),
            ],
          ),

          const SizedBox(height: 18),

          // Tab content
          if (_activeInspectorTab == 0) ...[
            if (rep.modality == AiDetectionModality.document) ...[
              AiTextHeatmapView(
                segments: rep.textSegments,
                burstinessVariance: rep.burstinessVariance,
                lexicalDiversityTtr: rep.lexicalDiversityTtr,
                detectedBoilerplatePhrases: rep.detectedBoilerplatePhrases,
              ),
            ] else ...[
              AiSpectralGridView(
                spectralGrid: rep.spectralFftGrid,
                highFrequencyAnomalyScore: rep.highFrequencyAnomalyScore,
                extractedMetadata: rep.extractedGenerativeMetadata,
                hasC2pa: rep.hasC2paManifest,
              ),
            ],
          ] else if (_activeInspectorTab == 1) ...[
            _buildCheckpointsList(rep),
          ] else ...[
            _buildRawTelemetry(rep),
          ],
        ],
      ),
    );
  }

  Widget _buildInspectorTabButton({
    required String title,
    required IconData icon,
    required int index,
  }) {
    final isActive = _activeInspectorTab == index;
    return InkWell(
      onTap: () => setState(() => _activeInspectorTab = index),
      borderRadius: BorderRadius.circular(8),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 180),
        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
        decoration: BoxDecoration(
          color: isActive
              ? CyberTheme.accentColor.withValues(alpha: 0.2)
              : const Color(0x10FFFFFF),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(
            color: isActive
                ? CyberTheme.accentColor
                : const Color(0x22FFFFFF),
            width: 1.0,
          ),
        ),
        child: Row(
          mainAxisSize: MainAxisSize.min,
          children: [
            Icon(
              icon,
              size: 15,
              color: isActive ? CyberTheme.accentColor : CyberTheme.textMuted,
            ),
            const SizedBox(width: 7),
            Text(
              title,
              style: GoogleFonts.spaceGrotesk(
                fontSize: 12,
                fontWeight: isActive ? FontWeight.w800 : FontWeight.w600,
                color: isActive ? Colors.white : CyberTheme.textMuted,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildCheckpointsList(AiDetectionReport rep) {
    return Column(
      children: rep.checkpoints.map((cp) {
        final color = cp.status == AiCheckpointStatus.flagged
            ? const Color(0xFFF43F5E)
            : cp.status == AiCheckpointStatus.warning
                ? const Color(0xFFF59E0B)
                : cp.status == AiCheckpointStatus.passed
                    ? const Color(0xFF10B981)
                    : const Color(0xFF38BDF8);

        return Container(
          margin: const EdgeInsets.only(bottom: 10),
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            color: const Color(0x14FFFFFF),
            borderRadius: BorderRadius.circular(10),
            border: Border.all(color: color.withValues(alpha: 0.35)),
          ),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(
                cp.status == AiCheckpointStatus.flagged
                    ? Icons.cancel_rounded
                    : cp.status == AiCheckpointStatus.warning
                        ? Icons.warning_amber_rounded
                        : cp.status == AiCheckpointStatus.passed
                            ? Icons.check_circle_rounded
                            : Icons.info_rounded,
                color: color,
                size: 20,
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Text(
                          cp.title,
                          style: GoogleFonts.spaceGrotesk(
                            fontSize: 13,
                            fontWeight: FontWeight.w800,
                            color: Colors.white,
                          ),
                        ),
                        const Spacer(),
                        Container(
                          padding: const EdgeInsets.symmetric(
                              horizontal: 6, vertical: 2),
                          decoration: BoxDecoration(
                            color: color.withValues(alpha: 0.15),
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: Text(
                            cp.status.name.toUpperCase(),
                            style: GoogleFonts.spaceGrotesk(
                              fontSize: 9.5,
                              fontWeight: FontWeight.w800,
                              color: color,
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(height: 2),
                    Text(
                      cp.subtitle,
                      style: GoogleFonts.plusJakartaSans(
                        fontSize: 11,
                        color: CyberTheme.textMuted,
                      ),
                    ),
                    const SizedBox(height: 6),
                    Text(
                      cp.details,
                      style: GoogleFonts.plusJakartaSans(
                        fontSize: 12,
                        color: Colors.white.withValues(alpha: 0.9),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        );
      }).toList(),
    );
  }

  Widget _buildRawTelemetry(AiDetectionReport rep) {
    final prettyJson = rep.toPrettyJson();
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(
              'CANONICAL SHA-256: ${rep.sha256Hash}',
              style: GoogleFonts.spaceGrotesk(
                fontSize: 11,
                fontWeight: FontWeight.w700,
                color: CyberTheme.accentColor,
              ),
            ),
            IconButton(
              tooltip: 'Copy Telemetry JSON',
              icon: const Icon(Icons.copy_rounded, size: 16, color: Colors.white70),
              onPressed: () {
                Clipboard.setData(ClipboardData(text: prettyJson));
                _showSnackbar('Telemetry JSON copied to clipboard.');
              },
            ),
          ],
        ),
        const SizedBox(height: 8),
        Container(
          constraints: const BoxConstraints(maxHeight: 280),
          padding: const EdgeInsets.all(14),
          decoration: BoxDecoration(
            color: const Color(0x22000000),
            borderRadius: BorderRadius.circular(8),
            border: Border.all(color: const Color(0x33FFFFFF)),
          ),
          child: SingleChildScrollView(
            child: SelectableText(
              prettyJson,
              style: GoogleFonts.firaCode(fontSize: 11.5, color: Colors.white70),
            ),
          ),
        ),
      ],
    );
  }

  // ==========================================
  // ACTION BAR
  // ==========================================
  Widget _buildActionBar() {
    return Row(
      children: [
        // Analyze another
        CyberButton(
          icon: Icons.refresh_rounded,
          onTap: () => setState(() => _report = null),
          child: const Text('Scan Another File'),
        ),

        const SizedBox(width: 12),

        // Export PDF
        CyberButton(
          icon: Icons.picture_as_pdf_rounded,
          onTap: _exportPdfReport,
          child: const Text('Export Audit PDF'),
        ),

        const Spacer(),

        // Anchor to Immutable Zero-Trust Ledger
        CyberButton(
          icon: _isLedgerAnchored
              ? Icons.lock_clock_rounded
              : Icons.lock_outline_rounded,
          onTap: _isLedgerAnchored ? null : _anchorToLedger,
          child: Text(
            _isLedgerAnchored ? 'Anchored to Ledger' : 'Anchor to Ledger',
          ),
        ),
      ],
    );
  }
}
