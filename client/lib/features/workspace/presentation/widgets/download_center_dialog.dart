import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import '../../../../shared/theme/cyber_theme.dart';
import '../../services/platform_launcher_helper.dart';

/// Interactive modal dialog presenting official download options for Windows desktop and Android mobile.
class DownloadCenterDialog extends StatelessWidget {
  const DownloadCenterDialog({super.key});

  static void show(BuildContext context) {
    showDialog(
      context: context,
      barrierColor: Colors.black.withValues(alpha: 0.75),
      builder: (ctx) => const DownloadCenterDialog(),
    );
  }

  @override
  Widget build(BuildContext context) {
    final screenWidth = MediaQuery.of(context).size.width;
    final isMobile = screenWidth < 700;

    return Dialog(
      backgroundColor: Colors.transparent,
      insetPadding: EdgeInsets.symmetric(horizontal: isMobile ? 12 : 24, vertical: 24),
      child: Container(
        constraints: const BoxConstraints(maxWidth: 820),
        decoration: BoxDecoration(
          color: const Color(0xFF0C0A14),
          borderRadius: BorderRadius.circular(24),
          border: Border.all(color: CyberTheme.borderAccent, width: 1.5),
          boxShadow: [
            BoxShadow(
              color: CyberTheme.accentColor.withValues(alpha: 0.35),
              blurRadius: 40,
              spreadRadius: 2,
            ),
          ],
        ),
        child: SingleChildScrollView(
          padding: EdgeInsets.all(isMobile ? 20 : 32),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // Header with Title & Close Button
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                children: [
                  Row(
                    children: [
                      Container(
                        padding: const EdgeInsets.all(10),
                        decoration: BoxDecoration(
                          color: const Color(0x25A855F7),
                          shape: BoxShape.circle,
                          border: Border.all(color: CyberTheme.accentColor),
                        ),
                        child: const Icon(Icons.download_for_offline_rounded, color: Color(0xFFC084FC), size: 24),
                      ),
                      const SizedBox(width: 14),
                      Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'Download Obsidian Client',
                            style: GoogleFonts.plusJakartaSans(
                              color: Colors.white,
                              fontSize: isMobile ? 18 : 22,
                              fontWeight: FontWeight.w900,
                            ),
                          ),
                          Text(
                            'Zero-Trust Cross-Platform Distribution // v2.4.0',
                            style: GoogleFonts.jetBrainsMono(
                              color: CyberTheme.cyanLight,
                              fontSize: 11,
                              fontWeight: FontWeight.w600,
                            ),
                          ),
                        ],
                      ),
                    ],
                  ),
                  IconButton(
                    onPressed: () => Navigator.of(context).pop(),
                    icon: const Icon(Icons.close_rounded, color: CyberTheme.textSecondary),
                    splashRadius: 20,
                  ),
                ],
              ),
              const SizedBox(height: 24),

              // Description banner
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                decoration: BoxDecoration(
                  color: const Color(0x1538BDF8),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: const Color(0x3538BDF8)),
                ),
                child: Row(
                  children: [
                    const Icon(Icons.shield_outlined, color: Color(0xFF38BDF8), size: 18),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        'Direct binaries built with native Ed25519 cryptographic keystores and air-gapped AES-256 local ledgers. Choose your target platform below.',
                        style: GoogleFonts.plusJakartaSans(
                          color: const Color(0xFFBAE6FD),
                          fontSize: 12,
                          height: 1.45,
                        ),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(height: 28),

              // Platform Cards Grid (Windows vs Android)
              if (isMobile)
                Column(
                  children: [
                    _buildPlatformCard(
                      context: context,
                      icon: Icons.desktop_windows_rounded,
                      iconColor: const Color(0xFF38BDF8),
                      platformName: 'Windows Desktop (x64)',
                      fileName: 'Project-Kerberos-Windows.zip',
                      fileSize: '~58 MB',
                      architecture: 'Windows 10 / 11 Native 64-bit',
                      badgeText: 'RECOMMENDED DESKTOP',
                      badgeColor: const Color(0xFF0284C7),
                      features: const [
                        'Native Windows Runner with Direct GPU Acceleration',
                        'Hardware Ed25519 Keystore & C2PA Container Signing',
                        'Deep Binary & Vector Thermal Forensic Pipeline',
                        'Local WebRTC Radar Signaling & Peer File Mesh',
                      ],
                      onDownload: () => PlatformLauncherHelper.launchUrl(
                        context,
                        PlatformLauncherHelper.windowsDownloadUrl,
                        platformName: 'Windows Desktop',
                      ),
                    ),
                    const SizedBox(height: 16),
                    _buildPlatformCard(
                      context: context,
                      icon: Icons.phone_android_rounded,
                      iconColor: const Color(0xFF34D399),
                      platformName: 'Android Mobile App',
                      fileName: 'app-release.apk',
                      fileSize: '~29 MB',
                      architecture: 'Android 10+ (ARM64 / ARMv7)',
                      badgeText: 'MOBILE FIELD EDITION',
                      badgeColor: const Color(0xFF059669),
                      features: const [
                        'Mobile Forensic Scanner & UIDAI Secure QR Reader',
                        'Field Camera Ingest with Immutable Timestamping',
                        'Air-Gapped P2P Radar Mesh via Direct WebRTC',
                        'AES-256 Encrypted Local Hive Storage Enclave',
                      ],
                      onDownload: () => PlatformLauncherHelper.launchUrl(
                        context,
                        PlatformLauncherHelper.androidDownloadUrl,
                        platformName: 'Android APK',
                      ),
                    ),
                  ],
                )
              else
                Row(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Expanded(
                      child: _buildPlatformCard(
                        context: context,
                        icon: Icons.desktop_windows_rounded,
                        iconColor: const Color(0xFF38BDF8),
                        platformName: 'Windows Desktop (x64)',
                        fileName: 'Project-Kerberos-Windows.zip',
                        fileSize: '~58 MB',
                        architecture: 'Windows 10 / 11 Native 64-bit',
                        badgeText: 'RECOMMENDED DESKTOP',
                        badgeColor: const Color(0xFF0284C7),
                        features: const [
                          'Native Windows Runner with Direct GPU Acceleration',
                          'Hardware Ed25519 Keystore & C2PA Container Signing',
                          'Deep Binary & Vector Thermal Forensic Pipeline',
                          'Local WebRTC Radar Signaling & Peer File Mesh',
                        ],
                        onDownload: () => PlatformLauncherHelper.launchUrl(
                          context,
                          PlatformLauncherHelper.windowsDownloadUrl,
                          platformName: 'Windows Desktop',
                        ),
                      ),
                    ),
                    const SizedBox(width: 18),
                    Expanded(
                      child: _buildPlatformCard(
                        context: context,
                        icon: Icons.phone_android_rounded,
                        iconColor: const Color(0xFF34D399),
                        platformName: 'Android Mobile App',
                        fileName: 'app-release.apk',
                        fileSize: '~29 MB',
                        architecture: 'Android 10+ (ARM64 / ARMv7)',
                        badgeText: 'MOBILE FIELD EDITION',
                        badgeColor: const Color(0xFF059669),
                        features: const [
                          'Mobile Forensic Scanner & UIDAI Secure QR Reader',
                          'Field Camera Ingest with Immutable Timestamping',
                          'Air-Gapped P2P Radar Mesh via Direct WebRTC',
                          'AES-256 Encrypted Local Hive Storage Enclave',
                        ],
                        onDownload: () => PlatformLauncherHelper.launchUrl(
                          context,
                          PlatformLauncherHelper.androidDownloadUrl,
                          platformName: 'Android APK',
                        ),
                      ),
                    ),
                  ],
                ),
              const SizedBox(height: 20),

              // Web App / Live Portal Alternative Row
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
                decoration: BoxDecoration(
                  color: const Color(0x18A855F7),
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(color: const Color(0x35A855F7)),
                ),
                child: Row(
                  children: [
                    const Icon(Icons.language_rounded, color: Color(0xFFC084FC), size: 24),
                    const SizedBox(width: 14),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            'Prefer using in-browser without installing?',
                            style: GoogleFonts.plusJakartaSans(
                              color: Colors.white,
                              fontSize: 13,
                              fontWeight: FontWeight.bold,
                            ),
                          ),
                          Text(
                            'Launch the Web Enclave instantly on Chrome, Edge, or Safari with WebAssembly zk-SNARK verification.',
                            style: GoogleFonts.plusJakartaSans(
                              color: CyberTheme.textSecondary,
                              fontSize: 11.5,
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(width: 12),
                    ElevatedButton(
                      style: ElevatedButton.styleFrom(
                        backgroundColor: const Color(0xFF9333EA),
                        foregroundColor: Colors.white,
                        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(100)),
                      ),
                      onPressed: () => PlatformLauncherHelper.launchUrl(
                        context,
                        PlatformLauncherHelper.webAppUrl,
                        platformName: 'Web Enclave',
                      ),
                      child: const Text('Open Web App', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold)),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildPlatformCard({
    required BuildContext context,
    required IconData icon,
    required Color iconColor,
    required String platformName,
    required String fileName,
    required String fileSize,
    required String architecture,
    required String badgeText,
    required Color badgeColor,
    required List<String> features,
    required VoidCallback onDownload,
  }) {
    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: const Color(0xFF130E20),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: const Color(0x35A855F7)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Header Pill & Platform Name
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Container(
                padding: const EdgeInsets.all(10),
                decoration: BoxDecoration(
                  color: iconColor.withValues(alpha: 0.15),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: iconColor.withValues(alpha: 0.4)),
                ),
                child: Icon(icon, color: iconColor, size: 24),
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                decoration: BoxDecoration(
                  color: badgeColor.withValues(alpha: 0.2),
                  borderRadius: BorderRadius.circular(100),
                  border: Border.all(color: badgeColor.withValues(alpha: 0.6)),
                ),
                child: Text(
                  badgeText,
                  style: GoogleFonts.jetBrainsMono(
                    color: badgeColor,
                    fontSize: 9.5,
                    fontWeight: FontWeight.w800,
                    letterSpacing: 0.6,
                  ),
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          Text(
            platformName,
            style: GoogleFonts.plusJakartaSans(
              color: Colors.white,
              fontSize: 18,
              fontWeight: FontWeight.w900,
            ),
          ),
          const SizedBox(height: 4),
          Text(
            '$architecture • $fileSize',
            style: GoogleFonts.jetBrainsMono(
              color: const Color(0xFF94A3B8),
              fontSize: 11.5,
            ),
          ),
          const SizedBox(height: 16),

          // Features List
          ...features.map(
            (feat) => Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Padding(
                    padding: EdgeInsets.only(top: 3),
                    child: Icon(Icons.check_circle_rounded, color: Color(0xFF34D399), size: 14),
                  ),
                  const SizedBox(width: 8),
                  Expanded(
                    child: Text(
                      feat,
                      style: GoogleFonts.plusJakartaSans(
                        color: const Color(0xFFCBD5E1),
                        fontSize: 12,
                        height: 1.35,
                      ),
                    ),
                  ),
                ],
              ),
            ),
          ),
          const SizedBox(height: 20),

          // Action Download Button
          SizedBox(
            width: double.infinity,
            child: ElevatedButton.icon(
              style: ElevatedButton.styleFrom(
                backgroundColor: iconColor,
                foregroundColor: const Color(0xFF0A0712),
                padding: const EdgeInsets.symmetric(vertical: 14),
                shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(12)),
                elevation: 0,
              ),
              icon: const Icon(Icons.download_rounded, size: 18),
              label: Text(
                'Download $fileName',
                style: GoogleFonts.plusJakartaSans(
                  fontWeight: FontWeight.w900,
                  fontSize: 13,
                  letterSpacing: 0.2,
                ),
              ),
              onPressed: onDownload,
            ),
          ),
        ],
      ),
    );
  }
}
