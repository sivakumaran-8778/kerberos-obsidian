import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

import '../../../../shared/widgets/cyber_button.dart';

/// Alerts user before disconnecting an active P2P transmission
class NavigationGuardDialog extends StatelessWidget {
  final String fileName;
  final double progress;

  const NavigationGuardDialog({
    super.key,
    required this.fileName,
    required this.progress,
  });

  static Future<bool> show(
    BuildContext context, {
    required String fileName,
    required double progress,
  }) async {
    final result = await showDialog<bool>(
      context: context,
      barrierDismissible: false,
      builder: (ctx) => NavigationGuardDialog(fileName: fileName, progress: progress),
    );
    return result ?? false;
  }

  @override
  Widget build(BuildContext context) {
    return Dialog(
      backgroundColor: Colors.transparent,
      elevation: 0,
      child: Container(
        width: 440,
        padding: const EdgeInsets.all(26),
        decoration: BoxDecoration(
          color: const Color(0xFB160F2B),
          borderRadius: BorderRadius.circular(24),
          border: Border.all(color: const Color(0x60F43F5E), width: 1.5),
          boxShadow: [
            BoxShadow(
              color: const Color(0xFFF43F5E).withValues(alpha: 0.25),
              blurRadius: 36,
              spreadRadius: 2,
            ),
          ],
        ),
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Row(
              children: [
                Container(
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(
                    color: const Color(0x25F43F5E),
                    shape: BoxShape.circle,
                    border: Border.all(color: const Color(0x50F43F5E)),
                  ),
                  child: const Icon(Icons.warning_amber_rounded, color: Color(0xFFFB7185), size: 24),
                ),
                const SizedBox(width: 14),
                Expanded(
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'TRANSFER IN PROGRESS',
                        style: GoogleFonts.plusJakartaSans(
                          fontSize: 15,
                          fontWeight: FontWeight.w900,
                          letterSpacing: 0.8,
                          color: Colors.white,
                        ),
                      ),
                      const SizedBox(height: 2),
                      Text(
                        'Active WebRTC DTLS DataChannel',
                        style: GoogleFonts.jetBrainsMono(
                          fontSize: 10.5,
                          color: const Color(0xFFFB7185),
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                    ],
                  ),
                ),
              ],
            ),
            const SizedBox(height: 18),

            Text(
              'A sealed asset ("$fileName") is currently streaming across the peer tunnel (${(progress * 100).toStringAsFixed(0)}% complete). Navigating away now will sever the DTLS connection and abort the payload transmission.',
              style: GoogleFonts.plusJakartaSans(
                fontSize: 12.5,
                color: const Color(0xFFCBD5E1),
                height: 1.45,
              ),
            ),
            const SizedBox(height: 24),

            Row(
              mainAxisAlignment: MainAxisAlignment.end,
              children: [
                CyberButton(
                  variant: CyberButtonVariant.glassPill,
                  height: 38,
                  onTap: () => Navigator.pop(context, false),
                  child: const Text('Stay & Complete'),
                ),
                const SizedBox(width: 12),
                CyberButton(
                  variant: CyberButtonVariant.danger,
                  height: 38,
                  onTap: () => Navigator.pop(context, true),
                  child: const Text('Disconnect & Leave'),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }
}
