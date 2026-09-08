import 'package:flutter/material.dart';
import 'platform_launcher_stub.dart'
    if (dart.library.io) 'platform_launcher_io.dart'
    if (dart.library.html) 'platform_launcher_web.dart';

class PlatformLauncherHelper {
  static const String githubRepoUrl = 'https://github.com/sivakumaran-8778/kerberos-obsidian';
  static const String windowsDownloadUrl = 'https://github.com/sivakumaran-8778/kerberos-obsidian/releases/latest/download/Project-Kerberos-Windows.zip';
  static const String androidDownloadUrl = 'https://github.com/sivakumaran-8778/kerberos-obsidian/releases/latest/download/app-release.apk';
  static const String webAppUrl = 'https://kerberos-obsidian.vercel.app';

  static void launchUrl(BuildContext context, String url, {required String platformName}) {
    try {
      launchPlatformUrl(url);

      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            backgroundColor: const Color(0xFF0F172A),
            behavior: SnackBarBehavior.floating,
            shape: RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(12),
              side: const BorderSide(color: Color(0xFF38BDF8), width: 1.2),
            ),
            duration: const Duration(seconds: 4),
            content: Row(
              children: [
                const Icon(Icons.downloading_rounded, color: Color(0xFF38BDF8), size: 20),
                const SizedBox(width: 12),
                Expanded(
                  child: Text(
                    'Opening $platformName download mirror...',
                    style: const TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.w600),
                  ),
                ),
              ],
            ),
          ),
        );
      }
    } catch (e) {
      if (context.mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            backgroundColor: const Color(0xFF3B0764),
            content: Text('Notice: Could not open download mirror ($e)'),
          ),
        );
      }
    }
  }
}
