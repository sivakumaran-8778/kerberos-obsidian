import 'dart:io';

void launchPlatformUrl(String url) {
  try {
    if (Platform.isWindows) {
      Process.run('cmd', ['/c', 'start', '', url]);
    } else if (Platform.isMacOS) {
      Process.run('open', [url]);
    } else if (Platform.isLinux) {
      Process.run('xdg-open', [url]);
    }
  } catch (e) {
    print(">> [PlatformLauncher] Error launching native URL: $e");
  }
}
