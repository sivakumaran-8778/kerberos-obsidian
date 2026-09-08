// ignore: avoid_web_libraries_in_flutter, deprecated_member_use
import 'dart:html' as html;

void launchPlatformUrl(String url) {
  try {
    html.window.open(url, '_blank');
  } catch (e) {
    print(">> [PlatformLauncher] Error launching web URL: $e");
  }
}
