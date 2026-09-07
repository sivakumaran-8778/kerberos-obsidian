import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:record/record.dart';
import 'package:path_provider/path_provider.dart';
import 'package:path/path.dart' as p;
import 'package:cross_file/cross_file.dart';

class VoiceNoteResult {
  final Uint8List bytes;
  final int durationSeconds;
  final String fileName;
  final String? localFilePath;

  const VoiceNoteResult({
    required this.bytes,
    required this.durationSeconds,
    required this.fileName,
    this.localFilePath,
  });
}

/// Robust cross-platform microphone recording service for WhatsApp-style voice notes.
/// Fully compatible with Flutter Web (MediaStream/WebM/Opus) and Desktop/Mobile (MediaFoundation/AAC).
class VoiceNoteService extends ChangeNotifier {
  final AudioRecorder _recorder = AudioRecorder();
  Timer? _timer;
  int _durationSeconds = 0;
  bool _isRecording = false;
  String? lastErrorMessage;
  AudioEncoder _activeEncoder = AudioEncoder.aacLc;

  bool get isRecording => _isRecording;
  int get durationSeconds => _durationSeconds;

  String get formattedDuration {
    final m = (_durationSeconds ~/ 60).toString().padLeft(2, '0');
    final s = (_durationSeconds % 60).toString().padLeft(2, '0');
    return '$m:$s';
  }

  /// Determines the best audio encoder supported on the current platform.
  Future<AudioEncoder> _determineBestEncoder() async {
    if (kIsWeb) {
      if (await _recorder.isEncoderSupported(AudioEncoder.opus)) {
        return AudioEncoder.opus;
      }
    }
    if (await _recorder.isEncoderSupported(AudioEncoder.aacLc)) {
      return AudioEncoder.aacLc;
    }
    return AudioEncoder.aacLc;
  }

  /// Starts recording a voice note.
  Future<bool> startRecording() async {
    lastErrorMessage = null;
    try {
      final hasPerm = await _recorder.hasPermission();
      if (!hasPerm) {
        lastErrorMessage = 'Microphone permission not granted. Please allow microphone access in your browser or system settings.';
        debugPrint('[VoiceNoteService] $lastErrorMessage');
        return false;
      }

      _activeEncoder = await _determineBestEncoder();

      String recordPath = '';
      if (!kIsWeb) {
        // Desktop / Mobile temp path
        try {
          final tempDir = await getTemporaryDirectory();
          final ext = _activeEncoder == AudioEncoder.aacLc ? 'm4a' : 'opus';
          final fileName = 'voice_note_${DateTime.now().millisecondsSinceEpoch}.$ext';
          recordPath = p.join(tempDir.path, fileName);
        } catch (_) {
          recordPath = '';
        }
      }

      await _recorder.start(
        RecordConfig(
          encoder: _activeEncoder,
          bitRate: 128000,
          sampleRate: 44100,
        ),
        path: recordPath,
      );

      _isRecording = true;
      _durationSeconds = 0;
      notifyListeners();

      _timer?.cancel();
      _timer = Timer.periodic(const Duration(seconds: 1), (timer) {
        _durationSeconds++;
        notifyListeners();
      });

      return true;
    } catch (e) {
      lastErrorMessage = 'Recording initialization failed: $e';
      debugPrint('[VoiceNoteService] startRecording error: $e');
      _isRecording = false;
      notifyListeners();
      return false;
    }
  }

  /// Finalizes and returns the recorded voice note audio bytes.
  Future<VoiceNoteResult?> stopRecording() async {
    _timer?.cancel();
    if (!_isRecording) return null;

    try {
      final recordedPath = await _recorder.stop();
      _isRecording = false;
      final finalDuration = _durationSeconds > 0 ? _durationSeconds : 1;
      _durationSeconds = 0;
      notifyListeners();

      if (recordedPath == null || recordedPath.isEmpty) {
        return null;
      }

      // Read bytes using XFile (safe on Web Blob URLs and Desktop local paths)
      final xfile = XFile(recordedPath);
      final bytes = await xfile.readAsBytes();
      if (bytes.isEmpty) {
        return null;
      }

      final ext = _activeEncoder == AudioEncoder.aacLc ? 'm4a' : 'webm';
      final fileName = 'voice_note_${DateTime.now().millisecondsSinceEpoch}.$ext';

      return VoiceNoteResult(
        bytes: bytes,
        durationSeconds: finalDuration,
        fileName: fileName,
        localFilePath: kIsWeb ? null : recordedPath,
      );
    } catch (e) {
      debugPrint('[VoiceNoteService] stopRecording error: $e');
      _isRecording = false;
      _durationSeconds = 0;
      notifyListeners();
      return null;
    }
  }

  /// Aborts and cancels the current recording without saving.
  Future<void> cancelRecording() async {
    _timer?.cancel();
    if (!_isRecording) return;

    try {
      await _recorder.stop();
      _isRecording = false;
      _durationSeconds = 0;
      notifyListeners();
    } catch (e) {
      debugPrint('[VoiceNoteService] cancelRecording error: $e');
      _isRecording = false;
      _durationSeconds = 0;
      notifyListeners();
    }
  }

  @override
  void dispose() {
    _timer?.cancel();
    _recorder.dispose();
    super.dispose();
  }
}
