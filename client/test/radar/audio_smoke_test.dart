import 'package:flutter_test/flutter_test.dart';
import 'package:record/record.dart';
import 'package:audioplayers/audioplayers.dart';

void main() {
  TestWidgetsFlutterBinding.ensureInitialized();

  test('Audio packages import and compile test', () {
    print('AudioEncoder values: ${AudioEncoder.values}');
    expect(AudioEncoder.values, isNotEmpty);
    expect(AudioPlayer, isNotNull);
  });
}
