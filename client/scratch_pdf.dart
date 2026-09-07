import 'dart:io';
import 'package:syncfusion_flutter_pdf/pdf.dart';

void main(List<String> args) {
  if (args.isEmpty) {
    print('Provide PDF path');
    return;
  }
  final bytes = File(args[0]).readAsBytesSync();
  final document = PdfDocument(inputBytes: bytes);
  
  for (int i = 0; i < document.pages.count; i++) {
    final page = document.pages[i];
    print('Page $i annotations: ${page.annotations.count}');
    for (int j = 0; j < page.annotations.count; j++) {
      final ann = page.annotations[j];
      print(' Annotation $j: bounds=${ann.bounds}');
    }
  }
}
