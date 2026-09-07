import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:desktop_drop/desktop_drop.dart';
import 'package:file_picker/file_picker.dart';
import 'package:cross_file/cross_file.dart';
import '../../../shared/widgets/neomorphic_container.dart';
import '../providers/provenance_providers.dart';

class UploadScreen extends ConsumerStatefulWidget {
  const UploadScreen({super.key});

  @override
  ConsumerState<UploadScreen> createState() => _UploadScreenState();
}

class _UploadScreenState extends ConsumerState<UploadScreen> {
  bool _isDragging = false;

  @override
  Widget build(BuildContext context) {
    final taskState = ref.watch(provenanceTaskNotifierProvider);

    return Scaffold(
      body: SafeArea(
        child: Padding(
          padding: const EdgeInsets.all(48.0),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  IconButton(
                    icon: const Icon(Icons.arrow_back, color: kTextColor),
                    onPressed: () => Navigator.pop(context),
                  ),
                  const SizedBox(width: 16),
                  Text('INGESTION // SEALING', style: Theme.of(context).textTheme.headlineSmall),
                ],
              ),
              const SizedBox(height: 48),
              
              // Depressed Light Drop Zone
              Expanded(
                child: DropTarget(
                  onDragEntered: (_) => setState(() => _isDragging = true),
                  onDragExited: (_) => setState(() => _isDragging = false),
                  onDragDone: (details) {
                    setState(() => _isDragging = false);
                    if (details.files.isNotEmpty) {
                      final file = details.files.first;
                      ref.read(provenanceTaskNotifierProvider.notifier).ingestFile(file);
                    }
                  },
                  child: GestureDetector(
                    onTap: () async {
                      final result = await FilePicker.platform.pickFiles();
                      if (result != null && result.files.isNotEmpty) {
                        if (kIsWeb) {
                          final bytes = result.files.single.bytes;
                          final name = result.files.single.name;
                          if (bytes != null) {
                            ref.read(provenanceTaskNotifierProvider.notifier).ingestFile(XFile.fromData(bytes, name: name));
                          }
                        } else {
                          // FilePicker returns path natively
                          final pickedPath = result.files.single.path;
                          if (pickedPath != null) {
                            ref.read(provenanceTaskNotifierProvider.notifier).ingestFile(XFile(pickedPath));
                          }
                        }
                      }
                    },
                    child: NeomorphicContainer(
                      depressed: true,
                      width: double.infinity,
                      child: Column(
                        mainAxisAlignment: MainAxisAlignment.center,
                        children: [
                          Icon(
                            Icons.file_upload_outlined, 
                            size: 48, 
                            color: _isDragging ? kAccentColor : kTextColor.withValues(alpha: 0.5),
                          ),
                          const SizedBox(height: 24),
                          Text(
                            _isDragging ? '> DROP TO INGEST' : '> CLICK OR DROP TO INGEST...', 
                            style: Theme.of(context).textTheme.bodyLarge?.copyWith(
                              color: _isDragging ? kAccentColor : kTextColor,
                            ),
                          ),
                        if (taskState.isLoading)
                          const Padding(
                            padding: EdgeInsets.only(top: 24.0),
                            child: CircularProgressIndicator(color: kAccentColor, strokeWidth: 2),
                          ),
                      ],
                    ),
                  ),
                ), // closes GestureDetector
              ), // closes DropTarget
            ), // closes Expanded
              
              const SizedBox(height: 32),
              
              // Elevated Status Container (Text-lane alerts only)
              NeomorphicContainer(
                width: double.infinity,
                child: taskState.when(
                  data: (metadata) {
                    if (metadata == null) {
                      return const Text('> STANDBY', style: TextStyle(color: kTextColor));
                    }
                    return Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        const Text('SEALING COMPLETE. ZERO-TRUST LEDGER UPDATED.', style: TextStyle(color: kAccentColor, fontWeight: FontWeight.bold)),
                        const SizedBox(height: 16),
                        Text('PATH: ${metadata.filePath}', style: const TextStyle(color: kTextColor)),
                        const SizedBox(height: 8),
                        Text('SHA-256: ${metadata.sha256Hash}', style: const TextStyle(color: kTextColor)),
                      ],
                    );
                  },
                  error: (err, stack) => SizedBox(
                    height: 100, // Constrain height to prevent overflow
                    child: SingleChildScrollView(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const Text('ZERO-TRUST FAULT DETECTED.', style: TextStyle(color: kAlertColor, fontWeight: FontWeight.bold)),
                          const SizedBox(height: 16),
                          Text(err.toString(), style: const TextStyle(color: kTextColor)),
                        ],
                      ),
                    ),
                  ),
                  loading: () => const Text('> PROCESSING ISOLATE IN BACKGROUND...', style: TextStyle(color: kTextColor)),
                ),
              )
            ],
          ),
        ),
      ),
    );
  }
}
