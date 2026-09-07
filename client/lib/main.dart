import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_dotenv/flutter_dotenv.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

import 'shared/theme/cyber_theme.dart';
import 'features/ledger/services/ledger_service.dart';
import 'features/auth/providers/auth_providers.dart';
import 'features/auth/presentation/auth_screen.dart';
import 'features/network/providers/network_providers.dart';
import 'features/workspace/presentation/workspace_screen.dart';

// Global Provider for the securely initialized ledger
final ledgerProvider = Provider<LedgerService>((ref) {
  throw UnimplementedError('LedgerService must be initialized before runApp');
});

final GlobalKey<NavigatorState> rootNavigatorKey = GlobalKey<NavigatorState>();

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // 1. Strict Environment Load
  await dotenv.load(fileName: ".env");

  // 2. Global Supabase Client with persistent Auth Storage
  await Supabase.initialize(
    url: getSupabaseUrl(),
    anonKey: getSupabaseAnonKey(),
  );

  // 3. Air-gapped AES-256 Ledger Boot
  final secureLedger = LedgerService();
  await secureLedger.initialize();

  runApp(
    ProviderScope(
      overrides: [
        ledgerProvider.overrideWithValue(secureLedger),
      ],
      child: const KerberosApp(),
    ),
  );
}

class KerberosApp extends ConsumerWidget {
  const KerberosApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    // Watch current user authentication state
    final currentUser = ref.watch(currentUserProvider);

    // Eagerly boot signaling, WebRTC, and incoming transfer listeners when authenticated
    if (currentUser != null) {
      ref.watch(webRtcServiceProvider);
      ref.watch(incomingTransferNotifierProvider);
    }

    return MaterialApp(
      navigatorKey: rootNavigatorKey,
      title: 'Obsidian Protocol',
      theme: CyberTheme.darkTheme,
      home: currentUser != null ? const WorkspaceScreen() : const AuthScreen(),
      debugShowCheckedModeBanner: false,
    );
  }
}
