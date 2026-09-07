import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:supabase_flutter/supabase_flutter.dart';
import '../services/auth_service.dart';

final authServiceProvider = Provider<AuthService>((ref) {
  return AuthService(Supabase.instance.client);
});

final authStateProvider = StreamProvider<AuthState>((ref) {
  final authService = ref.watch(authServiceProvider);
  return authService.onAuthStateChange;
});

final currentUserProvider = Provider<User?>((ref) {
  final authState = ref.watch(authStateProvider);
  return authState.value?.session?.user ?? ref.watch(authServiceProvider).currentUser;
});

class UserProfile {
  final String id;
  final String displayName;
  final String email;
  final String initials;

  const UserProfile({
    this.id = '',
    required this.displayName,
    required this.email,
    required this.initials,
  });
}

final userProfileProvider = Provider<UserProfile>((ref) {
  final user = ref.watch(currentUserProvider);
  if (user == null) {
    return const UserProfile(
      id: 'anonymous-node',
      displayName: 'Guest Agent',
      email: 'offline@enclave.local',
      initials: 'GA',
    );
  }

  final meta = user.userMetadata;
  String name = 'Agent';
  if (meta != null && meta['display_name'] != null && meta['display_name'].toString().trim().isNotEmpty) {
    name = meta['display_name'].toString().trim();
  } else if (meta != null && meta['name'] != null && meta['name'].toString().trim().isNotEmpty) {
    name = meta['name'].toString().trim();
  } else if (user.email != null && user.email!.contains('@')) {
    name = user.email!.split('@').first;
  }

  final email = user.email ?? '';
  
  // Calculate initials
  String initials = 'K';
  final parts = name.trim().split(RegExp(r'\s+'));
  if (parts.length >= 2 && parts[0].isNotEmpty && parts[1].isNotEmpty) {
    initials = '${parts[0][0]}${parts[1][0]}'.toUpperCase();
  } else if (name.isNotEmpty) {
    initials = name.substring(0, name.length >= 2 ? 2 : 1).toUpperCase();
  }

  return UserProfile(
    id: user.id,
    displayName: name,
    email: email,
    initials: initials,
  );
});
