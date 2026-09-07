import 'package:flutter_test/flutter_test.dart';
import 'package:supabase_flutter/supabase_flutter.dart';
import 'package:kerberos_client/features/auth/services/auth_service.dart';

void main() {
  test('AuthService Validation Tests', () async {
    const url = 'https://kyojroqhbvadzocdpnqn.supabase.co';
    const anonKey = 'sb_publishable_trcpGuxjaKxTlb8Sa-b8vA_qWRPTwTf';

    final client = SupabaseClient(url, anonKey);
    final authService = AuthService(client);

    // 1. Validate invalid email formats
    expect(
      () => authService.signInWithPassword(email: 'invalid-email', password: 'password123'),
      throwsA(predicate((e) => e.toString().contains('valid email address'))),
    );

    expect(
      () => authService.signInWithPassword(email: '', password: 'password123'),
      throwsA(predicate((e) => e.toString().contains('valid email address'))),
    );

    // 2. Validate empty password
    expect(
      () => authService.signInWithPassword(email: 'test@example.com', password: ''),
      throwsA(predicate((e) => e.toString().contains('Password cannot be empty'))),
    );

    // 3. Validate short password on registration
    expect(
      () => authService.signUp(email: 'test@example.com', password: '123', displayName: 'Agent Alpha'),
      throwsA(predicate((e) => e.toString().contains('at least 6 characters'))),
    );

    // 4. Validate empty display name on registration
    expect(
      () => authService.signUp(email: 'test@example.com', password: 'password123', displayName: ''),
      throwsA(predicate((e) => e.toString().contains('enter your display name'))),
    );

    // 5. Validate reset password email validation
    expect(
      () => authService.resetPasswordForEmail('bad-email'),
      throwsA(predicate((e) => e.toString().contains('valid email address'))),
    );

    print("ALL AUTH VALIDATION TESTS PASSED CLEANLY!");
  });
}
