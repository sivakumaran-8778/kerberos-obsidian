import 'dart:async';
import 'package:flutter/foundation.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

class AuthService {
  final SupabaseClient _supabase;

  AuthService(this._supabase);

  User? get currentUser => _supabase.auth.currentUser;

  Stream<AuthState> get onAuthStateChange => _supabase.auth.onAuthStateChange;

  bool get isAuthenticated => _supabase.auth.currentUser != null;

  String? get defaultRedirectUrl {
    if (kIsWeb) {
      try {
        final origin = Uri.base.origin;
        if (origin.isNotEmpty && !origin.contains('null')) {
          return origin;
        }
      } catch (_) {}
    }
    return null;
  }

  String get userDisplayName {
    final user = _supabase.auth.currentUser;
    if (user == null) return 'User';
    final meta = user.userMetadata;
    if (meta != null && meta['display_name'] != null && meta['display_name'].toString().trim().isNotEmpty) {
      return meta['display_name'].toString().trim();
    }
    if (meta != null && meta['name'] != null && meta['name'].toString().trim().isNotEmpty) {
      return meta['name'].toString().trim();
    }
    if (user.email != null && user.email!.contains('@')) {
      return user.email!.split('@').first;
    }
    return 'User';
  }

  String get userEmail {
    return _supabase.auth.currentUser?.email ?? '';
  }

  /// Sign in with email and password.
  Future<AuthResponse> signInWithPassword({
    required String email,
    required String password,
  }) async {
    final cleanEmail = email.trim();
    if (cleanEmail.isEmpty || !cleanEmail.contains('@') || !cleanEmail.contains('.')) {
      throw Exception("Please enter a valid email address.");
    }
    if (password.isEmpty) {
      throw Exception("Password cannot be empty.");
    }

    try {
      final response = await _supabase.auth.signInWithPassword(
        email: cleanEmail,
        password: password,
      );
      return response;
    } on AuthException catch (e) {
      if (e.message.toLowerCase().contains("invalid login credentials")) {
        throw Exception("Invalid credentials. The email does not exist or the password is incorrect.");
      } else if (e.message.toLowerCase().contains("email not confirmed")) {
        throw Exception("Email not confirmed. Please enter the verification code sent to your email.");
      }
      throw Exception(e.message);
    } catch (e) {
      throw Exception("Authentication failed: ${e.toString().replaceFirst(RegExp(r'^Exception:\s*'), '')}");
    }
  }

  /// Sign up a new user account with display name and password.
  Future<AuthResponse> signUp({
    required String email,
    required String password,
    required String displayName,
  }) async {
    final cleanEmail = email.trim();
    final cleanName = displayName.trim();

    if (cleanName.isEmpty) {
      throw Exception("Please enter your display name.");
    }
    if (cleanEmail.isEmpty || !cleanEmail.contains('@') || !cleanEmail.contains('.')) {
      throw Exception("Please enter a valid email address.");
    }
    if (password.length < 6) {
      throw Exception("Password must be at least 6 characters long.");
    }

    try {
      final response = await _supabase.auth.signUp(
        email: cleanEmail,
        password: password,
        data: {
          'display_name': cleanName,
          'name': cleanName,
        },
        emailRedirectTo: defaultRedirectUrl,
      );
      return response;
    } on AuthException catch (e) {
      if (e.message.toLowerCase().contains("already registered")) {
        throw Exception("This email is already registered. Please sign in instead or reset your password.");
      }
      throw Exception(e.message);
    } catch (e) {
      throw Exception("Registration failed: ${e.toString().replaceFirst(RegExp(r'^Exception:\s*'), '')}");
    }
  }

  /// Send password recovery link / code to the user's email.
  Future<void> resetPasswordForEmail(String email) async {
    final cleanEmail = email.trim();
    if (cleanEmail.isEmpty || !cleanEmail.contains('@') || !cleanEmail.contains('.')) {
      throw Exception("Please enter a valid email address to reset password.");
    }

    try {
      await _supabase.auth.resetPasswordForEmail(
        cleanEmail,
        redirectTo: defaultRedirectUrl,
      );
    } on AuthException catch (e) {
      throw Exception(e.message);
    } catch (e) {
      throw Exception("Password reset failed: ${e.toString().replaceFirst(RegExp(r'^Exception:\s*'), '')}");
    }
  }

  /// Verify 6-digit OTP code (for signup confirmation or password recovery)
  Future<AuthResponse> verifyOTP({
    required String email,
    required String token,
    required OtpType type,
  }) async {
    final cleanEmail = email.trim();
    final cleanToken = token.trim();
    if (cleanEmail.isEmpty) throw Exception("Please enter your email address.");
    if (cleanToken.isEmpty) throw Exception("Please enter the 6-digit verification code.");

    try {
      final response = await _supabase.auth.verifyOTP(
        email: cleanEmail,
        token: cleanToken,
        type: type,
      );
      return response;
    } on AuthException catch (e) {
      if (e.message.toLowerCase().contains("expired") || e.message.toLowerCase().contains("invalid")) {
        throw Exception("Invalid or expired verification code. Please check your email or request a new code.");
      }
      throw Exception(e.message);
    } catch (e) {
      throw Exception("Verification failed: ${e.toString().replaceFirst(RegExp(r'^Exception:\s*'), '')}");
    }
  }

  /// Reset password directly using 6-digit recovery OTP code
  Future<void> resetPasswordWithOTP({
    required String email,
    required String token,
    required String newPassword,
  }) async {
    if (newPassword.length < 6) {
      throw Exception("New password must be at least 6 characters long.");
    }
    // 1. Verify recovery OTP
    await verifyOTP(
      email: email,
      token: token,
      type: OtpType.recovery,
    );
    // 2. Update to new password
    try {
      await _supabase.auth.updateUser(
        UserAttributes(password: newPassword),
      );
    } on AuthException catch (e) {
      throw Exception(e.message);
    } catch (e) {
      throw Exception("Failed to set new password: ${e.toString().replaceFirst(RegExp(r'^Exception:\s*'), '')}");
    }
  }

  /// Resend signup verification code
  Future<void> resendVerificationEmail(String email) async {
    final cleanEmail = email.trim();
    if (cleanEmail.isEmpty) throw Exception("Please enter your email address.");
    try {
      await _supabase.auth.resend(
        type: OtpType.signup,
        email: cleanEmail,
        emailRedirectTo: defaultRedirectUrl,
      );
    } on AuthException catch (e) {
      throw Exception(e.message);
    } catch (e) {
      throw Exception("Failed to resend code: ${e.toString().replaceFirst(RegExp(r'^Exception:\s*'), '')}");
    }
  }

  /// Change password by first verifying the current (previous) password, then updating to the new password.
  Future<void> changePassword({
    required String currentPassword,
    required String newPassword,
  }) async {
    final email = userEmail;
    if (email.isEmpty) {
      throw Exception("No authenticated user found.");
    }
    if (currentPassword.isEmpty) {
      throw Exception("Please enter your current password.");
    }
    if (newPassword.length < 6) {
      throw Exception("New password must be at least 6 characters long.");
    }
    if (currentPassword == newPassword) {
      throw Exception("New password must be different from your current password.");
    }

    // Step 1: Validate current password by re-authenticating
    try {
      await _supabase.auth.signInWithPassword(
        email: email,
        password: currentPassword,
      );
    } on AuthException catch (e) {
      if (e.message.toLowerCase().contains("invalid login credentials")) {
        throw Exception("Previous password is incorrect. Please enter your correct current password or use password recovery.");
      }
      throw Exception("Verification failed: ${e.message}");
    } catch (e) {
      throw Exception("Previous password is incorrect. Please try again or use the recovery link.");
    }

    // Step 2: Update password via Supabase Auth
    try {
      await _supabase.auth.updateUser(
        UserAttributes(password: newPassword),
      );
    } on AuthException catch (e) {
      throw Exception(e.message);
    } catch (e) {
      throw Exception("Failed to update password: ${e.toString().replaceFirst(RegExp(r'^Exception:\s*'), '')}");
    }
  }

  /// Update user profile details (such as display name).
  Future<void> updateProfile({required String displayName}) async {
    final cleanName = displayName.trim();
    if (cleanName.isEmpty) {
      throw Exception("Display name cannot be empty.");
    }
    try {
      await _supabase.auth.updateUser(
        UserAttributes(data: {'display_name': cleanName, 'name': cleanName}),
      );
    } on AuthException catch (e) {
      throw Exception(e.message);
    } catch (e) {
      throw Exception("Failed to update profile: ${e.toString().replaceFirst(RegExp(r'^Exception:\s*'), '')}");
    }
  }

  /// Sign out current user.
  Future<void> signOut() async {
    await _supabase.auth.signOut();
  }
}
