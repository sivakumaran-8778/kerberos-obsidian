import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:supabase_flutter/supabase_flutter.dart';

import '../../../shared/theme/cyber_theme.dart';
import '../../../shared/widgets/cyber_button.dart';
import '../../../shared/widgets/shards_background.dart';
import '../providers/auth_providers.dart';

enum AuthMode {
  signIn,
  signUp,
  verifyOtp,
  forgotPassword,
}

class AuthScreen extends ConsumerStatefulWidget {
  const AuthScreen({super.key});

  @override
  ConsumerState<AuthScreen> createState() => _AuthScreenState();
}

class _AuthScreenState extends ConsumerState<AuthScreen> {
  AuthMode _mode = AuthMode.signIn;
  bool _isLoading = false;
  bool _obscurePassword = true;
  bool _obscureConfirmPassword = true;
  String? _errorMessage;
  String? _successMessage;

  // Recovery & verification flow state
  bool _recoveryCodeSent = false;
  bool _showManualOtpInput = false;

  final TextEditingController _nameController = TextEditingController();
  final TextEditingController _emailController = TextEditingController();
  final TextEditingController _passwordController = TextEditingController();
  final TextEditingController _confirmPasswordController = TextEditingController();
  final TextEditingController _otpController = TextEditingController();
  final TextEditingController _newPasswordController = TextEditingController();

  @override
  void dispose() {
    _nameController.dispose();
    _emailController.dispose();
    _passwordController.dispose();
    _confirmPasswordController.dispose();
    _otpController.dispose();
    _newPasswordController.dispose();
    super.dispose();
  }

  void _switchMode(AuthMode mode) {
    setState(() {
      _mode = mode;
      _errorMessage = null;
      _successMessage = null;
      _recoveryCodeSent = false;
      _showManualOtpInput = false;
    });
  }

  Future<void> _submitSignIn() async {
    setState(() {
      _errorMessage = null;
      _successMessage = null;
      _isLoading = true;
    });

    final authService = ref.read(authServiceProvider);
    final email = _emailController.text.trim();
    final password = _passwordController.text;

    try {
      await authService.signInWithPassword(
        email: email,
        password: password,
      );
    } catch (e) {
      final error = e.toString().replaceFirst(RegExp(r'^Exception:\s*'), '');
      setState(() {
        _errorMessage = error;
      });
      // If email is not confirmed, offer OTP verification
      if (error.toLowerCase().contains('not confirmed') || error.toLowerCase().contains('verification code')) {
        setState(() {
          _mode = AuthMode.verifyOtp;
          _successMessage = 'Please enter the 6-digit verification code sent to your email.';
        });
      }
    } finally {
      if (mounted) {
        setState(() => _isLoading = false);
      }
    }
  }

  Future<void> _submitSignUp() async {
    setState(() {
      _errorMessage = null;
      _successMessage = null;
      _isLoading = true;
    });

    final authService = ref.read(authServiceProvider);
    final name = _nameController.text.trim();
    final email = _emailController.text.trim();
    final password = _passwordController.text;
    final confirmPassword = _confirmPasswordController.text;

    try {
      if (name.isEmpty) {
        throw Exception('Please enter your full name.');
      }
      if (password != confirmPassword) {
        throw Exception('Passwords do not match.');
      }
      if (password.length < 6) {
        throw Exception('Password must be at least 6 characters long.');
      }

      final response = await authService.signUp(
        email: email,
        password: password,
        displayName: name,
      );

      // Check if session was granted immediately or if email confirmation is required
      if (response.session != null) {
        setState(() {
          _successMessage = 'Account created successfully! Signing in...';
        });
      } else {
        // Email confirmation is required by Supabase
        setState(() {
          _mode = AuthMode.verifyOtp;
          _successMessage =
              'Confirmation email dispatched! Follow the link sent to $email, or enter your code below.';
        });
      }
    } catch (e) {
      setState(() {
        _errorMessage = e.toString().replaceFirst(RegExp(r'^Exception:\s*'), '');
      });
    } finally {
      if (mounted) {
        setState(() => _isLoading = false);
      }
    }
  }

  Future<void> _submitVerifyOtp() async {
    setState(() {
      _errorMessage = null;
      _successMessage = null;
      _isLoading = true;
    });

    final authService = ref.read(authServiceProvider);
    final email = _emailController.text.trim();
    final token = _otpController.text.trim();

    try {
      await authService.verifyOTP(
        email: email,
        token: token,
        type: OtpType.signup,
      );
      setState(() {
        _successMessage = 'Email verified successfully! Entering workspace...';
      });
    } catch (e) {
      setState(() {
        _errorMessage = e.toString().replaceFirst(RegExp(r'^Exception:\s*'), '');
      });
    } finally {
      if (mounted) {
        setState(() => _isLoading = false);
      }
    }
  }

  Future<void> _resendSignupCode() async {
    final email = _emailController.text.trim();
    if (email.isEmpty) {
      setState(() => _errorMessage = 'Please enter your email address first.');
      return;
    }

    setState(() {
      _errorMessage = null;
      _isLoading = true;
    });

    try {
      await ref.read(authServiceProvider).resendVerificationEmail(email);
      setState(() {
        _successMessage = 'A fresh confirmation email has been dispatched to $email.';
      });
    } catch (e) {
      setState(() {
        _errorMessage = e.toString().replaceFirst(RegExp(r'^Exception:\s*'), '');
      });
    } finally {
      if (mounted) {
        setState(() => _isLoading = false);
      }
    }
  }

  Future<void> _sendRecoveryCode() async {
    final email = _emailController.text.trim();
    if (email.isEmpty || !email.contains('@')) {
      setState(() => _errorMessage = 'Please enter a valid email address.');
      return;
    }

    setState(() {
      _errorMessage = null;
      _successMessage = null;
      _isLoading = true;
    });

    try {
      await ref.read(authServiceProvider).resetPasswordForEmail(email);
      setState(() {
        _recoveryCodeSent = true;
        _successMessage = 'Recovery code sent! Check your inbox for the 6-digit code or link, then set your new password below.';
      });
    } catch (e) {
      setState(() {
        _errorMessage = e.toString().replaceFirst(RegExp(r'^Exception:\s*'), '');
      });
    } finally {
      if (mounted) {
        setState(() => _isLoading = false);
      }
    }
  }

  Future<void> _submitResetPasswordWithOtp() async {
    final email = _emailController.text.trim();
    final code = _otpController.text.trim();
    final newPassword = _newPasswordController.text;

    if (code.isEmpty) {
      setState(() => _errorMessage = 'Please enter the 6-digit recovery code from your email.');
      return;
    }
    if (newPassword.length < 6) {
      setState(() => _errorMessage = 'New password must be at least 6 characters long.');
      return;
    }

    setState(() {
      _errorMessage = null;
      _successMessage = null;
      _isLoading = true;
    });

    try {
      await ref.read(authServiceProvider).resetPasswordWithOTP(
            email: email,
            token: code,
            newPassword: newPassword,
          );
      setState(() {
        _mode = AuthMode.signIn;
        _recoveryCodeSent = false;
        _passwordController.text = newPassword;
        _successMessage = 'Password updated successfully! You can now sign in with your new password.';
      });
    } catch (e) {
      setState(() {
        _errorMessage = e.toString().replaceFirst(RegExp(r'^Exception:\s*'), '');
      });
    } finally {
      if (mounted) {
        setState(() => _isLoading = false);
      }
    }
  }

  Widget _buildStepItem({required String step, required String text}) {
    return Row(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Container(
          width: 18,
          height: 18,
          decoration: BoxDecoration(
            color: const Color(0x35C084FC),
            shape: BoxShape.circle,
            border: Border.all(color: const Color(0x60C084FC), width: 1),
          ),
          child: Center(
            child: Text(
              step,
              style: GoogleFonts.jetBrainsMono(
                fontSize: 10,
                fontWeight: FontWeight.w800,
                color: Colors.white,
              ),
            ),
          ),
        ),
        const SizedBox(width: 10),
        Expanded(
          child: Text(
            text,
            style: GoogleFonts.plusJakartaSans(
              fontSize: 12,
              color: const Color(0xFFCBD5E1),
              height: 1.4,
            ),
          ),
        ),
      ],
    );
  }

  Widget _buildTextField({
    required TextEditingController controller,
    required String label,
    required String hintText,
    required IconData prefixIcon,
    bool obscureText = false,
    Widget? suffixIcon,
    TextInputType? keyboardType,
    int? maxLength,
    TextAlign textAlign = TextAlign.start,
    TextStyle? customStyle,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: GoogleFonts.plusJakartaSans(
            fontSize: 12,
            fontWeight: FontWeight.w700,
            color: const Color(0xFFE2E8F0),
            letterSpacing: 0.2,
          ),
        ),
        const SizedBox(height: 7),
        Container(
          decoration: BoxDecoration(
            color: const Color(0x12FFFFFF),
            borderRadius: BorderRadius.circular(14),
            border: Border.all(color: const Color(0x28FFFFFF), width: 1.0),
          ),
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 2),
          child: TextField(
            controller: controller,
            obscureText: obscureText,
            keyboardType: keyboardType,
            maxLength: maxLength,
            textAlign: textAlign,
            style: customStyle ??
                GoogleFonts.plusJakartaSans(
                  color: Colors.white,
                  fontSize: 13.5,
                  fontWeight: FontWeight.w500,
                ),
            decoration: InputDecoration(
              counterText: '',
              border: InputBorder.none,
              icon: Icon(prefixIcon, color: const Color(0xFF94A3B8), size: 19),
              hintText: hintText,
              hintStyle: GoogleFonts.plusJakartaSans(
                color: const Color(0xFF64748B),
                fontSize: 13,
              ),
              suffixIcon: suffixIcon,
            ),
          ),
        ),
      ],
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: CyberTheme.background,
      body: Stack(
        children: [
          // 1. 3D Prismatic Shards Interactive Background
          const Positioned.fill(
            child: ShardsBackground(),
          ),

          // 2. Central Industrial-Grade Auth Glass Container
          Center(
            child: SingleChildScrollView(
              padding: const EdgeInsets.symmetric(vertical: 48, horizontal: 20),
              child: ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 480),
                child: Container(
                  decoration: BoxDecoration(
                    color: const Color(0xF00F091C),
                    borderRadius: BorderRadius.circular(28),
                    border: Border.all(color: const Color(0x35FFFFFF), width: 1.2),
                    boxShadow: [
                      const BoxShadow(
                        color: Color(0x99000000),
                        blurRadius: 48,
                        offset: Offset(0, 20),
                      ),
                      BoxShadow(
                        color: CyberTheme.accentColor.withValues(alpha: 0.25),
                        blurRadius: 36,
                        spreadRadius: -4,
                      ),
                    ],
                  ),
                  child: ClipRRect(
                    borderRadius: BorderRadius.circular(28),
                    child: BackdropFilter(
                      filter: ImageFilter.blur(sigmaX: 24, sigmaY: 24),
                      child: Padding(
                        padding: const EdgeInsets.symmetric(horizontal: 36, vertical: 40),
                        child: Column(
                          mainAxisSize: MainAxisSize.min,
                          crossAxisAlignment: CrossAxisAlignment.stretch,
                          children: [
                            // Brand Badge Emblem & Header
                            Center(
                              child: Container(
                                width: 56,
                                height: 56,
                                decoration: BoxDecoration(
                                  shape: BoxShape.circle,
                                  gradient: CyberTheme.shardGradient,
                                  boxShadow: [
                                    BoxShadow(
                                      color: CyberTheme.accentColor.withValues(alpha: 0.45),
                                      blurRadius: 20,
                                      spreadRadius: 2,
                                    ),
                                  ],
                                ),
                                child: const Icon(
                                  Icons.all_inclusive_rounded,
                                  color: Colors.white,
                                  size: 30,
                                ),
                              ),
                            ),
                            const SizedBox(height: 16),
                            Center(
                              child: Text(
                                'OBSIDIAN PROTOCOL',
                                style: GoogleFonts.plusJakartaSans(
                                  fontSize: 22,
                                  fontWeight: FontWeight.w900,
                                  letterSpacing: 0.5,
                                  color: Colors.white,
                                ),
                              ),
                            ),
                            const SizedBox(height: 6),
                            Center(
                              child: Container(
                                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 3),
                                decoration: BoxDecoration(
                                  color: const Color(0x22C084FC),
                                  borderRadius: BorderRadius.circular(100),
                                  border: Border.all(color: CyberTheme.borderAccent),
                                ),
                                child: Text(
                                  'ZERO-TRUST DIGITAL PROVENANCE',
                                  style: GoogleFonts.jetBrainsMono(
                                    fontSize: 9.5,
                                    fontWeight: FontWeight.w800,
                                    letterSpacing: 1.0,
                                    color: const Color(0xFFE9D5FF),
                                  ),
                                ),
                              ),
                            ),
                            const SizedBox(height: 28),

                            // Segmented Switcher (Sign In vs Create Account)
                            if (_mode == AuthMode.signIn || _mode == AuthMode.signUp)
                              Container(
                                padding: const EdgeInsets.all(4),
                                decoration: BoxDecoration(
                                  color: const Color(0x12FFFFFF),
                                  borderRadius: BorderRadius.circular(100),
                                  border: Border.all(color: const Color(0x22FFFFFF)),
                                ),
                                child: Row(
                                  children: [
                                    Expanded(
                                      child: InkWell(
                                        borderRadius: BorderRadius.circular(100),
                                        onTap: () => _switchMode(AuthMode.signIn),
                                        child: AnimatedContainer(
                                          duration: const Duration(milliseconds: 200),
                                          curve: Curves.easeOutCubic,
                                          padding: const EdgeInsets.symmetric(vertical: 10),
                                          decoration: BoxDecoration(
                                            color: _mode == AuthMode.signIn
                                                ? const Color(0x2CFFFFFF)
                                                : Colors.transparent,
                                            borderRadius: BorderRadius.circular(100),
                                            border: _mode == AuthMode.signIn
                                                ? Border.all(color: const Color(0x55FFFFFF))
                                                : null,
                                            boxShadow: _mode == AuthMode.signIn
                                                ? const [
                                                    BoxShadow(
                                                      color: Color(0x20000000),
                                                      blurRadius: 6,
                                                    ),
                                                  ]
                                                : null,
                                          ),
                                          child: Center(
                                            child: Text(
                                              'Sign In',
                                              style: GoogleFonts.plusJakartaSans(
                                                fontSize: 13,
                                                fontWeight: _mode == AuthMode.signIn
                                                    ? FontWeight.w800
                                                    : FontWeight.w500,
                                                color: _mode == AuthMode.signIn
                                                    ? Colors.white
                                                    : const Color(0x88FFFFFF),
                                              ),
                                            ),
                                          ),
                                        ),
                                      ),
                                    ),
                                    Expanded(
                                      child: InkWell(
                                        borderRadius: BorderRadius.circular(100),
                                        onTap: () => _switchMode(AuthMode.signUp),
                                        child: AnimatedContainer(
                                          duration: const Duration(milliseconds: 200),
                                          curve: Curves.easeOutCubic,
                                          padding: const EdgeInsets.symmetric(vertical: 10),
                                          decoration: BoxDecoration(
                                            color: _mode == AuthMode.signUp
                                                ? const Color(0x2CFFFFFF)
                                                : Colors.transparent,
                                            borderRadius: BorderRadius.circular(100),
                                            border: _mode == AuthMode.signUp
                                                ? Border.all(color: const Color(0x55FFFFFF))
                                                : null,
                                            boxShadow: _mode == AuthMode.signUp
                                                ? const [
                                                    BoxShadow(
                                                      color: Color(0x20000000),
                                                      blurRadius: 6,
                                                    ),
                                                  ]
                                                : null,
                                          ),
                                          child: Center(
                                            child: Text(
                                              'Create Account',
                                              style: GoogleFonts.plusJakartaSans(
                                                fontSize: 13,
                                                fontWeight: _mode == AuthMode.signUp
                                                    ? FontWeight.w800
                                                    : FontWeight.w500,
                                                color: _mode == AuthMode.signUp
                                                    ? Colors.white
                                                    : const Color(0x88FFFFFF),
                                              ),
                                            ),
                                          ),
                                        ),
                                      ),
                                    ),
                                  ],
                                ),
                              ),

                            // Header for Verify Email Mode
                            if (_mode == AuthMode.verifyOtp) ...[
                              Row(
                                children: [
                                  IconButton(
                                    icon: const Icon(Icons.arrow_back_rounded, color: Colors.white, size: 20),
                                    onPressed: () => _switchMode(AuthMode.signIn),
                                    tooltip: 'Back to Sign In',
                                  ),
                                  const SizedBox(width: 6),
                                  Text(
                                    'Check Your Inbox',
                                    style: GoogleFonts.plusJakartaSans(
                                      fontSize: 17,
                                      fontWeight: FontWeight.w800,
                                      color: Colors.white,
                                    ),
                                  ),
                                ],
                              ),
                              const SizedBox(height: 6),
                              Text(
                                'A verification email has been dispatched by Supabase Auth to confirm your identity.',
                                style: GoogleFonts.plusJakartaSans(
                                  fontSize: 12.5,
                                  color: CyberTheme.textSecondary,
                                  height: 1.5,
                                ),
                              ),
                            ],

                            // Header for Forgot Password Mode
                            if (_mode == AuthMode.forgotPassword) ...[
                              Row(
                                children: [
                                  IconButton(
                                    icon: const Icon(Icons.arrow_back_rounded, color: Colors.white, size: 20),
                                    onPressed: () => _switchMode(AuthMode.signIn),
                                    tooltip: 'Back to Sign In',
                                  ),
                                  const SizedBox(width: 6),
                                  Text(
                                    'Password Recovery',
                                    style: GoogleFonts.plusJakartaSans(
                                      fontSize: 17,
                                      fontWeight: FontWeight.w800,
                                      color: Colors.white,
                                    ),
                                  ),
                                ],
                              ),
                              const SizedBox(height: 6),
                              Text(
                                _recoveryCodeSent
                                    ? 'Enter the 6-digit recovery code from your email and your new password.'
                                    : 'Enter your account email. We will send a 6-digit code and secure recovery link.',
                                style: GoogleFonts.plusJakartaSans(
                                  fontSize: 12.5,
                                  color: CyberTheme.textSecondary,
                                  height: 1.5,
                                ),
                              ),
                            ],

                            const SizedBox(height: 24),

                            // Mode-Specific Form Fields
                            if (_mode == AuthMode.signUp) ...[
                              _buildTextField(
                                controller: _nameController,
                                label: 'Full Name',
                                hintText: 'Enter your name or alias',
                                prefixIcon: Icons.badge_outlined,
                              ),
                              const SizedBox(height: 16),
                            ],

                            if (_mode == AuthMode.signIn || _mode == AuthMode.signUp || _mode == AuthMode.forgotPassword) ...[
                              _buildTextField(
                                controller: _emailController,
                                label: 'Email Address',
                                hintText: 'name@example.com',
                                prefixIcon: Icons.email_outlined,
                                keyboardType: TextInputType.emailAddress,
                              ),
                              const SizedBox(height: 16),
                            ],

                            if (_mode == AuthMode.signIn || _mode == AuthMode.signUp) ...[
                              _buildTextField(
                                controller: _passwordController,
                                label: 'Password',
                                hintText: _mode == AuthMode.signUp ? 'Minimum 6 characters' : 'Enter your password',
                                prefixIcon: Icons.lock_outline,
                                obscureText: _obscurePassword,
                                suffixIcon: IconButton(
                                  icon: Icon(
                                    _obscurePassword ? Icons.visibility_off_outlined : Icons.visibility_outlined,
                                    color: const Color(0xFF94A3B8),
                                    size: 18,
                                  ),
                                  onPressed: () => setState(() => _obscurePassword = !_obscurePassword),
                                ),
                              ),
                            ],

                            if (_mode == AuthMode.signUp) ...[
                              const SizedBox(height: 16),
                              _buildTextField(
                                controller: _confirmPasswordController,
                                label: 'Confirm Password',
                                hintText: 'Re-enter your password',
                                prefixIcon: Icons.lock_clock_outlined,
                                obscureText: _obscureConfirmPassword,
                                suffixIcon: IconButton(
                                  icon: Icon(
                                    _obscureConfirmPassword ? Icons.visibility_off_outlined : Icons.visibility_outlined,
                                    color: const Color(0xFF94A3B8),
                                    size: 18,
                                  ),
                                  onPressed: () => setState(() => _obscureConfirmPassword = !_obscureConfirmPassword),
                                ),
                              ),
                            ],

                            // Forgot Password Link on Sign In
                            if (_mode == AuthMode.signIn) ...[
                              const SizedBox(height: 10),
                              Row(
                                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                                children: [
                                  TextButton(
                                    onPressed: () => _switchMode(AuthMode.verifyOtp),
                                    style: TextButton.styleFrom(
                                      padding: EdgeInsets.zero,
                                      minimumSize: Size.zero,
                                      tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                                    ),
                                    child: Text(
                                      'Have a verification code?',
                                      style: GoogleFonts.plusJakartaSans(
                                        fontSize: 12,
                                        color: CyberTheme.textSecondary,
                                        fontWeight: FontWeight.w500,
                                      ),
                                    ),
                                  ),
                                  TextButton(
                                    onPressed: () => _switchMode(AuthMode.forgotPassword),
                                    style: TextButton.styleFrom(
                                      padding: EdgeInsets.zero,
                                      minimumSize: Size.zero,
                                      tapTargetSize: MaterialTapTargetSize.shrinkWrap,
                                    ),
                                    child: Text(
                                      'Forgot Password?',
                                      style: GoogleFonts.plusJakartaSans(
                                        fontSize: 12,
                                        color: const Color(0xFFC084FC),
                                        fontWeight: FontWeight.w700,
                                      ),
                                    ),
                                  ),
                                ],
                              ),
                            ],

                            // Email Confirmation & Verification Status
                            if (_mode == AuthMode.verifyOtp) ...[
                              Container(
                                padding: const EdgeInsets.all(16),
                                decoration: BoxDecoration(
                                  color: const Color(0x18C084FC),
                                  borderRadius: BorderRadius.circular(16),
                                  border: Border.all(color: const Color(0x35C084FC)),
                                ),
                                child: Column(
                                  crossAxisAlignment: CrossAxisAlignment.start,
                                  children: [
                                    Row(
                                      children: [
                                        Container(
                                          padding: const EdgeInsets.all(8),
                                          decoration: BoxDecoration(
                                            color: const Color(0x25C084FC),
                                            borderRadius: BorderRadius.circular(10),
                                          ),
                                          child: const Icon(Icons.mark_email_read_outlined, color: Color(0xFFC084FC), size: 20),
                                        ),
                                        const SizedBox(width: 12),
                                        Expanded(
                                          child: Column(
                                            crossAxisAlignment: CrossAxisAlignment.start,
                                            children: [
                                              Text(
                                                'Confirmation Link Sent',
                                                style: GoogleFonts.plusJakartaSans(
                                                  fontSize: 13.5,
                                                  fontWeight: FontWeight.w800,
                                                  color: Colors.white,
                                                ),
                                              ),
                                              const SizedBox(height: 2),
                                              Text(
                                                _emailController.text.isNotEmpty ? _emailController.text : 'your email',
                                                style: GoogleFonts.jetBrainsMono(
                                                  fontSize: 11.5,
                                                  color: const Color(0xFFE9D5FF),
                                                ),
                                                overflow: TextOverflow.ellipsis,
                                              ),
                                            ],
                                          ),
                                        ),
                                      ],
                                    ),
                                    const SizedBox(height: 14),
                                    Container(
                                      height: 1,
                                      color: Colors.white.withValues(alpha: 0.08),
                                    ),
                                    const SizedBox(height: 12),
                                    _buildStepItem(
                                      step: '1',
                                      text: 'Open the email from Supabase Auth in your inbox.',
                                    ),
                                    const SizedBox(height: 8),
                                    _buildStepItem(
                                      step: '2',
                                      text: 'Click the "Confirm email address" link.',
                                    ),
                                    const SizedBox(height: 8),
                                    _buildStepItem(
                                      step: '3',
                                      text: 'Return here and click "I\'ve Confirmed My Email" below.',
                                    ),
                                  ],
                                ),
                              ),
                              const SizedBox(height: 10),
                              Row(
                                mainAxisAlignment: MainAxisAlignment.spaceBetween,
                                children: [
                                  TextButton.icon(
                                    onPressed: _isLoading ? null : _resendSignupCode,
                                    icon: const Icon(Icons.refresh_rounded, size: 14, color: Color(0xFFC084FC)),
                                    label: Text(
                                      'Resend link',
                                      style: GoogleFonts.plusJakartaSans(
                                        fontSize: 12,
                                        color: const Color(0xFFC084FC),
                                        fontWeight: FontWeight.w700,
                                      ),
                                    ),
                                  ),
                                  TextButton(
                                    onPressed: () => setState(() => _showManualOtpInput = !_showManualOtpInput),
                                    child: Text(
                                      _showManualOtpInput ? 'Hide code input' : 'Have a 6-digit code?',
                                      style: GoogleFonts.plusJakartaSans(
                                        fontSize: 12,
                                        color: CyberTheme.textSecondary,
                                        fontWeight: FontWeight.w600,
                                      ),
                                    ),
                                  ),
                                ],
                              ),
                              if (_showManualOtpInput) ...[
                                const SizedBox(height: 8),
                                _buildTextField(
                                  controller: _otpController,
                                  label: '6-Digit Verification Code',
                                  hintText: '123456',
                                  prefixIcon: Icons.pin_outlined,
                                  keyboardType: TextInputType.number,
                                  maxLength: 6,
                                  textAlign: TextAlign.center,
                                  customStyle: GoogleFonts.jetBrainsMono(
                                    fontSize: 22,
                                    fontWeight: FontWeight.w800,
                                    letterSpacing: 8.0,
                                    color: Colors.white,
                                  ),
                                ),
                              ],
                            ],

                            // Forgot Password Recovery Step 2 Fields
                            if (_mode == AuthMode.forgotPassword && _recoveryCodeSent) ...[
                              _buildTextField(
                                controller: _otpController,
                                label: '6-Digit Recovery Code',
                                hintText: '123456',
                                prefixIcon: Icons.pin_outlined,
                                keyboardType: TextInputType.number,
                                maxLength: 6,
                                textAlign: TextAlign.center,
                                customStyle: GoogleFonts.jetBrainsMono(
                                  fontSize: 20,
                                  fontWeight: FontWeight.w800,
                                  letterSpacing: 6.0,
                                  color: Colors.white,
                                ),
                              ),
                              const SizedBox(height: 16),
                              _buildTextField(
                                controller: _newPasswordController,
                                label: 'New Password',
                                hintText: 'Minimum 6 characters',
                                prefixIcon: Icons.lock_outline,
                                obscureText: _obscurePassword,
                                suffixIcon: IconButton(
                                  icon: Icon(
                                    _obscurePassword ? Icons.visibility_off_outlined : Icons.visibility_outlined,
                                    color: const Color(0xFF94A3B8),
                                    size: 18,
                                  ),
                                  onPressed: () => setState(() => _obscurePassword = !_obscurePassword),
                                ),
                              ),
                            ],

                            // Error Message Banner
                            if (_errorMessage != null) ...[
                              const SizedBox(height: 18),
                              Container(
                                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 11),
                                decoration: BoxDecoration(
                                  color: const Color(0x1EFF5252),
                                  borderRadius: BorderRadius.circular(12),
                                  border: Border.all(color: const Color(0x50FF5252)),
                                ),
                                child: Row(
                                  children: [
                                    const Icon(Icons.error_outline_rounded, color: Color(0xFFFF6B6B), size: 18),
                                    const SizedBox(width: 10),
                                    Expanded(
                                      child: Text(
                                        _errorMessage!,
                                        style: GoogleFonts.plusJakartaSans(
                                          color: const Color(0xFFFF9999),
                                          fontSize: 12,
                                          fontWeight: FontWeight.w600,
                                        ),
                                      ),
                                    ),
                                  ],
                                ),
                              ),
                            ],

                            // Success Message Banner
                            if (_successMessage != null) ...[
                              const SizedBox(height: 18),
                              Container(
                                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 11),
                                decoration: BoxDecoration(
                                  color: const Color(0x1E34D399),
                                  borderRadius: BorderRadius.circular(12),
                                  border: Border.all(color: const Color(0x4034D399)),
                                ),
                                child: Row(
                                  children: [
                                    const Icon(Icons.check_circle_outline_rounded, color: Color(0xFF34D399), size: 18),
                                    const SizedBox(width: 10),
                                    Expanded(
                                      child: Text(
                                        _successMessage!,
                                        style: GoogleFonts.plusJakartaSans(
                                          color: const Color(0xFF6EE7B7),
                                          fontSize: 12,
                                          fontWeight: FontWeight.w600,
                                        ),
                                      ),
                                    ),
                                  ],
                                ),
                              ),
                            ],

                            const SizedBox(height: 26),

                            // Primary Action Button (with hover pop effect)
                            if (_mode == AuthMode.signIn)
                              CyberButton(
                                isExpanded: true,
                                variant: CyberButtonVariant.whitePill,
                                height: 48,
                                isLoading: _isLoading,
                                onTap: _submitSignIn,
                                child: Text(
                                  'Sign In',
                                  style: GoogleFonts.plusJakartaSans(
                                    fontSize: 14,
                                    fontWeight: FontWeight.w800,
                                  ),
                                ),
                              ),

                            if (_mode == AuthMode.signUp)
                              CyberButton(
                                isExpanded: true,
                                variant: CyberButtonVariant.whitePill,
                                height: 48,
                                isLoading: _isLoading,
                                onTap: _submitSignUp,
                                child: Text(
                                  'Create Account',
                                  style: GoogleFonts.plusJakartaSans(
                                    fontSize: 14,
                                    fontWeight: FontWeight.w800,
                                  ),
                                ),
                              ),

                            if (_mode == AuthMode.verifyOtp) ...[
                              CyberButton(
                                isExpanded: true,
                                variant: CyberButtonVariant.whitePill,
                                height: 48,
                                isLoading: _isLoading,
                                onTap: _submitSignIn,
                                child: Text(
                                  "I've Confirmed My Email — Sign In",
                                  style: GoogleFonts.plusJakartaSans(
                                    fontSize: 14,
                                    fontWeight: FontWeight.w800,
                                  ),
                                ),
                              ),
                              if (_showManualOtpInput) ...[
                                const SizedBox(height: 10),
                                CyberButton(
                                  isExpanded: true,
                                  variant: CyberButtonVariant.purple,
                                  height: 44,
                                  isLoading: _isLoading,
                                  onTap: _submitVerifyOtp,
                                  child: Text(
                                    'Verify 6-Digit Code',
                                    style: GoogleFonts.plusJakartaSans(
                                      fontSize: 13.5,
                                      fontWeight: FontWeight.w700,
                                    ),
                                  ),
                                ),
                              ],
                            ],

                            if (_mode == AuthMode.forgotPassword)
                              CyberButton(
                                isExpanded: true,
                                variant: CyberButtonVariant.whitePill,
                                height: 48,
                                isLoading: _isLoading,
                                onTap: _recoveryCodeSent ? _submitResetPasswordWithOtp : _sendRecoveryCode,
                                child: Text(
                                  _recoveryCodeSent ? 'Save New Password' : 'Send Recovery Code',
                                  style: GoogleFonts.plusJakartaSans(
                                    fontSize: 14,
                                    fontWeight: FontWeight.w800,
                                  ),
                                ),
                              ),
                          ],
                        ),
                      ),
                    ),
                  ),
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
