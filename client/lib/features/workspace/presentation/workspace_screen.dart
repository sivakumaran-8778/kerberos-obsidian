import 'dart:ui';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:desktop_drop/desktop_drop.dart';
import 'package:file_picker/file_picker.dart';
import 'package:cross_file/cross_file.dart';
import 'package:google_fonts/google_fonts.dart';

import '../../../shared/theme/cyber_theme.dart';
import '../../../shared/widgets/glass_container.dart';
import '../../../shared/widgets/cyber_button.dart';
import '../../../shared/widgets/shards_background.dart';
import '../../auth/providers/auth_providers.dart';
import '../../provenance/providers/provenance_providers.dart';
import '../../network/providers/network_providers.dart';
import '../../../main.dart'; // for ledgerProvider
import '../../verification/presentation/verification_page.dart';
import '../../radar/presentation/radar_page.dart';
import '../../radar/providers/radar_providers.dart';
import '../../radar/services/p2p_session_service.dart';
import '../../radar/models/radar_models.dart';

enum ActiveDeckModal {
  none,
  studio,
  verify,
  radar,
  ledger,
  profile,
}

class WorkspaceScreen extends ConsumerStatefulWidget {
  const WorkspaceScreen({super.key});

  @override
  ConsumerState<WorkspaceScreen> createState() => _WorkspaceScreenState();
}

class _WorkspaceScreenState extends ConsumerState<WorkspaceScreen> with SingleTickerProviderStateMixin {
  final ScrollController _scrollController = ScrollController();
  bool _isDragging = false;
  ActiveDeckModal _activeModal = ActiveDeckModal.none;
  late AnimationController _pulseController;

  // User Profile dedicated page controllers & state
  final TextEditingController _profileDisplayNameController = TextEditingController();
  final TextEditingController _currentPasswordController = TextEditingController();
  final TextEditingController _newPasswordController = TextEditingController();
  final TextEditingController _confirmPasswordController = TextEditingController();
  bool _showCurrentPassword = false;
  bool _showNewPassword = false;
  bool _showConfirmPassword = false;
  bool _isUpdatingPassword = false;
  bool _isUpdatingName = false;
  bool _isSendingPasswordReset = false;
  String? _profileStatusMessage;
  bool _isProfileSuccessMessage = false;
  bool _nameInitialized = false;

  @override
  void initState() {
    super.initState();
    _pulseController = AnimationController(
      vsync: this,
      duration: const Duration(seconds: 2),
    )..repeat(reverse: true);
  }

  @override
  void dispose() {
    _scrollController.dispose();
    _pulseController.dispose();
    _profileDisplayNameController.dispose();
    _currentPasswordController.dispose();
    _newPasswordController.dispose();
    _confirmPasswordController.dispose();
    super.dispose();
  }

  Future<void> _navigateToPage(int index) async {
    // Persistent P2P Session: Navigating to other pages (Verify, Studio, Ledger, Home)
    // keeps the active connection alive in the background.
    // The session only ends at both ends when either user clicks 'End Session'.
    if (_activeModal == ActiveDeckModal.radar && index != 3) {
      final sessionService = ref.read(p2pSessionServiceProvider);
      if (sessionService.sessionState != P2PSessionState.connected) {
        ref.read(signalingServiceProvider).setInRadar(false);
      }
    } else if (index == 3) {
      ref.read(signalingServiceProvider).setInRadar(true);
    }

    setState(() {
      switch (index) {
        case 0:
          _activeModal = ActiveDeckModal.none;
          break;
        case 1:
          _activeModal = ActiveDeckModal.studio;
          break;
        case 2:
          _activeModal = ActiveDeckModal.verify;
          break;
        case 3:
          _activeModal = ActiveDeckModal.radar;
          break;
        case 4:
          _activeModal = ActiveDeckModal.ledger;
          break;
        case 5:
          _activeModal = ActiveDeckModal.profile;
          break;
      }
    });
  }

  Future<void> _confirmSignOut() async {
    final confirm = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: CyberTheme.surfaceElevated,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(18),
          side: const BorderSide(color: CyberTheme.borderAccent),
        ),
        title: Text(
          'Sign Out?',
          style: GoogleFonts.plusJakartaSans(
            color: CyberTheme.textPrimary,
            fontWeight: FontWeight.w800,
          ),
        ),
        content: Text(
          'Are you sure you want to sign out of your account?',
          style: GoogleFonts.plusJakartaSans(color: CyberTheme.textSecondary),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx, false),
            child: Text(
              'CANCEL',
              style: GoogleFonts.plusJakartaSans(color: CyberTheme.textMuted),
            ),
          ),
          TextButton(
            onPressed: () => Navigator.pop(ctx, true),
            child: Text(
              'SIGN OUT',
              style: GoogleFonts.plusJakartaSans(
                color: CyberTheme.coral,
                fontWeight: FontWeight.w800,
              ),
            ),
          ),
        ],
      ),
    );
    if (confirm == true) {
      await ref.read(authServiceProvider).signOut();
    }
  }

  Widget _buildPasswordInput({
    required TextEditingController controller,
    required String label,
    required String hint,
    required bool isObscured,
    required VoidCallback onToggleVisibility,
  }) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Text(
          label,
          style: GoogleFonts.plusJakartaSans(
            fontSize: 12,
            fontWeight: FontWeight.w700,
            color: CyberTheme.textPrimary,
          ),
        ),
        const SizedBox(height: 6),
        Container(
          decoration: BoxDecoration(
            color: const Color(0x14FFFFFF),
            borderRadius: BorderRadius.circular(12),
            border: Border.all(color: const Color(0x28FFFFFF)),
          ),
          child: TextField(
            controller: controller,
            obscureText: isObscured,
            style: GoogleFonts.plusJakartaSans(fontSize: 13, color: Colors.white),
            decoration: InputDecoration(
              hintText: hint,
              hintStyle: GoogleFonts.plusJakartaSans(fontSize: 12.5, color: CyberTheme.textMuted),
              border: InputBorder.none,
              contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
              suffixIcon: IconButton(
                icon: Icon(
                  isObscured ? Icons.visibility_off_outlined : Icons.visibility_outlined,
                  size: 18,
                  color: CyberTheme.textMuted,
                ),
                onPressed: onToggleVisibility,
              ),
            ),
          ),
        ),
      ],
    );
  }

  // ==========================================
  // DEDICATED USER PROFILE PAGE
  // ==========================================
  Widget _buildUserProfilePage(UserProfile profile) {
    if (!_nameInitialized && profile.displayName.isNotEmpty) {
      _profileDisplayNameController.text = profile.displayName;
      _nameInitialized = true;
    }

    return SingleChildScrollView(
      padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 28),
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 1060),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              // Top Breadcrumb / Return to Home
              InkWell(
                onTap: () => _navigateToPage(0),
                borderRadius: BorderRadius.circular(100),
                child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      const Icon(Icons.arrow_back_rounded, color: Color(0xFFC084FC), size: 18),
                      const SizedBox(width: 8),
                      Text(
                        'Back to Home',
                        style: GoogleFonts.plusJakartaSans(
                          fontSize: 13,
                          fontWeight: FontWeight.w700,
                          color: const Color(0xFFC084FC),
                        ),
                      ),
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 16),

              // Page Title & Subtitle
              Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Text(
                    'User Profile',
                    style: GoogleFonts.plusJakartaSans(
                      fontSize: 32,
                      fontWeight: FontWeight.w900,
                      color: Colors.white,
                      letterSpacing: -0.5,
                    ),
                  ),
                  const SizedBox(height: 6),
                  Text(
                    'Manage your personal information, security settings, and credentials.',
                    style: GoogleFonts.plusJakartaSans(
                      fontSize: 14,
                      color: CyberTheme.textSecondary,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 28),

              // Responsive Two-Column Profile Layout
              LayoutBuilder(
                builder: (context, constraints) {
                  final isWide = constraints.maxWidth >= 840;

                  final leftCard = _buildProfileIdentityCard(profile);
                  final rightCards = Column(
                    crossAxisAlignment: CrossAxisAlignment.stretch,
                    children: [
                      _buildPersonalInfoCard(profile),
                      const SizedBox(height: 20),
                      _buildPasswordSecurityCard(profile),
                    ],
                  );

                  if (isWide) {
                    return Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        SizedBox(width: 340, child: leftCard),
                        const SizedBox(width: 24),
                        Expanded(child: rightCards),
                      ],
                    );
                  } else {
                    return Column(
                      children: [
                        leftCard,
                        const SizedBox(height: 20),
                        rightCards,
                      ],
                    );
                  }
                },
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildProfileIdentityCard(UserProfile profile) {
    return Container(
      padding: const EdgeInsets.all(26),
      decoration: BoxDecoration(
        color: const Color(0xF0120B22),
        borderRadius: BorderRadius.circular(24),
        border: Border.all(color: const Color(0x30FFFFFF), width: 1.2),
        boxShadow: const [
          BoxShadow(
            color: Color(0x66000000),
            blurRadius: 32,
            offset: Offset(0, 12),
          ),
        ],
      ),
      child: Column(
        children: [
          // Large Glowing Initials Avatar
          Container(
            width: 82,
            height: 82,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              gradient: const LinearGradient(
                colors: [Color(0xFFC084FC), Color(0xFF7C3AED)],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              ),
              boxShadow: [
                BoxShadow(
                  color: CyberTheme.accentColor.withValues(alpha: 0.45),
                  blurRadius: 20,
                  spreadRadius: 2,
                ),
              ],
            ),
            padding: const EdgeInsets.all(3),
            child: Container(
              decoration: const BoxDecoration(
                shape: BoxShape.circle,
                color: Color(0xFF140C28),
              ),
              child: Center(
                child: Text(
                  profile.initials,
                  style: GoogleFonts.plusJakartaSans(
                    fontSize: 26,
                    fontWeight: FontWeight.w900,
                    color: const Color(0xFFE9D5FF),
                  ),
                ),
              ),
            ),
          ),
          const SizedBox(height: 18),

          // User Name & Email
          Text(
            profile.displayName,
            style: GoogleFonts.plusJakartaSans(
              fontSize: 19,
              fontWeight: FontWeight.w800,
              color: Colors.white,
            ),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 4),
          Text(
            profile.email,
            style: GoogleFonts.plusJakartaSans(
              fontSize: 13,
              color: CyberTheme.textSecondary,
            ),
            textAlign: TextAlign.center,
          ),
          const SizedBox(height: 14),

          // Verified Account Status Badge
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
            decoration: BoxDecoration(
              color: const Color(0x1E34D399),
              borderRadius: BorderRadius.circular(100),
              border: Border.all(color: const Color(0x4034D399)),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                const Icon(Icons.verified_rounded, size: 13, color: Color(0xFF34D399)),
                const SizedBox(width: 6),
                Text(
                  'Verified Account',
                  style: GoogleFonts.plusJakartaSans(
                    fontSize: 11,
                    fontWeight: FontWeight.w700,
                    color: const Color(0xFF34D399),
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),
          const Divider(color: Color(0x22FFFFFF), thickness: 1),
          const SizedBox(height: 16),

          // Account ID Card
          Container(
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: const Color(0x10FFFFFF),
              borderRadius: BorderRadius.circular(14),
              border: Border.all(color: const Color(0x20FFFFFF)),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(
                  'Account ID',
                  style: GoogleFonts.plusJakartaSans(
                    fontSize: 11,
                    fontWeight: FontWeight.w700,
                    color: const Color(0xFF94A3B8),
                  ),
                ),
                const SizedBox(height: 6),
                Row(
                  children: [
                    Expanded(
                      child: Text(
                        profile.id.isNotEmpty
                            ? (profile.id.length > 20 ? '${profile.id.substring(0, 18)}...' : profile.id)
                            : 'active-session',
                        style: GoogleFonts.jetBrainsMono(
                          fontSize: 11.5,
                          color: const Color(0xFFE2E8F0),
                        ),
                      ),
                    ),
                    IconButton(
                      icon: const Icon(Icons.copy_rounded, size: 15, color: Color(0xFFC084FC)),
                      tooltip: 'Copy Account ID',
                      onPressed: () {
                        Clipboard.setData(ClipboardData(text: profile.id));
                        ScaffoldMessenger.of(context).showSnackBar(
                          SnackBar(
                            content: Text(
                              'Account ID copied to clipboard',
                              style: GoogleFonts.plusJakartaSans(fontSize: 13),
                            ),
                            backgroundColor: CyberTheme.surfaceElevated,
                            duration: const Duration(seconds: 2),
                          ),
                        );
                      },
                    ),
                  ],
                ),
              ],
            ),
          ),
          const SizedBox(height: 24),

          // Sign Out Action Button
          CyberButton(
            variant: CyberButtonVariant.danger,
            isExpanded: true,
            height: 40,
            icon: Icons.logout_rounded,
            onTap: _confirmSignOut,
            child: const Text('Sign Out'),
          ),
        ],
      ),
    );
  }

  Widget _buildPersonalInfoCard(UserProfile profile) {
    return Container(
      padding: const EdgeInsets.all(26),
      decoration: BoxDecoration(
        color: const Color(0xF0120B22),
        borderRadius: BorderRadius.circular(24),
        border: Border.all(color: const Color(0x30FFFFFF), width: 1.2),
        boxShadow: const [
          BoxShadow(
            color: Color(0x66000000),
            blurRadius: 32,
            offset: Offset(0, 12),
          ),
        ],
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
                  border: Border.all(color: CyberTheme.borderAccent),
                ),
                child: const Icon(Icons.person_outline_rounded, color: Color(0xFFC084FC), size: 18),
              ),
              const SizedBox(width: 12),
              Text(
                'Personal Information',
                style: GoogleFonts.plusJakartaSans(
                  fontSize: 17,
                  fontWeight: FontWeight.w800,
                  color: Colors.white,
                ),
              ),
            ],
          ),
          const SizedBox(height: 20),

          // Display Name Field with Save button
          Row(
            crossAxisAlignment: CrossAxisAlignment.end,
            children: [
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Display Name',
                      style: GoogleFonts.plusJakartaSans(
                        fontSize: 12,
                        fontWeight: FontWeight.w700,
                        color: const Color(0xFFE2E8F0),
                      ),
                    ),
                    const SizedBox(height: 7),
                    Container(
                      decoration: BoxDecoration(
                        color: const Color(0x12FFFFFF),
                        borderRadius: BorderRadius.circular(12),
                        border: Border.all(color: const Color(0x28FFFFFF)),
                      ),
                      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 2),
                      child: TextField(
                        controller: _profileDisplayNameController,
                        style: GoogleFonts.plusJakartaSans(fontSize: 13.5, color: Colors.white),
                        decoration: const InputDecoration(
                          border: InputBorder.none,
                          hintText: 'Enter your name',
                        ),
                      ),
                    ),
                  ],
                ),
              ),
              const SizedBox(width: 14),
              CyberButton(
                variant: CyberButtonVariant.whitePill,
                height: 42,
                isLoading: _isUpdatingName,
                onTap: () async {
                  final newName = _profileDisplayNameController.text.trim();
                  if (newName.isEmpty) return;
                  setState(() => _isUpdatingName = true);
                  try {
                    await ref.read(authServiceProvider).updateProfile(displayName: newName);
                    if (mounted) {
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(
                          content: Text('Profile name updated!', style: GoogleFonts.plusJakartaSans()),
                          backgroundColor: CyberTheme.emerald,
                        ),
                      );
                    }
                  } catch (e) {
                    if (mounted) {
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(
                          content: Text(e.toString().replaceFirst(RegExp(r'^Exception:\s*'), '')),
                          backgroundColor: CyberTheme.coral,
                        ),
                      );
                    }
                  } finally {
                    if (mounted) setState(() => _isUpdatingName = false);
                  }
                },
                child: const Text('Save Name'),
              ),
            ],
          ),
          const SizedBox(height: 16),

          // Email Field (Read Only)
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(
                'Email Address',
                style: GoogleFonts.plusJakartaSans(
                  fontSize: 12,
                  fontWeight: FontWeight.w700,
                  color: const Color(0xFFE2E8F0),
                ),
              ),
              const SizedBox(height: 7),
              Container(
                width: double.infinity,
                decoration: BoxDecoration(
                  color: const Color(0x0AFFFFFF),
                  borderRadius: BorderRadius.circular(12),
                  border: Border.all(color: const Color(0x18FFFFFF)),
                ),
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                child: Row(
                  children: [
                    const Icon(Icons.email_outlined, color: Color(0xFF64748B), size: 18),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(
                        profile.email,
                        style: GoogleFonts.plusJakartaSans(fontSize: 13, color: const Color(0xFF94A3B8)),
                      ),
                    ),
                    const Icon(Icons.lock_outline_rounded, color: Color(0xFF64748B), size: 16),
                  ],
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildPasswordSecurityCard(UserProfile profile) {
    return Container(
      padding: const EdgeInsets.all(26),
      decoration: BoxDecoration(
        color: const Color(0xF0120B22),
        borderRadius: BorderRadius.circular(24),
        border: Border.all(color: const Color(0x30FFFFFF), width: 1.2),
        boxShadow: const [
          BoxShadow(
            color: Color(0x66000000),
            blurRadius: 32,
            offset: Offset(0, 12),
          ),
        ],
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
                  border: Border.all(color: CyberTheme.borderAccent),
                ),
                child: const Icon(Icons.lock_reset_rounded, color: Color(0xFFC084FC), size: 18),
              ),
              const SizedBox(width: 12),
              Text(
                'Change Password',
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
            'To change your password, verify your identity by entering your current password first.',
            style: GoogleFonts.plusJakartaSans(
              fontSize: 12.5,
              color: CyberTheme.textSecondary,
            ),
          ),
          const SizedBox(height: 20),

          // Current Password
          _buildPasswordInput(
            controller: _currentPasswordController,
            label: 'Current Password',
            hint: 'Enter your existing password',
            isObscured: !_showCurrentPassword,
            onToggleVisibility: () => setState(() => _showCurrentPassword = !_showCurrentPassword),
          ),
          const SizedBox(height: 14),

          // New Password
          _buildPasswordInput(
            controller: _newPasswordController,
            label: 'New Password',
            hint: 'Minimum 6 characters',
            isObscured: !_showNewPassword,
            onToggleVisibility: () => setState(() => _showNewPassword = !_showNewPassword),
          ),
          const SizedBox(height: 14),

          // Confirm New Password
          _buildPasswordInput(
            controller: _confirmPasswordController,
            label: 'Confirm New Password',
            hint: 'Re-enter your new password',
            isObscured: !_showConfirmPassword,
            onToggleVisibility: () => setState(() => _showConfirmPassword = !_showConfirmPassword),
          ),
          const SizedBox(height: 16),

          // Status message display
          if (_profileStatusMessage != null)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
              margin: const EdgeInsets.only(bottom: 16),
              decoration: BoxDecoration(
                color: _isProfileSuccessMessage ? const Color(0x1E34D399) : const Color(0x1EFF5252),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(
                  color: _isProfileSuccessMessage ? const Color(0x4034D399) : const Color(0x50FF5252),
                ),
              ),
              child: Row(
                children: [
                  Icon(
                    _isProfileSuccessMessage ? Icons.check_circle_outline_rounded : Icons.error_outline_rounded,
                    size: 16,
                    color: _isProfileSuccessMessage ? const Color(0xFF34D399) : const Color(0xFFFF5252),
                  ),
                  const SizedBox(width: 10),
                  Expanded(
                    child: Text(
                      _profileStatusMessage!,
                      style: GoogleFonts.plusJakartaSans(
                        fontSize: 12,
                        color: _isProfileSuccessMessage ? const Color(0xFF34D399) : const Color(0xFFFF8080),
                        fontWeight: FontWeight.w600,
                      ),
                    ),
                  ),
                ],
              ),
            ),

          // Action row: Update Password Button & Forgot Password Link
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              CyberButton(
                variant: CyberButtonVariant.whitePill,
                height: 42,
                isLoading: _isUpdatingPassword,
                onTap: () async {
                  final currentPass = _currentPasswordController.text;
                  final newPass = _newPasswordController.text;
                  final confirmPass = _confirmPasswordController.text;

                  if (currentPass.isEmpty) {
                    setState(() {
                      _profileStatusMessage = 'Please enter your current password.';
                      _isProfileSuccessMessage = false;
                    });
                    return;
                  }
                  if (newPass.length < 6) {
                    setState(() {
                      _profileStatusMessage = 'New password must be at least 6 characters long.';
                      _isProfileSuccessMessage = false;
                    });
                    return;
                  }
                  if (newPass != confirmPass) {
                    setState(() {
                      _profileStatusMessage = 'New password and confirm password do not match.';
                      _isProfileSuccessMessage = false;
                    });
                    return;
                  }

                  setState(() {
                    _isUpdatingPassword = true;
                    _profileStatusMessage = null;
                  });

                  try {
                    await ref.read(authServiceProvider).changePassword(
                          currentPassword: currentPass,
                          newPassword: newPass,
                        );
                    if (mounted) {
                      setState(() {
                        _isUpdatingPassword = false;
                        _isProfileSuccessMessage = true;
                        _profileStatusMessage = 'Password updated successfully!';
                        _currentPasswordController.clear();
                        _newPasswordController.clear();
                        _confirmPasswordController.clear();
                      });
                    }
                  } catch (e) {
                    if (mounted) {
                      setState(() {
                        _isUpdatingPassword = false;
                        _isProfileSuccessMessage = false;
                        _profileStatusMessage = e.toString().replaceFirst(RegExp(r'^Exception:\s*'), '');
                      });
                    }
                  }
                },
                child: const Text('Update Password'),
              ),
              TextButton.icon(
                onPressed: _isSendingPasswordReset
                    ? null
                    : () async {
                        setState(() {
                          _isSendingPasswordReset = true;
                          _profileStatusMessage = null;
                        });
                        try {
                          await ref.read(authServiceProvider).resetPasswordForEmail(profile.email);
                          if (mounted) {
                            setState(() {
                              _isSendingPasswordReset = false;
                              _isProfileSuccessMessage = true;
                              _profileStatusMessage = 'Password recovery link sent to ${profile.email}.';
                            });
                          }
                        } catch (e) {
                          if (mounted) {
                            setState(() {
                              _isSendingPasswordReset = false;
                              _isProfileSuccessMessage = false;
                              _profileStatusMessage = e.toString().replaceFirst(RegExp(r'^Exception:\s*'), '');
                            });
                          }
                        }
                      },
                icon: const Icon(Icons.help_outline_rounded, size: 14, color: Color(0xFFC084FC)),
                label: Text(
                  'Forgot password?',
                  style: GoogleFonts.plusJakartaSans(
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                    color: const Color(0xFFC084FC),
                  ),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final userProfile = ref.watch(userProfileProvider);
    final provenanceState = ref.watch(provenanceTaskNotifierProvider);
    final incomingRequest = ref.watch(incomingTransferNotifierProvider);
    final sessionService = ref.watch(p2pSessionServiceProvider);

    final screenWidth = MediaQuery.of(context).size.width;
    final isMobile = screenWidth < 640;
    final isFullscreenChat = isMobile &&
        sessionService.sessionState == P2PSessionState.connected &&
        _activeModal == ActiveDeckModal.radar;

    return Scaffold(
      backgroundColor: CyberTheme.background,
      body: Stack(
        children: [
          // 1. Static 3D Prismatic Shards ("Wind Sculpture") Interactive Engine
          const Positioned.fill(
            child: ShardsBackground(),
          ),

          // 2. Clean Home Landing Page Content
          SafeArea(
            top: !isFullscreenChat,
            bottom: !isFullscreenChat,
            child: Column(
              children: [
                // Floating Glass Navbar (Hidden when P2P Chat is active on mobile for full-screen chatting)
                if (!isFullscreenChat)
                  Padding(
                    padding: EdgeInsets.symmetric(
                      horizontal: isMobile ? 12 : 24,
                      vertical: isMobile ? 8 : 14,
                    ),
                    child: Center(
                      child: ConstrainedBox(
                        constraints: const BoxConstraints(maxWidth: 1200),
                        child: _buildFloatingNavbar(userProfile),
                      ),
                    ),
                  ),

                // Floating Incoming Transfer Alert Banner (displayed when not on Radar page)
                if (incomingRequest != null && _activeModal != ActiveDeckModal.radar)
                  Padding(
                    padding: EdgeInsets.symmetric(
                      horizontal: isMobile ? 12 : 24,
                      vertical: 6,
                    ),
                    child: Center(
                      child: ConstrainedBox(
                        constraints: const BoxConstraints(maxWidth: 1200),
                        child: _buildIncomingTransferBanner(incomingRequest),
                      ),
                    ),
                  ),

                // Dedicated Screens (Instant non-sliding transition, Navbar indicator slides smoothly)
                Expanded(
                  child: IndexedStack(
                    index: _currentActivePageIndex,
                    children: [
                      // Page 0: Home Page
                      _buildHomePage(),

                      // Page 1: Studio Page
                      _buildPageLayout(
                        title: 'PROVENANCE STUDIO',
                        icon: Icons.fingerprint,
                        badge: 'C2PA SEED & HARDWARE MANIFEST',
                        description:
                            'Ingest digital originals, bind immutable C2PA hardware manifests, and extract perceptual cryptographic hash matrices.',
                        child: _buildProvenanceStudio(provenanceState),
                      ),

                      // Page 2: Verification & QA Audit Page
                      _buildPageLayout(
                        title: 'ZERO-TRUST VERIFICATION & ATTACK QA',
                        icon: Icons.verified_user_rounded,
                        badge: 'BITSTREAM / STEGANOGRAPHY / JUMBF / SANITIZATION',
                        description:
                            'Practical Quality Assurance (QA) testing protocol: Bitstream Shatter, Steganography Heat-Maps, Social Media Scrubbing, and UI Surface Sanitization.',
                        child: const VerificationPage(),
                      ),

                      // Page 3: Next-Gen Enclave Radar (Mentimeter Orbital Mesh + P2P Chat + Inline Sealing)
                      Padding(
                        padding: isFullscreenChat
                            ? EdgeInsets.zero
                            : EdgeInsets.fromLTRB(
                                isMobile ? 8 : 28,
                                isMobile ? 2 : 4,
                                isMobile ? 8 : 28,
                                isMobile ? 8 : 16,
                              ),
                        child: isFullscreenChat
                            ? RadarPage(
                                onNavigateToTab: (tabIndex) => _navigateToPage(tabIndex),
                              )
                            : Center(
                                child: ConstrainedBox(
                                  constraints: const BoxConstraints(maxWidth: 1400),
                                  child: RadarPage(
                                    onNavigateToTab: (tabIndex) => _navigateToPage(tabIndex),
                                  ),
                                ),
                              ),
                      ),

                      // Page 4: Ledger Page
                      _buildPageLayout(
                        title: 'IMMUTABLE ZERO-TRUST LEDGER',
                        icon: Icons.lock_clock,
                        badge: 'CRYPTOGRAPHIC AUDIT TRAIL',
                        description:
                            'Cryptographic tamper-evident provenance block history, verifying asset signature validity, perceptual hashes, and peer transmission logs.',
                        child: _buildLedgerAuditTrail(),
                      ),

                      // Page 5: Dedicated User Profile Page
                      _buildUserProfilePage(userProfile),
                    ],
                  ),
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  int get _activeNavIndex {
    switch (_activeModal) {
      case ActiveDeckModal.none:
        return 0; // Home
      case ActiveDeckModal.studio:
        return 1; // Studio
      case ActiveDeckModal.verify:
        return 2; // Verify
      case ActiveDeckModal.radar:
        return 3; // Radar
      case ActiveDeckModal.ledger:
        return 4; // Ledger
      case ActiveDeckModal.profile:
        return -1; // None of the 5 tabs is active
    }
  }

  int get _currentActivePageIndex {
    switch (_activeModal) {
      case ActiveDeckModal.none:
        return 0; // Home
      case ActiveDeckModal.studio:
        return 1; // Studio
      case ActiveDeckModal.verify:
        return 2; // Verify
      case ActiveDeckModal.radar:
        return 3; // Radar
      case ActiveDeckModal.ledger:
        return 4; // Ledger
      case ActiveDeckModal.profile:
        return 5; // User Profile
    }
  }

  // ==========================================
  // ANIMATED SLIDING NAV SEGMENTED CONTROL
  // ==========================================
  Widget _buildNavSegmentedControl() {
    const double tabWidth = 80.0;
    const double tabHeight = 36.0;
    final activeIndex = _activeNavIndex; // 0, 1, 2, 3, 4, or -1

    return Container(
      padding: const EdgeInsets.all(3.0),
      decoration: BoxDecoration(
        color: const Color(0x12FFFFFF), // Subtle frosted track
        borderRadius: BorderRadius.circular(100),
        border: Border.all(color: const Color(0x24FFFFFF), width: 1.0),
      ),
      child: SizedBox(
        width: tabWidth * 5,
        height: tabHeight,
        child: Stack(
          children: [
            // 1. Animated Sliding Indicator Pill & Bottom Glow Bar
            AnimatedPositioned(
              duration: const Duration(milliseconds: 320),
              curve: Curves.easeOutCubic,
              left: (activeIndex >= 0 ? activeIndex : 0) * tabWidth,
              top: 0,
              width: tabWidth,
              height: tabHeight,
              child: AnimatedOpacity(
                duration: const Duration(milliseconds: 200),
                opacity: activeIndex >= 0 ? 1.0 : 0.0,
                child: Container(
                  decoration: BoxDecoration(
                    color: const Color(0x32FFFFFF), // Visible frosted white pill
                    borderRadius: BorderRadius.circular(100),
                    border: Border.all(
                      color: const Color(0x60FFFFFF),
                      width: 1.0,
                    ),
                    boxShadow: const [
                      BoxShadow(
                        color: Color(0x35C084FC),
                        blurRadius: 14,
                        offset: Offset(0, 2),
                      ),
                      BoxShadow(
                        color: Color(0x20000000),
                        blurRadius: 6,
                        offset: Offset(0, 2),
                      ),
                    ],
                  ),
                  // Crisp bottom accent bar (refined electric amethyst micro-indicator)
                  child: Align(
                    alignment: Alignment.bottomCenter,
                    child: Container(
                      margin: const EdgeInsets.only(bottom: 3.0),
                      width: 24,
                      height: 2.5,
                      decoration: BoxDecoration(
                        color: const Color(0xFFC084FC),
                        borderRadius: BorderRadius.circular(2),
                        boxShadow: const [
                          BoxShadow(
                            color: Color(0xB0C084FC),
                            blurRadius: 6,
                            spreadRadius: 1,
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              ),
            ),

            // 2. Interactive Navigation Options (Home, Studio, Verify, Radar, Ledger)
            Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                _buildNavTabItem(
                  'Home',
                  0,
                  () => _navigateToPage(0),
                ),
                _buildNavTabItem(
                  'Studio',
                  1,
                  () => _navigateToPage(1),
                ),
                _buildNavTabItem(
                  'Verify',
                  2,
                  () => _navigateToPage(2),
                ),
                _buildNavTabItem(
                  'Radar',
                  3,
                  () => _navigateToPage(3),
                ),
                _buildNavTabItem(
                  'Ledger',
                  4,
                  () => _navigateToPage(4),
                ),
              ],
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildNavTabItem(String title, int index, VoidCallback onTap) {
    final isActive = _activeNavIndex == index;
    return SizedBox(
      width: 80.0,
      height: 36.0,
      child: Material(
        color: Colors.transparent,
        child: InkWell(
          borderRadius: BorderRadius.circular(100),
          onTap: onTap,
          hoverColor: const Color(0x15FFFFFF),
          child: Center(
            child: AnimatedDefaultTextStyle(
              duration: const Duration(milliseconds: 200),
              style: GoogleFonts.plusJakartaSans(
                color: isActive ? Colors.white : const Color(0x99FFFFFF),
                fontSize: 13,
                fontWeight: isActive ? FontWeight.w800 : FontWeight.w500,
                letterSpacing: 0.2,
              ),
              child: Text(title),
            ),
          ),
        ),
      ),
    );
  }

  // ==========================================
  // FLOATING GLASS NAVBAR (AESTHETIC CAPSULE)
  // ==========================================
  Widget _buildFloatingNavbar(UserProfile profile) {
    return Container(
      decoration: BoxDecoration(
        // Premium White Frosted Transparency Sheen
        color: const Color(0x14FFFFFF),
        borderRadius: BorderRadius.circular(100),
        border: Border.all(
          color: const Color(0x2EFFFFFF), // Crisp frosted white rim
          width: 1.0,
        ),
        boxShadow: const [
          BoxShadow(
            color: Color(0x66000000),
            blurRadius: 24,
            offset: Offset(0, 8),
          ),
          BoxShadow(
            color: Color(0x14FFFFFF),
            blurRadius: 1,
            spreadRadius: 0,
          ),
        ],
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(100),
        child: BackdropFilter(
          filter: ImageFilter.blur(sigmaX: 20, sigmaY: 20),
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 7),
            child: Row(
              children: [
                // Left: Logo & Brand (Obsidian Protocol)
                InkWell(
                  onTap: () => _navigateToPage(0),
                  borderRadius: BorderRadius.circular(100),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Container(
                        width: 34,
                        height: 34,
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          gradient: CyberTheme.shardGradient,
                          boxShadow: [
                            BoxShadow(
                              color: CyberTheme.accentColor.withValues(alpha: 0.5),
                              blurRadius: 14,
                              spreadRadius: 1,
                            ),
                          ],
                        ),
                        child: const Icon(Icons.all_inclusive_rounded, color: Colors.white, size: 20),
                      ),
                      const SizedBox(width: 10),
                      Text(
                        'Obsidian Protocol',
                        style: GoogleFonts.plusJakartaSans(
                          fontSize: 15,
                          fontWeight: FontWeight.w800,
                          letterSpacing: 0.2,
                          color: CyberTheme.textPrimary,
                        ),
                      ),
                      const SizedBox(width: 8),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2.5),
                        decoration: BoxDecoration(
                          color: CyberTheme.accentColor.withValues(alpha: 0.25),
                          borderRadius: BorderRadius.circular(100),
                          border: Border.all(color: CyberTheme.borderAccent),
                        ),
                        child: Text(
                          'ZERO-TRUST',
                          style: GoogleFonts.jetBrainsMono(
                            fontSize: 8.5,
                            fontWeight: FontWeight.w900,
                            letterSpacing: 0.8,
                            color: const Color(0xFFC084FC),
                          ),
                        ),
                      ),
                    ],
                  ),
                ),

                // Center: Animated Sliding Navigation Segmented Control
                Expanded(
                  child: Center(
                    child: _buildNavSegmentedControl(),
                  ),
                ),

                // Right: Combined Unified User Profile Capsule & Sign Out Menu
                _buildNavbarProfileCapsule(profile),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildNavbarProfileCapsule(UserProfile profile) {
    final isProfileActive = _activeModal == ActiveDeckModal.profile;

    return MouseRegion(
      cursor: SystemMouseCursors.click,
      child: InkWell(
        borderRadius: BorderRadius.circular(100),
        onTap: () => _showLuxuryProfileMenu(profile),
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 200),
          curve: Curves.easeOutCubic,
          padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
          decoration: BoxDecoration(
            color: isProfileActive ? const Color(0x30C084FC) : const Color(0x16FFFFFF),
            borderRadius: BorderRadius.circular(100),
            border: Border.all(
              color: isProfileActive ? const Color(0xFFA855F7) : const Color(0x30FFFFFF),
              width: 1.0,
            ),
            boxShadow: isProfileActive
                ? [
                    BoxShadow(
                      color: CyberTheme.accentColor.withValues(alpha: 0.35),
                      blurRadius: 14,
                      spreadRadius: 1,
                    ),
                  ]
                : null,
          ),
          child: Row(
            mainAxisSize: MainAxisSize.min,
            children: [
              // Initials Avatar
              Container(
                width: 28,
                height: 28,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  gradient: const LinearGradient(
                    colors: [Color(0xFFC084FC), Color(0xFF7C3AED)],
                    begin: Alignment.topLeft,
                    end: Alignment.bottomRight,
                  ),
                ),
                child: Center(
                  child: Text(
                    profile.initials,
                    style: GoogleFonts.plusJakartaSans(
                      color: Colors.white,
                      fontSize: 11,
                      fontWeight: FontWeight.w900,
                    ),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 110),
                child: Text(
                  profile.displayName.split(' ').first,
                  style: GoogleFonts.plusJakartaSans(
                    fontSize: 13,
                    fontWeight: FontWeight.w700,
                    color: Colors.white,
                  ),
                  overflow: TextOverflow.ellipsis,
                ),
              ),
              const SizedBox(width: 4),
              const Icon(
                Icons.keyboard_arrow_down_rounded,
                color: Color(0xFF94A3B8),
                size: 18,
              ),
            ],
          ),
        ),
      ),
    );
  }

  void _showLuxuryProfileMenu(UserProfile profile) {
    showGeneralDialog(
      context: context,
      barrierDismissible: true,
      barrierLabel: 'Dismiss Account Menu',
      barrierColor: Colors.black.withValues(alpha: 0.40),
      transitionDuration: const Duration(milliseconds: 220),
      pageBuilder: (dialogContext, anim1, anim2) {
        return Stack(
          children: [
            Positioned(
              top: 68,
              right: 24,
              child: Material(
                color: Colors.transparent,
                child: _LuxuryAccountPopover(
                  profile: profile,
                  onOpenProfile: () {
                    Navigator.of(dialogContext).pop();
                    setState(() => _activeModal = ActiveDeckModal.profile);
                  },
                  onSignOut: () {
                    Navigator.of(dialogContext).pop();
                    _confirmSignOut();
                  },
                ),
              ),
            ),
          ],
        );
      },
      transitionBuilder: (context, anim, secondaryAnim, child) {
        final curved = CurvedAnimation(parent: anim, curve: Curves.easeOutCubic);
        return Transform.scale(
          scale: 0.94 + (curved.value * 0.06),
          alignment: Alignment.topRight,
          child: Opacity(
            opacity: anim.value.clamp(0.0, 1.0),
            child: child,
          ),
        );
      },
    );
  }

  // ==========================================
  // FLOATING INCOMING TRANSFER ALERT BANNER
  // ==========================================
  Widget _buildIncomingTransferBanner(IncomingTransferRequest request) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 18, vertical: 12),
      decoration: BoxDecoration(
        color: CyberTheme.surfaceElevated.withValues(alpha: 0.95),
        borderRadius: BorderRadius.circular(16),
        border: Border.all(color: CyberTheme.emerald, width: 1.5),
        boxShadow: [
          BoxShadow(
            color: CyberTheme.emerald.withValues(alpha: 0.3),
            blurRadius: 20,
            spreadRadius: 2,
          ),
        ],
      ),
      child: Row(
        children: [
          Container(
            padding: const EdgeInsets.all(8),
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: CyberTheme.emerald.withValues(alpha: 0.2),
            ),
            child: const Icon(Icons.wifi_tethering, color: CyberTheme.emerald, size: 20),
          ),
          const SizedBox(width: 14),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              mainAxisSize: MainAxisSize.min,
              children: [
                Text(
                  'INCOMING AIRDROP REQUEST',
                  style: GoogleFonts.plusJakartaSans(
                    color: CyberTheme.emerald,
                    fontSize: 11,
                    fontWeight: FontWeight.w900,
                    letterSpacing: 0.8,
                  ),
                ),
                const SizedBox(height: 2),
                Text(
                  'Agent ${request.senderName} (${request.senderEmail.isNotEmpty ? request.senderEmail : request.senderId}) wants to stream an encrypted asset.',
                  style: GoogleFonts.plusJakartaSans(
                    color: CyberTheme.textPrimary,
                    fontSize: 12,
                    fontWeight: FontWeight.w500,
                  ),
                ),
              ],
            ),
          ),
          const SizedBox(width: 14),
          CyberButton(
            variant: CyberButtonVariant.danger,
            height: 32,
            padding: const EdgeInsets.symmetric(horizontal: 14),
            onTap: () {
              ref.read(webRtcServiceProvider).declineIncomingTransfer(request.senderId);
              ref.read(incomingTransferNotifierProvider.notifier).clear();
            },
            child: const Text('DECLINE'),
          ),
          const SizedBox(width: 8),
          CyberButton(
            variant: CyberButtonVariant.emerald,
            height: 32,
            padding: const EdgeInsets.symmetric(horizontal: 16),
            onTap: () {
              final peer = RadarPeer(
                uuid: request.senderId,
                displayName: request.senderName,
                email: request.senderEmail,
                platform: 'Mesh Node',
                pingMs: 16,
              );
              ref.read(p2pSessionServiceProvider).handleIncomingSessionAccepted(peer);
              ref.read(incomingTransferNotifierProvider.notifier).clear();
              _navigateToPage(3);
              ref.read(webRtcServiceProvider).acceptIncomingTransfer(request.senderId, request.offerPayload);
            },
            child: const Text('ACCEPT'),
          ),
        ],
      ),
    );
  }

  // ==========================================
  // HERO SECTION (CLEAN LANDING PAGE WITH QUOTE ALONE)
  // ==========================================
  Widget _buildHeroSection() {
    return Column(
      mainAxisAlignment: MainAxisAlignment.center,
      children: [
        // Announcement Badge Pill
        InkWell(
          onTap: () => _navigateToPage(1),
          borderRadius: BorderRadius.circular(100),
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
            decoration: BoxDecoration(
              color: const Color(0x33A855F7),
              borderRadius: BorderRadius.circular(100),
              border: Border.all(color: CyberTheme.borderAccent),
              boxShadow: [
                BoxShadow(
                  color: CyberTheme.accentColor.withValues(alpha: 0.25),
                  blurRadius: 14,
                ),
              ],
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                  decoration: BoxDecoration(
                    color: Colors.white,
                    borderRadius: BorderRadius.circular(100),
                  ),
                  child: Text(
                    'NEW',
                    style: GoogleFonts.plusJakartaSans(
                      color: const Color(0xFF0C0814),
                      fontSize: 9,
                      fontWeight: FontWeight.w900,
                      letterSpacing: 0.6,
                    ),
                  ),
                ),
                const SizedBox(width: 10),
                Text(
                  'Creative Components // Digital Provenance',
                  style: GoogleFonts.plusJakartaSans(
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                    color: const Color(0xFFF3E8FF),
                  ),
                ),
                const SizedBox(width: 6),
                const Icon(Icons.arrow_forward_ios, size: 9, color: CyberTheme.shardColor),
              ],
            ),
          ),
        ),
        const SizedBox(height: 28), // Generous breathing room between badge and headline

        // Bold Crisp Modern Sans Headline with Theme-Highlighted Words
        Text.rich(
          TextSpan(
            children: [
              const TextSpan(text: "Don't touch them, they are "),
              TextSpan(
                text: "pretty sharp!\n",
                style: TextStyle(
                  color: const Color(0xFFC084FC), // Vibrant electric amethyst highlight
                  shadows: [
                    Shadow(
                      color: const Color(0xFFA855F7).withValues(alpha: 0.75),
                      blurRadius: 28,
                    ),
                  ],
                ),
              ),
              TextSpan(
                text: "Hardware-Sealed ",
                style: TextStyle(
                  color: const Color(0xFFA78BFA), // Cyber lavender theme highlight
                  shadows: [
                    Shadow(
                      color: const Color(0xFF8B5CF6).withValues(alpha: 0.65),
                      blurRadius: 24,
                    ),
                  ],
                ),
              ),
              const TextSpan(text: "Digital Originals."),
            ],
          ),
          textAlign: TextAlign.center,
          style: GoogleFonts.plusJakartaSans(
            fontSize: 44,
            fontWeight: FontWeight.w900,
            letterSpacing: -1.0,
            color: Colors.white,
            height: 1.24, // Comfortable line height for airy reading
            shadows: [
              Shadow(
                color: CyberTheme.accentColor.withValues(alpha: 0.4),
                blurRadius: 36,
              ),
            ],
          ),
        ),
        const SizedBox(height: 26), // Generous spacing before subtitle

        // Subtitle (Kept as plain uniform text)
        ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 720),
          child: Text(
            'Interactive 3D Prismatic Shards protecting true digital originals. Seal assets with C2PA hardware manifests, extract perceptual hash vectors, and stream encrypted payloads directly between peers over WebRTC DTLS tunnels.',
            textAlign: TextAlign.center,
            style: GoogleFonts.plusJakartaSans(
              fontSize: 14.5,
              fontWeight: FontWeight.w400,
              height: 1.65, // More legible and spacious
              color: CyberTheme.textSecondary,
            ),
          ),
        ),
        const SizedBox(height: 38), // Generous spacing before CTA buttons

        // Hero Action Buttons with Hover Pop Lift & Glow
        Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            CyberButton(
              variant: CyberButtonVariant.whitePill,
              height: 52,
              padding: const EdgeInsets.symmetric(horizontal: 32),
              icon: Icons.upload_file,
              enableHoverPop: true,
              onTap: () => _navigateToPage(1),
              child: Text(
                'Get started',
                style: GoogleFonts.plusJakartaSans(
                  fontWeight: FontWeight.w800,
                  fontSize: 15,
                  letterSpacing: 0.2,
                ),
              ),
            ),
            const SizedBox(width: 14),
            CyberButton(
              variant: CyberButtonVariant.glassPill,
              height: 52,
              padding: const EdgeInsets.symmetric(horizontal: 24),
              icon: Icons.verified_user_rounded,
              enableHoverPop: true,
              onTap: () => _navigateToPage(2),
              child: Text(
                'Verify & QA Audit',
                style: GoogleFonts.plusJakartaSans(
                  fontWeight: FontWeight.w700,
                  fontSize: 15,
                  letterSpacing: 0.2,
                ),
              ),
            ),
            const SizedBox(width: 14),
            CyberButton(
              variant: CyberButtonVariant.glassPill,
              height: 52,
              padding: const EdgeInsets.symmetric(horizontal: 24),
              icon: Icons.radar,
              enableHoverPop: true,
              onTap: () => _navigateToPage(3),
              child: Text(
                'Launch Radar',
                style: GoogleFonts.plusJakartaSans(
                  fontWeight: FontWeight.w700,
                  fontSize: 15,
                  letterSpacing: 0.2,
                ),
              ),
            ),
          ],
        ),
      ],
    );
  }

  // ==========================================
  // DEDICATED FULL PAGES UNDER NAVBAR
  // ==========================================
  Widget _buildHomePage() {
    return SingleChildScrollView(
      controller: _scrollController,
      padding: const EdgeInsets.only(left: 24, right: 24, top: 88, bottom: 64),
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 1100),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              _buildHeroSection(),
              const SizedBox(height: 96), // Airy, elegant vertical breathing room
              _buildApplicationExplainerSection(),
              const SizedBox(height: 56),
            ],
          ),
        ),
      ),
    );
  }

  // ==========================================
  // APPLICATION EXPLAINER SECTION (WHAT THE APP DOES)
  // ==========================================
  Widget _buildApplicationExplainerSection() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.stretch,
      children: [
        // Section Header
        Center(
          child: Column(
            children: [
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 5),
                decoration: BoxDecoration(
                  color: const Color(0x22C084FC),
                  borderRadius: BorderRadius.circular(100),
                  border: Border.all(color: CyberTheme.borderAccent),
                ),
                child: Text(
                  'SECURITY PROTOCOLS & CORE CAPABILITIES',
                  style: GoogleFonts.jetBrainsMono(
                    fontSize: 10,
                    fontWeight: FontWeight.w800,
                    color: const Color(0xFFE9D5FF),
                    letterSpacing: 1.2,
                  ),
                ),
              ),
              const SizedBox(height: 16),
              Text(
                'What is Obsidian Protocol?',
                style: GoogleFonts.plusJakartaSans(
                  fontSize: 34,
                  fontWeight: FontWeight.w900,
                  color: Colors.white,
                  letterSpacing: -1.0,
                ),
                textAlign: TextAlign.center,
              ),
              const SizedBox(height: 12),
              ConstrainedBox(
                constraints: const BoxConstraints(maxWidth: 760),
                child: Text(
                  'Obsidian Protocol is a decentralized, zero-trust digital provenance ecosystem. In an era saturated with generative AI, deepfakes, and untraceable media manipulation, Obsidian Protocol establishes an unbreakable cryptographic chain of custody from capture to peer transfer without relying on third-party cloud servers.',
                  textAlign: TextAlign.center,
                  style: GoogleFonts.plusJakartaSans(
                    fontSize: 14,
                    fontWeight: FontWeight.w400,
                    color: CyberTheme.textSecondary,
                    height: 1.6,
                  ),
                ),
              ),
            ],
          ),
        ),
        const SizedBox(height: 36),

        // Three Core Pillars (Responsive cards)
        LayoutBuilder(
          builder: (context, constraints) {
            final isWide = constraints.maxWidth >= 900;
            final pillar1 = _buildFeaturePillarCard(
              number: '01',
              title: 'C2PA Hardware Manifest Sealing',
              badge: 'STUDIO INGESTION',
              icon: Icons.fingerprint_rounded,
              accentColor: const Color(0xFFC084FC),
              description:
                  'Every digital asset ingested into the Studio receives an immutable cryptographic manifest bound to hardware identity. Kerberos generates cryptographic certificate chains (SHA-256 / Ed25519) that assert exact authorship, device signatures, and capture timestamps—guaranteeing tamper evidence against synthetic modification.',
            );

            final pillar2 = _buildFeaturePillarCard(
              number: '02',
              title: 'Direct Peer-to-Peer AirDrop Radar',
              badge: 'WEBRTC DTLS 1.3',
              icon: Icons.wifi_tethering_rounded,
              accentColor: const Color(0xFF34D399),
              description:
                  'Eliminate the risks of uploading confidential media to third-party cloud intermediaries. Kerberos uses peer signaling to discover authenticated desktop and mobile nodes, establishing point-to-point DTLS 1.3 encrypted WebRTC data channels for instantaneous, zero-retention raw binary streaming.',
            );

            final pillar3 = _buildFeaturePillarCard(
              number: '03',
              title: 'Perceptual Hash & Audit Ledger',
              badge: 'IMMUTABLE AUDIT TRAIL',
              icon: Icons.lock_clock_rounded,
              accentColor: const Color(0xFF38BDF8),
              description:
                  'Minor pixel cropping or compression is immediately distinguished from malicious content tampering. The engine extracts a 256-cell multi-band perceptual hash matrix and permanently appends every transfer handshake into a local cryptographic audit ledger.',
            );

            if (isWide) {
              return Row(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  Expanded(child: pillar1),
                  const SizedBox(width: 18),
                  Expanded(child: pillar2),
                  const SizedBox(width: 18),
                  Expanded(child: pillar3),
                ],
              );
            } else {
              return Column(
                children: [
                  pillar1,
                  const SizedBox(height: 16),
                  pillar2,
                  const SizedBox(height: 16),
                  pillar3,
                ],
              );
            }
          },
        ),
        const SizedBox(height: 36),

        // Step-by-Step Workflow Banner
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 28, vertical: 24),
          decoration: BoxDecoration(
            color: const Color(0x14FFFFFF),
            borderRadius: BorderRadius.circular(20),
            border: Border.all(color: const Color(0x28FFFFFF), width: 1.0),
          ),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Row(
                children: [
                  const Icon(Icons.sync_alt_rounded, color: CyberTheme.shardColor, size: 20),
                  const SizedBox(width: 10),
                  Text(
                    'HOW IT WORKS IN PRACTICE',
                    style: GoogleFonts.jetBrainsMono(
                      fontSize: 11,
                      fontWeight: FontWeight.w800,
                      color: CyberTheme.textPrimary,
                      letterSpacing: 1.0,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 18),
              LayoutBuilder(
                builder: (context, constraints) {
                  final isWide = constraints.maxWidth >= 720;
                  final step1 = _buildWorkflowStep(
                    step: 'STEP 1',
                    action: 'Ingest & Certify',
                    detail: 'Drag & drop media into Provenance Studio to bind cryptographic hardware manifests.',
                    onTap: () => _navigateToPage(1),
                  );
                  final step2 = _buildWorkflowStep(
                    step: 'STEP 2',
                    action: 'Discover & AirDrop',
                    detail: 'Locate nearby Windows and Mobile nodes on Radar and beam encrypted payloads directly.',
                    onTap: () => _navigateToPage(3),
                  );
                  final step3 = _buildWorkflowStep(
                    step: 'STEP 3',
                    action: 'Verify & QA Audit',
                    detail: 'Perform multi-vector Zero-Trust QA audits: bitstream shatter, steganography, scrub, & injection.',
                    onTap: () => _navigateToPage(2),
                  );

                  if (isWide) {
                    return Row(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Expanded(child: step1),
                        const SizedBox(width: 20),
                        Expanded(child: step2),
                        const SizedBox(width: 20),
                        Expanded(child: step3),
                      ],
                    );
                  } else {
                    return Column(
                      children: [
                        step1,
                        const SizedBox(height: 14),
                        step2,
                        const SizedBox(height: 14),
                        step3,
                      ],
                    );
                  }
                },
              ),
            ],
          ),
        ),
      ],
    );
  }

  Widget _buildFeaturePillarCard({
    required String number,
    required String title,
    required String badge,
    required IconData icon,
    required Color accentColor,
    required String description,
  }) {
    return Container(
      padding: const EdgeInsets.all(24),
      decoration: BoxDecoration(
        color: const Color(0x14FFFFFF),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: const Color(0x28FFFFFF), width: 1.0),
        boxShadow: const [
          BoxShadow(
            color: Color(0x2A000000),
            blurRadius: 20,
            offset: Offset(0, 8),
          ),
        ],
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Container(
                width: 42,
                height: 42,
                decoration: BoxDecoration(
                  shape: BoxShape.circle,
                  color: accentColor.withValues(alpha: 0.15),
                  border: Border.all(color: accentColor.withValues(alpha: 0.35)),
                ),
                child: Icon(icon, color: accentColor, size: 22),
              ),
              Text(
                number,
                style: GoogleFonts.jetBrainsMono(
                  fontSize: 16,
                  fontWeight: FontWeight.w900,
                  color: const Color(0x35FFFFFF),
                ),
              ),
            ],
          ),
          const SizedBox(height: 16),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
            decoration: BoxDecoration(
              color: accentColor.withValues(alpha: 0.1),
              borderRadius: BorderRadius.circular(6),
            ),
            child: Text(
              badge,
              style: GoogleFonts.jetBrainsMono(
                fontSize: 9,
                fontWeight: FontWeight.w800,
                color: accentColor,
                letterSpacing: 0.6,
              ),
            ),
          ),
          const SizedBox(height: 10),
          Text(
            title,
            style: GoogleFonts.plusJakartaSans(
              fontSize: 17,
              fontWeight: FontWeight.w800,
              color: Colors.white,
              letterSpacing: -0.3,
            ),
          ),
          const SizedBox(height: 8),
          Text(
            description,
            style: GoogleFonts.plusJakartaSans(
              fontSize: 12.5,
              fontWeight: FontWeight.w400,
              color: CyberTheme.textSecondary,
              height: 1.6,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildWorkflowStep({
    required String step,
    required String action,
    required String detail,
    VoidCallback? onTap,
  }) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(14),
      hoverColor: const Color(0x10C084FC),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 8),
        decoration: BoxDecoration(
          borderRadius: BorderRadius.circular(14),
        ),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              step,
              style: GoogleFonts.jetBrainsMono(
                fontSize: 10,
                fontWeight: FontWeight.w800,
                color: CyberTheme.shardColor,
                letterSpacing: 1.0,
              ),
            ),
            const SizedBox(height: 4),
            Row(
              children: [
                Text(
                  action,
                  style: GoogleFonts.plusJakartaSans(
                    fontSize: 14,
                    fontWeight: FontWeight.w800,
                    color: Colors.white,
                  ),
                ),
                if (onTap != null) ...[
                  const SizedBox(width: 5),
                  const Icon(Icons.arrow_forward_rounded, size: 14, color: Color(0xFFC084FC)),
                ],
              ],
            ),
            const SizedBox(height: 4),
            Text(
              detail,
              style: GoogleFonts.plusJakartaSans(
                fontSize: 12,
                fontWeight: FontWeight.w400,
                color: CyberTheme.textSecondary,
                height: 1.45,
              ),
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildPageLayout({
    required String title,
    required IconData icon,
    required String badge,
    required String description,
    required Widget child,
  }) {
    return SingleChildScrollView(
      padding: const EdgeInsets.symmetric(horizontal: 36, vertical: 16),
      child: Center(
        child: ConstrainedBox(
          constraints: const BoxConstraints(maxWidth: 1600),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // Page Header Bar
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
                margin: const EdgeInsets.only(bottom: 20),
                decoration: BoxDecoration(
                  color: const Color(0x14FFFFFF),
                  borderRadius: BorderRadius.circular(20),
                  border: Border.all(color: const Color(0x28FFFFFF), width: 1.0),
                  boxShadow: const [
                    BoxShadow(
                      color: Color(0x40000000),
                      blurRadius: 20,
                      offset: Offset(0, 6),
                    ),
                  ],
                ),
                child: Row(
                  children: [
                    Container(
                      width: 42,
                      height: 42,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        gradient: CyberTheme.shardGradient,
                        boxShadow: [
                          BoxShadow(
                            color: CyberTheme.accentColor.withValues(alpha: 0.4),
                            blurRadius: 14,
                          ),
                        ],
                      ),
                      child: Icon(icon, color: Colors.white, size: 20),
                    ),
                    const SizedBox(width: 16),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Row(
                            children: [
                              Text(
                                title,
                                style: GoogleFonts.plusJakartaSans(
                                  color: Colors.white,
                                  fontSize: 15,
                                  fontWeight: FontWeight.w800,
                                  letterSpacing: 0.5,
                                ),
                              ),
                              const SizedBox(width: 10),
                              Container(
                                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2.5),
                                decoration: BoxDecoration(
                                  color: CyberTheme.accentColor.withValues(alpha: 0.22),
                                  borderRadius: BorderRadius.circular(100),
                                  border: Border.all(color: CyberTheme.borderAccent),
                                ),
                                child: Text(
                                  badge,
                                  style: GoogleFonts.jetBrainsMono(
                                    color: const Color(0xFFC084FC),
                                    fontSize: 9,
                                    fontWeight: FontWeight.w700,
                                    letterSpacing: 0.5,
                                  ),
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 4),
                          Text(
                            description,
                            style: GoogleFonts.plusJakartaSans(
                              color: CyberTheme.textSecondary,
                              fontSize: 12,
                              height: 1.4,
                            ),
                          ),
                        ],
                      ),
                    ),
                    const SizedBox(width: 16),
                    // Back to Home Button
                    InkWell(
                      onTap: () => _navigateToPage(0),
                      borderRadius: BorderRadius.circular(100),
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 7),
                        decoration: BoxDecoration(
                          color: const Color(0x18FFFFFF),
                          borderRadius: BorderRadius.circular(100),
                          border: Border.all(color: const Color(0x33FFFFFF)),
                        ),
                        child: Row(
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            const Icon(Icons.arrow_back_rounded, size: 14, color: Colors.white),
                            const SizedBox(width: 6),
                            Text(
                              'Home',
                              style: GoogleFonts.plusJakartaSans(
                                color: Colors.white,
                                fontSize: 12,
                                fontWeight: FontWeight.w700,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ),
                  ],
                ),
              ),

              // Embedded Page Content Card
              child,

              const SizedBox(height: 32),
            ],
          ),
        ),
      ),
    );
  }



  // ==========================================
  // BENTO CARD 1: PROVENANCE STUDIO (INGEST & SEAL)
  // ==========================================
  Widget _buildProvenanceStudio(AsyncValue<dynamic> provenanceState) {
    return GlassContainer(
      glow: true,
      glowColor: CyberTheme.cyan,
      borderColor: CyberTheme.border,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Bento Card Header
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      color: CyberTheme.cyan.withValues(alpha: 0.12),
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: CyberTheme.borderCyan),
                    ),
                    child: const Icon(Icons.fingerprint, color: CyberTheme.cyan, size: 20),
                  ),
                  const SizedBox(width: 12),
                  const Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'PROVENANCE STUDIO',
                        style: TextStyle(
                          fontSize: 14,
                          fontWeight: FontWeight.w800,
                          letterSpacing: 1.0,
                          color: CyberTheme.textPrimary,
                        ),
                      ),
                      Text(
                        'C2PA HARDWARE MANIFEST & PERCEPTUAL VECTOR',
                        style: TextStyle(fontSize: 10, color: CyberTheme.textMuted, letterSpacing: 0.5),
                      ),
                    ],
                  ),
                ],
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                decoration: BoxDecoration(
                  color: CyberTheme.cyan.withValues(alpha: 0.1),
                  borderRadius: BorderRadius.circular(100),
                  border: Border.all(color: CyberTheme.borderCyan),
                ),
                child: const Text('ED25519 READY', style: TextStyle(color: CyberTheme.cyan, fontSize: 9, fontWeight: FontWeight.bold)),
              ),
            ],
          ),
          const SizedBox(height: 24),

          // Dotted Cyber Ingestion Portal
          DropTarget(
            onDragEntered: (_) => setState(() => _isDragging = true),
            onDragExited: (_) => setState(() => _isDragging = false),
            onDragDone: (details) {
              setState(() => _isDragging = false);
              if (details.files.isNotEmpty) {
                ref.read(provenanceTaskNotifierProvider.notifier).ingestFile(details.files.first);
              }
            },
            child: GestureDetector(
              onTap: _pickAndIngestFile,
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 200),
                width: double.infinity,
                padding: const EdgeInsets.symmetric(vertical: 36, horizontal: 20),
                decoration: BoxDecoration(
                  color: _isDragging
                      ? CyberTheme.accentColor.withValues(alpha: 0.18)
                      : CyberTheme.surfaceElevated.withValues(alpha: 0.6),
                  borderRadius: BorderRadius.circular(18),
                  border: Border.all(
                    color: _isDragging ? CyberTheme.accentColor : CyberTheme.borderShard,
                    width: _isDragging ? 2 : 1.2,
                  ),
                ),
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Container(
                      width: 58,
                      height: 58,
                      decoration: BoxDecoration(
                        shape: BoxShape.circle,
                        gradient: CyberTheme.shardGradient,
                        boxShadow: [
                          BoxShadow(
                            color: CyberTheme.accentColor.withValues(alpha: 0.35),
                            blurRadius: 18,
                            spreadRadius: 2,
                          ),
                        ],
                      ),
                      child: const Icon(Icons.cloud_upload_outlined, color: Colors.white, size: 28),
                    ),
                    const SizedBox(height: 16),
                    Text(
                      _isDragging ? 'RELEASE TO SEAL ASSET' : 'DRAG & DROP ASSET HERE OR BROWSE',
                      style: TextStyle(
                        fontSize: 13,
                        fontWeight: FontWeight.w800,
                        letterSpacing: 0.8,
                        color: _isDragging ? const Color(0xFFC084FC) : CyberTheme.textPrimary,
                      ),
                    ),
                    const SizedBox(height: 6),
                    const Text(
                      'Supports Images, PDFs, Docs, all PPTs, Videos, and Audio (All-Format C2PA Sealing)',
                      style: TextStyle(fontSize: 11, color: CyberTheme.textMuted),
                    ),
                    const SizedBox(height: 16),
                    CyberButton(
                      variant: CyberButtonVariant.whitePill,
                      height: 34,
                      padding: const EdgeInsets.symmetric(horizontal: 20),
                      icon: Icons.folder_open,
                      onTap: _pickAndIngestFile,
                      child: const Text('Browse Device'),
                    ),
                    if (provenanceState.isLoading) ...[
                      const SizedBox(height: 18),
                      const SizedBox(
                        width: 22,
                        height: 22,
                        child: CircularProgressIndicator(strokeWidth: 2, color: CyberTheme.accentColor),
                      ),
                    ],
                  ],
                ),
              ),
            ),
          ),
          const SizedBox(height: 20),

          // Sealing Results & Cryptographic Inspector
          provenanceState.when(
            data: (metadata) {
              if (metadata == null) {
                return Container(
                  width: double.infinity,
                  padding: const EdgeInsets.all(20),
                  decoration: BoxDecoration(
                    color: CyberTheme.surfaceElevated.withValues(alpha: 0.4),
                    borderRadius: BorderRadius.circular(14),
                    border: Border.all(color: CyberTheme.border),
                  ),
                  child: const Center(
                    child: Text(
                      'STANDBY: INGEST AN ASSET TO CALCULATE PERCEPTUAL VECTOR & SEAL WITH C2PA',
                      textAlign: TextAlign.center,
                      style: TextStyle(color: CyberTheme.textMuted, fontSize: 11, fontFamily: 'monospace'),
                    ),
                  ),
                );
              }

              return Container(
                width: double.infinity,
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                  color: CyberTheme.surfaceElevated.withValues(alpha: 0.8),
                  borderRadius: BorderRadius.circular(16),
                  border: Border.all(color: CyberTheme.borderEmerald, width: 1.2),
                ),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      children: [
                        Container(
                          padding: const EdgeInsets.all(6),
                          decoration: BoxDecoration(
                            color: CyberTheme.emerald.withValues(alpha: 0.15),
                            shape: BoxShape.circle,
                          ),
                          child: const Icon(Icons.verified, color: CyberTheme.emerald, size: 16),
                        ),
                        const SizedBox(width: 10),
                        const Text(
                          'C2PA HARDWARE SEAL VERIFIED',
                          style: TextStyle(
                            color: CyberTheme.emerald,
                            fontSize: 12,
                            fontWeight: FontWeight.w800,
                            letterSpacing: 1.0,
                          ),
                        ),
                        const Spacer(),
                        Container(
                          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                          decoration: BoxDecoration(
                            color: CyberTheme.emerald.withValues(alpha: 0.15),
                            borderRadius: BorderRadius.circular(4),
                          ),
                          child: const Text('IMMUTABLE HASH', style: TextStyle(color: CyberTheme.emerald, fontSize: 9, fontWeight: FontWeight.bold)),
                        ),
                      ],
                    ),
                    const SizedBox(height: 16),

                    // Vector Spectrum Equalizer Visualizer
                    if (metadata.perceptualHash != null && metadata.perceptualHash!.isNotEmpty) ...[
                      const Text(
                        'PERCEPTUAL VECTOR SPECTRUM (256-D EMBEDDING):',
                        style: TextStyle(fontSize: 10, color: CyberTheme.textMuted, fontWeight: FontWeight.w700),
                      ),
                      const SizedBox(height: 8),
                      Container(
                        height: 52,
                        width: double.infinity,
                        padding: const EdgeInsets.all(4),
                        decoration: BoxDecoration(
                          color: CyberTheme.surface,
                          borderRadius: BorderRadius.circular(8),
                          border: Border.all(color: CyberTheme.border),
                        ),
                        child: ClipRRect(
                          borderRadius: BorderRadius.circular(6),
                          child: CustomPaint(
                            painter: CyberHeatMapRenderer(metadata.perceptualHash!),
                          ),
                        ),
                      ),
                      const SizedBox(height: 16),
                    ],

                    _buildDetailRow('FILE PATH', metadata.filePath),
                    const SizedBox(height: 8),
                    _buildDetailRow('SHA-256', metadata.sha256Hash, isMonospace: true, copyable: true),
                    const SizedBox(height: 16),
                    Row(
                      mainAxisAlignment: MainAxisAlignment.end,
                      children: [
                        CyberButton(
                          variant: CyberButtonVariant.emerald,
                          height: 38,
                          icon: Icons.verified_outlined,
                          onTap: () {
                            _navigateToPage(2);
                          },
                          child: const Text('Audit in Verification Protocol ➔'),
                        ),
                      ],
                    ),
                  ],
                ),
              );
            },
            error: (err, stack) => Container(
              width: double.infinity,
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: CyberTheme.coral.withValues(alpha: 0.12),
                borderRadius: BorderRadius.circular(14),
                border: Border.all(color: CyberTheme.coral.withValues(alpha: 0.4)),
              ),
              child: Text(
                'Fault: ${err.toString()}',
                style: const TextStyle(color: Colors.white, fontSize: 11, fontFamily: 'monospace'),
              ),
            ),
            loading: () => Container(
              width: double.infinity,
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                color: CyberTheme.surfaceElevated,
                borderRadius: BorderRadius.circular(14),
                border: Border.all(color: CyberTheme.border),
              ),
              child: const Center(
                child: Text('> APPLYING ED25519 DIGITAL SIGNATURE & C2PA SEAL...', style: TextStyle(color: CyberTheme.cyan, fontSize: 11, fontFamily: 'monospace')),
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDetailRow(String label, String value, {bool isMonospace = false, bool copyable = false}) {
    return Row(
      children: [
        SizedBox(
          width: 80,
          child: Text(label, style: const TextStyle(fontSize: 10, fontWeight: FontWeight.w700, color: CyberTheme.textMuted)),
        ),
        Expanded(
          child: Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
            decoration: BoxDecoration(
              color: CyberTheme.surface,
              borderRadius: BorderRadius.circular(8),
              border: Border.all(color: CyberTheme.border),
            ),
            child: Row(
              children: [
                Expanded(
                  child: Text(
                    value,
                    overflow: TextOverflow.ellipsis,
                    style: TextStyle(
                      fontSize: 11,
                      color: CyberTheme.textPrimary,
                      fontFamily: isMonospace ? 'monospace' : null,
                    ),
                  ),
                ),
                if (copyable)
                  InkWell(
                    onTap: () {
                      Clipboard.setData(ClipboardData(text: value));
                      ScaffoldMessenger.of(context).showSnackBar(
                        const SnackBar(content: Text('Hash copied to clipboard!'), duration: Duration(seconds: 1)),
                      );
                    },
                    child: const Icon(Icons.copy, size: 14, color: CyberTheme.cyan),
                  ),
              ],
            ),
          ),
        ),
      ],
    );
  }

  // ==========================================
  // BENTO CARD 3: IMMUTABLE ZERO-TRUST LEDGER
  // ==========================================
  Widget _buildLedgerAuditTrail() {
    final ledger = ref.watch(ledgerProvider);
    final history = ledger.getHistory();

    return GlassContainer(
      padding: const EdgeInsets.all(24),
      borderColor: CyberTheme.border,
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Row(
                children: [
                  Container(
                    padding: const EdgeInsets.all(8),
                    decoration: BoxDecoration(
                      color: CyberTheme.indigo.withValues(alpha: 0.15),
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: const Color(0x666366F1)),
                    ),
                    child: const Icon(Icons.receipt_long, color: CyberTheme.indigo, size: 20),
                  ),
                  const SizedBox(width: 12),
                  const Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        'IMMUTABLE ZERO-TRUST LEDGER',
                        style: TextStyle(
                          fontSize: 14,
                          fontWeight: FontWeight.w800,
                          letterSpacing: 1.0,
                          color: CyberTheme.textPrimary,
                        ),
                      ),
                      Text(
                        'AIR-GAPPED AES-256 ENCRYPTED AUDIT TRAIL',
                        style: TextStyle(fontSize: 10, color: CyberTheme.textMuted, letterSpacing: 0.5),
                      ),
                    ],
                  ),
                ],
              ),
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                decoration: BoxDecoration(
                  color: CyberTheme.surfaceElevated,
                  borderRadius: BorderRadius.circular(100),
                  border: Border.all(color: CyberTheme.border),
                ),
                child: Text(
                  '${history.length} SEALED ASSETS',
                  style: const TextStyle(fontSize: 10, fontWeight: FontWeight.bold, color: CyberTheme.cyanLight),
                ),
              ),
            ],
          ),
          const SizedBox(height: 20),

          if (history.isEmpty)
            Container(
              padding: const EdgeInsets.all(28),
              alignment: Alignment.center,
              child: const Text(
                'NO ASSETS RECORDED IN AIR-GAPPED LEDGER YET',
                style: TextStyle(color: CyberTheme.textMuted, fontSize: 11, fontFamily: 'monospace'),
              ),
            )
          else
            ListView.builder(
              shrinkWrap: true,
              physics: const NeverScrollableScrollPhysics(),
              itemCount: history.length > 5 ? 5 : history.length,
              itemBuilder: (context, index) {
                final record = history[index];
                return Container(
                  margin: const EdgeInsets.only(bottom: 8),
                  padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                  decoration: BoxDecoration(
                    color: CyberTheme.surfaceElevated.withValues(alpha: 0.6),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: CyberTheme.border),
                  ),
                  child: Row(
                    children: [
                      const Icon(Icons.check_circle, color: CyberTheme.emerald, size: 16),
                      const SizedBox(width: 12),
                      Text(
                        record.filePath.split(RegExp(r'[\\/]')).last,
                        style: const TextStyle(fontSize: 13, fontWeight: FontWeight.w700, color: CyberTheme.textPrimary),
                      ),
                      const SizedBox(width: 16),
                      Expanded(
                        child: Text(
                          'SHA-256: ${record.originalFileHash}',
                          style: const TextStyle(fontSize: 10, fontFamily: 'monospace', color: CyberTheme.textMuted),
                          overflow: TextOverflow.ellipsis,
                        ),
                      ),
                      Container(
                        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                        decoration: BoxDecoration(
                          color: CyberTheme.surface,
                          borderRadius: BorderRadius.circular(6),
                          border: Border.all(color: CyberTheme.border),
                        ),
                        child: Text(
                          record.timestamp.toLocal().toString().substring(0, 16),
                          style: const TextStyle(fontSize: 10, color: CyberTheme.textMuted, fontFamily: 'monospace'),
                        ),
                      ),
                    ],
                  ),
                );
              },
            ),
        ],
      ),
    );
  }



  Future<void> _pickAndIngestFile() async {
    final result = await FilePicker.platform.pickFiles();
    if (result != null && result.files.isNotEmpty) {
      if (kIsWeb) {
        final bytes = result.files.single.bytes;
        final name = result.files.single.name;
        if (bytes != null) {
          ref.read(provenanceTaskNotifierProvider.notifier).ingestFile(XFile.fromData(bytes, name: name));
        }
      } else {
        final pickedPath = result.files.single.path;
        if (pickedPath != null) {
          ref.read(provenanceTaskNotifierProvider.notifier).ingestFile(XFile(pickedPath));
        }
      }
    }
  }
}

/// Hardware Accelerated Heatmap Renderer for Perceptual Hash
class CyberHeatMapRenderer extends CustomPainter {
  final List<double> vector;

  CyberHeatMapRenderer(this.vector);

  @override
  void paint(Canvas canvas, Size size) {
    if (vector.isEmpty) return;
    final paint = Paint()..style = PaintingStyle.fill;
    const int gridSize = 16;
    final cellWidth = size.width / gridSize;
    final cellHeight = size.height / gridSize;

    for (int i = 0; i < 256; i++) {
      if (i >= vector.length) break;
      final row = i ~/ gridSize;
      final col = i % gridSize;
      final rect = Rect.fromLTWH(col * cellWidth, row * cellHeight, cellWidth, cellHeight);

      final intensity = vector[i];
      if (intensity < 0.3) {
        paint.color = CyberTheme.surfaceElevated;
      } else if (intensity < 0.7) {
        paint.color = CyberTheme.shardColor.withValues(alpha: intensity);
      } else {
        paint.color = CyberTheme.accentColor.withValues(alpha: intensity);
      }
      canvas.drawRect(rect, paint);
    }
  }

  @override
  bool shouldRepaint(covariant CyberHeatMapRenderer oldDelegate) {
    return oldDelegate.vector != vector;
  }
}

/// Ultra-Premium Obsidian Glass Account Popover Card
class _LuxuryAccountPopover extends StatelessWidget {
  final UserProfile profile;
  final VoidCallback onOpenProfile;
  final VoidCallback onSignOut;

  const _LuxuryAccountPopover({
    required this.profile,
    required this.onOpenProfile,
    required this.onSignOut,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      width: 320,
      decoration: BoxDecoration(
        borderRadius: BorderRadius.circular(22),
        gradient: const LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [
            Color(0xFA160F2B),
            Color(0xFD0B0616),
          ],
        ),
        border: Border.all(
          color: const Color(0x35C084FC),
          width: 1.2,
        ),
        boxShadow: [
          BoxShadow(
            color: Colors.black.withValues(alpha: 0.75),
            blurRadius: 36,
            offset: const Offset(0, 16),
            spreadRadius: 4,
          ),
          BoxShadow(
            color: CyberTheme.accentColor.withValues(alpha: 0.22),
            blurRadius: 28,
            spreadRadius: -2,
          ),
        ],
      ),
      child: ClipRRect(
        borderRadius: BorderRadius.circular(22),
        child: BackdropFilter(
          filter: ImageFilter.blur(sigmaX: 30, sigmaY: 30),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch,
            children: [
              // Header: Identity Info & Online Node Badge
              Padding(
                padding: const EdgeInsets.all(18),
                child: Row(
                  children: [
                    Stack(
                      children: [
                        Container(
                          width: 44,
                          height: 44,
                          decoration: BoxDecoration(
                            shape: BoxShape.circle,
                            gradient: const LinearGradient(
                              colors: [Color(0xFFC084FC), Color(0xFF7C3AED)],
                              begin: Alignment.topLeft,
                              end: Alignment.bottomRight,
                            ),
                            boxShadow: [
                              BoxShadow(
                                color: const Color(0xFFC084FC).withValues(alpha: 0.45),
                                blurRadius: 14,
                                spreadRadius: 1,
                              ),
                            ],
                          ),
                          child: Center(
                            child: Text(
                              profile.initials,
                              style: GoogleFonts.plusJakartaSans(
                                color: Colors.white,
                                fontWeight: FontWeight.w900,
                                fontSize: 14,
                              ),
                            ),
                          ),
                        ),
                        Positioned(
                          right: 0,
                          bottom: 0,
                          child: Container(
                            width: 12,
                            height: 12,
                            decoration: BoxDecoration(
                              color: const Color(0xFF10B981),
                              shape: BoxShape.circle,
                              border: Border.all(color: const Color(0xFF130D24), width: 2),
                            ),
                          ),
                        ),
                      ],
                    ),
                    const SizedBox(width: 14),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        mainAxisSize: MainAxisSize.min,
                        children: [
                          Row(
                            children: [
                              Flexible(
                                child: Text(
                                  profile.displayName,
                                  style: GoogleFonts.plusJakartaSans(
                                    fontSize: 14,
                                    fontWeight: FontWeight.w800,
                                    color: Colors.white,
                                  ),
                                  overflow: TextOverflow.ellipsis,
                                ),
                              ),
                              const SizedBox(width: 6),
                              Container(
                                padding: const EdgeInsets.symmetric(horizontal: 5, vertical: 1.5),
                                decoration: BoxDecoration(
                                  color: const Color(0x22C084FC),
                                  borderRadius: BorderRadius.circular(100),
                                  border: Border.all(color: const Color(0x44C084FC)),
                                ),
                                child: Text(
                                  'NODE',
                                  style: GoogleFonts.jetBrainsMono(
                                    fontSize: 8,
                                    fontWeight: FontWeight.w900,
                                    color: const Color(0xFFC084FC),
                                  ),
                                ),
                              ),
                            ],
                          ),
                          const SizedBox(height: 3),
                          Text(
                            profile.email,
                            style: GoogleFonts.plusJakartaSans(
                              fontSize: 11.5,
                              color: const Color(0xFF94A3B8),
                            ),
                            overflow: TextOverflow.ellipsis,
                          ),
                        ],
                      ),
                    ),
                  ],
                ),
              ),

              // Soft Translucent Divider
              Container(
                height: 1,
                margin: const EdgeInsets.symmetric(horizontal: 14),
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: [
                      Colors.transparent,
                      Colors.white.withValues(alpha: 0.10),
                      Colors.transparent,
                    ],
                  ),
                ),
              ),
              const SizedBox(height: 6),

              // Menu Tile 1: User Profile
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 3),
                child: _LuxuryMenuTile(
                  icon: Icons.person_rounded,
                  accentColor: const Color(0xFFC084FC),
                  title: 'User Profile',
                  subtitle: 'Identity, keys & security',
                  onTap: onOpenProfile,
                ),
              ),

              // Soft Translucent Divider
              Container(
                height: 1,
                margin: const EdgeInsets.symmetric(horizontal: 14, vertical: 4),
                decoration: BoxDecoration(
                  gradient: LinearGradient(
                    colors: [
                      Colors.transparent,
                      Colors.white.withValues(alpha: 0.08),
                      Colors.transparent,
                    ],
                  ),
                ),
              ),

              // Menu Tile 2: Sign Out
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 3),
                child: _LuxuryMenuTile(
                  icon: Icons.logout_rounded,
                  accentColor: const Color(0xFFF43F5E),
                  title: 'Sign Out',
                  subtitle: 'Disconnect secure session',
                  isDestructive: true,
                  onTap: onSignOut,
                ),
              ),

              const SizedBox(height: 8),

              // Footer: Protocol Info Chip
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 9),
                decoration: BoxDecoration(
                  color: Colors.black.withValues(alpha: 0.25),
                  border: Border(
                    top: BorderSide(
                      color: Colors.white.withValues(alpha: 0.05),
                      width: 1,
                    ),
                  ),
                ),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    Text(
                      'OBSIDIAN PROTOCOL',
                      style: GoogleFonts.jetBrainsMono(
                        fontSize: 8.5,
                        fontWeight: FontWeight.w700,
                        letterSpacing: 0.8,
                        color: const Color(0x70FFFFFF),
                      ),
                    ),
                    Row(
                      children: [
                        Container(
                          width: 6,
                          height: 6,
                          decoration: const BoxDecoration(
                            color: Color(0xFF10B981),
                            shape: BoxShape.circle,
                          ),
                        ),
                        const SizedBox(width: 5),
                        Text(
                          'ONLINE',
                          style: GoogleFonts.jetBrainsMono(
                            fontSize: 8.5,
                            fontWeight: FontWeight.w800,
                            letterSpacing: 0.6,
                            color: const Color(0xFF10B981),
                          ),
                        ),
                      ],
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class _LuxuryMenuTile extends StatefulWidget {
  final IconData icon;
  final Color accentColor;
  final String title;
  final String subtitle;
  final VoidCallback onTap;
  final bool isDestructive;

  const _LuxuryMenuTile({
    required this.icon,
    required this.accentColor,
    required this.title,
    required this.subtitle,
    required this.onTap,
    this.isDestructive = false,
  });

  @override
  State<_LuxuryMenuTile> createState() => _LuxuryMenuTileState();
}

class _LuxuryMenuTileState extends State<_LuxuryMenuTile> {
  bool _isHovered = false;

  @override
  Widget build(BuildContext context) {
    final hoverBg = widget.isDestructive
        ? const Color(0x1EF43F5E)
        : widget.accentColor.withValues(alpha: 0.12);
    final hoverBorder = widget.isDestructive
        ? const Color(0x40F43F5E)
        : widget.accentColor.withValues(alpha: 0.25);

    return MouseRegion(
      cursor: SystemMouseCursors.click,
      onEnter: (_) => setState(() => _isHovered = true),
      onExit: (_) => setState(() => _isHovered = false),
      child: InkWell(
        onTap: widget.onTap,
        borderRadius: BorderRadius.circular(14),
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 180),
          curve: Curves.easeOutCubic,
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          decoration: BoxDecoration(
            color: _isHovered ? hoverBg : Colors.transparent,
            borderRadius: BorderRadius.circular(14),
            border: Border.all(
              color: _isHovered ? hoverBorder : Colors.transparent,
              width: 1,
            ),
          ),
          child: Row(
            children: [
              Container(
                width: 34,
                height: 34,
                decoration: BoxDecoration(
                  color: widget.accentColor.withValues(alpha: _isHovered ? 0.24 : 0.14),
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(
                    color: widget.accentColor.withValues(alpha: _isHovered ? 0.5 : 0.25),
                    width: 1,
                  ),
                ),
                child: Icon(
                  widget.icon,
                  size: 17,
                  color: widget.isDestructive ? const Color(0xFFFB7185) : widget.accentColor,
                ),
              ),
              const SizedBox(width: 12),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  mainAxisSize: MainAxisSize.min,
                  children: [
                    Text(
                      widget.title,
                      style: GoogleFonts.plusJakartaSans(
                        fontSize: 13,
                        fontWeight: FontWeight.w700,
                        color: widget.isDestructive
                            ? const Color(0xFFFB7185)
                            : Colors.white,
                      ),
                    ),
                    const SizedBox(height: 1.5),
                    Text(
                      widget.subtitle,
                      style: GoogleFonts.plusJakartaSans(
                        fontSize: 10.5,
                        color: const Color(0xFF94A3B8),
                      ),
                    ),
                  ],
                ),
              ),
              AnimatedSlide(
                duration: const Duration(milliseconds: 180),
                offset: Offset(_isHovered ? 0.12 : 0.0, 0),
                child: Icon(
                  Icons.chevron_right_rounded,
                  size: 16,
                  color: _isHovered
                      ? (widget.isDestructive ? const Color(0xFFFB7185) : Colors.white)
                      : const Color(0x50FFFFFF),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
