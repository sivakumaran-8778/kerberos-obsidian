import 'package:flutter/material.dart';
import '../theme/cyber_theme.dart';

enum CyberButtonVariant {
  whitePill, // Solid white pill with dark text (Obsidian Protocol primary)
  glassPill, // Dark translucent glass pill with subtle border
  purple,    // Electric purple accent pill (#A855F7)
  primary,
  emerald,
  gradient,
  glass,
  danger,
}

class CyberButton extends StatefulWidget {
  final Widget child;
  final VoidCallback? onTap;
  final CyberButtonVariant variant;
  final IconData? icon;
  final bool isLoading;
  final double? width;
  final double height;
  final EdgeInsetsGeometry padding;
  final bool isExpanded;
  final double borderRadius;
  final bool enableHoverPop;

  const CyberButton({
    super.key,
    required this.child,
    this.onTap,
    this.variant = CyberButtonVariant.whitePill,
    this.icon,
    this.isLoading = false,
    this.width,
    this.height = 42,
    this.padding = const EdgeInsets.symmetric(horizontal: 22),
    this.isExpanded = false,
    this.borderRadius = 100.0, // Default to rounded-full pill
    this.enableHoverPop = true,
  });

  @override
  State<CyberButton> createState() => _CyberButtonState();
}

class _CyberButtonState extends State<CyberButton> {
  bool _isHovered = false;
  bool _isPressed = false;

  @override
  Widget build(BuildContext context) {
    Color? bgColor;
    Gradient? bgGradient;
    Color borderColor;
    Color glowColor;
    Color textColor;

    switch (widget.variant) {
      case CyberButtonVariant.whitePill:
        bgColor = _isHovered ? Colors.white : const Color(0xFFF8FAFC);
        borderColor = _isHovered ? const Color(0xFFE9D5FF) : const Color(0xFFE2E8F0);
        glowColor = const Color(0xFFA855F7);
        textColor = const Color(0xFF0F0B1E);
        break;
      case CyberButtonVariant.glassPill:
        bgColor = _isHovered ? const Color(0x28FFFFFF) : const Color(0x14FFFFFF);
        borderColor = _isHovered ? const Color(0x80C084FC) : const Color(0x28FFFFFF);
        glowColor = const Color(0xFFA855F7);
        textColor = Colors.white;
        break;
      case CyberButtonVariant.purple:
        bgColor = _isHovered ? const Color(0xFF9333EA) : CyberTheme.accentColor;
        borderColor = const Color(0xFFC084FC);
        glowColor = CyberTheme.accentColor;
        textColor = Colors.white;
        break;
      case CyberButtonVariant.gradient:
        bgGradient = _isHovered
            ? const LinearGradient(
                colors: [Color(0xFF9333EA), Color(0xFF6366F1)],
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
              )
            : CyberTheme.shardGradient;
        borderColor = const Color(0x66A855F7);
        glowColor = CyberTheme.accentColor;
        textColor = Colors.white;
        break;
      case CyberButtonVariant.primary:
        bgColor = _isHovered ? const Color(0xFF9333EA) : CyberTheme.accentColor;
        borderColor = const Color(0xFFC084FC);
        glowColor = CyberTheme.accentColor;
        textColor = Colors.white;
        break;
      case CyberButtonVariant.emerald:
        bgColor = _isHovered ? const Color(0xFF059669) : CyberTheme.emerald;
        borderColor = CyberTheme.emeraldLight;
        glowColor = CyberTheme.emerald;
        textColor = const Color(0xFF021B12);
        break;
      case CyberButtonVariant.danger:
        bgColor = _isHovered ? const Color(0xFFE11D48) : CyberTheme.coral;
        borderColor = const Color(0xFFFB7185);
        glowColor = CyberTheme.coral;
        textColor = Colors.white;
        break;
      case CyberButtonVariant.glass:
        bgColor = _isHovered ? CyberTheme.surfaceElevated : CyberTheme.surface;
        borderColor = _isHovered ? CyberTheme.borderBright : CyberTheme.border;
        glowColor = CyberTheme.accentColor;
        textColor = CyberTheme.textPrimary;
        break;
    }

    final isPopActive = _isHovered && !widget.isLoading && widget.onTap != null && widget.enableHoverPop;

    Widget content = AnimatedContainer(
      duration: const Duration(milliseconds: 260),
      curve: Curves.easeOutCubic,
      width: widget.isExpanded ? double.infinity : widget.width,
      height: widget.height,
      padding: widget.padding,
      decoration: BoxDecoration(
        color: bgColor,
        gradient: bgGradient,
        borderRadius: BorderRadius.circular(widget.borderRadius),
        border: Border.all(color: borderColor, width: 1.0),
        boxShadow: _isHovered && widget.onTap != null
            ? [
                BoxShadow(
                  color: glowColor.withValues(
                    alpha: widget.variant == CyberButtonVariant.whitePill ? 0.32 : 0.40,
                  ),
                  blurRadius: widget.enableHoverPop ? 22 : 14,
                  spreadRadius: widget.enableHoverPop ? 1 : 0,
                  offset: widget.enableHoverPop ? const Offset(0, 6) : const Offset(0, 2),
                ),
                if (widget.enableHoverPop)
                  BoxShadow(
                    color: const Color(0xFFA855F7).withValues(
                      alpha: widget.variant == CyberButtonVariant.whitePill ? 0.20 : 0.28,
                    ),
                    blurRadius: 36,
                    spreadRadius: 2,
                    offset: const Offset(0, 10),
                  ),
              ]
            : null,
      ),
      child: Center(
        child: widget.isLoading
            ? SizedBox(
                width: 18,
                height: 18,
                child: CircularProgressIndicator(
                  strokeWidth: 2,
                  valueColor: AlwaysStoppedAnimation<Color>(textColor),
                ),
              )
            : Row(
                mainAxisSize: MainAxisSize.min,
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  if (widget.icon != null) ...[
                    AnimatedSlide(
                      duration: const Duration(milliseconds: 260),
                      curve: Curves.easeOutCubic,
                      offset: Offset(isPopActive ? 0.08 : 0.0, 0),
                      child: Icon(widget.icon, size: 16, color: textColor),
                    ),
                    const SizedBox(width: 8),
                  ],
                  DefaultTextStyle(
                    style: TextStyle(
                      color: textColor,
                      fontSize: 13,
                      fontWeight: FontWeight.w700,
                      letterSpacing: 0.3,
                    ),
                    child: widget.child,
                  ),
                ],
              ),
      ),
    );

    return MouseRegion(
      cursor: widget.onTap != null && !widget.isLoading
          ? SystemMouseCursors.click
          : SystemMouseCursors.basic,
      onEnter: (_) => setState(() => _isHovered = true),
      onExit: (_) => setState(() => _isHovered = false),
      child: GestureDetector(
        onTapDown: (_) => setState(() => _isPressed = true),
        onTapUp: (_) => setState(() => _isPressed = false),
        onTapCancel: () => setState(() => _isPressed = false),
        onTap: widget.isLoading ? null : widget.onTap,
        child: AnimatedSlide(
          offset: Offset(0, isPopActive ? -0.07 : 0.0),
          duration: const Duration(milliseconds: 260),
          curve: Curves.easeOutCubic,
          child: AnimatedScale(
            scale: _isPressed ? 0.97 : (isPopActive ? 1.028 : 1.0),
            duration: const Duration(milliseconds: 260),
            curve: Curves.easeOutCubic,
            child: content,
          ),
        ),
      ),
    );
  }
}
