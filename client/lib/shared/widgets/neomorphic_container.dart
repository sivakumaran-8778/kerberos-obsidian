import 'package:flutter/material.dart';

// Forensic Light Neomorphism Palette
const Color kNeomorphicBaseColor = Color(0xFFE0E5EC);
const Color kHighlightColor = Color(0xFFFFFFFF);
const Color kShadowColor = Color(0xFFA3B1C6);
const Color kAccentColor = Color(0xFF2980B9); // Forensic Blue
const Color kTextColor = Color(0xFF2C3E50); // High-contrast charcoal
const Color kAlertColor = Color(0xFFE74C3C); // Forensic Red for silent alerts

/// Core reusable container that enforces the clean-room Light Neomorphic aesthetic.
class NeomorphicContainer extends StatelessWidget {
  final Widget child;
  final EdgeInsetsGeometry padding;
  final double borderRadius;
  final bool depressed;
  final double? width;
  final double? height;

  const NeomorphicContainer({
    super.key,
    required this.child,
    this.padding = const EdgeInsets.all(20),
    this.borderRadius = 16.0,
    this.depressed = false,
    this.width,
    this.height,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      width: width,
      height: height,
      padding: padding,
      decoration: BoxDecoration(
        color: kNeomorphicBaseColor,
        borderRadius: BorderRadius.circular(borderRadius),
        // Simulating the depressed inner-shadow effect natively
        border: depressed ? Border.all(color: Colors.white60, width: 2) : null,
        boxShadow: depressed
            ? null
            : [
                // Bottom-Right Soft Grey Extrusion Shadow
                const BoxShadow(
                  color: kShadowColor,
                  offset: Offset(8, 8),
                  blurRadius: 16,
                  spreadRadius: 1,
                ),
                // Top-Left Pure White Highlight
                const BoxShadow(
                  color: kHighlightColor,
                  offset: Offset(-8, -8),
                  blurRadius: 16,
                  spreadRadius: 1,
                ),
              ],
        gradient: depressed
            ? const LinearGradient(
                begin: Alignment.topLeft,
                end: Alignment.bottomRight,
                colors: [
                  kShadowColor,
                  kHighlightColor,
                ],
              )
            : null,
      ),
      child: child,
    );
  }
}
