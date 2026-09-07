import 'package:flutter/material.dart';
import 'neomorphic_container.dart';

/// Reusable Light Neomorphic Button with tactile depressed state animations.
class NeomorphicButton extends StatefulWidget {
  final Widget child;
  final VoidCallback onTap;
  final bool isExpanded;

  const NeomorphicButton({
    super.key,
    required this.child,
    required this.onTap,
    this.isExpanded = false,
  });

  @override
  State<NeomorphicButton> createState() => _NeomorphicButtonState();
}

class _NeomorphicButtonState extends State<NeomorphicButton> {
  bool _isPressed = false;

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTapDown: (_) => setState(() => _isPressed = true),
      onTapUp: (_) {
        setState(() => _isPressed = false);
        widget.onTap();
      },
      onTapCancel: () => setState(() => _isPressed = false),
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 100),
        width: widget.isExpanded ? double.infinity : null,
        child: NeomorphicContainer(
          depressed: _isPressed,
          padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 16),
          child: Center(
            widthFactor: widget.isExpanded ? null : 1.0,
            child: widget.child,
          ),
        ),
      ),
    );
  }
}
