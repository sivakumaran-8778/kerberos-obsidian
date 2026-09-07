import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

/// Ultra-Rich Amethyst & Prismatic Theme for Project Kerberos.
/// Saturated, vibrant luxury dark mode with rich glowing depths.
class CyberTheme {
  // Deep Saturated Midnight Amethyst
  static const Color background = Color(0xFF0C0814); // Rich velvet black with violet undertone
  static const Color backgroundRadial = Color(0xFF240E3E); // Glowing radiant purple core
  
  // Vibrant Prismatic Shard Palette (High Saturation)
  static const Color shardColor = Color(0xFFA78BFA); // Electric vibrant lavender
  static const Color shardGlow = Color(0xFFC084FC); // Radiant purple-orchid
  static const Color accentColor = Color(0xFFA855F7); // Electric purple accent
  static const Color accentVibrant = Color(0xFF9333EA); // High-saturation royal violet
  static const Color accentDeep = Color(0xFF7C3AED); // Deep indigo-violet

  // Surface Glassmorphism
  static const Color surface = Color(0xFF161026); // Deep rich glass
  static const Color surfaceElevated = Color(0xFF23183C); // Elevated rich amethyst glass
  static const Color surfaceGlass = Color(0xEE161026); // Translucent backdrop overlay

  // Precision Glass Borders
  static const Color border = Color(0x2EFFFFFF); // 18% crisp white luxury edge
  static const Color borderBright = Color(0x4DFFFFFF); // 30% white on hover
  static const Color borderAccent = Color(0x88A855F7); // Luminous electric purple border
  static const Color borderShard = Color(0x77A78BFA); // Electric lavender border
  static const Color borderEmerald = Color(0x8810B981); // Radiant emerald border
  static const Color borderCyan = Color(0x8806B6D4); // Neon cyan border

  // Chromatic Edge Dispersions
  static const Color cyan = Color(0xFF06B6D4); // Neon cyan chromatic edge
  static const Color cyanLight = Color(0xFF38BDF8);
  static const Color cyanGlow = Color(0xFF22D3EE);
  static const Color emerald = Color(0xFF10B981); // Luminous emerald verified state
  static const Color emeraldLight = Color(0xFF34D399);
  static const Color emeraldGlow = Color(0xFF059669);
  static const Color coral = Color(0xFFF43F5E); // Chromatic aberration ruby/magenta
  static const Color indigo = Color(0xFFA855F7);

  // High-Contrast Typography
  static const Color textPrimary = Color(0xFFFFFFFF);
  static const Color textSecondary = Color(0xFFD4C8EC); // Rich readable lavender-grey
  static const Color textMuted = Color(0xFF9482B3); // Muted amethyst-grey

  // Rich Gradients
  static const LinearGradient shardGradient = LinearGradient(
    colors: [Color(0xFFC084FC), Color(0xFF9333EA), Color(0xFF7C3AED)],
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
  );

  static const LinearGradient accentGradient = LinearGradient(
    colors: [Color(0xFFA855F7), Color(0xFF6366F1)],
    begin: Alignment.topLeft,
    end: Alignment.bottomRight,
  );

  static const RadialGradient ambientGlowGradient = RadialGradient(
    colors: [
      Color(0x557C3AED),
      Color(0x224C1D95),
      Colors.transparent,
    ],
    radius: 0.8,
  );

  static const LinearGradient glassSheenGradient = LinearGradient(
    colors: [
      Color(0x28FFFFFF),
      Color(0x08FFFFFF),
      Color(0x00FFFFFF),
    ],
    begin: Alignment.topCenter,
    end: Alignment.bottomCenter,
  );

  static TextStyle font({
    double? fontSize,
    FontWeight? fontWeight,
    Color? color,
    double? letterSpacing,
    double? height,
  }) {
    return GoogleFonts.plusJakartaSans(
      fontSize: fontSize,
      fontWeight: fontWeight,
      color: color ?? textPrimary,
      letterSpacing: letterSpacing,
      height: height,
    );
  }

  static TextStyle monoFont({
    double? fontSize,
    FontWeight? fontWeight,
    Color? color,
    double? letterSpacing,
  }) {
    return GoogleFonts.jetBrainsMono(
      fontSize: fontSize,
      fontWeight: fontWeight,
      color: color ?? textPrimary,
      letterSpacing: letterSpacing,
    );
  }

  static ThemeData get darkTheme {
    final baseTextTheme = GoogleFonts.plusJakartaSansTextTheme(ThemeData.dark().textTheme);

    return ThemeData.dark().copyWith(
      scaffoldBackgroundColor: background,
      primaryColor: accentColor,
      colorScheme: const ColorScheme.dark(
        primary: accentColor,
        secondary: shardColor,
        surface: surface,
        error: coral,
      ),
      iconTheme: const IconThemeData(color: textPrimary),
      textTheme: baseTextTheme.copyWith(
        displayLarge: GoogleFonts.plusJakartaSans(
          color: textPrimary,
          fontSize: 46,
          fontWeight: FontWeight.w900,
          letterSpacing: -1.2,
          height: 1.15,
        ),
        displayMedium: GoogleFonts.plusJakartaSans(
          color: textPrimary,
          fontSize: 34,
          fontWeight: FontWeight.w800,
          letterSpacing: -0.9,
          height: 1.2,
        ),
        headlineLarge: GoogleFonts.plusJakartaSans(
          color: textPrimary,
          fontSize: 24,
          fontWeight: FontWeight.w800,
          letterSpacing: -0.5,
        ),
        headlineMedium: GoogleFonts.plusJakartaSans(
          color: textPrimary,
          fontSize: 18,
          fontWeight: FontWeight.w700,
          letterSpacing: -0.3,
        ),
        headlineSmall: GoogleFonts.plusJakartaSans(
          color: textPrimary,
          fontSize: 15,
          fontWeight: FontWeight.w700,
          letterSpacing: 0.1,
        ),
        titleMedium: GoogleFonts.plusJakartaSans(
          color: textPrimary,
          fontSize: 13,
          fontWeight: FontWeight.w600,
        ),
        bodyLarge: GoogleFonts.plusJakartaSans(
          color: textPrimary,
          fontSize: 14,
          fontWeight: FontWeight.w500,
        ),
        bodyMedium: GoogleFonts.plusJakartaSans(
          color: textSecondary,
          fontSize: 13,
          fontWeight: FontWeight.w400,
          height: 1.6,
        ),
        bodySmall: GoogleFonts.jetBrainsMono(
          color: textMuted,
          fontSize: 11,
          fontWeight: FontWeight.w500,
        ),
      ),
    );
  }
}
